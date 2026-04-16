#include "dumper.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <vector>

#include "iat_rebuilder.hpp"
#include "section_cleaner.hpp"
#include "simply_log.hpp"
#include "themida_stubs.hpp"

namespace simply {

namespace {

constexpr std::size_t kPageSize = 0x1000;

// unreadable = uncommitted or PAGE_NOACCESS / PAGE_GUARD; RPM would fail, leave zeros
bool page_is_readable(HANDLE process, std::uintptr_t addr, std::size_t& region_end) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) != sizeof(mbi)) {
        region_end = addr + kPageSize;
        return false;
    }
    region_end = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    return true;
}

DWORD align_up(DWORD value, DWORD alignment) {
    if (alignment == 0) return value;
    const DWORD rem = value % alignment;
    return rem ? value + (alignment - rem) : value;
}

/*
   turn the RVA-layout snapshot into a valid PE:
     FileAlignment := SectionAlignment (so raw offsets == virtual)
     PointerToRawData := VirtualAddress
     SizeOfRawData := aligned VirtualSize
     AddressOfEntryPoint := OEP RVA
   imports aren't touched, IAT rebuild handles those
 */
bool fix_pe_headers(std::vector<std::uint8_t>& image, std::uint32_t oep_rva) {
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return false;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        log::error("rebuild: dump does not start with a DOS header");
        return false;
    }

    const std::size_t nt_off = static_cast<std::size_t>(dos->e_lfanew);
    if (nt_off + sizeof(IMAGE_NT_HEADERS) > image.size()) return false;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(image.data() + nt_off);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        log::error("rebuild: missing PE\\0\\0 signature");
        return false;
    }

    const DWORD section_alignment = nt->OptionalHeader.SectionAlignment;
    if (section_alignment == 0) {
        log::error("rebuild: SectionAlignment is zero");
        return false;
    }

    // standard dumper trick: raw == virtual, FileAlignment = SectionAlignment
    nt->OptionalHeader.FileAlignment = section_alignment;
    nt->OptionalHeader.AddressOfEntryPoint = oep_rva;
    nt->OptionalHeader.SizeOfHeaders =
        align_up(nt->OptionalHeader.SizeOfHeaders, section_alignment);

    auto* section = IMAGE_FIRST_SECTION(nt);
    const unsigned count = nt->FileHeader.NumberOfSections;
    for (unsigned i = 0; i < count; ++i, ++section) {
        section->PointerToRawData = section->VirtualAddress;
        section->SizeOfRawData = align_up(section->Misc.VirtualSize, section_alignment);
    }

    return true;
}

/*
   rewrite OptionalHeader.ImageBase back to the input PE's preferred base and
   sweep the dump for 8-byte values that look like pointers into the runtime
   image, shifting them by the same delta. ASLR hands Themida-protected
   processes a high base (e.g. 0x7ff7c3200000) that gets baked into every
   absolute pointer the unpacker resolved during init (vtables, function
   tables, FindWindow class-name arrays, anything in writable data). without
   this rebase the dump loads at a giant kernel-mode-ish VA, IDA labels every
   function sub_7FF7C32xxxxx, and the dump only runs at that one address.

   only data sections are scanned. code uses RIP-relative addressing in x64 so
   absolute pointers are vanishingly rare there and the false-positive risk of
   corrupting an instruction is real. headers excluded too, ImageBase gets a
   direct write below
 */
void rebase_image(std::vector<std::uint8_t>& image, std::uint64_t old_base, std::uint64_t new_base, std::uint32_t size_of_image) {
    if (old_base == new_base) return;
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    const std::uint64_t lo = old_base;
    const std::uint64_t hi = old_base + size_of_image;
    const std::int64_t  delta = static_cast<std::int64_t>(new_base) - static_cast<std::int64_t>(old_base);

    std::size_t patched = 0;
    auto* section = IMAGE_FIRST_SECTION(nt);
    const unsigned count = nt->FileHeader.NumberOfSections;
    for (unsigned i = 0; i < count; ++i, ++section) {
        // skip executable sections; x64 RIP-relative means absolute pointers in code are rare, false-positives corrupt instructions
        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) continue;
        // skip sections with no on-disk content (.stub placeholders left by section_cleaner)
        if (section->SizeOfRawData == 0) continue;

        const std::size_t off = section->PointerToRawData;
        const std::size_t len = section->SizeOfRawData;
        if (off + len > image.size()) continue;

        // pointers in initialised data are 8-byte aligned in MSVC output, step by 8
        for (std::size_t p = (off + 7) & ~std::size_t{7}; p + 8 <= off + len; p += 8) {
            std::uint64_t v;
            std::memcpy(&v, image.data() + p, sizeof(v));
            if (v >= lo && v < hi) {
                v = static_cast<std::uint64_t>(static_cast<std::int64_t>(v) + delta);
                std::memcpy(image.data() + p, &v, sizeof(v));
                ++patched;
            }
        }
    }

    nt->OptionalHeader.ImageBase = new_base;

    log::info("rebase: ImageBase 0x{:x} -> 0x{:x}, patched {} pointer(s) in data sections",
              old_base, new_base, patched);
}

}  // namespace

bool dump_image(void* process_handle, std::uint64_t image_base, std::uint64_t preferred_image_base, std::uint32_t size_of_image, std::uint64_t oep_va, const std::filesystem::path& output_path, const CaptureResult* capture) {
    auto* process = static_cast<HANDLE>(process_handle);

    // snapshot the whole image as the loader laid it out; sections keep their virtual layout
    std::vector<std::uint8_t> buffer(size_of_image, 0);

    std::size_t bytes_read = 0;
    std::size_t holes = 0;

    std::uintptr_t cursor = static_cast<std::uintptr_t>(image_base);
    const std::uintptr_t end = cursor + size_of_image;

    while (cursor < end) {
        std::size_t region_end = 0;
        const bool readable = page_is_readable(process, cursor, region_end);
        if (region_end > end) region_end = end;
        if (region_end <= cursor) {
            region_end = cursor + kPageSize;
            if (region_end > end) region_end = end;
        }

        const std::size_t len = region_end - cursor;
        if (readable) {
            SIZE_T got = 0;
            const std::size_t off = cursor - static_cast<std::uintptr_t>(image_base);
            if (ReadProcessMemory(process, reinterpret_cast<LPCVOID>(cursor),
                                  buffer.data() + off, len, &got) && got > 0) {
                bytes_read += got;
            } else {
                ++holes;
            }
        } else {
            ++holes;
        }

        cursor = region_end;
    }

    if (oep_va < image_base) {
        log::error("rebuild: OEP 0x{:x} is below image base 0x{:x}", oep_va, image_base);
        return false;
    }
    const auto oep_rva = static_cast<std::uint32_t>(oep_va - image_base);

    // rebuild imports BEFORE header fixup so the new section's raw size gets aligned by the header pass
    rebuild_iat(process_handle, buffer, image_base);

    if (!fix_pe_headers(buffer, oep_rva)) return false;

    /*
     * for stubs the static walker can't peel (themida VM-Macro), turn the
     * captured runtime landings into proper IAT slots in .simply so the
     * rewritten call sites survive ASLR on the next load
     */
    std::unordered_map<std::uint64_t, std::uint32_t> stub_iat_overrides;
    if (capture && !capture->stub_to_api.empty()) {
        const auto api_to_iat = extend_iat_for_captures(
            process_handle, buffer, image_base, capture->stub_to_api);
        // join: stub_va -> api_va -> iat_rva
        for (const auto& [stub_va, api_va] : capture->stub_to_api) {
            auto it = api_to_iat.find(api_va);
            if (it != api_to_iat.end()) stub_iat_overrides[stub_va] = it->second;
        }
    }

    /*
     * for themida-poisoned data slots (e.g. .idata entries that originally
     * pointed at real apis but now hold stub VAs), add IMPORT descriptors
     * with FirstThunk = existing_slot_rva so the loader fills the slot with
     * the real api on next load. no slot rewriting needed, the original
     * `mov rax,[slot]; call rax` works as-is
     */
    if (capture && !capture->slot_to_stub.empty() && !capture->stub_to_api.empty()) {
        rebind_poisoned_slots(process_handle, buffer, image_base,
                              capture->slot_to_stub, capture->stub_to_api);
    }

    /*
     * retarget call sites still reaching into packer sections via themida api
     * stubs. uses static FF25/E9/EB chain walk first, then the
     * stub_va -> iat_rva override map for VM stubs. after this .text should
     * have no xrefs into .themida so it can be dropped
     */
    rewrite_themida_stubs(buffer, image_base,
                          stub_iat_overrides.empty() ? nullptr : &stub_iat_overrides);

    // drop packer sections, rename blank ones, repack
    clean_dump(buffer, oep_rva);

    /*
     * collapse runtime ASLR base back to the input PE's preferred base. makes
     * IDA labels match what a non-protected build would produce and gives the
     * dump a portable load address instead of pinning it to one ASLR slot
     * that probably won't be free on the next process
     */
    rebase_image(buffer, image_base, preferred_image_base, size_of_image);

    std::ofstream out(output_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        log::error("dump: failed to open {} for writing", output_path.string());
        return false;
    }
    out.write(reinterpret_cast<const char*>(buffer.data()),
              static_cast<std::streamsize>(buffer.size()));
    if (!out) {
        log::error("dump: write failed for {}", output_path.string());
        return false;
    }

    log::info("dumped {} bytes to {} ({} unreadable region(s) zeroed)",
              bytes_read, output_path.string(), holes);
    log::info("rebuilt PE: entry_point=0x{:x} (RVA 0x{:x})",
              preferred_image_base + oep_rva, oep_rva);
    return true;
}

}  // namespace simply

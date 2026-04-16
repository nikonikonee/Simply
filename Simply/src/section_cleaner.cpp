#include "section_cleaner.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>

#include "simply_log.hpp"

namespace simply {

namespace {

// themida 2.x/3.x + common alt-packer sigs found next to themida builds
constexpr std::array<std::string_view, 9> kPackerNames = {
    ".themida", ".boot", ".winlice", "WinLicen",
    ".vmp0", ".vmp1",
    ".mpress1", ".mpress2",
    ".enigma1"
};

DWORD align_up(DWORD value, DWORD alignment) {
    if (alignment == 0) return value;
    const DWORD rem = value % alignment;
    return rem ? value + (alignment - rem) : value;
}

std::string section_name(const IMAGE_SECTION_HEADER& s) {
    char buf[9] = {};
    std::memcpy(buf, s.Name, 8);
    return std::string(buf);
}

bool is_packer_section(const IMAGE_SECTION_HEADER& s) {
    const std::string n = section_name(s);
    return std::any_of(kPackerNames.begin(), kPackerNames.end(),
                       [&](std::string_view k) { return n == k; });
}

bool is_named(const IMAGE_SECTION_HEADER& s) {
    // themida wipes names with 0x20, not zeros
    for (int i = 0; i < 8; ++i) {
        const std::uint8_t b = s.Name[i];
        if (b == 0) return i > 0;
        if (b != ' ' && b != '\t') return true;
    }
    return false;
}

void set_name(IMAGE_SECTION_HEADER& s, std::string_view name) {
    std::memset(s.Name, 0, 8);
    const std::size_t n = (std::min)(name.size(), std::size_t{8});
    std::memcpy(s.Name, name.data(), n);
}

std::string guess_name(const IMAGE_SECTION_HEADER& s, std::span<const std::uint8_t> data, std::uint32_t pdata_rva, bool& used_pdata) {
    const DWORD c = s.Characteristics;
    const bool exec = (c & IMAGE_SCN_MEM_EXECUTE) != 0;
    const bool write = (c & IMAGE_SCN_MEM_WRITE) != 0;
    const bool read = (c & IMAGE_SCN_MEM_READ) != 0;

    if (!used_pdata && pdata_rva && s.VirtualAddress == pdata_rva) {
        used_pdata = true;
        return ".pdata";
    }

    if (exec) return ".text";
    if (read && !write) return ".rdata";

    if (read && write) {
        // mostly-zero R/W is typical .data with bss tail
        std::size_t nonzero = 0;
        const std::size_t sample = (std::min)(data.size(), std::size_t{4096});
        for (std::size_t i = 0; i < sample; ++i) if (data[i]) ++nonzero;
        return nonzero == 0 ? ".bss" : ".data";
    }

    return ".unk";
}

/*
   minimal x64 disasm for the stolen-byte signature at OEP: themida copies
   the original prologue into its own region and leaves a redirect behind.
 */
struct FirstInsn {
    bool          is_branch = false;
    bool          leaves_text = false;
    std::uint64_t target_va = 0;
};

FirstInsn classify_first_insn(std::span<const std::uint8_t> bytes, std::uint64_t insn_va, std::uint64_t text_lo, std::uint64_t text_hi) {
    FirstInsn r{};
    if (bytes.empty()) return r;

    auto rel32 = [&](std::size_t off) -> std::int32_t {
        if (bytes.size() < off + 4) return 0;
        std::int32_t v;
        std::memcpy(&v, bytes.data() + off, 4);
        return v;
    };

    const std::uint8_t op = bytes[0];
    if (op == 0xE9 && bytes.size() >= 5) {
        r.is_branch = true;
        r.target_va = insn_va + 5 + static_cast<std::int64_t>(rel32(1));
    } else if (op == 0xE8 && bytes.size() >= 5) {
        r.is_branch = true;
        r.target_va = insn_va + 5 + static_cast<std::int64_t>(rel32(1));
    } else if (op == 0xEB && bytes.size() >= 2) {
        r.is_branch = true;
        r.target_va = insn_va + 2 + static_cast<std::int8_t>(bytes[1]);
    } else if (op == 0xFF && bytes.size() >= 2 && (bytes[1] == 0x25)) {
        r.is_branch = true;
        // target is data, flag as leaving text
        r.target_va = 0;
        r.leaves_text = true;
        return r;
    } else {
        return r;
    }

    r.leaves_text = (r.target_va < text_lo) || (r.target_va >= text_hi);
    return r;
}

}  // namespace

void clean_dump(std::vector<std::uint8_t>& image, std::uint32_t oep_rva) {
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    const std::size_t nt_off = static_cast<std::size_t>(dos->e_lfanew);
    if (nt_off + sizeof(IMAGE_NT_HEADERS64) > image.size()) return;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + nt_off);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        log::warn("clean: not x64, skipping (machine 0x{:x})", nt->FileHeader.Machine);
        return;
    }

    auto* sections = IMAGE_FIRST_SECTION(nt);
    const unsigned orig_count = nt->FileHeader.NumberOfSections;

    const std::uint32_t pdata_rva =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;

    // need .text bytes to xref-scan packer candidates
    const IMAGE_SECTION_HEADER* text_sec = nullptr;
    for (unsigned i = 0; i < orig_count; ++i) {
        if ((sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            !is_packer_section(sections[i])) {
            text_sec = &sections[i];
            break;
        }
    }

    // count rip-relative call/jmp targets from .text into a candidate range
    auto count_xrefs_into = [&](std::uint32_t lo_rva, std::uint32_t hi_rva) -> std::size_t {
        if (!text_sec) return 0;
        const std::size_t off = text_sec->PointerToRawData;
        const std::size_t len = (std::min)(static_cast<std::size_t>(text_sec->Misc.VirtualSize),
                                           static_cast<std::size_t>(text_sec->SizeOfRawData));
        if (off >= image.size() || len == 0) return 0;
        const std::size_t avail = (std::min)(len, image.size() - off);
        const std::uint8_t* p = image.data() + off;
        const std::uint32_t base_rva = text_sec->VirtualAddress;
        std::size_t hits = 0;
        for (std::size_t i = 0; i + 6 <= avail; ++i) {
            const std::uint8_t op = p[i];
            if (op == 0xE8 || op == 0xE9) {
                std::int32_t disp;
                std::memcpy(&disp, p + i + 1, 4);
                const std::uint64_t insn_end = base_rva + i + 5;
                const std::int64_t target = static_cast<std::int64_t>(insn_end) + disp;
                if (target < 0) continue;
                const std::uint64_t t = static_cast<std::uint64_t>(target);
                if (t >= lo_rva && t < hi_rva) ++hits;
            } else if (op == 0xFF && (p[i + 1] == 0x15 || p[i + 1] == 0x25)) {
                // call/jmp qword ptr [rip+disp32]: the iat pointer itself
                // sits at insn_end + disp, that address may live in the
                // dropped section
                std::int32_t disp;
                std::memcpy(&disp, p + i + 2, 4);
                const std::uint64_t insn_end = base_rva + i + 6;
                const std::int64_t addr = static_cast<std::int64_t>(insn_end) + disp;
                if (addr < 0) continue;
                const std::uint64_t a = static_cast<std::uint64_t>(addr);
                if (a >= lo_rva && a < hi_rva) ++hits;
            }
        }
        return hits;
    };

    /*
     * partition strategy:
     *   trailing packer sections can be removed from the section table
     *   entirely (cut the tail off SizeOfImage, shrink the file).
     *   middle packer sections can't: removing them creates a VA gap and
     *   the loader rejects the image. for those, keep the header but mark
     *   it uninitialized (PointerToRawData=0, SizeOfRawData=0, rename) so
     *   the loader maps zeroed pages and the raw bytes get stripped by
     *   the repack pass.
     */
    std::vector<IMAGE_SECTION_HEADER> kept;
    kept.reserve(orig_count);
    std::vector<std::string> dropped;
    std::vector<std::string> stubbed;
    std::size_t dropped_bytes = 0;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> dropped_ranges;

    auto has_kept_at_higher_va = [&](std::uint32_t va) {
        for (unsigned j = 0; j < orig_count; ++j) {
            if (sections[j].VirtualAddress > va && !is_packer_section(sections[j])) {
                return true;
            }
        }
        return false;
    };

    for (unsigned i = 0; i < orig_count; ++i) {
        if (is_packer_section(sections[i])) {
            const std::uint32_t lo = sections[i].VirtualAddress;
            const std::uint32_t hi = lo + (std::max)(sections[i].Misc.VirtualSize,
                                                     sections[i].SizeOfRawData);
            const std::size_t xrefs = count_xrefs_into(lo, hi);
            if (xrefs > 0) {
                log::warn("clean: keeping '{}' - {} call/jmp ref(s) from .text point into it (themida api stubs not yet rewritten)",
                          section_name(sections[i]), xrefs);
                kept.push_back(sections[i]);
                continue;
            }

            if (has_kept_at_higher_va(lo)) {
                IMAGE_SECTION_HEADER stub = sections[i];
                stub.PointerToRawData = 0;
                stub.SizeOfRawData = 0;
                stub.Characteristics =
                    (stub.Characteristics & ~(IMAGE_SCN_CNT_CODE |
                                              IMAGE_SCN_CNT_INITIALIZED_DATA |
                                              IMAGE_SCN_MEM_EXECUTE |
                                              IMAGE_SCN_MEM_WRITE)) |
                    IMAGE_SCN_CNT_UNINITIALIZED_DATA |
                    IMAGE_SCN_MEM_READ;
                std::memset(stub.Name, 0, 8);
                std::memcpy(stub.Name, ".stub", 5);
                stubbed.emplace_back(section_name(sections[i]));
                dropped_bytes += sections[i].SizeOfRawData;
                dropped_ranges.emplace_back(lo, hi);
                kept.push_back(stub);
                continue;
            }

            dropped.emplace_back(section_name(sections[i]));
            dropped_bytes += sections[i].SizeOfRawData;
            dropped_ranges.emplace_back(lo, hi);
            continue;
        }
        kept.push_back(sections[i]);
    }

    /*
     * null out data directory entries whose rva fell into a dropped
     * section. leaving exception/security/loadcfg etc. dangling here
     * makes the loader reject the image with "this app can't run".
     */
    auto rva_dropped = [&](std::uint32_t rva) {
        for (const auto& [lo, hi] : dropped_ranges) {
            if (rva >= lo && rva < hi) return true;
        }
        return false;
    };
    auto& dirs = nt->OptionalHeader.DataDirectory;
    const unsigned ndir = nt->OptionalHeader.NumberOfRvaAndSizes;
    static constexpr const char* kDirNames[] = {
        "Export", "Import", "Resource", "Exception", "Security", "Reloc",
        "Debug", "Arch", "GlobalPtr", "TLS", "LoadCfg", "BoundImp",
        "IAT", "DelayImp", "COM", "Reserved"
    };
    for (unsigned i = 0; i < ndir && i < 16; ++i) {
        if (dirs[i].VirtualAddress && rva_dropped(dirs[i].VirtualAddress)) {
            log::info("clean: clearing stale {} dir (rva 0x{:x} was in dropped section)",
                      kDirNames[i], dirs[i].VirtualAddress);
            dirs[i].VirtualAddress = 0;
            dirs[i].Size = 0;
        }
    }
    // user-mode loader ignores CheckSum for non-system images, zero it so
    // signed-binary tooling stops complaining
    nt->OptionalHeader.CheckSum = 0;

    /*
     * themida's runtime-built pdata describes its own code. after dump,
     * those RUNTIME_FUNCTION entries point at garbage and the x64 loader
     * refuses the image. nulling it out degrades SEH unwind but the
     * binary loads.
     */
    auto& exc = dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exc.VirtualAddress || exc.Size) {
        log::info("clean: clearing Exception dir (themida runtime pdata, stale after dump)");
        exc.VirtualAddress = 0;
        exc.Size = 0;
    }
    // load config: themida sometimes leaves a stub here pointing into its
    // own data, CFG/SafeSEH validation can reject malformed entries
    auto& lcd = dirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (lcd.VirtualAddress || lcd.Size) {
        log::info("clean: clearing LoadConfig dir (likely themida-mangled)");
        lcd.VirtualAddress = 0;
        lcd.Size = 0;
    }
    // dump is fixed at the runtime base, no relocs needed
    auto& bre = dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (bre.VirtualAddress || bre.Size) {
        log::info("clean: clearing Reloc dir (dump fixed at runtime base)");
        bre.VirtualAddress = 0;
        bre.Size = 0;
    }
    nt->OptionalHeader.DllCharacteristics &= ~(
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
        IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA |
        IMAGE_DLLCHARACTERISTICS_GUARD_CF);
    nt->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;

    if (dropped.empty() && stubbed.empty()) {
        log::info("clean: no packer sections found");
    } else {
        for (const auto& n : dropped) log::info("clean: dropped '{}' (trailing)", n);
        for (const auto& n : stubbed) {
            log::info("clean: stubbed '{}' (middle - content stripped, VA reserved)", n);
        }
    }

    bool used_pdata = false;
    for (auto& s : kept) {
        if (is_named(s)) continue;
        const std::size_t off = s.PointerToRawData;
        const std::size_t sz = s.SizeOfRawData;
        std::span<const std::uint8_t> data;
        if (off < image.size()) {
            const std::size_t avail = (std::min)(sz, image.size() - off);
            data = std::span<const std::uint8_t>(image.data() + off, avail);
        }
        const std::string name = guess_name(s, data, pdata_rva, used_pdata);
        log::info("clean: renaming blank section at RVA 0x{:x} -> '{}'",
                  s.VirtualAddress, name);
        set_name(s, name);
    }

    // stolen-byte check at OEP: does the first insn immediately leave .text?
    if (oep_rva) {
        std::uint64_t image_base = nt->OptionalHeader.ImageBase;
        std::uint64_t text_lo = 0, text_hi = 0;
        for (const auto& s : kept) {
            if (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                text_lo = image_base + s.VirtualAddress;
                text_hi = text_lo + s.Misc.VirtualSize;
                if (oep_rva >= s.VirtualAddress &&
                    oep_rva < s.VirtualAddress + s.Misc.VirtualSize) {
                    break;
                }
            }
        }
        for (const auto& s : kept) {
            if (oep_rva < s.VirtualAddress ||
                oep_rva >= s.VirtualAddress + s.Misc.VirtualSize) continue;
            const std::size_t off = s.PointerToRawData + (oep_rva - s.VirtualAddress);
            if (off + 16 > image.size()) break;
            const auto fi = classify_first_insn(
                std::span<const std::uint8_t>(image.data() + off, 16),
                image_base + oep_rva, text_lo, text_hi);
            if (fi.is_branch && fi.leaves_text) {
                log::warn("clean: OEP first insn jumps OUT of .text (target 0x{:x}) - likely stolen bytes (unrecoverable from dump)",
                          fi.target_va);
            }
            break;
        }
    }

    // repack raw layout: VAs preserved, raw offsets rewritten with smaller FileAlignment
    constexpr DWORD kFileAlign = 0x200;

    std::sort(kept.begin(), kept.end(),
              [](const IMAGE_SECTION_HEADER& a, const IMAGE_SECTION_HEADER& b) {
                  return a.VirtualAddress < b.VirtualAddress;
              });

    DWORD raw_cursor = align_up(nt->OptionalHeader.SizeOfHeaders, kFileAlign);

    struct SectionCopy {
        IMAGE_SECTION_HEADER hdr;
        std::size_t          src_off = 0;
        std::size_t          src_len = 0;
    };
    std::vector<SectionCopy> copies;
    copies.reserve(kept.size());

    for (const auto& s : kept) {
        SectionCopy c{};
        c.hdr = s;

        // stubbed (uninitialized) sections have no raw bytes in file
        if (s.SizeOfRawData == 0 && s.PointerToRawData == 0) {
            c.src_off = 0;
            c.src_len = 0;
            copies.push_back(c);
            continue;
        }

        // loader only maps up to VirtualSize
        std::size_t copy_len = (std::min)(static_cast<std::size_t>(s.Misc.VirtualSize),
                                          static_cast<std::size_t>(s.SizeOfRawData));
        const std::size_t src_off = s.PointerToRawData;
        if (src_off >= image.size()) {
            copy_len = 0;
        } else if (src_off + copy_len > image.size()) {
            copy_len = image.size() - src_off;
        }

        c.src_off = src_off;
        c.src_len = copy_len;

        const DWORD raw_size = align_up(static_cast<DWORD>(copy_len), kFileAlign);
        c.hdr.PointerToRawData = raw_cursor;
        c.hdr.SizeOfRawData = raw_size;

        raw_cursor = align_up(raw_cursor + raw_size, kFileAlign);
        copies.push_back(c);
    }

    DWORD max_va_end = 0;
    const DWORD section_align = nt->OptionalHeader.SectionAlignment;
    for (const auto& c : copies) {
        const DWORD end = c.hdr.VirtualAddress +
                          align_up(c.hdr.Misc.VirtualSize, section_align);
        if (end > max_va_end) max_va_end = end;
    }

    std::vector<std::uint8_t> out(raw_cursor, 0);

    const std::size_t hdr_copy = (std::min)(static_cast<std::size_t>(nt->OptionalHeader.SizeOfHeaders),
                                            image.size());
    std::memcpy(out.data(), image.data(), hdr_copy);

    auto* out_dos = reinterpret_cast<IMAGE_DOS_HEADER*>(out.data());
    auto* out_nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(out.data() + out_dos->e_lfanew);
    out_nt->FileHeader.NumberOfSections = static_cast<WORD>(copies.size());
    out_nt->OptionalHeader.FileAlignment = kFileAlign;
    out_nt->OptionalHeader.SizeOfImage = max_va_end;

    auto* out_sections = IMAGE_FIRST_SECTION(out_nt);
    std::memset(out_sections, 0, sizeof(IMAGE_SECTION_HEADER) * orig_count);
    for (std::size_t i = 0; i < copies.size(); ++i) {
        out_sections[i] = copies[i].hdr;
    }

    for (const auto& c : copies) {
        if (c.src_len == 0) continue;
        std::memcpy(out.data() + c.hdr.PointerToRawData,
                    image.data() + c.src_off, c.src_len);
    }

    log::info("clean: {} bytes -> {} bytes ({} sections in table: {} dropped, {} stubbed, {} bytes of content stripped)",
              image.size(), out.size(), copies.size(),
              dropped.size(), stubbed.size(), dropped_bytes);

    image = std::move(out);
}

}  // namespace simply

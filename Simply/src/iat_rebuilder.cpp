#include "iat_rebuilder.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <psapi.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "simply_log.hpp"

#pragma comment(lib, "psapi.lib")

namespace simply {

namespace {

struct ModuleInfo {
    std::uint64_t base = 0;
    std::uint32_t size = 0;
    std::string   name;  // base name lowercased, e.g. "kernel32.dll"
};

struct ResolvedImport {
    std::uint32_t module_index = 0;
    std::string   func_name;
};

using ExportMap = std::unordered_map<std::uint64_t, ResolvedImport>;

// one contiguous run of IAT pointers in the dump
struct IatRun {
    std::uint32_t              rva       = 0;
    std::uint32_t              count     = 0;
    std::uint32_t              module_ix = 0;
    std::vector<std::string>   names;
};

DWORD align_up(DWORD value, DWORD alignment) {
    if (alignment == 0) return value;
    const DWORD rem = value % alignment;
    return rem ? value + (alignment - rem) : value;
}

std::string lower(std::string s) {
    for (auto& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    }
    return s;
}

template <typename T>
bool read_remote(HANDLE process, std::uint64_t addr, T& out) {
    SIZE_T n = 0;
    return ReadProcessMemory(process, reinterpret_cast<LPCVOID>(addr), &out, sizeof(T), &n)
           && n == sizeof(T);
}

bool read_remote_bytes(HANDLE process, std::uint64_t addr, void* out, std::size_t len) {
    SIZE_T n = 0;
    return ReadProcessMemory(process, reinterpret_cast<LPCVOID>(addr), out, len, &n)
           && n == len;
}

std::string read_remote_string(HANDLE process, std::uint64_t addr, std::size_t max_len = 256) {
    std::string s;
    s.reserve(64);
    char ch = 0;
    for (std::size_t i = 0; i < max_len; ++i) {
        if (!read_remote(process, addr + i, ch)) break;
        if (ch == '\0') break;
        s.push_back(ch);
    }
    return s;
}

std::vector<ModuleInfo> enum_modules(HANDLE process) {
    std::vector<ModuleInfo> out;
    HMODULE mods[1024];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(process, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
        log::error("iat: EnumProcessModulesEx failed: {}", GetLastError());
        return out;
    }
    const DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; ++i) {
        wchar_t pathw[MAX_PATH] = {};
        if (!GetModuleFileNameExW(process, mods[i], pathw, MAX_PATH)) continue;
        MODULEINFO mi{};
        if (!GetModuleInformation(process, mods[i], &mi, sizeof(mi))) continue;

        std::wstring wpath = pathw;
        const auto slash = wpath.find_last_of(L"\\/");
        std::wstring wname = (slash == std::wstring::npos) ? wpath : wpath.substr(slash + 1);

        std::string name(wname.size(), '\0');
        for (size_t j = 0; j < wname.size(); ++j) name[j] = static_cast<char>(wname[j] & 0xFF);

        out.push_back(ModuleInfo{
            .base = reinterpret_cast<std::uint64_t>(mi.lpBaseOfDll),
            .size = static_cast<std::uint32_t>(mi.SizeOfImage),
            .name = lower(name),
        });
    }
    return out;
}

/*
   walk a module's export table and record every exported address.
   forwarders (export RVA lands inside the export directory range) get
   skipped since they don't have a callable address in this module.
 */
void collect_module_exports(HANDLE process, std::uint32_t module_index, const ModuleInfo& mod, ExportMap& out_map) {
    IMAGE_DOS_HEADER dos{};
    if (!read_remote(process, mod.base, dos)) return;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return;

    IMAGE_NT_HEADERS nt{};
    if (!read_remote(process, mod.base + dos.e_lfanew, nt)) return;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return;

    const auto& export_dir_entry = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_dir_entry.VirtualAddress == 0 || export_dir_entry.Size == 0) return;

    IMAGE_EXPORT_DIRECTORY exp{};
    if (!read_remote(process, mod.base + export_dir_entry.VirtualAddress, exp)) return;

    const std::uint32_t func_count = exp.NumberOfFunctions;
    const std::uint32_t name_count = exp.NumberOfNames;
    if (func_count == 0) return;

    std::vector<std::uint32_t> func_rvas(func_count);
    if (!read_remote_bytes(process, mod.base + exp.AddressOfFunctions,
                           func_rvas.data(), func_rvas.size() * sizeof(std::uint32_t))) {
        return;
    }

    std::vector<std::uint32_t> name_rvas(name_count);
    std::vector<std::uint16_t> ordinals(name_count);
    if (name_count > 0) {
        if (!read_remote_bytes(process, mod.base + exp.AddressOfNames,
                               name_rvas.data(), name_rvas.size() * sizeof(std::uint32_t))) {
            return;
        }
        if (!read_remote_bytes(process, mod.base + exp.AddressOfNameOrdinals,
                               ordinals.data(), ordinals.size() * sizeof(std::uint16_t))) {
            return;
        }
    }

    std::vector<std::string> names_by_ordinal(func_count);
    for (std::uint32_t i = 0; i < name_count; ++i) {
        const std::uint16_t ord = ordinals[i];
        if (ord >= func_count) continue;
        const std::uint32_t name_rva = name_rvas[i];
        if (name_rva == 0) continue;
        names_by_ordinal[ord] = read_remote_string(process, mod.base + name_rva);
    }

    const std::uint32_t exp_dir_lo = export_dir_entry.VirtualAddress;
    const std::uint32_t exp_dir_hi = exp_dir_lo + export_dir_entry.Size;

    for (std::uint32_t i = 0; i < func_count; ++i) {
        const std::uint32_t rva = func_rvas[i];
        if (rva == 0) continue;
        // forwarder: RVA points at a "kernel32.SomeFunc" string inside the export dir
        if (rva >= exp_dir_lo && rva < exp_dir_hi) continue;

        const std::uint64_t va = mod.base + rva;
        // prefer the named entry if multiple ordinals share an address
        auto it = out_map.find(va);
        if (it == out_map.end() || (it->second.func_name.empty() && !names_by_ordinal[i].empty())) {
            ResolvedImport ri;
            ri.module_index = module_index;
            ri.func_name = names_by_ordinal[i];
            out_map[va] = std::move(ri);
        }
    }
}

ExportMap build_export_map(HANDLE process, const std::vector<ModuleInfo>& modules) {
    ExportMap map;
    map.reserve(8192);
    for (std::uint32_t i = 0; i < modules.size(); ++i) {
        collect_module_exports(process, i, modules[i], map);
    }
    return map;
}

/*
   walk the dump for runs of consecutive qwords that resolve to known
   exports from the same module. a run ends at NULL or any unresolved
   qword. skips the headers area, IAT slots never live there.
 */
std::vector<IatRun> find_iat_runs(const std::vector<std::uint8_t>& image, std::uint64_t image_base, const ExportMap& exports) {
    std::vector<IatRun> runs;

    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return runs;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return runs;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return runs;

    /*
     * record packer section ranges so we skip runs that live inside
     * themida/vmp data (those runs are the packer's own bookkeeping,
     * not imports the original program calls). after section_cleaner
     * strips packer sections to zero-sized .stub entries IDA can't
     * display their slots anyway (no file bytes at the RVA), so keeping
     * them just pollutes the Imports view with un-navigable names.
     */
    static constexpr std::array<std::string_view, 9> kPackerNames = {
        ".themida", ".boot", ".winlice", "WinLicen",
        ".vmp0", ".vmp1", ".mpress1", ".mpress2", ".enigma1",
    };
    std::vector<std::pair<std::uint32_t, std::uint32_t>> packer_ranges;
    {
        const auto* sec = IMAGE_FIRST_SECTION(nt);
        const unsigned scount = nt->FileHeader.NumberOfSections;
        for (unsigned s = 0; s < scount; ++s) {
            char name[9] = {};
            std::memcpy(name, sec[s].Name, 8);
            const std::string_view nv = name;
            for (auto pk : kPackerNames) {
                if (nv == pk) {
                    const std::uint32_t lo = sec[s].VirtualAddress;
                    const std::uint32_t hi = lo + (std::max)(sec[s].Misc.VirtualSize,
                                                              sec[s].SizeOfRawData);
                    packer_ranges.emplace_back(lo, hi);
                    break;
                }
            }
        }
    }
    auto in_packer = [&](std::uint32_t rva) {
        for (const auto& [lo, hi] : packer_ranges) {
            if (rva >= lo && rva < hi) return true;
        }
        return false;
    };

    const std::uint32_t headers_size = nt->OptionalHeader.SizeOfHeaders;
    const std::uint32_t image_size   = static_cast<std::uint32_t>(image.size());

    std::uint32_t i = (headers_size + 7u) & ~7u;
    while (i + 8 <= image_size) {
        if (in_packer(i)) { i += 8; continue; }
        std::uint64_t qw = 0;
        std::memcpy(&qw, image.data() + i, 8);

        auto it = exports.find(qw);
        if (it == exports.end()) {
            i += 8;
            continue;
        }

        IatRun run;
        run.rva = i;
        run.module_ix = it->second.module_index;

        std::uint32_t j = i;
        while (j + 8 <= image_size) {
            std::uint64_t v = 0;
            std::memcpy(&v, image.data() + j, 8);
            if (v == 0) break;
            auto rit = exports.find(v);
            if (rit == exports.end()) break;
            if (rit->second.module_index != run.module_ix) break;
            run.names.push_back(rit->second.func_name);
            ++run.count;
            j += 8;
        }

        /*
         * accept single-entry runs. small test targets show up as length-1
         * and we'd miss them otherwise. false-positive risk is small since
         * the qword still has to exactly match an export VA.
         */
        runs.push_back(std::move(run));
        i = j + 8;
    }
    return runs;
}

std::uint32_t append_bytes(std::vector<std::uint8_t>& out, const void* data, std::size_t len) {
    const auto off = static_cast<std::uint32_t>(out.size());
    const auto* src = static_cast<const std::uint8_t*>(data);
    out.insert(out.end(), src, src + len);
    return off;
}

void pad_to(std::vector<std::uint8_t>& out, std::size_t alignment) {
    while (out.size() % alignment) out.push_back(0);
}

}  // namespace

bool rebuild_iat(void* process_handle, std::vector<std::uint8_t>& image, std::uint64_t image_base) {
    auto* process = static_cast<HANDLE>(process_handle);

    if (image.size() < sizeof(IMAGE_DOS_HEADER)) {
        log::error("iat: image too small");
        return false;
    }

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const std::size_t nt_off = dos->e_lfanew;
    if (nt_off + sizeof(IMAGE_NT_HEADERS) > image.size()) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(image.data() + nt_off);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto modules = enum_modules(process);
    if (modules.empty()) {
        log::error("iat: no modules enumerated in target");
        return false;
    }
    const auto exports = build_export_map(process, modules);
    log::debug("iat: collected {} exports across {} modules", exports.size(), modules.size());

    auto runs = find_iat_runs(image, image_base, exports);
    if (runs.empty()) {
        log::warn("iat: no IAT runs found, IAT may be obfuscated or missing");
        return false;
    }

    log::info("iat: found {} import run(s)", runs.size());
    for (const auto& r : runs) {
        log::debug("  run rva=0x{:x} count={} module={}", r.rva, r.count, modules[r.module_ix].name);
    }

    // append a fresh RVA-aligned section for descriptors, INT, hint/name, dll names
    const DWORD section_alignment = nt->OptionalHeader.SectionAlignment;
    const std::uint32_t old_size_of_image = nt->OptionalHeader.SizeOfImage;
    const std::uint32_t new_section_rva = align_up(static_cast<DWORD>(image.size()), section_alignment);

    image.resize(new_section_rva, 0);

    std::vector<std::uint8_t> blob;
    blob.reserve(0x4000);

    // one descriptor per run + null terminator
    const std::size_t descriptor_count = runs.size() + 1;
    blob.resize(descriptor_count * sizeof(IMAGE_IMPORT_DESCRIPTOR), 0);

    struct PendingDescriptor {
        std::uint32_t int_offset = 0;
        std::uint32_t name_offset = 0;
        std::uint32_t iat_offset = 0;
    };
    std::vector<PendingDescriptor> pending(runs.size());

    for (std::size_t r = 0; r < runs.size(); ++r) {
        const auto& run = runs[r];
        auto& pd = pending[r];

        std::vector<std::uint64_t> int_entries(run.count + 1, 0);
        for (std::uint32_t k = 0; k < run.count; ++k) {
            const std::string& name = run.names[k];
            if (name.empty()) {
                // ordinal-only export, mark ordinal-import (bit 63). rare.
                int_entries[k] = 0x8000000000000000ULL;
                continue;
            }
            // IMAGE_IMPORT_BY_NAME: WORD Hint + CHAR Name[]
            std::vector<std::uint8_t> hn(2 + name.size() + 1, 0);
            std::memcpy(hn.data() + 2, name.data(), name.size());
            const std::uint32_t off = append_bytes(blob, hn.data(), hn.size());
            int_entries[k] = static_cast<std::uint64_t>(new_section_rva + off);
        }
        /*
         * align INT to 8 so IDA's PE loader parses cleanly. unaligned reads
         * work at runtime but IDA treats a misaligned import directory as
         * malformed and can drop later descriptors from its Imports view.
         */
        pad_to(blob, 8);

        pd.int_offset = static_cast<std::uint32_t>(blob.size());
        append_bytes(blob, int_entries.data(), int_entries.size() * sizeof(std::uint64_t));

        const std::string& dll_name = modules[run.module_ix].name;
        pd.name_offset = append_bytes(blob, dll_name.c_str(), dll_name.size() + 1);

        pd.iat_offset = run.rva;
    }
    pad_to(blob, 8);

    auto* descriptors = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(blob.data());
    for (std::size_t r = 0; r < runs.size(); ++r) {
        IMAGE_IMPORT_DESCRIPTOR& d = descriptors[r];
        d.OriginalFirstThunk = new_section_rva + pending[r].int_offset;
        d.TimeDateStamp = 0;
        d.ForwarderChain = 0;
        d.Name = new_section_rva + pending[r].name_offset;
        d.FirstThunk = pending[r].iat_offset;
    }
    // last entry already zeroed (null terminator)

    // grow image then copy blob. nt/section ptrs from image.data() are stale after this.
    const std::uint32_t blob_virtual_size = static_cast<std::uint32_t>(blob.size());
    const std::uint32_t blob_aligned_size = align_up(blob_virtual_size, section_alignment);
    const std::size_t   final_size        = new_section_rva + blob_aligned_size;
    image.resize(final_size, 0);
    std::memcpy(image.data() + new_section_rva, blob.data(), blob.size());

    auto* dos2 = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    auto* nt2  = reinterpret_cast<IMAGE_NT_HEADERS*>(image.data() + dos2->e_lfanew);

    // need room for one more section header between the table and the first section
    auto* section_table = IMAGE_FIRST_SECTION(nt2);
    const unsigned section_count = nt2->FileHeader.NumberOfSections;
    const std::uintptr_t section_table_end = reinterpret_cast<std::uintptr_t>(section_table + section_count);
    const std::uintptr_t headers_end =
        reinterpret_cast<std::uintptr_t>(image.data()) + nt2->OptionalHeader.SizeOfHeaders;
    if (section_table_end + sizeof(IMAGE_SECTION_HEADER) > headers_end) {
        log::error("iat: no room in PE headers for an extra section header");
        return false;
    }

    IMAGE_SECTION_HEADER& new_sec = section_table[section_count];
    std::memset(&new_sec, 0, sizeof(new_sec));
    std::memcpy(new_sec.Name, ".simply", 7);
    new_sec.Misc.VirtualSize  = blob_virtual_size;
    new_sec.VirtualAddress    = new_section_rva;
    new_sec.SizeOfRawData     = blob_aligned_size;
    new_sec.PointerToRawData  = new_section_rva;  // raw == virtual after fix_pe_headers
    new_sec.Characteristics   = IMAGE_SCN_CNT_INITIALIZED_DATA
                              | IMAGE_SCN_MEM_READ
                              | IMAGE_SCN_MEM_WRITE;

    nt2->FileHeader.NumberOfSections = static_cast<WORD>(section_count + 1);
    const std::uint32_t needed_size_of_image = new_section_rva + blob_aligned_size;
    if (needed_size_of_image > old_size_of_image) {
        nt2->OptionalHeader.SizeOfImage = needed_size_of_image;
    }

    // leave IAT directory pointing at the largest run so the loader pre-populates it
    auto& import_dir = nt2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    import_dir.VirtualAddress = new_section_rva;
    import_dir.Size = static_cast<DWORD>(descriptor_count * sizeof(IMAGE_IMPORT_DESCRIPTOR));

    std::size_t biggest = 0;
    for (std::size_t r = 1; r < runs.size(); ++r) {
        if (runs[r].count > runs[biggest].count) biggest = r;
    }
    auto& iat_dir = nt2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    iat_dir.VirtualAddress = runs[biggest].rva;
    iat_dir.Size = runs[biggest].count * static_cast<DWORD>(sizeof(std::uint64_t));

    log::info("iat: rebuilt {} descriptor(s), new section .simply @ rva=0x{:x} size=0x{:x}",
              runs.size(), new_section_rva, blob_aligned_size);
    return true;
}

namespace {

IMAGE_SECTION_HEADER* find_simply_section(IMAGE_NT_HEADERS64* nt) {
    auto* sections = IMAGE_FIRST_SECTION(nt);
    const unsigned count = nt->FileHeader.NumberOfSections;
    for (unsigned i = 0; i < count; ++i) {
        if (std::memcmp(sections[i].Name, ".simply", 7) == 0) return &sections[i];
    }
    return nullptr;
}

}  // namespace

std::unordered_map<std::uint64_t, std::uint32_t>
extend_iat_for_captures(void* process_handle, std::vector<std::uint8_t>& image, std::uint64_t /*image_base*/, const std::unordered_map<std::uint64_t, std::uint64_t>& landings) {
    std::unordered_map<std::uint64_t, std::uint32_t> out;
    auto* process = static_cast<HANDLE>(process_handle);

    if (landings.empty()) return out;
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return out;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return out;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return out;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return out;

    IMAGE_SECTION_HEADER* simply_sec = find_simply_section(nt);
    if (!simply_sec) {
        log::warn("iat-extend: no .simply section, skipping");
        return out;
    }

    // resolve each api_va -> (module, func_name), dedupe by api_va per module
    auto modules = enum_modules(process);
    if (modules.empty()) return out;
    const auto exports = build_export_map(process, modules);

    /*
     * themida VM stubs often land at an interior offset of the target
     * function (post-prologue or inside a helper). exact match in the
     * export map misses these, fall back to "largest exported VA <= api_va
     * within the containing module".
     */
    std::vector<std::vector<std::uint64_t>> module_export_vas(modules.size());
    for (const auto& [va, ri] : exports) {
        if (ri.module_index < module_export_vas.size()) {
            module_export_vas[ri.module_index].push_back(va);
        }
    }
    for (auto& v : module_export_vas) std::sort(v.begin(), v.end());

    auto module_containing = [&](std::uint64_t va) -> std::uint32_t {
        for (std::uint32_t i = 0; i < modules.size(); ++i) {
            if (va >= modules[i].base && va < modules[i].base + modules[i].size) return i;
        }
        return UINT32_MAX;
    };

    auto resolve_with_fallback = [&](std::uint64_t api_va,
                                     std::uint64_t& out_va,
                                     const ResolvedImport*& out_ri) -> bool {
        if (auto it = exports.find(api_va); it != exports.end()) {
            out_va = api_va;
            out_ri = &it->second;
            return true;
        }
        const std::uint32_t mi = module_containing(api_va);
        if (mi == UINT32_MAX) return false;
        const auto& vec = module_export_vas[mi];
        auto ub = std::upper_bound(vec.begin(), vec.end(), api_va);
        if (ub == vec.begin()) return false;
        const std::uint64_t cand = *(--ub);
        auto it = exports.find(cand);
        if (it == exports.end()) return false;
        if (it->second.func_name.empty()) return false;
        out_va = cand;
        out_ri = &it->second;
        return true;
    };

    struct PerApi {
        std::uint64_t api_va = 0;       // captured runtime VA (key for stub join)
        std::uint64_t resolved_va = 0;  // exported VA we mapped it to
        std::string   name;
        std::uint16_t ordinal_only = 0;
    };
    std::vector<std::vector<PerApi>> by_module(modules.size());

    std::unordered_set<std::uint64_t> seen;
    std::uint32_t skipped = 0;
    for (const auto& [stub_va, api_va] : landings) {
        if (!seen.insert(api_va).second) continue;
        std::uint64_t rva_va = 0;
        const ResolvedImport* ri = nullptr;
        if (!resolve_with_fallback(api_va, rva_va, ri)) {
            ++skipped;
            log::warn("iat-extend: api 0x{:x} not in any export map", api_va);
            continue;
        }
        if (rva_va != api_va) {
            log::info("iat-extend: api 0x{:x} resolved to nearest export {}!{} at 0x{:x} (+0x{:x})",
                      api_va, modules[ri->module_index].name, ri->func_name,
                      rva_va, api_va - rva_va);
        } else {
            log::info("iat-extend: api 0x{:x} -> {}!{} (exact)",
                      api_va, modules[ri->module_index].name, ri->func_name);
        }
        PerApi pa;
        pa.api_va = api_va;
        pa.resolved_va = rva_va;
        pa.name = ri->func_name;
        by_module[ri->module_index].push_back(std::move(pa));
    }

    std::size_t total_apis = 0;
    for (const auto& v : by_module) total_apis += v.size();
    if (total_apis == 0) {
        log::info("iat-extend: nothing to add ({} unresolved)", skipped);
        return out;
    }

    std::size_t mods_with_apis = 0;
    for (const auto& v : by_module) if (!v.empty()) ++mods_with_apis;

    // read existing descriptors so we can splice with the new ones
    auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    std::vector<IMAGE_IMPORT_DESCRIPTOR> existing;
    if (import_dir.VirtualAddress != 0) {
        const std::uint32_t off = import_dir.VirtualAddress;
        if (off + sizeof(IMAGE_IMPORT_DESCRIPTOR) > image.size()) return out;
        const auto* p = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(image.data() + off);
        const std::size_t max_count = (image.size() - off) / sizeof(IMAGE_IMPORT_DESCRIPTOR);
        for (std::size_t i = 0; i < max_count; ++i) {
            const auto& d = p[i];
            if (d.OriginalFirstThunk == 0 && d.FirstThunk == 0 && d.Name == 0) break;
            existing.push_back(d);
        }
    }

    const DWORD section_alignment = nt->OptionalHeader.SectionAlignment;
    const std::uint32_t append_rva =
        simply_sec->VirtualAddress +
        align_up(simply_sec->Misc.VirtualSize, 8u);

    std::vector<std::uint8_t> blob;
    blob.reserve(0x400);

    auto blob_off = [&]() { return static_cast<std::uint32_t>(blob.size()); };
    auto pad8 = [&]() { while (blob.size() & 7) blob.push_back(0); };

    struct ModuleAdd {
        std::uint32_t iat_rva  = 0;
        std::uint32_t int_rva  = 0;
        std::uint32_t name_rva = 0;
        std::uint32_t count    = 0;
    };
    std::vector<ModuleAdd> adds;
    adds.reserve(mods_with_apis);

    for (std::size_t mi = 0; mi < by_module.size(); ++mi) {
        auto& apis = by_module[mi];
        if (apis.empty()) continue;
        ModuleAdd m{};
        m.count = static_cast<std::uint32_t>(apis.size());

        // hint/name first so we have rvas when filling INT/IAT
        std::vector<std::uint32_t> hint_rva(apis.size(), 0);
        for (std::size_t k = 0; k < apis.size(); ++k) {
            if (apis[k].name.empty()) continue;
            pad8();
            const std::uint32_t off = blob_off();
            blob.push_back(0); blob.push_back(0);  // hint = 0
            blob.insert(blob.end(), apis[k].name.begin(), apis[k].name.end());
            blob.push_back(0);
            hint_rva[k] = append_rva + off;
        }
        pad8();
        m.name_rva = append_rva + blob_off();
        const std::string& dll = modules[mi].name;
        blob.insert(blob.end(), dll.begin(), dll.end());
        blob.push_back(0);

        // INT (one qword per api + null terminator)
        pad8();
        m.int_rva = append_rva + blob_off();
        for (std::size_t k = 0; k < apis.size(); ++k) {
            std::uint64_t v = hint_rva[k] != 0
                ? static_cast<std::uint64_t>(hint_rva[k])
                : 0x8000000000000000ULL;  // ordinal-only fallback (rare)
            blob.insert(blob.end(),
                        reinterpret_cast<std::uint8_t*>(&v),
                        reinterpret_cast<std::uint8_t*>(&v) + 8);
        }
        std::uint64_t zero = 0;
        blob.insert(blob.end(),
                    reinterpret_cast<std::uint8_t*>(&zero),
                    reinterpret_cast<std::uint8_t*>(&zero) + 8);

        // IAT: loader fills at load time, start zeroed. record slot rvas so stubs trampoline through them
        pad8();
        m.iat_rva = append_rva + blob_off();
        for (std::size_t k = 0; k < apis.size(); ++k) {
            blob.insert(blob.end(),
                        reinterpret_cast<std::uint8_t*>(&zero),
                        reinterpret_cast<std::uint8_t*>(&zero) + 8);
            out[apis[k].api_va] = m.iat_rva + static_cast<std::uint32_t>(k * 8);
        }
        // null terminator IAT slot
        blob.insert(blob.end(),
                    reinterpret_cast<std::uint8_t*>(&zero),
                    reinterpret_cast<std::uint8_t*>(&zero) + 8);

        adds.push_back(m);
    }

    // combined descriptor array: existing + new + null terminator
    pad8();
    const std::uint32_t new_descr_rva = append_rva + blob_off();
    const std::size_t new_descr_count = existing.size() + adds.size() + 1;
    const std::size_t descr_bytes = new_descr_count * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    blob.resize(blob.size() + descr_bytes, 0);
    auto* descr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
        blob.data() + (new_descr_rva - append_rva));
    for (std::size_t i = 0; i < existing.size(); ++i) descr[i] = existing[i];
    for (std::size_t i = 0; i < adds.size(); ++i) {
        IMAGE_IMPORT_DESCRIPTOR d{};
        d.OriginalFirstThunk = adds[i].int_rva;
        d.Name = adds[i].name_rva;
        d.FirstThunk = adds[i].iat_rva;
        descr[existing.size() + i] = d;
    }
    // descr[new_descr_count - 1] already zero (null terminator)

    const std::size_t new_image_end = static_cast<std::size_t>(append_rva) + blob.size();
    if (new_image_end > image.size()) image.resize(new_image_end, 0);
    std::memcpy(image.data() + append_rva, blob.data(), blob.size());

    // re-fetch headers (image.resize may have moved the buffer)
    auto* dos2 = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    auto* nt2 = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + dos2->e_lfanew);
    IMAGE_SECTION_HEADER* simply2 = find_simply_section(nt2);

    // grow .simply (raw == virtual after fix_pe_headers)
    const std::uint32_t new_section_end = static_cast<std::uint32_t>(new_image_end);
    const std::uint32_t new_vsize = new_section_end - simply2->VirtualAddress;
    simply2->Misc.VirtualSize = new_vsize;
    simply2->SizeOfRawData = align_up(new_vsize, nt2->OptionalHeader.FileAlignment);

    auto& import_dir2 = nt2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    import_dir2.VirtualAddress = new_descr_rva;
    import_dir2.Size = static_cast<DWORD>(descr_bytes);

    const DWORD section_align = nt2->OptionalHeader.SectionAlignment;
    const DWORD aligned_end = align_up(new_section_end, section_align);
    if (aligned_end > nt2->OptionalHeader.SizeOfImage) {
        nt2->OptionalHeader.SizeOfImage = aligned_end;
    }

    log::info("iat-extend: added {} api(s) across {} module(s) ({} not in exports, descriptor array now {})",
              total_apis, adds.size(), skipped, new_descr_count - 1);
    return out;
}

std::uint32_t rebind_poisoned_slots(void* process_handle, std::vector<std::uint8_t>& image, std::uint64_t image_base, const std::unordered_map<std::uint64_t, std::uint64_t>& slot_to_stub, const std::unordered_map<std::uint64_t, std::uint64_t>& stub_to_api) {

    auto* process = static_cast<HANDLE>(process_handle);
    if (slot_to_stub.empty() || stub_to_api.empty()) return 0;
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return 0;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return 0;

    IMAGE_SECTION_HEADER* simply_sec = find_simply_section(nt);
    if (!simply_sec) {
        log::warn("rebind: no .simply section, skipping");
        return 0;
    }

    auto modules = enum_modules(process);
    if (modules.empty()) return 0;
    const auto exports = build_export_map(process, modules);

    // nearest-lower fallback for interior captures (body of function, map to containing export)
    std::vector<std::vector<std::uint64_t>> module_export_vas(modules.size());
    for (const auto& [va, ri] : exports) {
        if (ri.module_index < module_export_vas.size()) {
            module_export_vas[ri.module_index].push_back(va);
        }
    }
    for (auto& v : module_export_vas) std::sort(v.begin(), v.end());

    auto module_containing = [&](std::uint64_t va) -> std::uint32_t {
        for (std::uint32_t i = 0; i < modules.size(); ++i) {
            if (va >= modules[i].base && va < modules[i].base + modules[i].size) return i;
        }
        return UINT32_MAX;
    };

    auto resolve = [&](std::uint64_t api_va, std::string& name_out, std::uint32_t& mi_out) {
        if (auto it = exports.find(api_va); it != exports.end()) {
            name_out = it->second.func_name;
            mi_out = it->second.module_index;
            return !name_out.empty();
        }
        const std::uint32_t mi = module_containing(api_va);
        if (mi == UINT32_MAX) return false;
        const auto& vec = module_export_vas[mi];
        auto ub = std::upper_bound(vec.begin(), vec.end(), api_va);
        if (ub == vec.begin()) return false;
        const std::uint64_t cand = *(--ub);
        auto it = exports.find(cand);
        if (it == exports.end() || it->second.func_name.empty()) return false;
        name_out = it->second.func_name;
        mi_out = it->second.module_index;
        return true;
    };

    /*
     * each poisoned slot needs its own descriptor (FirstThunk = slot_rva).
     * group by module for sensible Name fields. duplicates of the same
     * (slot_rva, module) get a single single-entry descriptor pointing at
     * that slot.
     */
    struct SlotEntry {
        std::uint32_t slot_rva = 0;
        std::string   func_name;
        std::uint32_t module_index = 0;
    };
    std::vector<SlotEntry> slots;
    slots.reserve(slot_to_stub.size());

    std::uint32_t skipped_no_stub = 0;
    std::uint32_t skipped_no_export = 0;
    for (const auto& [slot_va, stub_va] : slot_to_stub) {
        auto sit = stub_to_api.find(stub_va);
        if (sit == stub_to_api.end()) { ++skipped_no_stub; continue; }
        std::string name;
        std::uint32_t mi = 0;
        if (!resolve(sit->second, name, mi)) { ++skipped_no_export; continue; }
        if (slot_va < image_base) continue;
        const std::uint64_t rva64 = slot_va - image_base;
        if (rva64 > UINT32_MAX) continue;
        slots.push_back({static_cast<std::uint32_t>(rva64), std::move(name), mi});
    }


    if (slots.empty()) {
        log::info("rebind: no poisoned slots resolvable ({} no-stub, {} no-export)",
                  skipped_no_stub, skipped_no_export);
        return 0;
    }

    /*
     * per slot: IMAGE_IMPORT_BY_NAME entry (hint+name, NUL-term), one-entry
     * INT array (qword -> IMAGE_IMPORT_BY_NAME, then null), dll name string
     * (deduped per module). then the rebuilt descriptor array (existing +
     * one-per-slot + null).
     *
     * grow .simply by appending after Misc.VirtualSize. raw == virtual here
     * (fix_pe_headers already ran), so file offset == RVA.
     */
    const DWORD section_alignment = nt->OptionalHeader.SectionAlignment;
    const std::uint32_t append_rva =
        simply_sec->VirtualAddress +
        align_up(simply_sec->Misc.VirtualSize, 8u);

    std::vector<std::uint8_t> blob;
    blob.reserve(0x800);
    auto blob_off = [&]() { return static_cast<std::uint32_t>(blob.size()); };
    auto pad8 = [&]() { while (blob.size() & 7) blob.push_back(0); };

    std::unordered_map<std::uint32_t, std::uint32_t> dll_name_rva;
    auto dll_rva_for = [&](std::uint32_t mi) -> std::uint32_t {
        auto it = dll_name_rva.find(mi);
        if (it != dll_name_rva.end()) return it->second;
        pad8();
        const std::uint32_t rva = append_rva + blob_off();
        const std::string& dll = modules[mi].name;
        blob.insert(blob.end(), dll.begin(), dll.end());
        blob.push_back(0);
        dll_name_rva[mi] = rva;
        return rva;
    };

    struct PerSlot {
        std::uint32_t hint_rva = 0;
        std::uint32_t int_rva  = 0;
        std::uint32_t name_rva = 0;
        std::uint32_t slot_rva = 0;
    };
    std::vector<PerSlot> per_slot;
    per_slot.reserve(slots.size());

    for (const auto& s : slots) {
        PerSlot p{};
        p.slot_rva = s.slot_rva;
        pad8();
        p.hint_rva = append_rva + blob_off();
        blob.push_back(0); blob.push_back(0);
        blob.insert(blob.end(), s.func_name.begin(), s.func_name.end());
        blob.push_back(0);
        pad8();
        p.int_rva = append_rva + blob_off();
        std::uint64_t entry = static_cast<std::uint64_t>(p.hint_rva);
        blob.insert(blob.end(),
                    reinterpret_cast<std::uint8_t*>(&entry),
                    reinterpret_cast<std::uint8_t*>(&entry) + 8);
        std::uint64_t zero = 0;
        blob.insert(blob.end(),
                    reinterpret_cast<std::uint8_t*>(&zero),
                    reinterpret_cast<std::uint8_t*>(&zero) + 8);
        p.name_rva = dll_rva_for(s.module_index);
        per_slot.push_back(p);
    }

    /*
     * write the pre-load IAT value into each FT slot: a 64-bit RVA to the
     * IMAGE_IMPORT_BY_NAME entry, high bit clear. this is what the PE spec
     * says the IAT must contain before the loader binds it, so IDA
     * resolves call sites to the real import name instead of unk_<stub>.
     * the loader overwrites the slot at load time, runtime behavior
     * matches a freshly linked binary. raw == virtual here.
     */
    for (const auto& p : per_slot) {
        if (static_cast<std::size_t>(p.slot_rva) + 8 > image.size()) continue;
        const std::uint64_t pre_load = static_cast<std::uint64_t>(p.hint_rva);
        std::memcpy(image.data() + p.slot_rva, &pre_load, 8);
    }

    // read existing descriptors so we can splice the new ones in
    auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    std::vector<IMAGE_IMPORT_DESCRIPTOR> existing;
    if (import_dir.VirtualAddress != 0) {
        const std::uint32_t off = import_dir.VirtualAddress;
        if (off + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= image.size()) {
            const auto* p = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(image.data() + off);
            const std::size_t max_count = (image.size() - off) / sizeof(IMAGE_IMPORT_DESCRIPTOR);
            for (std::size_t i = 0; i < max_count; ++i) {
                const auto& d = p[i];
                if (d.OriginalFirstThunk == 0 && d.FirstThunk == 0 && d.Name == 0) break;
                existing.push_back(d);
            }
        }
    }

    pad8();
    const std::uint32_t new_descr_rva = append_rva + blob_off();
    const std::size_t new_descr_count = existing.size() + per_slot.size() + 1;
    const std::size_t descr_bytes = new_descr_count * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    blob.resize(blob.size() + descr_bytes, 0);
    auto* descr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
        blob.data() + (new_descr_rva - append_rva));
    for (std::size_t i = 0; i < existing.size(); ++i) descr[i] = existing[i];
    for (std::size_t i = 0; i < per_slot.size(); ++i) {
        IMAGE_IMPORT_DESCRIPTOR d{};
        d.OriginalFirstThunk = per_slot[i].int_rva;
        d.Name = per_slot[i].name_rva;
        d.FirstThunk = per_slot[i].slot_rva;  // existing in-image slot
        descr[existing.size() + i] = d;
    }

    const std::size_t new_image_end = static_cast<std::size_t>(append_rva) + blob.size();
    if (new_image_end > image.size()) image.resize(new_image_end, 0);
    std::memcpy(image.data() + append_rva, blob.data(), blob.size());

    auto* dos2 = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    auto* nt2 = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + dos2->e_lfanew);
    IMAGE_SECTION_HEADER* simply2 = find_simply_section(nt2);

    const std::uint32_t new_section_end = static_cast<std::uint32_t>(new_image_end);
    const std::uint32_t new_vsize = new_section_end - simply2->VirtualAddress;
    simply2->Misc.VirtualSize = new_vsize;
    simply2->SizeOfRawData = align_up(new_vsize, nt2->OptionalHeader.FileAlignment);

    /*
     * point IMPORT at the rebuilt descriptor array. existing IAT data
     * directory (if any) still points at the largest pre-existing run;
     * the new one-entry IATs at scattered slot RVAs don't need to be in
     * that table, the loader walks descriptors regardless.
     */
    auto& import_dir2 = nt2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    import_dir2.VirtualAddress = new_descr_rva;
    import_dir2.Size = static_cast<DWORD>(descr_bytes);

    const DWORD section_align = nt2->OptionalHeader.SectionAlignment;
    const DWORD aligned_end = align_up(new_section_end, section_align);
    if (aligned_end > nt2->OptionalHeader.SizeOfImage) {
        nt2->OptionalHeader.SizeOfImage = aligned_end;
    }

    log::info("rebind: bound {} poisoned slot(s) to imports ({} no-stub, {} no-export, descriptor array now {})",
              per_slot.size(), skipped_no_stub, skipped_no_export, new_descr_count - 1);
    return static_cast<std::uint32_t>(per_slot.size());
}

}  // namespace simply

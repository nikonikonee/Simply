#include "pe_inspector.hpp"

#include <windows.h>

#include <cstddef>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#include "simply_log.hpp"

namespace simply {

const char* to_string(ThemidaVersion v) {
    switch (v) {
        case ThemidaVersion::None:       return "none";
        case ThemidaVersion::V2x:        return "Themida 2.x";
        case ThemidaVersion::V3x:        return "Themida 3.x";
        case ThemidaVersion::WinLicense: return "WinLicense";
        case ThemidaVersion::Unknown:    return "unknown";
    }
    return "?";
}

const char* to_string(PeArch a) {
    return a == PeArch::X64 ? "x64" : "x86";
}

namespace {

// IMAGE_SECTION_HEADER::Name is 8 bytes, not NUL-terminated when it fills the field
std::string section_name_to_string(const IMAGE_SECTION_HEADER& sec) {
    const char* p = reinterpret_cast<const char*>(sec.Name);
    std::size_t n = 0;
    while (n < IMAGE_SIZEOF_SHORT_NAME && p[n] != '\0') ++n;
    return std::string(p, n);
}

bool is_themida_section(std::string_view n) {
    return n == ".themida" || n == ".boot" || n == ".winlice" || n == "WinLicen";
}

struct TextRegion {
    std::uint32_t rva = 0;
    std::uint32_t virtual_size = 0;
    std::string   name;
};

TextRegion find_text_region(const IMAGE_SECTION_HEADER* secs, std::uint16_t count) {
    TextRegion best;
    for (std::uint16_t i = 0; i < count; ++i) {
        const auto& s = secs[i];
        const std::string name = section_name_to_string(s);
        if (is_themida_section(name)) continue;

        const bool executable = (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        if (!executable) continue;

        if (name == ".text") {
            return {s.VirtualAddress, s.Misc.VirtualSize, name};
        }
        if (best.name.empty()) {
            best = {s.VirtualAddress, s.Misc.VirtualSize, name};
        }
    }
    return best;
}

std::pair<ThemidaVersion, std::string> classify(const IMAGE_SECTION_HEADER* secs, std::uint16_t count) {
    bool has_themida = false, has_boot = false, has_winlice = false, has_winlicen_legacy = false;
    std::string hit;

    for (std::uint16_t i = 0; i < count; ++i) {
        std::string n = section_name_to_string(secs[i]);
        if (n == ".themida")       { has_themida = true; hit = n; }
        else if (n == ".boot")     { has_boot = true;    if (hit.empty()) hit = n; }
        else if (n == ".winlice")  { has_winlice = true; if (hit.empty()) hit = n; }
        else if (n == "WinLicen")  { has_winlicen_legacy = true; if (hit.empty()) hit = n; }
    }

    // winlicense = themida + licensing, pick the more specific when both match
    if (has_winlice && (has_themida || has_boot)) return {ThemidaVersion::WinLicense, hit};
    if (has_winlicen_legacy)                      return {ThemidaVersion::WinLicense, hit};
    if (has_themida || has_boot)                  return {ThemidaVersion::V3x, hit};
    if (has_winlice)                              return {ThemidaVersion::V2x, hit};
    return {ThemidaVersion::None, ""};
}

std::optional<std::vector<std::uint8_t>> read_file(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return std::nullopt;
    const auto size = f.tellg();
    if (size <= 0) return std::nullopt;
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(size));
    f.seekg(0);
    if (!f.read(reinterpret_cast<char*>(buf.data()), size)) return std::nullopt;
    return buf;
}

}  // namespace

std::optional<PeInfo> inspect_pe(const std::filesystem::path& path) {
    auto file = read_file(path);
    if (!file) {
        log::error("failed to read file: {}", path.string());
        return std::nullopt;
    }
    const auto& buf = *file;

    if (buf.size() < sizeof(IMAGE_DOS_HEADER)) {
        log::error("file too small to be a PE: {}", path.string());
        return std::nullopt;
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        log::error("not a PE (missing MZ): {}", path.string());
        return std::nullopt;
    }

    const auto nt_off = static_cast<std::size_t>(dos->e_lfanew);
    if (nt_off + sizeof(IMAGE_NT_HEADERS64) > buf.size()) {
        log::error("truncated NT headers: {}", path.string());
        return std::nullopt;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buf.data() + nt_off);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        log::error("missing PE signature: {}", path.string());
        return std::nullopt;
    }

    PeInfo info{};
    info.arch = (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) ? PeArch::X64 : PeArch::X86;

    if (info.arch == PeArch::X64) {
        info.image_base    = nt->OptionalHeader.ImageBase;
        info.entry_rva     = nt->OptionalHeader.AddressOfEntryPoint;
        info.size_of_image = nt->OptionalHeader.SizeOfImage;
    } else {
        // PE32 has a narrower OptionalHeader with 32-bit ImageBase
        const auto* nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(buf.data() + nt_off);
        info.image_base    = nt32->OptionalHeader.ImageBase;
        info.entry_rva     = nt32->OptionalHeader.AddressOfEntryPoint;
        info.size_of_image = nt32->OptionalHeader.SizeOfImage;
    }

    const auto sec_off = nt_off + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader;
    const std::uint16_t sec_count = nt->FileHeader.NumberOfSections;
    if (sec_off + static_cast<std::size_t>(sec_count) * sizeof(IMAGE_SECTION_HEADER) > buf.size()) {
        log::error("truncated section table: {}", path.string());
        return std::nullopt;
    }
    const auto* secs = reinterpret_cast<const IMAGE_SECTION_HEADER*>(buf.data() + sec_off);

    auto [version, hit]   = classify(secs, sec_count);
    info.themida          = version;
    info.detected_section = std::move(hit);

    const TextRegion tr     = find_text_region(secs, sec_count);
    info.text_rva           = tr.rva;
    info.text_virtual_size  = tr.virtual_size;
    info.text_section_name  = tr.name;

    log::info("arch:       {}", to_string(info.arch));
    log::info("image_base: 0x{:x}", info.image_base);
    log::info("entry_rva:  0x{:x}", info.entry_rva);
    log::info("size:       0x{:x}", info.size_of_image);
    log::info("protection: {}", to_string(info.themida));
    if (info.text_virtual_size > 0) {
        log::info("code section: '{}' rva=0x{:x} size=0x{:x}", info.text_section_name.empty() ? "(unnamed)" : info.text_section_name, info.text_rva, info.text_virtual_size);
    } else {
        log::warn("no non-themida executable section found");
    }
    if (!info.detected_section.empty()) log::debug("matched section: '{}'", info.detected_section);
    if (info.themida == ThemidaVersion::None) {
        log::warn("no themida sections detected, target may not be packed");
    }

    return info;
}

}  // namespace simply

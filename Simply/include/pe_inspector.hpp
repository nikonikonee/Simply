#pragma once

#include <filesystem>
#include <optional>
#include <string>

namespace simply {

enum class ThemidaVersion {
    None,
    V2x,
    V3x,
    WinLicense,
    Unknown,
};

enum class PeArch {
    X86,
    X64,
};

struct PeInfo {
    PeArch         arch;
    ThemidaVersion themida;
    std::uint64_t  image_base;
    std::uint32_t  entry_rva;
    std::uint32_t  size_of_image;
    std::string    detected_section;

    // where we expect OEP to land, literal .text if present else first exec non-packer section
    std::uint32_t  text_rva;
    std::uint32_t  text_virtual_size;
    std::string    text_section_name;
};

std::optional<PeInfo> inspect_pe(const std::filesystem::path& path);

const char* to_string(ThemidaVersion v);
const char* to_string(PeArch a);

}  // namespace simply

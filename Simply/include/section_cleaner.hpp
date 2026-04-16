#pragma once

#include <cstdint>
#include <vector>

namespace simply {

// drops trailing packer sections, renames empty-name ones, repacks with smaller
// FileAlignment. must run after fix_pe_headers and rebuild_iat.
void clean_dump(std::vector<std::uint8_t>& image, std::uint32_t oep_rva);

}  // namespace simply

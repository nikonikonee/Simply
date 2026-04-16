#pragma once

#include <cstdint>
#include <unordered_map>
#include <vector>

namespace simply {

/*
walks .text for call/jmp rel32 sites landing in a packer section. for each,
tries the static FF25/E9/EB chain walk, then falls back to stub_iat_overrides
for VM-Macro stubs. resolved sites get rewritten to jump through a 6-byte
FF25 trampoline in .simply slack, deduped by IAT slot. must run after
rebuild_iat, extend_iat_for_captures, and fix_pe_headers.
*/
std::uint32_t rewrite_themida_stubs(std::vector<std::uint8_t>& image, std::uint64_t image_base, const std::unordered_map<std::uint64_t, std::uint32_t>* stub_iat_overrides);

}  // namespace simply

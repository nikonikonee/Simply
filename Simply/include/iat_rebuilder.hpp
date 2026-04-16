#pragma once

#include <cstdint>
#include <unordered_map>
#include <vector>

namespace simply {

// scans the image for qword pointer runs that resolve to loaded-module exports,
// builds fresh import descriptors, appends a new .simply section.
bool rebuild_iat(void* process_handle, std::vector<std::uint8_t>& image, std::uint64_t image_base);

// takes stub_va -> api_va captures and adds real IAT descriptors for each api.
// returns api_va -> iat_rva for the trampoline emitter.
std::unordered_map<std::uint64_t, std::uint32_t> extend_iat_for_captures(void* process_handle, std::vector<std::uint8_t>& image, std::uint64_t image_base, const std::unordered_map<std::uint64_t, std::uint64_t>& landings);

/*
rebinds themida-poisoned data slots to real imports. each (slot, stub) pair
becomes an IMPORT descriptor with FirstThunk = slot_rva, so the loader writes
the real api address straight into the original slot at load time and the
program's `mov rax,[slot]; call rax` just works. run after extend_iat_for_captures
and before clean_dump.
*/
std::uint32_t rebind_poisoned_slots(void* process_handle, std::vector<std::uint8_t>& image, std::uint64_t image_base, const std::unordered_map<std::uint64_t, std::uint64_t>& slot_to_stub, const std::unordered_map<std::uint64_t, std::uint64_t>& stub_to_api);

}  // namespace simply

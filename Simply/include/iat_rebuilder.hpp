#pragma once

#include <cstdint>
#include <memory>
#include <unordered_map>
#include <vector>

namespace simply {

/*
opaque snapshot of every loaded module in the target plus their export tables.
take this BEFORE capture runs (target threads suspended at OEP). capture can
crash the target, and the rebuild stages below need module/export data that
EnumProcessModulesEx can't read from a dead process - the snapshot frees them
from a live handle.
*/
struct ModuleSnapshot;
struct ModuleSnapshotDeleter { void operator()(ModuleSnapshot*) const noexcept; };
using ModuleSnapshotPtr = std::unique_ptr<ModuleSnapshot, ModuleSnapshotDeleter>;

ModuleSnapshotPtr snapshot_modules(void* process_handle);

// scans the image for qword pointer runs that resolve to loaded-module exports,
// builds fresh import descriptors, appends a new .simply section.
bool rebuild_iat(const ModuleSnapshot& snap, std::vector<std::uint8_t>& image, std::uint64_t image_base);

// takes stub_va -> api_va captures and adds real IAT descriptors for each api.
// returns api_va -> iat_rva for the trampoline emitter.
std::unordered_map<std::uint64_t, std::uint32_t> extend_iat_for_captures(const ModuleSnapshot& snap, std::vector<std::uint8_t>& image, std::uint64_t image_base, const std::unordered_map<std::uint64_t, std::uint64_t>& landings);

/*
rebinds themida-poisoned data slots to real imports. each (slot, stub) pair
becomes an IMPORT descriptor with FirstThunk = slot_rva, so the loader writes
the real api address straight into the original slot at load time and the
program's `mov rax,[slot]; call rax` just works. run after extend_iat_for_captures
and before clean_dump.
*/
std::uint32_t rebind_poisoned_slots(const ModuleSnapshot& snap, std::vector<std::uint8_t>& image, std::uint64_t image_base, const std::unordered_map<std::uint64_t, std::uint64_t>& slot_to_stub, const std::unordered_map<std::uint64_t, std::uint64_t>& stub_to_api);

}  // namespace simply

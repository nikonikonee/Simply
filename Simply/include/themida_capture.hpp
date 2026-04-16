#pragma once

#include <cstdint>
#include <unordered_map>

namespace simply {

/*
runtime capture for themida-poisoned api refs. caller has the target frozen at OEP.
catches two shapes:
  1. call/jmp rel32 in .text hitting a packer section (the themida stub)
  2. qword data slots whose runtime value points into a packer section

for each, spawn a remote thread at the stub VA, TF-step until RIP lands in
a real system DLL, record the landing. shared stub_to_api because many slots
can alias the same stub.
*/
struct CaptureResult {
    std::unordered_map<std::uint64_t, std::uint64_t> stub_to_api;
    std::unordered_map<std::uint64_t, std::uint64_t> slot_to_stub;
};

CaptureResult capture_api_landings(void* process_handle, std::uint64_t image_base, std::uint32_t size_of_image);

}  // namespace simply

#pragma once

#include <cstdint>
#include <filesystem>
#include <vector>

#include "iat_rebuilder.hpp"
#include "themida_capture.hpp"

namespace simply {

// snapshot size_of_image bytes from the target. unreadable pages are zeroed.
// caller takes the buffer before running anything that might crash the target.
std::vector<std::uint8_t> snapshot_image(void* process_handle, std::uint64_t image_base, std::uint32_t size_of_image);

// turn a pre-taken image snapshot into a structurally valid PE on disk. snap
// must be taken from the live target before capture (capture can crash it,
// and the rebuild stages need module/export data).
// capture carries the runtime stub/slot maps, pass nullptr to skip that rewrite.
bool dump_image(const ModuleSnapshot& snap, std::vector<std::uint8_t> buffer, std::uint64_t image_base, std::uint64_t preferred_image_base, std::uint32_t size_of_image, std::uint64_t oep_va, const std::filesystem::path& output_path, const CaptureResult* capture);

}  // namespace simply

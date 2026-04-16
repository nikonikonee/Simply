#pragma once

#include <cstdint>
#include <filesystem>

#include "themida_capture.hpp"

namespace simply {

// reads size_of_image bytes from the target and writes a structurally valid PE.
// capture carries the runtime stub/slot maps, pass nullptr to skip that rewrite.
bool dump_image(void* process_handle, std::uint64_t image_base, std::uint64_t preferred_image_base, std::uint32_t size_of_image, std::uint64_t oep_va, const std::filesystem::path& output_path, const CaptureResult* capture);

}  // namespace simply

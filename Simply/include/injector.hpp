#pragma once

#include <cstdint>
#include <filesystem>

namespace simply {

// in-flight manual map. start, watch for the loader thread's exit, then finalize.
struct Injection {
    void* remote_image = nullptr;
    std::size_t remote_image_size = 0;
    void* remote_shellcode = nullptr;
    std::size_t remote_shellcode_size = 0;
    void* remote_thread = nullptr;
    std::uint32_t remote_thread_id = 0;
    bool started = false;
};

Injection start_dll_injection(void* process_handle, const std::filesystem::path& dll_path);

// reads the shellcode thread's exit code and frees remote allocs. true if DllMain returned non-zero.
bool finalize_injection(void* process_handle, Injection& inj);

}  // namespace simply

#include "injector.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winnt.h>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <vector>

#include "simply_log.hpp"

namespace simply {
namespace {

std::vector<std::uint8_t> read_file(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {};
    const auto size = static_cast<std::size_t>(f.tellg());
    f.seekg(0);
    std::vector<std::uint8_t> bytes(size);
    f.read(reinterpret_cast<char*>(bytes.data()), size);
    return bytes;
}

IMAGE_NT_HEADERS64* nt_of(std::uint8_t* p) {
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(p);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(p + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    return nt;
}

bool copy_headers_and_sections(const std::vector<std::uint8_t>& file, std::vector<std::uint8_t>& image) {
    auto* nt = nt_of(const_cast<std::uint8_t*>(file.data()));
    if (!nt) return false;
    const auto& opt = nt->OptionalHeader;
    image.assign(opt.SizeOfImage, 0);
    std::memcpy(image.data(), file.data(), opt.SizeOfHeaders);

    auto* sect = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const auto raw = sect[i].PointerToRawData;
        const auto rsize = sect[i].SizeOfRawData;
        if (rsize > 0 && raw + rsize <= file.size()) {
            std::memcpy(image.data() + sect[i].VirtualAddress,
                        file.data() + raw, rsize);
        }
    }
    return true;
}

void apply_relocs(std::uint8_t* image, std::uint64_t new_base) {
    auto* nt = nt_of(image);
    const auto& opt = nt->OptionalHeader;
    const auto delta = static_cast<std::int64_t>(new_base) -
                       static_cast<std::int64_t>(opt.ImageBase);
    if (delta == 0) return;
    const auto& dir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dir.Size == 0) return;

    auto* blk = reinterpret_cast<IMAGE_BASE_RELOCATION*>(image + dir.VirtualAddress);
    const auto* end = reinterpret_cast<const std::uint8_t*>(blk) + dir.Size;
    while (reinterpret_cast<const std::uint8_t*>(blk) < end && blk->SizeOfBlock >= sizeof(*blk)) {
        const auto count = (blk->SizeOfBlock - sizeof(*blk)) / sizeof(WORD);
        auto* entries = reinterpret_cast<WORD*>(blk + 1);
        for (DWORD i = 0; i < count; ++i) {
            const WORD e = entries[i];
            const WORD type = e >> 12;
            const WORD off = e & 0x0FFF;
            if (type == IMAGE_REL_BASED_DIR64) {
                auto* slot = reinterpret_cast<std::uint64_t*>(image + blk->VirtualAddress + off);
                *slot = static_cast<std::uint64_t>(*slot + delta);
            }
        }
        blk = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            reinterpret_cast<std::uint8_t*>(blk) + blk->SizeOfBlock);
    }
}

/*
   SimplyBypass is built /MT so imports are only system dlls (kernel32, ntdll,
   user32). those live at the same base across processes on a boot, so
   GetProcAddress in our process yields addresses valid in the target
 */
bool resolve_imports(std::uint8_t* image) {
    auto* nt = nt_of(image);
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.Size == 0) return true;

    auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(image + dir.VirtualAddress);
    for (; desc->Name != 0; ++desc) {
        const char* dll_name = reinterpret_cast<const char*>(image + desc->Name);
        HMODULE mod = GetModuleHandleA(dll_name);
        if (!mod) mod = LoadLibraryA(dll_name);
        if (!mod) {
            log::error("inject: cannot resolve import dll {}", dll_name);
            return false;
        }

        const auto int_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        std::vector<std::uintptr_t> thunks;
        auto* src = reinterpret_cast<std::uintptr_t*>(image + int_rva);
        while (*src) { thunks.push_back(*src); ++src; }

        auto* iat = reinterpret_cast<std::uintptr_t*>(image + desc->FirstThunk);
        for (auto thunk : thunks) {
            FARPROC fn = nullptr;
            if (IMAGE_SNAP_BY_ORDINAL64(thunk)) {
                fn = GetProcAddress(mod, reinterpret_cast<LPCSTR>(IMAGE_ORDINAL64(thunk)));
            } else {
                auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(image + thunk);
                fn = GetProcAddress(mod, ibn->Name);
            }
            if (!fn) {
                log::error("inject: cannot resolve import from {}", dll_name);
                return false;
            }
            *iat++ = reinterpret_cast<std::uintptr_t>(fn);
        }
    }
    return true;
}

// tiny x64 stub: call DllMain(base, DLL_PROCESS_ATTACH, 0) then ret. imm64s patched in place
std::vector<std::uint8_t> build_shellcode(std::uint64_t base, std::uint64_t dllmain) {
    std::vector<std::uint8_t> sc = {
        0x48, 0x83, 0xEC, 0x28,                         // sub rsp, 0x28
        0x48, 0xB9, 0,0,0,0,0,0,0,0,                    // mov rcx, imm64 (base)
        0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,       // mov rdx, 1
        0x4D, 0x31, 0xC0,                               // xor r8, r8
        0x48, 0xB8, 0,0,0,0,0,0,0,0,                    // mov rax, imm64 (dllmain)
        0xFF, 0xD0,                                     // call rax
        0x48, 0x83, 0xC4, 0x28,                         // add rsp, 0x28
        0xC3                                            // ret
    };
    std::memcpy(sc.data() + 6, &base, sizeof(base));
    std::memcpy(sc.data() + 26, &dllmain, sizeof(dllmain));
    return sc;
}

using NtCreateThreadEx_t = LONG (NTAPI*)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE,
    PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

}  // namespace

Injection start_dll_injection(void* process_handle, const std::filesystem::path& dll_path) {
    Injection inj{};
    auto* process = static_cast<HANDLE>(process_handle);

    const auto file = read_file(dll_path);
    if (file.empty()) {
        log::error("inject: cannot read dll {}", dll_path.string());
        return inj;
    }

    std::vector<std::uint8_t> image;
    if (!copy_headers_and_sections(file, image)) {
        log::error("inject: bad dll headers");
        return inj;
    }

    auto* nt = nt_of(image.data());
    const SIZE_T image_size = nt->OptionalHeader.SizeOfImage;

    void* remote = VirtualAllocEx(process, nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) {
        log::error("inject: VirtualAllocEx image failed: {}", GetLastError());
        return inj;
    }

    apply_relocs(image.data(), reinterpret_cast<std::uint64_t>(remote));
    if (!resolve_imports(image.data())) {
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        return inj;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remote, image.data(), image_size, &written)
        || written != image_size) {
        log::error("inject: WriteProcessMemory image failed: {}", GetLastError());
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        return inj;
    }

    const auto dllmain_va = reinterpret_cast<std::uint64_t>(remote) +
                            nt->OptionalHeader.AddressOfEntryPoint;
    const auto sc = build_shellcode(reinterpret_cast<std::uint64_t>(remote), dllmain_va);

    void* remote_sc = VirtualAllocEx(process, nullptr, sc.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_sc) {
        log::error("inject: VirtualAllocEx shellcode failed: {}", GetLastError());
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        return inj;
    }
    if (!WriteProcessMemory(process, remote_sc, sc.data(), sc.size(), &written)
        || written != sc.size()) {
        log::error("inject: WriteProcessMemory shellcode failed: {}", GetLastError());
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        VirtualFreeEx(process, remote_sc, 0, MEM_RELEASE);
        return inj;
    }

    auto* ntdll = GetModuleHandleW(L"ntdll.dll");
    auto nt_create = reinterpret_cast<NtCreateThreadEx_t>(
        GetProcAddress(ntdll, "NtCreateThreadEx"));
    if (!nt_create) {
        log::error("inject: NtCreateThreadEx not found");
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        VirtualFreeEx(process, remote_sc, 0, MEM_RELEASE);
        return inj;
    }

    HANDLE thread = nullptr;
    const LONG status = nt_create(&thread, THREAD_ALL_ACCESS, nullptr, process, remote_sc, nullptr, 0, 0, 0, 0, nullptr);
    if (status < 0 || !thread) {
        log::error("inject: NtCreateThreadEx failed: 0x{:x}", static_cast<std::uint32_t>(status));
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        VirtualFreeEx(process, remote_sc, 0, MEM_RELEASE);
        return inj;
    }

    inj.remote_image = remote;
    inj.remote_image_size = image_size;
    inj.remote_shellcode = remote_sc;
    inj.remote_shellcode_size = sc.size();
    inj.remote_thread = thread;
    inj.remote_thread_id = GetThreadId(thread);
    inj.started = true;

    log::debug("inject: manual-mapped image=0x{:x} tid={}",
               reinterpret_cast<std::uint64_t>(remote), inj.remote_thread_id);
    return inj;
}

bool finalize_injection(void* process_handle, Injection& inj) {
    if (!inj.started) return false;
    auto* process = static_cast<HANDLE>(process_handle);
    auto* thread = static_cast<HANDLE>(inj.remote_thread);

    DWORD exit_code = 0;
    GetExitCodeThread(thread, &exit_code);
    const bool ok = exit_code != 0;

    CloseHandle(thread);
    VirtualFreeEx(process, inj.remote_shellcode, 0, MEM_RELEASE);
    // leave the mapped image alive, hooks reference code inside it
    inj = {};

    if (ok) {
        log::info("bypass dll manual-mapped and initialised");
    } else {
        log::error("bypass dll DllMain returned zero");
    }
    return ok;
}

}  // namespace simply

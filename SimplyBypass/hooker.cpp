#include "hooker.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace simply::bypass::hooker {

namespace {

constexpr std::size_t kJmpAbsSize = 14;          // FF 25 00 00 00 00 <qword>
constexpr std::size_t kTrampSize  = 64;
constexpr std::size_t kMaxHooks   = 64;
constexpr std::size_t kPoolSize   = kMaxHooks * kTrampSize;

struct HookRecord {
    std::uint8_t* target;
    std::size_t   patch_len;
    std::uint8_t  saved[kJmpAbsSize];
};

HookRecord g_hooks[kMaxHooks];
std::size_t g_hook_count = 0;

std::uint8_t* g_pool = nullptr;
std::size_t   g_pool_used = 0;

// -- minimal x64 length disassembler --

struct Decoded {
    std::size_t length;
    bool is_relative;   // instruction has rel8/rel32 operand or RIP-relative modrm
};

Decoded ldisasm(const std::uint8_t* pc) {
    const std::uint8_t* p = pc;
    bool has_66 = false;
    bool rex_w  = false;

    // legacy prefixes
    while (true) {
        std::uint8_t b = *p;
        if (b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E ||
            b == 0x64 || b == 0x65 || b == 0x67 ||
            b == 0xF0 || b == 0xF2 || b == 0xF3) { ++p; continue; }
        if (b == 0x66) { has_66 = true; ++p; continue; }
        break;
    }

    // REX
    if ((*p & 0xF0) == 0x40) {
        rex_w = (*p & 0x08) != 0;
        ++p;
    }

    std::uint8_t op = *p++;

    bool has_modrm    = false;
    int  imm_size     = 0;
    bool is_relative  = false;
    bool known        = true;

    if (op == 0x0F) {
        std::uint8_t op2 = *p++;
        if (op2 == 0x05 || op2 == 0x31 || op2 == 0x34 || op2 == 0x35) {
            // SYSCALL / RDTSC / SYSENTER / SYSEXIT
        } else if (op2 == 0x1F) {
            has_modrm = true;                         // multi-byte NOP
        } else if ((op2 & 0xF0) == 0x80) {
            is_relative = true;                       // Jcc rel32
            imm_size = has_66 ? 2 : 4;
        } else if (op2 == 0xAF ||
                   op2 == 0xB6 || op2 == 0xB7 ||
                   op2 == 0xBE || op2 == 0xBF) {
            has_modrm = true;                         // IMUL, MOVZX, MOVSX
        } else {
            known = false;
        }
    } else {
        switch (op) {
            // ModRM only
            case 0x00: case 0x01: case 0x02: case 0x03:
            case 0x08: case 0x09: case 0x0A: case 0x0B:
            case 0x10: case 0x11: case 0x12: case 0x13:
            case 0x18: case 0x19: case 0x1A: case 0x1B:
            case 0x20: case 0x21: case 0x22: case 0x23:
            case 0x28: case 0x29: case 0x2A: case 0x2B:
            case 0x30: case 0x31: case 0x32: case 0x33:
            case 0x38: case 0x39: case 0x3A: case 0x3B:
            case 0x63:
            case 0x84: case 0x85: case 0x86: case 0x87:
            case 0x88: case 0x89: case 0x8A: case 0x8B:
            case 0x8D: case 0x8F:
            case 0xD0: case 0xD1: case 0xD2: case 0xD3:
            case 0xFE: case 0xFF:
                has_modrm = true; break;
            // ModRM + imm8
            case 0x80: case 0x82: case 0x83:
            case 0xC0: case 0xC1:
            case 0xC6:
                has_modrm = true; imm_size = 1; break;
            // ModRM + imm16/32
            case 0x81:
            case 0xC7:
                has_modrm = true; imm_size = has_66 ? 2 : 4; break;
            // F6/F7 imm only when /reg in {0,1} (TEST)
            case 0xF6:
            case 0xF7: {
                has_modrm = true;
                std::uint8_t mrm = *p;
                std::uint8_t reg = (mrm >> 3) & 7;
                if (reg <= 1) imm_size = (op == 0xF6) ? 1 : (has_66 ? 2 : 4);
                break;
            }
            // imm only, no ModRM
            case 0x04: case 0x0C: case 0x14: case 0x1C:
            case 0x24: case 0x2C: case 0x34: case 0x3C:
            case 0xA8:
                imm_size = 1; break;
            case 0x05: case 0x0D: case 0x15: case 0x1D:
            case 0x25: case 0x2D: case 0x35: case 0x3D:
            case 0xA9:
                imm_size = has_66 ? 2 : 4; break;
            case 0x68:                                // PUSH imm32
                imm_size = has_66 ? 2 : 4; break;
            case 0x6A:                                // PUSH imm8
                imm_size = 1; break;
            case 0x69:                                // IMUL r,r/m,imm32
                has_modrm = true; imm_size = has_66 ? 2 : 4; break;
            case 0x6B:                                // IMUL r,r/m,imm8
                has_modrm = true; imm_size = 1; break;
            // relative
            case 0x70: case 0x71: case 0x72: case 0x73:
            case 0x74: case 0x75: case 0x76: case 0x77:
            case 0x78: case 0x79: case 0x7A: case 0x7B:
            case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            case 0xE0: case 0xE1: case 0xE2: case 0xE3:
            case 0xEB:
                is_relative = true; imm_size = 1; break;
            case 0xE8: case 0xE9:
                is_relative = true; imm_size = has_66 ? 2 : 4; break;
            // MOV reg, imm
            case 0xB0: case 0xB1: case 0xB2: case 0xB3:
            case 0xB4: case 0xB5: case 0xB6: case 0xB7:
                imm_size = 1; break;
            case 0xB8: case 0xB9: case 0xBA: case 0xBB:
            case 0xBC: case 0xBD: case 0xBE: case 0xBF:
                imm_size = rex_w ? 8 : (has_66 ? 2 : 4); break;
            case 0xC2:                                // RET imm16
                imm_size = 2; break;
            case 0xCA:                                // RETF imm16
                imm_size = 2; break;
            case 0xCD:                                // INT imm8
                imm_size = 1; break;
            // single-byte no operand
            case 0x50: case 0x51: case 0x52: case 0x53:
            case 0x54: case 0x55: case 0x56: case 0x57:
            case 0x58: case 0x59: case 0x5A: case 0x5B:
            case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            case 0x90: case 0x91: case 0x92: case 0x93:
            case 0x94: case 0x95: case 0x96: case 0x97:
            case 0x98: case 0x99: case 0x9B: case 0x9C:
            case 0x9D: case 0x9E: case 0x9F:
            case 0xC3: case 0xC9: case 0xCB: case 0xCC: case 0xCE: case 0xCF:
            case 0xF4: case 0xF5:
            case 0xF8: case 0xF9: case 0xFA: case 0xFB:
            case 0xFC: case 0xFD:
                break;
            default:
                known = false;
                break;
        }
    }

    if (!known) return { 0, false };

    if (has_modrm) {
        std::uint8_t mrm = *p++;
        std::uint8_t mod = (mrm >> 6) & 3;
        std::uint8_t rm  = mrm & 7;
        if (mod != 3) {
            if (mod == 0 && rm == 5) {
                // RIP-relative in 64-bit mode
                is_relative = true;
                p += 4;
            } else if (rm == 4) {
                // SIB
                std::uint8_t sib = *p++;
                std::uint8_t base = sib & 7;
                if (mod == 0 && base == 5) p += 4;
                else if (mod == 1)          p += 1;
                else if (mod == 2)          p += 4;
            } else {
                if (mod == 1)      p += 1;
                else if (mod == 2) p += 4;
            }
        }
    }

    p += imm_size;
    return { static_cast<std::size_t>(p - pc), is_relative };
}

void write_abs_jmp(std::uint8_t* dst, const void* dest) {
    dst[0] = 0xFF;
    dst[1] = 0x25;
    dst[2] = 0x00; dst[3] = 0x00; dst[4] = 0x00; dst[5] = 0x00;
    std::memcpy(dst + 6, &dest, sizeof(dest));
}

}  // namespace

bool initialize() {
    if (g_pool) return true;
    g_pool = static_cast<std::uint8_t*>(
        VirtualAlloc(nullptr, kPoolSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    g_pool_used = 0;
    g_hook_count = 0;
    return g_pool != nullptr;
}

bool install(void* target, void* detour, void** original) {
    if (!g_pool || !target || !detour || !original) return false;
    if (g_hook_count >= kMaxHooks) return false;
    if (g_pool_used + kTrampSize > kPoolSize) return false;

    auto* t = static_cast<std::uint8_t*>(target);

    // walk instructions until we have at least 14 bytes of prologue to copy
    std::size_t patch_len = 0;
    while (patch_len < kJmpAbsSize) {
        Decoded d = ldisasm(t + patch_len);
        if (d.length == 0) return false;     // unknown opcode
        if (d.is_relative) return false;     // bail on rel or RIP-relative in prologue
        patch_len += d.length;
        if (patch_len > kTrampSize - kJmpAbsSize) return false;
    }

    std::uint8_t* tramp = g_pool + g_pool_used;
    g_pool_used += kTrampSize;

    // trampoline = saved prologue + abs jmp back to (target + patch_len)
    std::memcpy(tramp, t, patch_len);
    write_abs_jmp(tramp + patch_len, t + patch_len);

    HookRecord& rec = g_hooks[g_hook_count];
    rec.target = t;
    rec.patch_len = patch_len;
    std::memcpy(rec.saved, t, kJmpAbsSize);

    /*
       publish the trampoline pointer BEFORE patching the target. hooks like
       NtProtectVirtualMemory call VirtualProtect/NtClose themselves while
       we're still mid-install, so real_<X> must already be valid when the
       patched bytes fire.
     */
    *original = tramp;

    DWORD old = 0;
    if (!VirtualProtect(t, kJmpAbsSize, PAGE_EXECUTE_READWRITE, &old)) {
        *original = nullptr;
        g_pool_used -= kTrampSize;
        return false;
    }
    write_abs_jmp(t, detour);
    DWORD ignored = 0;
    VirtualProtect(t, kJmpAbsSize, old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), t, kJmpAbsSize);

    ++g_hook_count;
    return true;
}

void uninitialize() {
    for (std::size_t i = 0; i < g_hook_count; ++i) {
        HookRecord& rec = g_hooks[i];
        DWORD old = 0;
        if (VirtualProtect(rec.target, kJmpAbsSize, PAGE_EXECUTE_READWRITE, &old)) {
            std::memcpy(rec.target, rec.saved, kJmpAbsSize);
            DWORD ignored = 0;
            VirtualProtect(rec.target, kJmpAbsSize, old, &ignored);
            FlushInstructionCache(GetCurrentProcess(), rec.target, kJmpAbsSize);
        }
    }
    g_hook_count = 0;
    if (g_pool) {
        VirtualFree(g_pool, 0, MEM_RELEASE);
        g_pool = nullptr;
        g_pool_used = 0;
    }
}

}  // namespace simply::bypass::hooker

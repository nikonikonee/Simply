#include "themida_stubs.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <unordered_map>

#include "simply_log.hpp"

namespace simply {

namespace {

constexpr std::array<std::string_view, 9> kPackerNames = {
    ".themida", ".boot", ".winlice", "WinLicen",
    ".vmp0", ".vmp1",
    ".mpress1", ".mpress2",
    ".enigma1"
};

std::string section_name(const IMAGE_SECTION_HEADER& s) {
    char buf[9] = {};
    std::memcpy(buf, s.Name, 8);
    return std::string(buf);
}

bool is_packer_section(const IMAGE_SECTION_HEADER& s) {
    const std::string n = section_name(s);
    return std::any_of(kPackerNames.begin(), kPackerNames.end(),
                       [&](std::string_view k) { return n == k; });
}

const IMAGE_SECTION_HEADER* section_containing_rva(const IMAGE_SECTION_HEADER* secs, unsigned count, std::uint32_t rva) {
    for (unsigned i = 0; i < count; ++i) {
        const auto& s = secs[i];
        if (rva >= s.VirtualAddress &&
            rva < s.VirtualAddress + (std::max)(s.Misc.VirtualSize, s.SizeOfRawData)) {
            return &secs[i];
        }
    }
    return nullptr;
}

/*
   peel a themida api stub. patterns we handle:
     FF 25 disp32  -> jmp qword ptr [rip+disp32]
     E9 disp32     -> jmp rel32, follow the chain
     EB disp8      -> jmp rel8, follow
   returns the rva of the iat pointer, 0 if we can't tell
 */
std::uint32_t resolve_stub_iat_rva(const std::vector<std::uint8_t>& image, std::uint32_t stub_rva, unsigned max_follow = 4) {
    for (unsigned step = 0; step < max_follow; ++step) {
        if (stub_rva + 6 > image.size()) return 0;
        const std::uint8_t* p = image.data() + stub_rva;

        if (p[0] == 0xFF && p[1] == 0x25) {
            std::int32_t disp;
            std::memcpy(&disp, p + 2, 4);
            const std::uint64_t next = static_cast<std::uint64_t>(stub_rva) + 6;
            const std::int64_t iat_rva64 = static_cast<std::int64_t>(next) + disp;
            if (iat_rva64 < 0 || static_cast<std::uint64_t>(iat_rva64) + 8 > image.size()) return 0;
            return static_cast<std::uint32_t>(iat_rva64);
        }
        if (p[0] == 0xE9) {
            std::int32_t disp;
            std::memcpy(&disp, p + 1, 4);
            const std::uint64_t next = static_cast<std::uint64_t>(stub_rva) + 5;
            const std::int64_t nxt = static_cast<std::int64_t>(next) + disp;
            if (nxt < 0 || static_cast<std::uint64_t>(nxt) + 6 > image.size()) return 0;
            stub_rva = static_cast<std::uint32_t>(nxt);
            continue;
        }
        if (p[0] == 0xEB) {
            const std::int8_t d = static_cast<std::int8_t>(p[1]);
            stub_rva = static_cast<std::uint32_t>(
                static_cast<std::int64_t>(stub_rva) + 2 + d);
            continue;
        }
        return 0;
    }
    return 0;
}

}  // namespace

std::uint32_t rewrite_themida_stubs(std::vector<std::uint8_t>& image, std::uint64_t image_base, const std::unordered_map<std::uint64_t, std::uint32_t>* stub_iat_overrides) {
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return 0;
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    const std::size_t nt_off = dos->e_lfanew;
    if (nt_off + sizeof(IMAGE_NT_HEADERS64) > image.size()) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + nt_off);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return 0;

    auto* sections = IMAGE_FIRST_SECTION(nt);
    const unsigned count = nt->FileHeader.NumberOfSections;

    // trampolines go into .simply slack space
    const IMAGE_SECTION_HEADER* text_sec = nullptr;
    IMAGE_SECTION_HEADER* simply_sec = nullptr;
    for (unsigned i = 0; i < count; ++i) {
        if (!text_sec &&
            (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            !is_packer_section(sections[i])) {
            text_sec = &sections[i];
        }
        if (!simply_sec && std::memcmp(sections[i].Name, ".simply", 7) == 0) {
            simply_sec = &sections[i];
        }
    }
    if (!text_sec) {
        log::warn("stubs: no .text section found");
        return 0;
    }
    if (!simply_sec) {
        log::warn("stubs: no .simply section (did rebuild_iat succeed?)");
        return 0;
    }

    struct Range { std::uint32_t lo, hi; };
    std::vector<Range> packer_ranges;
    for (unsigned i = 0; i < count; ++i) {
        if (is_packer_section(sections[i])) {
            const auto& s = sections[i];
            const std::uint32_t hi =
                s.VirtualAddress + (std::max)(s.Misc.VirtualSize, s.SizeOfRawData);
            packer_ranges.push_back({s.VirtualAddress, hi});
        }
    }
    if (packer_ranges.empty()) return 0;

    auto in_packer = [&](std::uint32_t rva) {
        for (const auto& r : packer_ranges) {
            if (rva >= r.lo && rva < r.hi) return true;
        }
        return false;
    };

    /*
     * scan .text for call/jmp rel32 into a packer section. unresolved sites
     * get left alone (we warn and keep the packer section around).
     */
    struct Hit {
        std::uint32_t site_rva = 0;  // location of the disp32 field
        std::uint32_t insn_end = 0;  // rip after the instruction
        std::uint32_t iat_rva  = 0;
    };
    std::vector<Hit> resolved;
    std::uint32_t unresolved = 0;

    const std::uint32_t t_off = text_sec->PointerToRawData;
    const std::uint32_t t_len = (std::min)(text_sec->Misc.VirtualSize, text_sec->SizeOfRawData);
    if (t_off >= image.size()) return 0;
    const std::uint32_t avail = (std::min<std::uint32_t>)(t_len,
        static_cast<std::uint32_t>(image.size() - t_off));
    const std::uint8_t* text_p = image.data() + t_off;
    const std::uint32_t text_base_rva = text_sec->VirtualAddress;

    for (std::uint32_t i = 0; i + 5 <= avail; ++i) {
        const std::uint8_t op = text_p[i];
        if (op != 0xE8 && op != 0xE9) continue;
        std::int32_t disp;
        std::memcpy(&disp, text_p + i + 1, 4);
        const std::uint64_t insn_end = static_cast<std::uint64_t>(text_base_rva) + i + 5;
        const std::int64_t tgt = static_cast<std::int64_t>(insn_end) + disp;
        if (tgt < 0) continue;
        const std::uint32_t tgt_rva = static_cast<std::uint32_t>(tgt);
        if (!in_packer(tgt_rva)) continue;

        std::uint32_t iat_rva = resolve_stub_iat_rva(image, tgt_rva);
        if (iat_rva == 0 && stub_iat_overrides) {
            // static walk failed, check for a runtime-capture override
            auto it = stub_iat_overrides->find(image_base + tgt_rva);
            if (it != stub_iat_overrides->end()) iat_rva = it->second;
        }
        if (iat_rva != 0) {
            resolved.push_back(Hit{
                .site_rva = text_base_rva + i + 1,
                .insn_end = static_cast<std::uint32_t>(insn_end),
                .iat_rva  = iat_rva,
            });
            continue;
        }

        ++unresolved;
        char hex[3 * 24 + 1] = {};
        const std::size_t dump_len = (tgt_rva + 24 <= image.size()) ? 24 :
                                     (image.size() - tgt_rva);
        for (std::size_t k = 0; k < dump_len; ++k) {
            std::snprintf(hex + 3 * k, 4, "%02X ", image[tgt_rva + k]);
        }
        log::debug("stubs: unresolved call at rva 0x{:x} -> stub 0x{:x}: {}",
                   text_base_rva + i, tgt_rva, hex);

        /*
         * leave the site untouched. themida 3.x VM-Macro stubs implement
         * actual logic and return values into .text, so neutering with int3
         * makes the dump crash on first reach. the original E8/E9 disp32
         * still points into .themida, which keeps section_cleaner's xref
         * count > 0 so the packer section content is preserved.
         */
    }

    if (resolved.empty()) {
        if (unresolved > 0) {
            log::warn("stubs: {} call site(s) into packer section unresolved (left intact, .themida content preserved)", unresolved);
        }
        return 0;
    }

    // one 6-byte FF25 trampoline per unique iat slot
    constexpr std::uint32_t kTrampSize = 6;

    std::uint32_t simply_va    = simply_sec->VirtualAddress;
    std::uint32_t simply_vsize = simply_sec->Misc.VirtualSize;
    std::uint32_t simply_raw   = simply_sec->SizeOfRawData;
    std::uint32_t slack_start  = simply_va + simply_vsize;
    std::uint32_t slack_end    = simply_va + simply_raw;
    std::uint32_t tramp_cursor = slack_start;

    std::unordered_map<std::uint32_t, std::uint32_t> tramp_by_iat;

    auto alloc_tramp = [&](std::uint32_t iat_rva) -> std::uint32_t {
        auto it = tramp_by_iat.find(iat_rva);
        if (it != tramp_by_iat.end()) return it->second;
        if (tramp_cursor + kTrampSize > slack_end) return 0;
        const std::uint32_t at = tramp_cursor;
        std::uint8_t* tp = image.data() + at;
        tp[0] = 0xFF; tp[1] = 0x25;
        const std::int64_t d = static_cast<std::int64_t>(iat_rva) -
                               (static_cast<std::int64_t>(at) + 6);
        if (d < INT32_MIN || d > INT32_MAX) return 0;
        const std::int32_t d32 = static_cast<std::int32_t>(d);
        std::memcpy(tp + 2, &d32, 4);
        tramp_cursor += kTrampSize;
        // soft-align to 8 for readability
        const std::uint32_t pad = (8 - (tramp_cursor & 7)) & 7;
        if (tramp_cursor + pad + kTrampSize <= slack_end) tramp_cursor += pad;
        tramp_by_iat[iat_rva] = at;
        return at;
    };

    std::uint32_t rewritten = 0;
    std::uint32_t tramp_overflow = 0;
    for (const auto& h : resolved) {
        const std::uint32_t tramp_rva = alloc_tramp(h.iat_rva);
        if (tramp_rva == 0) { ++tramp_overflow; continue; }

        const std::int64_t c_disp64 =
            static_cast<std::int64_t>(tramp_rva) - static_cast<std::int64_t>(h.insn_end);
        if (c_disp64 < INT32_MIN || c_disp64 > INT32_MAX) { ++tramp_overflow; continue; }
        const std::int32_t c_disp32 = static_cast<std::int32_t>(c_disp64);
        std::memcpy(image.data() + h.site_rva, &c_disp32, 4);
        ++rewritten;
    }

    const std::uint32_t new_vsize = tramp_cursor - simply_va;
    if (new_vsize > simply_vsize) simply_sec->Misc.VirtualSize = new_vsize;

    // .simply was emitted RW by rebuild_iat, trampolines need exec
    if (rewritten > 0) {
        simply_sec->Characteristics |= IMAGE_SCN_MEM_EXECUTE;
    }

    log::info("stubs: rewrote {} call site(s) via {} trampoline(s) in .simply slack ({} unresolved, {} overflow)",
              rewritten, tramp_by_iat.size(), unresolved, tramp_overflow);
    return rewritten;
}

}  // namespace simply

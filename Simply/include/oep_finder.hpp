#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

struct _EXCEPTION_DEBUG_INFO;

namespace simply {

// VA range with PAGE_EXECUTE stripped. first instruction fetch into it pins the OEP.
struct OepTrap {
    std::uint64_t text_base = 0;
    std::size_t   text_size = 0;
    // full module range lets us tell a real OEP from a themida VM sub-call
    std::uint64_t image_base = 0;
    std::size_t   image_size = 0;
    bool          armed     = false;

    // one-shot HW exec BP on DR0 for re-arming after VM sub-calls return.
    // HW BP because themida re-encrypts .themida in the background and clobbers int3.
    std::uint64_t bp_addr   = 0;
    bool          bp_active = false;
};

enum class OepFaultKind {
    Unrelated,
    RealOep,
    VmSubcall,
    ReturnBp,
    // themida pro: only byte in .text is a JMP rel32 into a runtime VM region.
    // step the JMP, let the VM run, pick up the next .text fetch as real OEP.
    VirtualizedThunk,
};

struct OepFaultInfo {
    OepFaultKind  kind      = OepFaultKind::Unrelated;
    std::uint64_t fault_va  = 0;
    std::uint64_t return_va = 0;
};

bool arm_oep_trap(void* process_handle, OepTrap& trap);
bool disarm_oep_trap(void* process_handle, OepTrap& trap);

// DR0 exec BP, one at a time. HW so themida's page re-encryption can't clobber it.
bool set_return_bp(void* process_handle, OepTrap& trap, void* thread_handle, std::uint64_t addr);
bool clear_return_bp(void* process_handle, OepTrap& trap, void* thread_handle);

// flips EFlags TF for single-stepping the EPV JMP thunk
bool set_trap_flag(void* thread_handle, bool enable);

OepFaultInfo classify_fault(const _EXCEPTION_DEBUG_INFO& ex, const OepTrap& trap, void* process_handle, void* thread_handle);

}  // namespace simply

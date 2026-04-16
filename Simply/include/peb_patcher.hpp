#pragma once

namespace simply {

// hides debugger presence before any themida code runs
bool patch_peb(void* process_handle);

// drops SeDebugPrivilege, themida probes for it by trying OpenProcess(csrss.exe)
bool strip_debug_privilege(void* process_handle);

}  // namespace simply

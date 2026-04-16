#pragma once

namespace simply::bypass::hooker {

/*
   tiny inline hook engine for x64. patches the first bytes of `target` with
   a 14-byte abs jmp (FF 25 00 00 00 00 <qword>) to `detour`, and hands back
   a trampoline that runs the original prologue then returns to the rest of
   the function. no minhook.
 */

bool initialize();
void uninitialize();
bool install(void* target, void* detour, void** original);

}  // namespace simply::bypass::hooker

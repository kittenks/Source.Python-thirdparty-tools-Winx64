/**
* =============================================================================
* Source Python
* Copyright (C) 2012-2015 Source Python Development Team.  All rights reserved.
* =============================================================================
*
* This program is free software; you can redistribute it and/or modify it under
* the terms of the GNU General Public License, version 3.0, as published by the
* Free Software Foundation.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
* details.
*
* You should have received a copy of the GNU General Public License along with
* this program.  If not, see <http://www.gnu.org/licenses/>.
*
* As a special exception, the Source Python Team gives you permission
* to link the code of this program (as well as its derivative works) to
* "Half-Life 2," the "Source Engine," and any Game MODs that run on software
* by the Valve Corporation.  You must obey the GNU General Public License in
* all respects for all other code used.  Additionally, the Source.Python
* Development Team grants this exception to all derivative works.
*/

// ============================================================================
// >> INCLUDES
// ============================================================================
#include "memory_hooks.h"
#include "memory_utilities.h"
#include "memory_pointer.h"
#include "utilities/wrap_macros.h"
#include "utilities/sp_util.h"

// manager.h declares CHookManager, whose m_Hooks list the tracer walks. It comes
// in through hook.h on some toolchains and not on others, and a missing include
// here would be a confusing error a long way from this line.
#include "manager.h"

// The tracer is Windows-only, and is compiled to nothing elsewhere rather than
// being #ifdef'd at every call site. It needs VirtualQuery to ask "is this
// pointer readable" without taking the read and dying, and the PE headers to
// turn an address into "module+offset"; none of that exists on the Linux
// build, and the crash this traces is a Windows x86-64 crash, so there is
// nothing to preserve by making it portable.
#if defined(_WIN32)
#include <windows.h>
#include <crtdbg.h>
#include <cstdlib>   // getenv, for the SP_HOOK_MINIMAL switch
#endif

#include <boost/python.hpp>
using namespace boost::python;


// ============================================================================
// >> GLOBAL VARIABLES
// ============================================================================
// g_mapCallbacks[<CHook *>][<HookType_t>] -> [<object>, <object>, ...]
std::map<CHook *, std::map<HookType_t, std::list<object> > > g_mapCallbacks;

bool g_HooksDisabled;


// ============================================================================
// >> HELPER FUNCTIONS
// ============================================================================
template<class T>
void SetReturnValue(CHook* pHook, object value)
{
	T val = extract<T>(value);
	pHook->SetReturnValue<T>(val);
}

template<class T>
object GetReturnValue(CHook* pHook)
{
	return object(pHook->GetReturnValue<T>());
}

template<class T>
void SetArgument(CHook* pHook, int iIndex, object value)
{
	T val = extract<T>(value);
	pHook->SetArgument<T>(iIndex, val);
}

template<class T>
object GetArgument(CHook* pHook, int iIndex)
{
	return object(pHook->GetArgument<T>(iIndex));
}


// Page-level write protection on a hook's calling convention, added 2026-09-29.
//
// WHY, AND WHY DELAYED
//
// Everything else has been ruled out. The pointer is loaded from CHook+0x18,
// confirmed by two independently compiled pieces of code agreeing on that
// offset; at runtime that field holds a healthy x64MsWin64 whose vtable is inside
// core.dll and whose GetRegisters is inside core.dll; the bridge agrees with
// m_Hooks; the CRT heap is self-consistent throughout; and it dies on the first
// dispatch, so nothing accumulates. Yet the fault says the object's first eight
// bytes - the vptr - are 0xFFFFFFFFFFFFFFF7.
//
// That leaves exactly one explanation: something wrote that slot. Page write
// protection turns that from an inference into a measurement, because the write
// faults at the writing instruction instead of showing up 40 ms later at a read.
//
// The delay is not cosmetic and not laziness. m_bHooked lives in the same object
// as the vptr, and SP writes it legitimately: DynamicHooks sets it while hooking,
// ~CFunction clears it, DeleteHook clears it. Protecting the page immediately
// would fault on those, produce a crash that looks exactly like the answer, and
// teach nothing. So protection is armed once the hand-off is 300 ms old, by which
// point every legitimate write to that object has already happened.
//
// WHAT A RESULT MEANS
//
// A fault while protected, at a RIP that is not one of the three legitimate
// writers above, is the wild write, and its RIP names it. A fault at one of the
// three is a false positive and is recognised as one. No fault at all, with the
// crash still happening at GetRegisters, means nobody wrote that slot - and then
// the question moves to whether pConvention is the pointer anyone thinks it is at
// the moment of the call.
//
// The protection is deliberately left in place rather than removed after a
// fault. This build exists to be crashed.

namespace
{

// Defined further down, in the SP_HOOK_TRACE block. Anonymous namespaces in one
// translation unit are the same namespace, so a forward declaration here is
// enough and is preferable to reordering the file: the write-protection block
// reads more sensibly next to the reasoning that produced it than after the
// emitter it happens to use.
void SpHookTraceAppend(const char* text);

// Both are defined further down and called from the fault filter, which runs
// before them in the file. Forward declarations rather than reordering: this
// file has twice been left structurally broken by hand-moving blocks, and the
// dependency is two function names.
bool SpIsReadable(const void* p);
void SpHookTraceFlushFaults();

// Defined below the fault handler that calls it, so it is declared here rather
// than moved: relocating a 70-line function to satisfy one forward declaration is
// the kind of edit that has twice left this file structurally broken.
void SpScanServerTextAgainstDisk();

// Defined below the thin vectored handler that calls it. Forward declared rather
// than moving code: this file has twice been left structurally broken by
// hand-reordering blocks, and the dependency is one function name.
LONG SpHookTraceVehHeavy(EXCEPTION_POINTERS* info);

// Used by the vectored handler to turn a return address into "module+RVA", which
// is what makes a stack walk readable. Defined further down.
bool SpDescribeAddr(uintptr_t addr, char* out, size_t outSize);

// Defined in SP_HOOK_WATCHPOINT, which sits below this block because it needs
// the tracked-hook table defined here. A forward declaration is preferable to
// moving the blocks again: the dependency is one function, and reordering a file
// this size by hand is exactly the operation that has already twice left it
// structurally broken.
int SpWatchArmAddress(uintptr_t addr);

struct SpTrackedHook
{
	CHook* pHook;
	DWORD dwFirstSeen;   // when the poll first saw this hook
	bool bArmed;         // page protection - superseded by the watchpoint, kept
	                     // so the two can be compared in one build
	bool bWatched;       // a debug register is now on this hook's convention
};

// Small and fixed on purpose. A std::vector here would allocate on the sampling
// thread while the main thread is allocating too, and a diagnostic that can run
// out of memory is a diagnostic that can fail in the middle of the run it exists
// to explain. A fixed array cannot run out.
const int SpMaxTracked = 32;
SpTrackedHook g_spTracked[SpMaxTracked];
int g_spTrackedCount = 0;

// How long after a hook first appears before its watchpoint is armed.
//
// Zero, and that is a change forced by measurement rather than chosen.
//
// At 300 ms - the value that page protection needed - the watchpoint was never
// armed at all: the run_command hook is created and the server dies roughly
// 80 ms later, so the delay outlasted the hook and the experiment collected
// nothing. A probe that is installed after the thing it watches has gone is not
// a slow probe, it is a probe that answers nothing.
//
// The 300 ms existed to keep a legitimate m_bHooked write from being counted as
// a wild write. That reason does not apply the same way now, because every
// watchpoint hit records the RIP, and the RIP of ~CFunction or DeleteHook is
// recognisable. Better to trap the known write and name it than to be certain of
// not trapping it and thereby trap nothing at all.
const DWORD SpHookTraceProtectDelayMs = 0;

} // namespace

// Called from the sampling thread on every pass.
//
// First pass over a hook only records when it was seen. A later pass, once
// SpHookTraceProtectDelayMs has elapsed, makes its page read-only. The first
// pass is what makes the delay meaningful: without it the clock would start at
// the moment protection was considered, which is the moment protection is
// applied, and the delay would be zero.
void SpHookTracePollWriteProtect()
{
	CHookManager* manager = GetHookManager();
	if (!manager)
		return;

	DWORD now = GetTickCount();

	// The list is walked from the sampling thread while the main thread may be
	// mutating it, so this is inside a catch(...). A throw here costs one missed
	// tracking pass and no more - which is the right failure, since a hang in the
	// diagnostic would be indistinguishable from the bug.
	try
	{
		for (std::list<CHook*>::iterator it = manager->m_Hooks.begin();
			it != manager->m_Hooks.end(); ++it)
		{
			CHook* pHook = *it;
			if (!pHook || !pHook->m_pCallingConvention)
				continue;

			int idx = -1;
			for (int i = 0; i < g_spTrackedCount; i++)
			{
				if (g_spTracked[i].pHook == pHook)
				{
					idx = i;
					break;
				}
			}

			if (idx < 0)
			{
				if (g_spTrackedCount >= SpMaxTracked)
					continue;
				idx = g_spTrackedCount++;
				g_spTracked[idx].pHook = pHook;
				g_spTracked[idx].dwFirstSeen = now;
				g_spTracked[idx].bArmed = false;
				g_spTracked[idx].bWatched = false;
			}

			// Arming is NOT done here.
			//
			// This function used to arm the watchpoint on
			// (uintptr_t) pHook->m_pCallingConvention - the convention object's
			// first eight bytes, the vtable slot - and then set bWatched, which
			// meant SpHookTracePollWatchpoint below never got to arm anything.
			// Two runs (run27 and run28) therefore both re-ran the vptr
			// experiment while their own comments and log wording claimed they
			// were watching the *field*. The armed address in the log proves it:
			// run28 armed 0x...55B62A0, which is the engine.dll hook's convention
			// value, not any CHook + 0x18.
			//
			// This function's only job is tracking - noticing a new hook and
			// recording when it first appeared. Arming happens in exactly one
			// place, SpHookTracePollWatchpoint, so that there is one address
			// choice to reason about instead of two that silently override.
		}
	}
	catch (...)
	{
	}
}



// ============================================================================
// >> SP_HOOK_WATCHPOINT
// ============================================================================
// A hardware data watchpoint on each hook convention's first eight bytes.
//
// WHY, AFTER PAGE PROTECTION FAILED
//
// Page protection was the wrong instrument. The page holding a convention is part
// of the process heap, which every DLL in the process allocates from, so a
// read-only page faults on legitimate traffic - the run recorded writes from
// RPCRT4.dll and ntdll.dll on three threads, all of them the runtime doing its
// own work. A probe that fires on things it should not cannot answer the question
// it was asked.
//
// A data watchpoint is a different instrument. DR0-DR3 hold up to four addresses
// and the CPU compares them per access, so only an access to one of these eight
// bytes traps. Everything else on the page - the rest of the process heap, RPC,
// ntdll, Steam - is untouched and unaffected. That is the property the page
// approach lacked.
//
// WHAT IT CANNOT DO
//
// It does not prevent the write; on x86 a data breakpoint reports *after* the
// instruction that accessed the memory. So this identifies the writer, it does
// not stop it. That is the right trade here: the question is who writes it, and
// preventing it would hide the answer while leaving the corruption in place.
//
// The watchpoint is per thread. Threads created after arming do not have it, so
// a dispatch on a new thread would be missed. Engine dispatch happens on the
// thread that installed the hook, which exists before this runs, but the limit is
// real and is why the run logs how many threads were armed.
//
// Four slots is the hardware limit. With more live hooks than that the extra
// ones are not watched, and the run says so rather than looking complete.

#if defined(_WIN32)

#include <tlhelp32.h>

namespace
{

// The watched addresses, indexed by debug register number. -1 means the slot is
// free. The value is the address of the vptr, i.e. the convention itself.
const int SpMaxWatch = 4;
uintptr_t g_spWatchAddr[SpMaxWatch];
int g_spWatchSlotUsed[SpMaxWatch];

DWORD g_spSamplerThread = 0;
int g_spWatchThreadsArmed = 0;
int g_spWatchArmFailures = 0;

// The thread the engine's game loop runs on, captured by sp_main.cpp at load
// time because that is the only place guaranteed to be running on it.
//
// This is not a convenience. The dispatch that crashes happens on this thread and
// nowhere else, so "no watchpoint hit" means nothing unless this thread was
// actually armed - and the aggregate counts cannot answer that, because they move
// wildly between runs (1068 armed / 188 failed in one, 156 / 872 in another) as
// the thread population at the moment of the poll changes.
//
// Debug registers are per thread, not a per-CPU pool. Arming one thread does not
// consume another's slots, so the aggregate spread is a thread-enumeration
// effect, not contention for hardware resources.
DWORD g_spMainThreadId = 0;
int g_spMainArmedTries = 0;
int g_spMainArmedOk = 0;

void SpWatchReset()
{
	for (int i = 0; i < SpMaxWatch; i++)
	{
		g_spWatchAddr[i] = 0;
		g_spWatchSlotUsed[i] = 0;
	}
	g_spWatchThreadsArmed = 0;
	g_spWatchArmFailures = 0;
}

int SpWatchFreeSlot()
{
	for (int i = 0; i < SpMaxWatch; i++)
	{
		if (!g_spWatchSlotUsed[i])
			return i;
	}
	return -1;
}

// Sets one debug register on one thread.
//
// The thread must be suspended: a thread that is running has no stable CONTEXT,
// and writing a debug register underneath it would race with its own execution.
// Suspend, set, resume - the window is a few microseconds, and the alternative is
// a probe that arms itself non-deterministically.
BOOL SpWatchArmOnThread(DWORD tid, int slot, uintptr_t addr)
{
	HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
	                      THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
	if (!h)
		return FALSE;

	BOOL ok = FALSE;
	if (SuspendThread(h) == (DWORD) -1)
	{
		CloseHandle(h);
		return FALSE;
	}

	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(ctx));
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (GetThreadContext(h, &ctx))
	{
		// Only take a slot that is still free. Overwriting someone else's
		// breakpoint would replace a debugger's - and silently changing what the
		// process does under an attached debugger is not a trade worth making.
		if (!((ctx.Dr7 >> (slot * 2)) & 0x3))
		{
			// Dr0..Dr3 are DWORD64 on x86-64, not DWORD, so the slot is indexed
			// through a DWORD64 pointer. uintptr_t and DWORD64 are the same width
			// on the only architecture this file's body is compiled for.
			DWORD64* pDr = &ctx.Dr0;
			pDr[slot] = (DWORD64) addr;
			// Ln = local enable, R/Wn = 01 write-only. Break on write, not on
			// read: every dispatch reads the vptr, and a read watchpoint would
			// fire on the crash itself and drown the signal it is looking for.
			ctx.Dr7 |= (1UL << (slot * 2));
			ctx.Dr7 |= (1UL << (16 + slot * 2));
			ctx.Dr6 = 0;
			ok = SetThreadContext(h, &ctx) ? TRUE : FALSE;
		}
	}

	ResumeThread(h);
	CloseHandle(h);
	return ok;
}

// Arms the current thread only, immediately, for one address.
//
// THIS IS THE FUNCTION THAT ACTUALLY MATTERS, and it is a different design from
// the polling arming above.
//
// Why it exists: run29 armed DR0 on the engine.dll hook's field - a real field,
// so the previous round's mistake was fixed - but the crashing run_command hook
// was never watched at all. It appeared with six log lines left before the
// process died, and the sampling thread polls every 40 ms and spends most of
// that walking hundreds of threads. It simply never got a turn before the thing
// it was meant to watch was dead.
//
// Arming from the poll therefore loses this race by construction. The hook is
// created by the same thread that will dispatch it, moments before the dispatch,
// so the watchpoint has to be installed there and then. Enumerating threads and
// suspending 150 of them would reintroduce the same delay in a worse place: on
// the main thread, at hook time.
//
// Only the current thread is armed, because it is the only one that can be
// guaranteed both to be present and to be the dispatcher. The main-thread gate
// that run28 added is what makes this sound: if this thread is the engine's main
// thread, then it is precisely the thread the verdict is about.
//
// Deliberately cheap: no allocation, no locks, no enumeration. It runs on the
// main thread inside AddHook, and a diagnostic that stalls the thread it is
// measuring would be indistinguishable from the bug it is looking for.
BOOL SpWatchArmCurrentThread(uintptr_t addr, const char* label)
{
	int slot = SpWatchFreeSlot();
	if (slot < 0)
		return FALSE;

	HANDLE h = GetCurrentThread();
	if (!h)
		return FALSE;

	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(ctx));
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	BOOL ok = FALSE;
	if (GetThreadContext(h, &ctx))
	{
		if (!((ctx.Dr7 >> (slot * 2)) & 0x3))
		{
			DWORD64* pDr = &ctx.Dr0;
			pDr[slot] = (DWORD64) addr;
			ctx.Dr7 |= (1UL << (slot * 2));
			ctx.Dr7 |= (1UL << (16 + slot * 2));
			ctx.Dr6 = 0;
			ok = SetThreadContext(h, &ctx) ? TRUE : FALSE;
		}
	}

	if (ok)
	{
		g_spWatchAddr[slot] = addr;
		g_spWatchSlotUsed[slot] = 1;

		if (GetCurrentThreadId() == g_spMainThreadId)
		{
			g_spMainArmedTries++;
			g_spMainArmedOk++;
		}

		// The label and both addresses go in the line. The armed address is what
		// makes the run checkable: a reader can confirm it is CHook + 0x18 for
		// the hook named, rather than having to trust which arming path fired.
		char line[320];
		_snprintf_s(line, sizeof(line), _TRUNCATE,
			"ARMED     DR%d label=%-10s addr=%016llX slot_is_CHook+0x18=yes"
			" tid=%lu is_main=%d",
			slot, label ? label : "?", (unsigned long long) addr,
			(unsigned long) GetCurrentThreadId(),
			GetCurrentThreadId() == g_spMainThreadId ? 1 : 0);
		SpHookTraceAppend(line);
	}
	else
	{
		char line[200];
		_snprintf_s(line, sizeof(line), _TRUNCATE,
			"ARM-FAIL  label=%-10s addr=%016llX err=%lu",
			label ? label : "?", (unsigned long long) addr,
			(unsigned long) GetLastError());
		SpHookTraceAppend(line);
	}
	return ok;
}

int SpWatchArmAddress(uintptr_t addr)
{
	int slot = SpWatchFreeSlot();
	if (slot < 0)
		return -1;

	int armed = 0;
	int failed = 0;

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snap == INVALID_HANDLE_VALUE)
		return -1;

	THREADENTRY32 te;
	te.dwSize = sizeof(te);
	if (Thread32First(snap, &te))
	{
		do
		{
			// The sampling thread is skipped on purpose: it reads these bytes
			// every 40 ms by design, and arming it would trap on the probe.
			if (te.th32ThreadID == g_spSamplerThread)
				continue;

			BOOL bMain = (te.th32ThreadID == g_spMainThreadId);
			if (bMain)
				g_spMainArmedTries++;

			BOOL okT = SpWatchArmOnThread(te.th32ThreadID, slot, addr);
			if (bMain && okT)
				g_spMainArmedOk++;
			if (okT)
				armed++;
			else
				failed++;
		} while (Thread32Next(snap, &te));
	}
	CloseHandle(snap);

	if (armed == 0)
		return -1;

	g_spWatchAddr[slot] = addr;
	g_spWatchSlotUsed[slot] = 1;
	g_spWatchThreadsArmed += armed;
	g_spWatchArmFailures += failed;

	char line[300];
	_snprintf_s(line, sizeof(line), _TRUNCATE,
		"WATCH     %s DR%d addr=%016llX threads_armed=%d threads_failed=%d"
		" | MAINTHREAD %lu armed=%d of %d seen",
		// Whether the main thread is armed decides whether this run means
		// anything, so it is stated on the line rather than left to be inferred
		// from an aggregate that moves by a factor of seven between runs.
		(g_spMainThreadId && g_spMainArmedOk > 0) ? "armed  " : "NO-MAIN!",
		slot, (unsigned long long) addr, armed, failed,
		(unsigned long) g_spMainThreadId, g_spMainArmedOk, g_spMainArmedTries);
	SpHookTraceAppend(line);
	return slot;
}

// Arms a watchpoint for every tracked hook that has not got one yet.
//
// THE FIELD, NOT THE OBJECT IT POINTS TO
//
// The first version of this armed on (uintptr_t) pHook->m_pCallingConvention -
// the eight bytes at the start of the convention object, which is where a
// corrupted vtable pointer would show up. It was armed on 1068 threads and never
// fired once, so "a wild write overwrote the vptr" is ruled out.
//
// That rules out one of two different eight-byte fields, and the other one is
// still live:
//
//   CHook+0x18                 the pointer to the convention
//   *(CHook+0x18)              the vptr inside the convention
//
// If the *field* is overwritten with some other pointer P, then the dispatch
// reads pConvention as P, dereferences P, and gets whatever is at P - and the
// convention object itself is never touched, so the first watchpoint correctly
// reported nothing. Watching the field catches that, and the two together leave
// nowhere for the pointer to have changed without a trap.
//
// The tracking itself - noticing a new hook, recording when it first appeared -
// happens in SpHookTracePollWriteProtect, which the sampling thread calls. This
// function only does the arming, and skips hooks that already have one.
//
// An earlier version had `if (!bWatched) continue;`, which inverted the test and
// made the whole loop a no-op: every hook starts unwatched, so every hook was
// skipped and the experiment collected nothing for two runs without that being
// obvious from the outside.
void SpHookTracePollWatchpoint()
{
	for (int i = 0; i < g_spTrackedCount; i++)
	{
		if (g_spTracked[i].bWatched)
			continue;
		CHook* pHook = g_spTracked[i].pHook;
		if (!pHook)
			continue;

		// The address of the field, not its value. Written out as a cast of the
		// member's address so the intent survives a future reordering of the
		// members: a watchpoint on the *value* is a different experiment, and it
		// is the one that has already been done and came back empty.
		uintptr_t addr = (uintptr_t) &pHook->m_pCallingConvention;

		// The synchronous path has usually got here first: CFunction::AddHook arms
		// this exact address the moment the hook is created, which is the only
		// moment early enough to catch a hook that dies milliseconds later. If
		// that already claimed a debug register, marking the hook watched and
		// moving on avoids spending a second slot - and, more importantly, avoids
		// the appearance of having armed it here when the verdict belongs to the
		// other path.
		bool bAlreadyArmed = false;
		for (int s = 0; s < SpMaxWatch; s++)
		{
			if (g_spWatchSlotUsed[s] && g_spWatchAddr[s] == addr)
				bAlreadyArmed = true;
		}
		if (bAlreadyArmed)
		{
			g_spTracked[i].bWatched = true;
			continue;
		}

		SpWatchArmAddress(addr);
		g_spTracked[i].bWatched = true;
	}
}

} // namespace

// Outside the anonymous namespace on purpose. It is called from sp_main.cpp, and
// a function in an anonymous namespace has internal linkage, so putting it in
// there compiles and then fails at link with an unresolved external - which is
// exactly what happened the first time.
void SpHookTraceSetMainThreadId(unsigned long id)
{
	g_spMainThreadId = (DWORD) id;
	char line[200];
	_snprintf_s(line, sizeof(line), _TRUNCATE,
		"MAINTHREAD id=%lu captured at plugin load. Every watchpoint verdict in"
		" this run is only valid if this thread is reported armed.",
		id);
	SpHookTraceAppend(line);
}

// Called from CFunction::AddHook at the instant a hook is created, on the thread
// that is about to dispatch it.
//
// This is the third attempt to arm the watchpoint on the right object, and the
// first one that can win the race. The previous two armed from the 40 ms
// sampling poll, which is slower than the hook's lifetime: run29 armed a real
// CHook+0x18 field, but for the engine.dll hook, while the run_command hook that
// actually crashes lived and died between two polls - it appeared with six log
// lines left before the process died.
//
// Watches the FIELD, &CHook::m_pCallingConvention. The convention object's own
// first eight bytes were watched in run26 and never written; the field is the
// other candidate, and it is the one a wild pointer or a freed-and-reused CHook
// would have to go through.
//
// No-op off Windows so callers need no #ifdef. Outside the anonymous namespace
// for the same reason as above: it is called from another translation unit.
void SpHookTraceArmHookNow(CHook* pHook)
{
#if defined(_WIN32)
	if (!pHook)
		return;
	// CHook carries no calling-convention kind of its own - m_eCallingConvention
	// belongs to the SP-side CFunction, not to the hook DynamicHooks created - so
	// the label is the hooked address and the kind comes from the lifecycle line
	// that was just written a few statements earlier in AddHook.
	SpWatchArmCurrentThread((uintptr_t) &pHook->m_pCallingConvention, "hookfield");
#else
	(void) pHook;
#endif
}

#endif // _WIN32


// ============================================================================
// >> SP_HOOK_FAULT_COLLECTOR
// ============================================================================
// A recoverable handler for writes to the protected pages, added 2026-09-29.
//
// Placed after SP_HOOK_WRITEPROTECT because it reads the tracked-hook table that
// block defines, and before the SP_HOOK_TRACE block because it uses the emitter
// that block defines - the forward declaration at the top of the anonymous
// namespace is what makes that work.
//
// WHY
//
// Page protection found the first wild write - steamclient64.dll writing into
// Source.Python's CRT heap - but a fault ends the process, so one run yields one
// address. One address cannot distinguish a single stray write from a spray, and
// the question that matters is whether the addresses written include the one
// holding the convention's vptr, at page+0x80 in the run observed.
//
// So the write is allowed to proceed: the page is made writable again, the fault
// is recorded, and execution continues. The process keeps running and the
// history accumulates.
//
// WHAT IS AND IS NOT SWALLOWED
//
// Only an access violation whose ExceptionInformation[0] is 1 - a write - and
// only when the address lands on a page this diagnostic protected. Everything
// else returns EXCEPTION_CONTINUE_SEARCH, including the read violation that is
// the actual bug. The original crash therefore still happens and still reports
// itself; what changes is that the writes leading up to it are visible.
//
// That distinction is the whole reason this is a diagnostic and not a fix. A
// handler that swallowed every fault would make the server look stable while the
// memory underneath kept being damaged, which is a worse outcome than crashing
// because it hides the thing being looked for.
//
// NO RE-PROTECTION
//
// A protected page is unprotected once and stays that way. Re-arming it would
// fault again on the next write to the same address, and a writer in a loop
// would spin. The trade is that later writes to the page are not trapped, and
// the compensation is that the distinct set of addresses is what is wanted - one
// pass over the writer's targets is enough, and it completes before the process
// dies.
//
// A filter runs on the faulting thread, inside the engine, with no unwind record
// behind it. So: no allocation, no Python, no locks, nothing that can fail -
// because anything that fails here fails in the worst possible place. The
// recorded data is flushed by the sampling thread, which can afford to be
// ordinary code.

namespace
{

struct SpFaultRecord
{
	DWORD dwThread;
	DWORD dwCode;
	uintptr_t uRip;
	uintptr_t uAddr;
	BOOL bWrite;
	BOOL bOnProtectedPage;
};

const int SpMaxFaults = 8192;
SpFaultRecord g_spFaults[SpMaxFaults];
volatile LONG g_spFaultCount = 0;
volatile LONG g_spFaultFlushed = 0;

LPTOP_LEVEL_EXCEPTION_FILTER g_spPreviousFilter = NULL;

BOOL SpPageIsProtected(uintptr_t addr, uintptr_t* pageOut)
{
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	uintptr_t mask = ~(uintptr_t)(si.dwPageSize - 1);
	uintptr_t page = addr & mask;
	for (int i = 0; i < g_spTrackedCount; i++)
	{
		if (!g_spTracked[i].bArmed)
			continue;
		CHook* pHook = g_spTracked[i].pHook;
		if (!pHook || !pHook->m_pCallingConvention)
			continue;
		if (((uintptr_t) pHook->m_pCallingConvention & mask) == page)
		{
			if (pageOut)
				*pageOut = page;
			return TRUE;
		}
	}
	return FALSE;
}

LONG WINAPI SpHookTraceFaultFilter(EXCEPTION_POINTERS* info)
{
	if (!info || !info->ExceptionRecord)
		return EXCEPTION_CONTINUE_SEARCH;

	DWORD code = info->ExceptionRecord->ExceptionCode;

#if defined(_WIN32)
	// A hardware data watchpoint, if one of ours fired.
	//
	// A single-step can also arrive from the trap flag or from someone else's
	// debugger, so this does not assume: DR6 says which register matched, and
	// only a bit belonging to a slot this diagnostic claimed is treated as ours.
	// Anything else is passed straight through, because swallowing a trap flag
	// that belongs to the engine or to an attached debugger would change the
	// process's behaviour in a way nobody asked for.
	if (code == EXCEPTION_SINGLE_STEP)
	{
		CONTEXT ctx;
		ZeroMemory(&ctx, sizeof(ctx));
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		if (GetThreadContext(GetCurrentThread(), &ctx))
		{
			for (int slot = 0; slot < SpMaxWatch; slot++)
			{
				if (!g_spWatchSlotUsed[slot])
					continue;
				if (!(ctx.Dr6 & (1UL << slot)))
					continue;

				LONG idx = InterlockedIncrement(&g_spFaultCount) - 1;
				if (idx >= 0 && idx < SpMaxFaults)
				{
					SpFaultRecord& r = g_spFaults[idx];
					r.dwThread = GetCurrentThreadId();
					r.dwCode = code;
					// Rip is the instruction *after* the access on x86, so the
					// writer is identified by the instruction that touched the
					// bytes, not by this address. Both are recorded, and the gap
					// between them is the width of one instruction.
					r.uRip = (uintptr_t) ctx.Rip;
					r.uAddr = g_spWatchAddr[slot];
					r.bWrite = TRUE;
					r.bOnProtectedPage = FALSE;
				}

				// DR6 status is cleared, DR7 stays enabled. The breakpoint keeps
				// working and the next trap is unambiguously a new one.
				ctx.Dr6 = 0;
				SetThreadContext(GetCurrentThread(), &ctx);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
		return EXCEPTION_CONTINUE_SEARCH;
	}
#endif

	if (code != EXCEPTION_ACCESS_VIOLATION)
		return EXCEPTION_CONTINUE_SEARCH;

	ULONG_PTR* params = info->ExceptionRecord->ExceptionInformation;
	BOOL bWrite = (params[0] == 1);

	uintptr_t page = 0;
	BOOL bTracked = SpPageIsProtected((uintptr_t) params[1], &page);

	// Recorded whatever it is. A write that is not on a protected page is still
	// worth having, because it may be the same writer doing something else at
	// the same moment, and correlating the two is free once both are logged.
	LONG idx = InterlockedIncrement(&g_spFaultCount) - 1;
	if (idx >= 0 && idx < SpMaxFaults)
	{
		SpFaultRecord& r = g_spFaults[idx];
		r.dwThread = GetCurrentThreadId();
		r.dwCode = code;
		r.uRip = (uintptr_t) info->ExceptionRecord->ExceptionAddress;
		r.uAddr = (uintptr_t) params[1];
		r.bWrite = bWrite;
		r.bOnProtectedPage = bTracked;
	}

	// Only a write to a page this diagnostic protected is allowed through. A read
	// is the real bug and is left to crash; so is a write anywhere else.
	// The fatal record is written by the vectored handler instead.
	//
	// run31 put it here and produced no line at all, which is what established
	// that the unhandled-exception filter is never reached: this is a single
	// process-wide slot and the engine installs its own handler after plugin
	// load. Keeping a second copy here would mean two sources for one event,
	// one of them known not to fire, and the run32 register capture below was
	// the worse half of it - it asked for a context instead of using the one
	// the kernel already put in EXCEPTION_POINTERS, and got a partly wrong one.
	if (!bWrite || !bTracked)
		return EXCEPTION_CONTINUE_SEARCH;

	SYSTEM_INFO si;
	GetSystemInfo(&si);
	DWORD old = 0;
	VirtualProtect((void*) page, si.dwPageSize, PAGE_READWRITE, &old);

	// Marked disarmed so the poll does not re-arm it, which would fault on the
	// next write to the same place and spin.
	for (int i = 0; i < g_spTrackedCount; i++)
	{
		if (!g_spTracked[i].bArmed)
			continue;
		CHook* pHook = g_spTracked[i].pHook;
		if (pHook && pHook->m_pCallingConvention &&
			(((uintptr_t) pHook->m_pCallingConvention) & ~(uintptr_t)(si.dwPageSize - 1)) == page)
		{
			g_spTracked[i].bArmed = false;
			break;
		}
	}

	return EXCEPTION_CONTINUE_EXECUTION;
}

// Reads one quadword, reporting failure instead of faulting.
//
// This has to be its own function, with nothing else in it.
//
// MSVC forbids __try/__except in any function that requires object unwinding
// (error C2712), and SpHookTraceVeh has a destructor-bearing object in it - the
// SpVehScope guard - plus several std::string-free but still non-trivial locals.
// Putting the __try inline would not compile. So the read lives here, in a
// function with no destructors at all, and the caller only ever sees a bool.
//
// The SEH wrapper is not decoration. rax+8 may itself be unreadable, and a bare
// read of it inside a vectored handler would raise a nested exception in the
// middle of handling the first one - which is precisely the failure mode that
// destroyed run33, where a faulting probe recursed until the stack ran out.
//
// A side effect worth naming: this is the first thing in this diagnostic that
// looks like a fix but is not. It changes nothing about what happens next; it
// only reads. The process still dies with the same exception at the same
// address, and if the run's evidence is any good, that is still visible.
static bool __declspec(noinline) SpSafeReadQword(uintptr_t addr, uintptr_t* out)
{
	__try
	{
		*out = *(const uintptr_t*) addr;
		return true;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		*out = 0;
		return false;
	}
}

// The vectored handler. This is the one that has to work.
//
// WHY NOT ONLY THE UNHANDLED EXCEPTION FILTER
//
// run31 put the fatal record in the UEF and still produced no FAULTFATAL line,
// even though the file ends mid-run with the process dead - so the UEF was not
// reached at all. run23 is the proof that the filter body itself works: it
// swallowed three page faults and wrote all three. Same code, different
// outcome, so the difference is in *whether the filter gets called*, not in
// what it does.
//
// SetUnhandledExceptionFilter is a single process-wide slot, and anything that
// calls it later replaces ours. The engine's own crash handling does exactly
// that, and it does it later than plugin load, which is exactly where this
// filter is installed. That accounts for a filter that is installed, is
// correct, and is never invoked.
//
// A vectored exception handler is called first, before the unhandled-exception
// filter and before any frame-based handler, and no later SetUnhandledException
// Filter can displace it. That is the property needed here.
//
// It returns EXCEPTION_CONTINUE_SEARCH in every case, so it observes and never
// alters: the engine still sees its own crash and still reports it the same way.
// Observing is the entire job.
// The vectored handler. This is the one that has to work.
//
// WHY IT IS SPLIT IN TWO
//
// cdb found this, and it is not something any amount of staring at the source
// would have shown. The stack it produced was an unbroken loop:
//
//   ntdll!KiUserExceptionDispatch
//   core!__chkstk
//   core!SpHookTracePollWriteProtect        <- this handler, at the fault
//   ntdll!RtlpCallVectoredHandlers
//   ntdll!RtlDispatchException
//   ntdll!KiUserExceptionDispatch           <- and around again
//
// The cause: MSVC allocates the ENTIRE frame of a function in its prologue.
// Between the register buffer, the line buffers, two CONTEXT copies and the
// TEXTDIFF scan, this handler put several kilobytes on the stack of a thread
// that had just faulted. __chkstk probes that allocation before a single line
// of the handler executes - including the re-entrancy guard.
//
// So the guard could never do its job. Each re-entry consumed its whole frame
// first and overflowed before reaching the check. run33's 118-deep recursion
// and run34's silent swallow and run47's lost unwind trace were all this one
// defect wearing different faces, and the guard added to stop it addressed the
// wrong thing: it limited how much work each entry did, not how much stack each
// entry needed.
//
// The outer handler below therefore has a frame of a few dozen bytes - just the
// flag and a pointer - so its prologue cannot overflow and the guard runs on
// the first re-entry. All the work lives in a separate noinline function, and
// __declspec(noinline) is load-bearing: if the compiler inlined it back, the
// frames would merge and this would regress silently.
static __declspec(thread) int g_spVehDepth = 0;

LONG WINAPI SpHookTraceVeh(EXCEPTION_POINTERS* info)
{
	// Thread local rather than a shared flag: the fault is per thread, and a
	// process-wide flag would let one thread's handler silence another's.
	if (g_spVehDepth)
		return EXCEPTION_CONTINUE_SEARCH;
	g_spVehDepth = 1;

	// A destructor rather than __try/__finally, which MSVC rejects (C2712) in a
	// function that requires object unwinding. It does not here, but relying on
	// that is exactly the kind of assumption this file has been bitten by.
	struct SpVehScope
	{
		~SpVehScope() { g_spVehDepth = 0; }
	} vehScope;

	return SpHookTraceVehHeavy(info);
}

static LONG __declspec(noinline) SpHookTraceVehHeavy(EXCEPTION_POINTERS* info)
{
	if (!info || !info->ExceptionRecord)
		return EXCEPTION_CONTINUE_SEARCH;

	// Only the code this diagnostic exists to explain. Everything else is not
	// ours to report and would only dilute the one line that matters.
	if (info->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION &&
		info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
		return EXCEPTION_CONTINUE_SEARCH;

	ULONG_PTR* params = info->ExceptionRecord->ExceptionInformation;
	BOOL bWrite = (params[0] == 1);

	// The kernel's copy of the faulting context, not one asked for.
	//
	// run32 called GetThreadContext(GetCurrentThread()) here and got a CONTEXT
	// whose Rip pointed into an address space that was not core.dll, while the
	// exception record's ExceptionAddress - from the same call - was core.dll
	// + 0x4915A2. So that CONTEXT was partly wrong, and rsp/rdx looked plausible
	// while Rip did not, which is the dangerous kind of wrong: it survives a
	// sanity check.
	//
	// EXCEPTION_POINTERS::ContextRecord is the context the kernel built for this
	// exact exception. Using it instead removes the question entirely, and
	// checking Rip against ExceptionAddress turns the self-consistency of the
	// record into something the log proves rather than something I assume.
	const CONTEXT* pCtx = info->ContextRecord;

	char regs[700];
	if (pCtx && (pCtx->ContextFlags & CONTEXT_CONTROL))
	{
		_snprintf_s(regs, sizeof(regs), _TRUNCATE,
			" rip=%016llX rax=%016llX rbx=%016llX rcx=%016llX rdx=%016llX"
			" rsi=%016llX rdi=%016llX rbp=%016llX rsp=%016llX"
			" r8=%016llX r9=%016llX r10=%016llX r11=%016llX"
			"  rip_matches_exception_addr=%d",
			(unsigned long long) pCtx->Rip, (unsigned long long) pCtx->Rax,
			(unsigned long long) pCtx->Rbx, (unsigned long long) pCtx->Rcx,
			(unsigned long long) pCtx->Rdx, (unsigned long long) pCtx->Rsi,
			(unsigned long long) pCtx->Rdi, (unsigned long long) pCtx->Rbp,
			(unsigned long long) pCtx->Rsp, (unsigned long long) pCtx->R8,
			(unsigned long long) pCtx->R9, (unsigned long long) pCtx->R10,
			(unsigned long long) pCtx->R11,
			(uintptr_t) pCtx->Rip ==
				(uintptr_t) info->ExceptionRecord->ExceptionAddress ? 1 : 0);
	}
	else
	{
		_snprintf_s(regs, sizeof(regs), _TRUNCATE,
			" (no usable context record; flags=%08lX)",
			pCtx ? (unsigned long) pCtx->ContextFlags : 0UL);
	}

	char desc[80];
	SpDescribeAddr((uintptr_t) info->ExceptionRecord->ExceptionAddress,
		desc, sizeof(desc));

	// What the call would jump to.
	//
	// The faulting instruction is `call qword ptr [rax+8]` and the kernel says the
	// access was to 0xFFFFFFFFFFFFFFFF, while rax+8 is 0x7FFD8A1120F8. Those cannot
	// both describe the same memory read, so the value sitting at [rax+8] is the
	// one measurement that separates the two stories:
	//
	//   [rax+8] == -1        the read succeeded and the call took -1 as its target,
	//                        which puts the fault at instruction fetch and leaves
	//                        Rip-at-the-call as the thing needing explaining.
	//   [rax+8] != -1        the read did not produce this access at all, and
	//                        ExceptionInformation[1] belongs to something else.
	//
	// Previously this could only have come from the dump, and only if that page
	// happened to be captured. It is one instruction to read here instead.
	// Guarded, and that guard is the bug run36 introduced: the first version of
	// this dereferenced pCtx unconditionally while the register dump below it
	// checks pCtx for NULL. One unguarded dereference inside a vectored handler
	// is a nested exception, which is how a one-line measurement turns into a
	// run that produces no log at all.
	const bool bCtxUsable = (pCtx != NULL) && (pCtx->ContextFlags & CONTEXT_CONTROL);

	uintptr_t callTarget = 0;
	bool bTargetReadable = bCtxUsable &&
		SpSafeReadQword((uintptr_t) pCtx->Rax + 8, &callTarget);

	// What module is rax in, and what does its first slot hold?
	//
	// This is the measurement that says whether rax is a vtable pointer at all.
	// It cannot be one: SP allocates the convention with `new x64MsWin64(...)`
	// (memory_function.cpp:292 -> :228), so a live x64MsWin64's vptr must point
	// into core.dll. The tracked convention's vptr is core.dll+0x5D32B8, while
	// the faulting rax has consistently been in a different module. Something is
	// being called through a pointer that is not the convention's vtable.
	//
	// Naming the module turns "a different module" into a specific answer, and
	// reading [rax] distinguishes "a real vtable whose slot 1 is stale" from
	// "not an object at all".
	char raxDesc[80];
	char vptrDesc[80];
	uintptr_t vptrVal = 0;
	bool bVptrReadable = false;
	MEMORY_BASIC_INFORMATION mbi;
	ZeroMemory(&mbi, sizeof(mbi));
	bool bMbiOk = false;
	char allocDesc[80];

	if (bCtxUsable)
	{
		SpDescribeAddr((uintptr_t) pCtx->Rax, raxDesc, sizeof(raxDesc));
		bVptrReadable = SpSafeReadQword((uintptr_t) pCtx->Rax, &vptrVal);
		if (bVptrReadable)
			SpDescribeAddr(vptrVal, vptrDesc, sizeof(vptrDesc));
		else
			_snprintf_s(vptrDesc, sizeof(vptrDesc), _TRUNCATE, "(unreadable)");

		// Which kind of memory is rax in?
		//
		// "This address holds different bytes than the file" is only a finding if
		// the address really is inside that module's image. If rax were in a
		// VirtualAlloc'd executable page, "memory differs from disk" would be
		// true by construction and would mean nothing - and a watchpoint aimed at
		// it would be chasing a second ghost.
		//
		// MEM_IMAGE versus MEM_PRIVATE is the dividing line, and Protect says
		// whether anyone made the page writable. Both are read here, in one call,
		// rather than inferred.
		bMbiOk = VirtualQuery((LPCVOID)(uintptr_t) pCtx->Rax, &mbi, sizeof(mbi)) != 0;
		if (bMbiOk)
			SpDescribeAddr((uintptr_t) mbi.AllocationBase, allocDesc, sizeof(allocDesc));
		else
			_snprintf_s(allocDesc, sizeof(allocDesc), _TRUNCATE, "(query failed)");
	}
	else
	{
		_snprintf_s(raxDesc, sizeof(raxDesc), _TRUNCATE, "(no context)");
		_snprintf_s(vptrDesc, sizeof(vptrDesc), _TRUNCATE, "(no context)");
		_snprintf_s(allocDesc, sizeof(allocDesc), _TRUNCATE, "(no context)");
	}

	// Inline rather than a helper function. A `static` function with block scope -
	// which is what "static" inside a function body is - is illegal C++, and the
	// compiler says so plainly ("block scope function has illegal storage class").
	// The value is formatted by hand instead, which also keeps the naming visible
	// in the log rather than hiding it behind a call.
	const char* typeName = "(other)";
	if (mbi.Type == MEM_IMAGE)   typeName = "MEM_IMAGE";
	else if (mbi.Type == MEM_MAPPED)  typeName = "MEM_MAPPED";
	else if (mbi.Type == MEM_PRIVATE) typeName = "MEM_PRIVATE";

	char raxLine[420];
	if (bCtxUsable && bMbiOk)
	{
		_snprintf_s(raxLine, sizeof(raxLine), _TRUNCATE,
			"  rax_is=[%s] readable=%d [rax]=%016llX [%s]"
			" | page: allocbase=%016llX [%s] type=%s protect=%08lX size=%lu",
			raxDesc, bVptrReadable ? 1 : 0, (unsigned long long) vptrVal, vptrDesc,
			(unsigned long long) (uintptr_t) mbi.AllocationBase, allocDesc,
			typeName, (unsigned long) mbi.Protect,
			(unsigned long) mbi.RegionSize);
	}
	else
	{
		_snprintf_s(raxLine, sizeof(raxLine), _TRUNCATE,
			"  rax_is=[%s] readable=%d [rax]=%016llX [%s] | page: %s",
			raxDesc, bVptrReadable ? 1 : 0, (unsigned long long) vptrVal, vptrDesc,
			bCtxUsable ? "(VirtualQuery failed)" : "(no context)");
	}

	char target[160];
	if (bTargetReadable)
	{
		char tdesc[80];
		SpDescribeAddr(callTarget, tdesc, sizeof(tdesc));
		_snprintf_s(target, sizeof(target), _TRUNCATE,
			" [rax+8]=%016llX [%s]%s",
			(unsigned long long) callTarget, tdesc,
			callTarget == (uintptr_t) -1 ? "  <<< THE CALL TARGET IS -1" : "");
	}
	else
	{
		_snprintf_s(target, sizeof(target), _TRUNCATE,
			bCtxUsable ? " [rax+8] unreadable at %016llX" : " [rax+8] not measured (no usable context)",
			(unsigned long long) (bCtxUsable ? ((uintptr_t) pCtx->Rax + 8) : 0));
	}

	SpHookTraceAppend(raxLine);

	// The heavy diagnostics below are skipped when SP_HOOK_MINIMAL is set.
	//
	// cdb found the reason this exists. Under a debugger the faulting thread's
	// stack is exhausted before any of this runs, and the resulting stack
	// overflow faults again inside the vectored handler, which the re-entrancy
	// guard then swallows. The stack it produced showed the recursion directly:
	//
	//   ntdll!KiUserExceptionDispatch
	//   core!__chkstk
	//   core!SpHookTracePollWriteProtect      <- the handler, at fault
	//   ntdll!RtlpCallVectoredHandlers
	//   ntdll!RtlDispatchException
	//   ntdll!KiUserExceptionDispatch         <- and around again
	//
	// This handler is not a small function. Between the register buffer, the
	// line buffers, the two CONTEXT copies and the TEXTDIFF scan it puts several
	// kilobytes on the stack of a thread that has just faulted. That was true
	// before cdb too; cdb only made it visible by giving the thread somewhere to
	// survive long enough to overflow.
	//
	// A debugger can do all of this properly, with native unwind and no stack
	// pressure on the faulting thread. So when it is in use, this diagnostic
	// gets out of the way and leaves the fault to the debugger.
	{
		static LONG bMinimal = -1;
		if (bMinimal < 0)
		{
			bMinimal = (getenv("SP_HOOK_MINIMAL") != NULL) ? 1 : 0;
			if (bMinimal)
				SpHookTraceAppend("  MODE  minimal: heavy diagnostics off (SP_HOOK_MINIMAL)");
		}
		if (bMinimal)
			return EXCEPTION_CONTINUE_SEARCH;
	}


	// Dump the CHook's leading bytes as they are at the instant of the fault.
	//
	// rdi is the CHook: at this point in X64Invocation's constructor it has already
	// been passed in, and in every run so far rdi has matched the hooked CHook
	// exactly. Printed as raw 8-byte words and deliberately NOT dereferenced -
	// following any of these pointers could fault inside the handler and destroy
	// the evidence, which has happened twice already.
	//
	// The word to look for is the value of rcx, because the faulting instruction
	// is `mov rax,[rcx]; call [rax+8]`, so rcx is the pointer that was read out of
	// a CHook slot. Wherever rcx appears in this dump is the slot the dispatch path
	// is using as m_pCallingConvention.
	if (bCtxUsable)
	{
		// The constructor's own parameters, read back off the stack.
		//
		// X64Invocation's prologue spills its three arguments before the prologue
		// grows the frame:
		//
		//   mov [rsp+18h], r8    <- pConvention (3rd)
		//   mov [rsp+10h], rdx   <- pHook        (2nd)
		//   mov [rsp+8],   rcx   <- this         (1st)
		//   sub rsp, 98h
		//
		// so after the subtraction they sit at [rsp+0B0], [rsp+0A8], [rsp+0A0],
		// and nothing between there and the faulting call writes to them. That
		// makes pHook recoverable at the crash even though rdx was long since
		// reused - which matters, because rdx at the fault is NOT the pHook.
		//
		// This is the measurement that separates the two remaining stories:
		// whether the CHook's own field holds the bad value, or whether the call
		// site simply did not read that field.
		uintptr_t faultHook = 0, faultConv = 0, faultThis = 0;
		bool bHookRead = SpSafeReadQword((uintptr_t) pCtx->Rsp + 0xA8, &faultHook);
		bool bConvRead = SpSafeReadQword((uintptr_t) pCtx->Rsp + 0xB0, &faultConv);
		bool bThisRead = SpSafeReadQword((uintptr_t) pCtx->Rsp + 0xA0, &faultThis);

		if (bHookRead && bConvRead)
		{
			uintptr_t hookFieldVal = 0;
			bool bFieldRead = SpSafeReadQword(faultHook + 0x18, &hookFieldVal);

			char hd[80], cd[80], fd[80], thd[80];
			SpDescribeAddr(faultHook, hd, sizeof(hd));
			SpDescribeAddr(faultConv, cd, sizeof(cd));
			SpDescribeAddr(hookFieldVal, fd, sizeof(fd));
			SpDescribeAddr(faultThis, thd, sizeof(thd));

			// Read the first slots as well, because "is this object a CHook at
			// all" is settled by its own vptr, not by anything the tracer knows.
			// A CHook's first slot is not a vtable pointer; an engine C++ object's
			// is. That single comparison separates the two remaining stories, and
			// +0x10 gives a second opinion - on a real CHook that is the address
			// of the function being hooked.
			uintptr_t h0 = 0, h8 = 0, h10 = 0, h20 = 0;
			bool b0 = SpSafeReadQword(faultHook + 0x00, &h0);
			bool b8 = SpSafeReadQword(faultHook + 0x08, &h8);
			bool b10 = SpSafeReadQword(faultHook + 0x10, &h10);
			bool b20 = SpSafeReadQword(faultHook + 0x20, &h20);

			char d0[80], d8[80], d10[80], d20[80];
			SpDescribeAddr(h0, d0, sizeof(d0));
			SpDescribeAddr(h8, d8, sizeof(d8));
			SpDescribeAddr(h10, d10, sizeof(d10));
			SpDescribeAddr(h20, d20, sizeof(d20));

			char pl[900];
			_snprintf_s(pl, sizeof(pl), _TRUNCATE,
				"  CTORARGS this=%016llX [%s] pHook=%016llX [%s] pConv=%016llX [%s]"
				" | pHook+0x18=%016llX [%s] readable=%d%s"
				" | pHook+0x00=%016llX [%s]"
				" | +0x08=%016llX [%s] +0x10=%016llX [%s] +0x20=%016llX [%s]",
				(unsigned long long) faultThis, thd,
				(unsigned long long) faultHook, hd,
				(unsigned long long) faultConv, cd,
				(unsigned long long) hookFieldVal, fd,
				bFieldRead ? 1 : 0,
				(bFieldRead && hookFieldVal == faultConv)
					? "  <<<< the CHook field DOES hold this value"
					: ((bFieldRead) ? "  <<<< the CHook field holds something ELSE"
					                : ""),
				(unsigned long long) h0, d0,
				(unsigned long long) h8, d8,
				(unsigned long long) h10, d10,
				(unsigned long long) h20, d20);
			SpHookTraceAppend(pl);
		}
		else
		{
			char pl[200];
			_snprintf_s(pl, sizeof(pl), _TRUNCATE,
				"  CTORARGS unreadable (pHook=%d pConv=%d this=%d)",
				bHookRead ? 1 : 0, bConvRead ? 1 : 0, bThisRead ? 1 : 0);
			SpHookTraceAppend(pl);
		}

		for (int off = 0; off < 0x90; off += 8)
		{
			uintptr_t word = 0;
			if (!SpSafeReadQword((uintptr_t) pCtx->Rdi + off, &word))
			{
				char d[120];
				_snprintf_s(d, sizeof(d), _TRUNCATE,
					"  CHookDump +0x%02X  unreadable", off);
				SpHookTraceAppend(d);
				continue;
			}

			char wdesc[80];
			SpDescribeAddr(word, wdesc, sizeof(wdesc));

			char d[220];
			_snprintf_s(d, sizeof(d), _TRUNCATE,
				"  CHookDump +0x%02X = %016llX [%s]%s",
				off, (unsigned long long) word, wdesc,
				word == (uintptr_t) pCtx->Rcx
					? "   <<<< equals rcx: this is the slot used as m_pCallingConvention"
					: "");
			SpHookTraceAppend(d);
		}
	}


	// Independent check on the watchpoint, and the thing that measures the
	// corruption instead of assuming it is eight bytes wide.
	SpScanServerTextAgainstDisk();

	char line[900];
	_snprintf_s(line, sizeof(line), _TRUNCATE,
		"FAULTFATAL tid=%lu %s access=%016llX exception_addr=%016llX [%s]%s%s",
		(unsigned long) GetCurrentThreadId(),
		bWrite ? "WRITE" : "READ",
		(unsigned long long) (uintptr_t) params[1],
		(unsigned long long) (uintptr_t) info->ExceptionRecord->ExceptionAddress,
		desc,
		target,
		regs);

	// Read the hooks as they are at the instant of the fault, not as a previous
	// sample saw them. Every previous answer about what the convention pointer
	// contained came from a snapshot taken before the crash; this is the first
	// reading taken after it, which is the only one that can contradict them.
	for (int i = 0; i < g_spTrackedCount; i++)
	{
		CHook* pH = g_spTracked[i].pHook;
		if (!pH)
			continue;
		uintptr_t convVal = (uintptr_t) pH->m_pCallingConvention;
		uintptr_t vptrVal = SpIsReadable((void*) convVal)
			? *(const uintptr_t*) convVal : 0;

		char detail[400];
		_snprintf_s(detail, sizeof(detail), _TRUNCATE,
			"FAULTHOOK #%d hook=%016llX field=%016llX field_value=%016llX"
			" vptr=%016llX vptr_readable=%d m_bHooked=%d",
			i, (unsigned long long) (uintptr_t) pH,
			(unsigned long long) (uintptr_t) &pH->m_pCallingConvention,
			(unsigned long long) convVal,
			(unsigned long long) vptrVal,
			SpIsReadable((void*) convVal) ? 1 : 0,
			pH->m_pCallingConvention ? (pH->m_pCallingConvention->m_bHooked ? 1 : 0) : -1);
		SpHookTraceAppend(detail);
	}

	SpHookTraceAppend(line);

	// Unwind, on a context this code built itself.
	//
	// Two things are wrong with feeding EXCEPTION_POINTERS::ContextRecord to
	// RtlVirtualUnwind directly, and the first one is mine.
	//
	// 1. I have never verified that record is a standard CONTEXT64. In the run35
	//    minidump I read the registers at eight-byte strides starting +0x78 and
	//    concluded the layout was non-standard - but the context SIZE recorded in
	//    that same dump was 1232, which is exactly sizeof(CONTEXT64). So the
	//    likelier explanation is that I misread the base by 0x24 and shifted every
	//    register with it. That is the same class of error as the stale RVA and the
	//    two-coordinate comparisons: a self-consistent misparse.
	//
	// 2. Whatever it is, it is not the record I want to unwind. The record is the
	//    context the kernel interrupted; the context that describes where THIS
	//    thread actually is right now is the one GetThreadContext returns.
	//
	// So the context is rebuilt here with GetThreadContext, and its layout is
	//    verified against the documented offsets before it is used for anything.
	//    The offsets are read out of the live structure rather than assumed.
	//
	// Every step logs before and after, so a fault inside RtlVirtualUnwind can no
	//    longer produce a silently truncated log: the "about to call" line is
	//    already on disk before the call is made.
	{
		char pre[200];
		_snprintf_s(pre, sizeof(pre), _TRUNCATE,
			"  UNWIND sizeof(CONTEXT)=%lu offsetof(Rip)=%lu offsetof(Rsp)=%lu offsetof(Rbp)=%lu",
			(unsigned long) sizeof(CONTEXT),
			(unsigned long) offsetof(CONTEXT, Rip),
			(unsigned long) offsetof(CONTEXT, Rsp),
			(unsigned long) offsetof(CONTEXT, Rbp));
		SpHookTraceAppend(pre);

		CONTEXT clean;
		ZeroMemory(&clean, sizeof(clean));
		clean.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
		BOOL bClean = GetThreadContext(GetCurrentThread(), &clean) ? TRUE : FALSE;

		char cl[200];
		_snprintf_s(cl, sizeof(cl), _TRUNCATE,
			"  UNWIND getthreadcontext=%d err=%lu rip=%016llX rsp=%016llX rbp=%016llX",
			bClean ? 1 : 0, (unsigned long) GetLastError(),
			(unsigned long long) clean.Rip, (unsigned long long) clean.Rsp,
			(unsigned long long) clean.Rbp);
		SpHookTraceAppend(cl);

		typedef PVOID (WINAPI *RtlVirtualUnwindFn)(
			PVOID HandlerType, PVOID TargetBase, ULONG64 ImageBase,
			ULONG64 ControlPc, PCONTEXT Context, PVOID HandlerData,
			ULONG64* EstablisherFrame, ULONG64* ContextPointers);

		static HMODULE hNtdll = NULL;
		static RtlVirtualUnwindFn pfnUnwind = NULL;
		if (!hNtdll)
		{
			hNtdll = GetModuleHandleW(L"ntdll.dll");
			if (hNtdll)
				pfnUnwind = (RtlVirtualUnwindFn) GetProcAddress(hNtdll, "RtlVirtualUnwind");
		}

		if (!bClean || !pfnUnwind)
		{
			SpHookTraceAppend("  UNWIND not attempted: no clean context or no ntdll export");
		}
		else
		{
			const int kMaxFrames = 16;
			CONTEXT walk;
			memcpy(&walk, &clean, sizeof(walk));
			ULONG64 handlerData = 0, establisher = 0, ctxPointers = 0;
			int frames = 0;
			bool bFailed = false;

			SpHookTraceAppend("  UNWIND about to call RtlVirtualUnwind");

			for (int depth = 0; depth < kMaxFrames; depth++)
			{
				ULONG64 before = walk.Rip;
				pfnUnwind(NULL, NULL, 0, walk.Rip ? walk.Rip - 1 : 0,
					&walk, &handlerData, &establisher, &ctxPointers);

				if (walk.Rip == before)
				{
					bFailed = true;
					char m[140];
					_snprintf_s(m, sizeof(m), _TRUNCATE,
						"  UNWIND stalled at depth %d, %d frame(s) valid", depth, frames);
					SpHookTraceAppend(m);
					break;
				}

				BOOL bAfterCall = FALSE;
				if (SpIsReadable((const void*) (walk.Rip - 1)))
					bAfterCall = (*(const BYTE*) (walk.Rip - 1) == 0xE8 ||
					              *(const BYTE*) (walk.Rip - 1) == 0xFF);

				char rdesc[80];
				SpDescribeAddr((uintptr_t) walk.Rip, rdesc, sizeof(rdesc));
				char fl[260];
				_snprintf_s(fl, sizeof(fl), _TRUNCATE,
					"  FRAME %02d ret=%016llX [%s] after_call_opcode=%d",
					depth, (unsigned long long) walk.Rip, rdesc, bAfterCall ? 1 : 0);
				SpHookTraceAppend(fl);
				frames++;
			}

			char done[120];
			_snprintf_s(done, sizeof(done), _TRUNCATE,
				"  UNWIND returned normally, %d frame(s)%s", frames,
				bFailed ? ", stopped early" : "");
			SpHookTraceAppend(done);
		}
	}

	// Never swallow. The read violation is the bug and it is left to crash; the
	// engine's own reporting is left intact so this run's evidence is not
	// changed by the act of watching it.
	return EXCEPTION_CONTINUE_SEARCH;
}

void SpHookTraceInstallFaultCollector()
{
	// First, before the unhandled filter, because if that one displaces this
	// one there must still be a handler that runs.
	AddVectoredExceptionHandler(1, SpHookTraceVeh);
	g_spPreviousFilter = SetUnhandledExceptionFilter(SpHookTraceFaultFilter);
}

// Flushes whatever the filter has recorded since the last pass.
//
// Only the module name and base are resolved, not a symbol. The faulting module
// is the finding, and resolving a name for a module that is not ours would mean
// shipping a symbol reader to answer a question the base address settles.
void SpHookTraceFlushFaults()
{
	LONG total = g_spFaultCount;
	LONG done = g_spFaultFlushed;
	if (total <= done)
		return;

	SYSTEM_INFO si;
	GetSystemInfo(&si);

	for (LONG i = done; i < total && i < SpMaxFaults; i++)
	{
		SpFaultRecord& r = g_spFaults[i];
		HMODULE mod = NULL;
		char modName[MAX_PATH];
		modName[0] = 0;
		if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
		                        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		                        (LPCWSTR) r.uRip, &mod))
		{
			if (GetModuleFileNameA((HMODULE) mod, modName, MAX_PATH))
			{
				char* slash = strrchr(modName, '\\');
				if (slash)
					memmove(modName, slash + 1, strlen(slash + 1) + 1);
			}
		}

		char line[320];
		_snprintf_s(line, sizeof(line), _TRUNCATE,
			"%s #%ld tid=%lu %s addr=%016llX rip=%016llX [%s+0x%llX]%s",
			r.dwCode == EXCEPTION_SINGLE_STEP ? "WATCHPT" : "FAULT  ",
			(long) i, r.dwThread,
			r.bWrite ? "WRITE" : "READ ",
			(unsigned long long) r.uAddr,
			(unsigned long long) r.uRip,
			modName[0] ? modName : "(unknown)",
			(unsigned long long) ((uintptr_t) mod ? (r.uRip - (uintptr_t) mod) : 0),
			r.dwCode == EXCEPTION_SINGLE_STEP ? "  <== THE VTABLE BYTE WAS WRITTEN" : "");
		SpHookTraceAppend(line);
	}
	g_spFaultFlushed = total;
}

} // namespace


// 2026-09-29. Temporary: it exists to explain one crash and nothing else.
//
// WHY IT IS HERE
//
// The fault is deterministic and reproducible. Bots join, and within the same
// second the server dies with 0xC0000005 at
//
//   core.dll+0x48DFD2   call qword ptr [rax + 8]
//
// which /MAP names as DynamicHooks' X64Invocation::X64Invocation, whose source
// is hook_x64.cpp:106, where the constructor does
//
//   new CRegisters(pConvention->GetRegisters())
//
// with pConvention == pHook->m_pCallingConvention.
//
// The exception record says the faulting read was at 0xFFFFFFFFFFFFFFFF. The
// faulting instruction is "call [rax+8]", so rax was 0xFFFFFFFFFFFFFFF7 - all
// ones except the low three bits - and rax came from "[rax]" where rax was
// pConvention. So pConvention itself was readable, and the eight bytes at its
// start held 0xFFFFFFFFFFFFFFF7.
//
// That value is not a vtable pointer. It is the shape memory filled with 0xFF
// has, and DynamicHooks fills the memory it allocates for bridges and
// trampolines with 0xFF. So the working theory is that m_pCallingConvention is
// not a convention object at all, but a stale pointer into freed JIT memory.
//
// The theory is a theory. Nothing so far has printed what pointer the hook
// actually holds, because every dump of this crash has 32-byte stub contexts -
// SourceMod truncates them, and so does the engine's own breakpad handler, and
// -nobreakpad does not stop it - so the one register that would settle this is
// never written to disk. Hence this: read the pointer out of the live objects
// from inside the process, while it is still alive to be read.
//
// WHAT IT WRITES
//
// logs/source-python/sp_hook_trace.txt, two kinds of line:
//
//   LIFECYCLE  one per hand-off to a hook and one per destruction, so the log
//              shows whether an address that was given to a hook was later
//              freed by the CFunction that created it
//
//   SNAPSHOT   every live hook with the liveness of its convention, throttled,
//              so the last snapshot before a crash describes the state that
//              caused it
//
// SAFETY
//
// This code dereferences pointers it suspects of being invalid, which is the
// exact operation that takes the server down, so every read is preceded by a
// VirtualQuery and the whole body is inside catch(...). It deliberately does
// not use SP's own TRY_SEGV/EXCEPT_SEGV: that filter raises a C++ exception
// from inside an SEH filter, which is undefined behaviour and is a separate
// known defect, and using it here would make the tracer capable of the failure
// it is trying to observe.
//
// It also does not allocate for its own sake, and it holds no lock, so a
// half-written line is possible if the process dies mid-write. That is
// acceptable: the interesting lines are the last ones, and a truncated tail is
// still evidence, whereas a deadlock would be indistinguishable from a hang.

#if defined(_WIN32)

#include <cstdio>
#include <cstdint>

namespace
{

// Resolved once from the already-imported sourcepython.paths module, the same
// source SpCallTrace uses, so the tracer does not hardcode a second copy of the
// game path that could drift from the real one. The result is cached in a
// static buffer because this may be called from ~CFunction, possibly during
// interpreter shutdown, when importing anything is not safe.
char* SpHookTracePath()
{
	static char path[MAX_PATH] = { 0 };
	if (path[0])
		return path;

	try
	{
		PyObject* paths = PyImport_ImportModule("paths");
		if (!paths)
		{
			PyErr_Clear();
			return NULL;
		}
		PyObject* root = PyObject_GetAttrString(paths, "GAME_PATH");
		Py_DECREF(paths);
		if (!root)
		{
			PyErr_Clear();
			return NULL;
		}
		PyObject* root_str = PyObject_Str(root);
		Py_DECREF(root);
		if (!root_str)
		{
			PyErr_Clear();
			return NULL;
		}
		const char* chars = PyUnicode_AsUTF8(root_str);
		if (!chars)
		{
			Py_DECREF(root_str);
			PyErr_Clear();
			return NULL;
		}
		_snprintf_s(path, sizeof(path), _TRUNCATE,
			"%s/logs/source-python/sp_hook_trace.txt", chars);
		Py_DECREF(root_str);
		return path;
	}
	catch (...)
	{
		return NULL;
	}
}

// Would a read of eight bytes at p fault? This is the question every read in
// the tracer has to ask, and asking VirtualQuery is strictly safer than asking
// the CPU, because a failed probe costs nothing and a failed read is the bug
// being chased.
bool SpIsReadable(const void* p)
{
	if (!p)
		return false;

	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0)
		return false;
	if (mbi.State != MEM_COMMIT)
		return false;
	if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
		return false;
	return true;
}

// core.dll's image range. The vtable of x64MsWin64 lives in core.dll's data and
// GetRegisters in its code, so being able to say "this pointer is inside
// core.dll" turns an unreadable-looking number into a verdict.
bool SpCoreImage(uintptr_t* base, uintptr_t* size)
{
	static bool resolved = false;
	static uintptr_t cachedBase = 0;
	static uintptr_t cachedSize = 0;

	if (!resolved)
	{
		resolved = true;
		HMODULE h = GetModuleHandleA("core.dll");
		if (h)
		{
			cachedBase = (uintptr_t) h;
			// Our own image is always mapped, so these reads cannot fault.
			IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*) cachedBase;
			if (dos->e_magic == IMAGE_DOS_SIGNATURE)
			{
				IMAGE_NT_HEADERS64* nt =
					(IMAGE_NT_HEADERS64*) (cachedBase + dos->e_lfanew);
				if (nt->Signature == IMAGE_NT_SIGNATURE)
					cachedSize = nt->OptionalHeader.SizeOfImage;
			}
		}
	}

	*base = cachedBase;
	*size = cachedSize;
	return cachedSize != 0;
}

// The image range of a named module, or false if it is not loaded.
//
// Why this exists: the tracer would otherwise log bare absolute addresses, and
// every run has a different address space, so nothing logged could be compared
// against anything - not between runs, not against a symbol map, not against
// SourceMod's gamedata. Logging an address as "module+offset" makes the log
// self-describing, and this is the only place the answer can be produced: inside
// the process, while the modules are mapped and before the machine is gone.
bool SpModuleRange(const char* name, uintptr_t* base, uintptr_t* size)
{
	HMODULE h = GetModuleHandleA(name);
	if (!h)
		return false;

	uintptr_t b = (uintptr_t) h;
	// Our own image is always mapped, so these reads cannot fault.
	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*) b;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return false;
	IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*) (b + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return false;

	*base = b;
	*size = nt->OptionalHeader.SizeOfImage;
	return true;
}

// Which module an address is in, written as "module+0xRVA". Returns false if it
// is in none of the modules worth naming, which is itself a result worth having
// on the page: it means the address is in JIT or trampoline memory, which is
// exactly the hypothesis being tested.
bool SpDescribeAddr(uintptr_t addr, char* out, size_t outSize)
{
	static const char* names[] = { "core.dll", "server.dll", "engine.dll" };
	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
	{
		uintptr_t base = 0;
		uintptr_t size = 0;
		if (!SpModuleRange(names[i], &base, &size))
			continue;
		if (addr >= base && addr < base + size)
		{
			_snprintf_s(out, outSize, _TRUNCATE, "%s+0x%llX", names[i],
				(unsigned long long) (addr - base));
			return true;
		}
	}
	return false;
}

// Append one already-formatted line.
//
// Deliberately not variadic. The variadic form wanted _vfprintf, and MSVC's
// <cstdio> does not reliably put that name in scope here - which is a silly
// thing to spend a build cycle on when there is exactly one caller that has to
// format the line anyway.
void SpHookTraceAppend(const char* text)
{
	char* path = SpHookTracePath();
	if (!path)
		return;

	FILE* handle = _tfopen(path, "a");
	if (!handle)
		return;

	fputs(text, handle);
	fputc('\n', handle);
	fflush(handle);
	fclose(handle);
}

unsigned long SpHookTraceTicks = 0;

// One snapshot per this many dispatches once the early phase is over.
//
// The early phase gets a snapshot on *every* dispatch, because the question
// that matters is whether the fault is on the first dispatch or on the
// thousandth, and a throttle that starts at 16 cannot answer that. A fault on
// the first dispatch and a fault after some accumulation are different bugs
// with different fixes, so the measurement has to be able to tell them apart
// before anything is changed.
const unsigned long SpHookTraceInterval = 16;
const unsigned long SpHookTraceEveryDispatchUpTo = 32;

#if defined(_WIN32)

// _CrtCheckMemory walks the CRT's own block headers and free lists and reports
// whether they are self-consistent. It is here because "the heap is being
// corrupted by something on this path" is the leading explanation for a
// faulting pointer that is a plausible-looking address at every sample and
// 0xFFFFFFFFFFFFFFF7 at the fault - and it is the only way to test that claim
// without changing anything first.
//
// Two honest limits, both of which make a negative result weaker than it looks:
//
//   It is not the page heap. It validates the CRT's own metadata, so heap
//   corruption that only the OS page heap checker would see - a write past the
//   end of a block into another block's payload, for instance - can pass it.
//
//   It reports the first inconsistency it finds and does not say where it is.
//   So a positive result says the heap is broken, and nothing more.
//
// A clean result therefore does not exonerate the heap. It does mean the next
// hypothesis is worth testing, and it is cheap enough to leave running.
int SpHookTraceHeapState()
{
	// _CrtCheckMemory does not touch the Python state machine, so this is safe
	// to call from the sampling thread. It is not documented as thread-safe
	// against concurrent allocation, so a false positive from a block being
	// reallocated mid-walk is possible; a run of consecutive failures is
	// therefore what counts, not a single one.
	return _CrtCheckMemory() ? 1 : 0;
}

// Records a change in the CRT heap's self-consistency.
//
// A transition line rather than a per-sample line, because a heap that has been
// broken since the second bot joined and stays broken is one fact, and
// 170-odd identical lines would bury it. The tick number is included so the
// transition can be placed against the dispatch snapshots.
void SpHookTraceHeapChange(int healthy)
{
	char line[160];
	_snprintf_s(line, sizeof(line), _TRUNCATE,
		"HEAP      %-12s dispatch_ticks=%lu",
		healthy ? "ok" : "CORRUPT", SpHookTraceTicks);
	SpHookTraceAppend(line);
}

DWORD WINAPI SpHookTraceThread(LPVOID)
{
	// Why a thread at all, when SpHookTraceTick exists.
	//
	// The crash is inside CHook::DispatchPre, which builds the X64Invocation
	// before any callback runs. Every callback SP owns therefore executes *after*
	// the fault, so a snapshot taken from a callback cannot see the moment of the
	// crash - it can only see the moment before the callback that would have run
	// after it. Two attempts at covering this with callbacks both failed for the
	// same reason: the crashing hook's callback is ISimpleEntityHook's handler,
	// which is not SP_HookHandler, and the first bot joining produced exactly one
	// hand-off and zero ticks.
	//
	// A thread needs no coverage. It samples on the wall clock, so the last
	// sample before the process dies is by construction close to the death, and
	// it does not matter which hook fired.
	//
	// The walk races the main thread: m_Hooks is a std::list that CHookManager
	// mutates. A torn read here produces a nonsense line in a diagnostic log,
	// which is the right failure - a hang or a crash in the tracer would be
	// indistinguishable from the bug it is chasing, and the previous line always
	// remains to compare against.
	int lastHeap = 1;
	SpWatchReset();
	g_spSamplerThread = GetCurrentThreadId();
	for (;;)
	{
		Sleep(40);

		// Tracking first, then arming. The order matters and was wrong once: the
		// poll that notices a new hook is what fills the table, so a loop that
		// only arms has nothing to arm and the run produces no data at all.
		SpHookTracePollWriteProtect();
		SpHookTracePollWatchpoint();

		// Flushed first, so a watchpoint hit is on the page before the state
		// that followed it.
		SpHookTraceFlushFaults();

		int heap = SpHookTraceHeapState();
		// Only say something when the state changes, so a heap that has been
		// clean for a thousand samples costs one line rather than a thousand.
		if (heap != lastHeap)
		{
			SpHookTraceHeapChange(heap);
			lastHeap = heap;
		}
		SpHookTraceSnapshot("wallclock");
	}
	return 0;
}

// The RVA inside server.dll that run39 showed to be overwritten at run time.
//
// Hardcoded, and that is a real limitation worth stating rather than hiding: the
// offset was found in one particular server.dll build, and if a future build puts
// legitimate data there the watchpoint will simply never fire. A probe that stays
// quiet is not evidence either way - which is why the scan below exists as an
// independent check that does not depend on this constant being right.
const uintptr_t SpServerTextCorruptRva = 0x1E20F0;

// Arms a write watchpoint on the known-corrupt run of server.dll's .text.
//
// On the calling thread, which is the engine's main thread - the same requirement
// as the CHook field watchpoint, for the same reason: the thread that writes is
// the thread we must cover, and covering it at load time is the only way to beat
// the timing. Nothing here walks the thread list, allocates, or takes a lock; it
// runs inside plugin load.
static void SpArmServerTextWatchpoint()
{
	HMODULE h = GetModuleHandleW(L"server.dll");
	if (!h)
	{
		char line[160];
		_snprintf_s(line, sizeof(line), _TRUNCATE,
			"TEXTWATCH server.dll is not loaded; no watchpoint armed");
		SpHookTraceAppend(line);
		return;
	}

	uintptr_t target = (uintptr_t) h + SpServerTextCorruptRva;

	char line[320];
	_snprintf_s(line, sizeof(line), _TRUNCATE,
		"TEXTWATCH arming on server.dll+0x%llX = %016llX",
		(unsigned long long) SpServerTextCorruptRva, (unsigned long long) target);
	SpHookTraceAppend(line);

	SpWatchArmCurrentThread(target, "srvtext");
}

// Compares server.dll's .text in memory against the copy on disk and reports
// every 4 KB page that differs.
//
// This is the independent check on the whole line of reasoning. The watchpoint
// above depends on one hardcoded RVA being right; this does not depend on it at
// all. It also answers the question the watchpoint cannot: not just that eight
// bytes were overwritten, but how MANY, and where they begin and end. The extent
// of a wild write is what identifies the buffer it came from - a few bytes is a
// bad pointer arithmetic, a few hundred kilobytes is a missing bounds check.
//
// Read once, from the fault path, so it costs nothing on a healthy run. Reading
// the file is not something a vectored handler should be doing by preference, but
// the alternative is concluding "the corruption is eight bytes" from eight bytes.
static void SpScanServerTextAgainstDisk()
{
	static LONG bScanned = 0;
	if (InterlockedCompareExchange(&bScanned, 1, 0) != 0)
		return;

	// Every exit below reports. The first version returned silently on every
	// failure path, so a scan that never ran and a scan that found nothing looked
	// identical - which is the one ambiguity this whole exercise has been
	// repeatedly bitten by. "I found no difference" and "I did not get far enough
	// to look" are opposite findings.
	char why[200];
	why[0] = 0;

	HMODULE h = GetModuleHandleW(L"server.dll");
	if (!h)
	{
		_snprintf_s(why, sizeof(why), _TRUNCATE, "TEXTDIFF FAILED: server.dll not loaded");
		SpHookTraceAppend(why);
		return;
	}

	// Find the .text section from the loaded image, then the same section in the
	// file. Read from the headers rather than assuming a name, so a renamed or
	// reordered section cannot silently produce a zero-length comparison.
	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*) h;
	IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*) ((BYTE*) h + dos->e_lfanew);
	IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

		// The module file name, so this reads the same DLL that is mapped rather than
	// some other copy that happens to be next to it on disk.
	//
	// Kept as a wide string all the way through. The first version converted to
	// the ANSI code page and then handed that to CreateFileW, which is a type
	// error the compiler caught immediately - and it would have been worse than a
	// build failure had it compiled, since CreateFileW would have read garbage.
	WCHAR pathW[MAX_PATH];
	if (!GetModuleFileNameW(h, pathW, MAX_PATH))
	{
		_snprintf_s(why, sizeof(why), _TRUNCATE, "TEXTDIFF FAILED: GetModuleFileNameW");
		SpHookTraceAppend(why);
		return;
	}

	// Which file, in full. Without this, "differs from disk" cannot be acted on:
	// there may be more than one server.dll and reading the wrong one would make a
	// healthy process look corrupted.
	char pathA[MAX_PATH];
	WideCharToMultiByte(CP_ACP, 0, pathW, -1, pathA, MAX_PATH, NULL, NULL);
	{
		char pl[340];
		_snprintf_s(pl, sizeof(pl), _TRUNCATE, "TEXTDIFF comparing against: %s", pathA);
		SpHookTraceAppend(pl);
	}

	HANDLE hf = CreateFileW(pathW, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hf == INVALID_HANDLE_VALUE)
	{
		_snprintf_s(why, sizeof(why), _TRUNCATE,
			"TEXTDIFF FAILED: CreateFileW err=%lu", (unsigned long) GetLastError());
		SpHookTraceAppend(why);
		return;
	}

	// Mapped rather than read. The previous version used ReadFile into a
	// VirtualAlloc'd buffer and came back with ok=0 err=998 - ERROR_OVERLAPPED -
	// which meant the whole comparison never ran and the round produced nothing
	// to look at. A file mapping needs no transfer buffer, no size arithmetic and
	// no I/O completion state, so it removes an entire class of "it silently did
	// not run" failures from a diagnostic whose whole value is that it runs.
	HANDLE hMap = CreateFileMappingW(hf, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!hMap)
	{
		_snprintf_s(why, sizeof(why), _TRUNCATE,
			"TEXTDIFF FAILED: CreateFileMappingW err=%lu", (unsigned long) GetLastError());
		SpHookTraceAppend(why);
		CloseHandle(hf);
		return;
	}

	const BYTE* disk = (const BYTE*) MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
	if (!disk)
	{
		_snprintf_s(why, sizeof(why), _TRUNCATE,
			"TEXTDIFF FAILED: MapViewOfFile err=%lu", (unsigned long) GetLastError());
		SpHookTraceAppend(why);
		CloseHandle(hMap);
		CloseHandle(hf);
		return;
	}

	DWORD fileSize = GetFileSize(hf, NULL);
	DWORD got = fileSize;

	const DWORD kPage = 4096;
	DWORD firstBad = 0xFFFFFFFF, lastBad = 0;
	DWORD badPages = 0, badBytes = 0;
	DWORD pagesChecked = 0;
	DWORD textVa = 0, textSize = 0, rawPtr = 0;
	bool bFoundText = false;

	for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		if (strcmp((const char*) sec[i].Name, ".text") != 0)
			continue;

		textVa = sec[i].VirtualAddress;
		textSize = sec[i].Misc.VirtualSize;
		rawPtr = sec[i].PointerToRawData;
		bFoundText = true;

		for (DWORD off = 0; off + kPage <= textSize; off += kPage)
		{
			DWORD diskOff = rawPtr + off;
			if (diskOff + kPage > got || diskOff + kPage < diskOff)
				break;

			// If this page is backed by the file and differs, something wrote it.
			const BYTE* mem = (const BYTE*) h + textVa + off;
			if (!SpIsReadable(mem))
				continue;

			if (memcmp(mem, disk + diskOff, kPage) == 0)
				continue;

			badPages++;
			DWORD firstDiff = kPage, lastDiff = 0;
			for (DWORD k = 0; k < kPage; k++)
			{
				if (mem[k] != disk[diskOff + k])
				{
					if (firstDiff == kPage) firstDiff = k;
					lastDiff = k;
				}
			}
			badBytes += (lastDiff - firstDiff + 1);
			if (firstBad == 0xFFFFFFFF) firstBad = textVa + off + firstDiff;
			lastBad = textVa + off + lastDiff;
			pagesChecked++;
		}
		break;
	}

	UnmapViewOfFile(disk);
	CloseHandle(hMap);
	CloseHandle(hf);

	if (!bFoundText)
	{
		_snprintf_s(why, sizeof(why), _TRUNCATE,
			"TEXTDIFF FAILED: no .text section among %u sections",
			nt->FileHeader.NumberOfSections);
		SpHookTraceAppend(why);
		return;
	}

	// Reports the scope it looked at as well as the result. A comparison over zero
	// pages and a comparison over all of .text that found nothing are the same
	// line of output unless the scope is stated, and they mean opposite things.
	char line[460];
	_snprintf_s(line, sizeof(line), _TRUNCATE,
		"TEXTDIFF bad_pages=%lu bad_bytes~=%lu first=RVA0x%lX last=RVA0x%lX"
		" | .text RVA0x%lX size=%lu file_off=0x%lX file_bytes_read=%lu pages_checked=%lu",
		(unsigned long) badPages, (unsigned long) badBytes,
		(unsigned long) firstBad, (unsigned long) lastBad,
		(unsigned long) textVa, (unsigned long) textSize,
		(unsigned long) rawPtr, (unsigned long) got,
		(unsigned long) pagesChecked);
	SpHookTraceAppend(line);
}

void SpHookTraceStartThread()
{
	static bool started = false;
	if (started)
		return;
	started = true;

	// Installed before the thread starts, so a write is never missed by a filter
	// that had not been set up yet.
	SpHookTraceInstallFaultCollector();

	// Armed here rather than on the first crash: the write that corrupts .text
	// happens long before anything notices it, and by the time we have a fault to
	// investigate the writer is gone. Load time is the earliest this can be done
	// from inside the process.
	SpArmServerTextWatchpoint();

	HANDLE h = CreateThread(NULL, 0, SpHookTraceThread, NULL, 0, NULL);
	// Deliberately leaked. Closing the handle would be tidier and would also be
	// wrong here: the thread outlives every function that could hold the handle,
	// and this is a diagnostic that is about to be deleted.
	if (h)
		CloseHandle(h);
}

#endif // _WIN32

} // namespace

void SpHookTraceLifecycle(const char* event, const void* pFunc,
                          const void* pConv, bool bHooked, const char* kind)
{
	// Ahead of the first statement, so the sampling thread exists before the
	// first line is even read.
	SpHookTraceStartThread();

	// What the convention holds, if it holds anything readable. The vptr is the
	// value the crash record implies was 0xFFFFFFFFFFFFFFF7, so it is the whole
	// point of the line.
	uintptr_t vptr = 0;
	bool convReadable = SpIsReadable(pConv);
	if (convReadable)
		vptr = *(const uintptr_t*) pConv;

	char funcDesc[64] = "(outside any module)";
	char convDesc[64] = "(outside any module)";
	char vptrDesc[64] = "(outside any module)";
	SpDescribeAddr((uintptr_t) pFunc, funcDesc, sizeof(funcDesc));
	SpDescribeAddr((uintptr_t) pConv, convDesc, sizeof(convDesc));
	SpDescribeAddr(vptr, vptrDesc, sizeof(vptrDesc));

	// Bounded rather than exact. The longest field is an address plus a
	// "module+0xRVA" description, and 512 leaves room for all of them; a
	// truncation here would corrupt the line, which is the one thing this
	// tracer cannot afford to do.
	char line[512];
	_snprintf_s(line, sizeof(line), _TRUNCATE,
		"LIFECYCLE %-12s kind=%-8s func=%016llX [%s] conv=%016llX [%s] vptr=%016llX [%s] "
		"%s m_bHooked=%d",
		event,
		kind ? kind : "unknown",
		(unsigned long long)(uintptr_t) pFunc, funcDesc,
		(unsigned long long)(uintptr_t) pConv, convDesc,
		(unsigned long long) vptr, vptrDesc,
		convReadable ? "conv-readable" : "conv-UNREADABLE",
		bHooked ? 1 : 0);

	SpHookTraceAppend(line);

	// A hand-off is the most interesting moment in the whole run: it is the last
	// point at which a newly hooked function is known to be in a good state.
	// The server died on the very first dispatch of the last hook created, so
	// the window between the two is exactly the window the crash lives in, and
	// a snapshot either side of it is the measurement that can close it.
	//
	// Resetting the tick counter as well means the next dispatch also
	// snapshots, because SpHookTraceTick fires on its first call. If that
	// snapshot is missing from the log, the first dispatch never reached the
	// callback - which is itself a result, and a much sharper one than "the
	// server crashed".
	if (event != NULL && strncmp(event, "handoff", 7) == 0)
	{
		SpHookTraceSnapshot("after-handoff");
		SpHookTraceTicks = 0;
	}
}

void SpHookTraceSnapshot(const char* reason)
{
	char* path = SpHookTracePath();
	if (!path)
		return;

	FILE* handle = _tfopen(path, "a");
	if (!handle)
		return;

	uintptr_t coreBase = 0;
	uintptr_t coreSize = 0;
	SpCoreImage(&coreBase, &coreSize);

	CHookManager* manager = GetHookManager();
	unsigned int n = 0;

	fprintf(handle, "SNAPSHOT  reason=%s ticks=%lu core=%016llX..%016llX hooks=",
		reason ? reason : "?",
		SpHookTraceTicks,
		(unsigned long long) coreBase,
		(unsigned long long) (coreBase + coreSize));

	// The walk is inside its own catch(...). m_Hooks is a std::list owned by the
	// DynamicHooks library; if the tracer's whole premise is that this library
	// has been freeing memory behind SP's back, then iterating its list is not
	// a place to be confident. A throw here costs one truncated line, which is
	// a good trade for not taking the server down inside the diagnostic.
	try
	{
		if (manager)
		{
			n = (unsigned int) manager->m_Hooks.size();
			fprintf(handle, "%u\n", n);

			for (std::list<CHook*>::iterator it = manager->m_Hooks.begin();
				it != manager->m_Hooks.end(); ++it)
			{
				CHook* pHook = *it;
				if (!pHook)
					continue;

				ICallingConvention* pConv = pHook->m_pCallingConvention;

				// The convention object itself.
				bool convReadable = SpIsReadable(pConv);
				uintptr_t vptr = 0;
				bool hooked = false;
				if (convReadable)
				{
					vptr = *(const uintptr_t*) pConv;
					hooked = pConv->m_bHooked ? true : false;
				}

				// The vtable, and the two slots that matter. A live convention
				// has a vtable in core.dll's data, a destructor in its code,
				// and GetRegisters - slot 1, the one the crash is on - in its
				// code too.
				bool vptrReadable = SpIsReadable((const void*) vptr);
				bool vptrInCore = vptrReadable && coreSize &&
					vptr >= coreBase && vptr < coreBase + coreSize;
				uintptr_t slot0 = 0;
				uintptr_t slot1 = 0;
				bool slot0Readable = false;
				bool slot1InCore = false;
				if (vptrReadable)
				{
					slot0 = *(const uintptr_t*) vptr;
					slot1 = *(const uintptr_t*) (vptr + 8);
					slot0Readable = SpIsReadable((const void*) slot0);
					slot1InCore = SpIsReadable((const void*) slot1) && coreSize &&
						slot1 >= coreBase && slot1 < coreBase + coreSize;
				}

				// The bridge and trampoline are DynamicHooks' own allocations
				// and are the memory this whole line of reasoning is about, so
				// their liveness is reported too.
				bool bridgeLive = SpIsReadable(pHook->m_pBridge);
				bool trampLive = SpIsReadable(pHook->m_pTrampoline);

				// The JIT bridge bakes the CHook address in as an immediate, so
				// the bridge is a readable statement of which hook it dispatches.
				// Read rather than assumed: "the engine called the bridge for a
				// CHook that is no longer the one in m_Hooks" is the one
				// explanation left that fits every observation - the convention
				// healthy at every sample, the fault on the first dispatch, and
				// nothing in SP having freed anything.
				//
				// The immediate is not at a fixed offset: CreateBridge emits
				// endbr64, a stack adjustment and SaveSnapshot before it, and
				// SaveSnapshot spills 30 registers plus 16 XMM registers, which
				// pushes the mov well past 256 bytes. An earlier version scanned
				// only 256 and reported not-found on every snapshot, which read
				// as "the bridge does not bake in a hook address" when it only
				// meant the window was too small.
				//
				// 2048 is generous: it is more than twice the whole bridge for
				// this path. The offset it reports is what makes a negative
				// result trustworthy.
				uintptr_t baked = 0;
				unsigned int bakedAt = 0;
				bool bakedFound = false;
				if (bridgeLive)
				{
					const unsigned char* b = (const unsigned char*) pHook->m_pBridge;
					for (unsigned int bi = 0; bi + 10 <= 2048; bi++)
					{
						if (b[bi] == 0x48 && b[bi + 1] == 0xBF)
						{
							baked = *(const uintptr_t*) (const void*) (b + bi + 2);
							bakedAt = bi;
							bakedFound = true;
							break;
						}
					}
				}
				bool bakedMatches = bakedFound && baked == (uintptr_t) pHook;

				char funcDesc[64] = "(outside any module)";
				char vptrDesc[64] = "(outside any module)";
				char slot1Desc[64] = "(outside any module)";
				char convDesc[64] = "(outside any module)";
				SpDescribeAddr((uintptr_t) pHook->m_pFunc, funcDesc, sizeof(funcDesc));
				SpDescribeAddr(vptr, vptrDesc, sizeof(vptrDesc));
				SpDescribeAddr(slot1, slot1Desc, sizeof(slot1Desc));
				SpDescribeAddr((uintptr_t) pConv, convDesc, sizeof(convDesc));

				// "self" is printed alongside the bridge's baked-in immediate so the
				// two can be compared by eye. That comparison is the point: if a
				// bridge dispatches for a CHook other than the one in m_Hooks, the
				// engine is calling a bridge whose hook no longer exists, and
				// everything else observed follows from that - a healthy convention
				// in every sample, a fault on the first dispatch, and nothing in SP
				// having freed anything.
				fprintf(handle,
					"  HOOK self=%016llX func=%016llX [%s] conv=%016llX [%s] %s vptr=%016llX [%s] %s%s "
					"m_bHooked=%d slot0=%016llX%s slot1=%016llX [%s]%s "
					"bridge=%016llX%s tramp=%016llX%s baked=%s%016llX@%u%s\n",
					(unsigned long long)(uintptr_t) pHook,
					(unsigned long long)(uintptr_t) pHook->m_pFunc, funcDesc,
					(unsigned long long)(uintptr_t) pConv, convDesc,
					convReadable ? "ok " : "BAD",
					(unsigned long long) vptr, vptrDesc,
					vptrReadable ? "vptr-readable " : "vptr-UNREADABLE ",
					vptrInCore ? "vptr-in-core" : "vptr-NOT-in-core",
					hooked ? 1 : 0,
					(unsigned long long) slot0,
					slot0Readable ? " " : "(unreadable)",
					(unsigned long long) slot1, slot1Desc,
					slot1InCore ? " in-core" : " NOT-in-core",
					(unsigned long long)(uintptr_t) pHook->m_pBridge,
					bridgeLive ? " " : "(freed)",
					(unsigned long long)(uintptr_t) pHook->m_pTrampoline,
					trampLive ? "" : "(freed)",
					bakedFound ? "" : "not-found:",
					(unsigned long long) baked,
					bakedAt,
					bakedMatches ? " =MATCHES-hook" : " DIFFERS-from-hook");
			}
		}
		else
		{
			fprintf(handle, "?\n");
		}
	}
	catch (...)
	{
		fprintf(handle, "  <tracer aborted: exception while walking m_Hooks>\n");
	}

	fprintf(handle, "END SNAPSHOT\n");
	fflush(handle);
	fclose(handle);
}

void SpHookTraceTick(const char* reason)
{
	SpHookTraceTicks++;
	// Every dispatch in the early phase, then throttled.
	//
	// The early phase is the whole point. If the fault is on the first dispatch
	// of the run_command hook then the last snapshot before the crash is
	// snapshot N=1, and the cause is in the construction of the first invocation
	// - a bad convention, a bad bridge, a bad stack. If it is on the thousandth
	// then the cause is cumulative: allocation churn, a leak, a buffer that
	// overruns its own bounds slowly. Those need different fixes, and picking
	// between them by reasoning about the code has already produced one wrong
	// answer in this investigation.
	//
	// The throttle is by dispatch count rather than time because dispatch count
	// is what distinguishes the two cases.
	if (SpHookTraceTicks <= SpHookTraceEveryDispatchUpTo ||
		SpHookTraceTicks % SpHookTraceInterval == 0)
		SpHookTraceSnapshot(reason);
}

#else // !_WIN32

// The call sites stay unconditional. A diagnostic that needs a preprocessor
// guard at every caller is a diagnostic that gets commented out at one of them
// and then quietly stops reporting.
void SpHookTraceLifecycle(const char*, const void*, const void*, bool, const char*) {}
void SpHookTraceSnapshot(const char*) {}
void SpHookTraceTick(const char*) {}
void SpHookTraceStartThread() {}

#endif // _WIN32


// ============================================================================
// >> SP_HookHandler
// ============================================================================
bool SP_HookHandler(HookType_t eHookType, CHook* pHook)
{
	if (g_HooksDisabled)
		return false;

	// Placed before the g_mapCallbacks lookup on purpose. That lookup inserts
	// into a map, which allocates, and a diagnostic that allocates on every
	// dispatch would be a diagnostic that changes what it is measuring. This is
	// a counter and a modulo, and the snapshot it eventually triggers is the
	// point of the exercise.
	//
	// It is also the most useful place to snapshot from that SP owns: this runs
	// after CHook::DispatchPre has already built the X64Invocation for pHook,
	// so on a run that survives it is proof that pHook's convention was readable
	// and its vtable sane one dispatch ago. On the dispatch that kills the
	// server this never gets to run at all, and the previous snapshot is
	// therefore the last known good state.
	SpHookTraceTick("dispatch");

	std::list<object> callbacks = g_mapCallbacks[pHook][eHookType];

	// No need to do all this stuff, if there is no callback registered
	if (callbacks.empty())
		return false;

	object retval;
	if (eHookType == HOOKTYPE_POST)
	{
		switch(pHook->m_pCallingConvention->m_returnType)
		{
			case DATA_TYPE_VOID:		retval = object(); break;
			case DATA_TYPE_BOOL:		retval = GetReturnValue<bool>(pHook); break;
			case DATA_TYPE_CHAR:		retval = GetReturnValue<char>(pHook); break;
			case DATA_TYPE_UCHAR:		retval = GetReturnValue<unsigned char>(pHook); break;
			case DATA_TYPE_SHORT:		retval = GetReturnValue<short>(pHook); break;
			case DATA_TYPE_USHORT:		retval = GetReturnValue<unsigned short>(pHook); break;
			case DATA_TYPE_INT:			retval = GetReturnValue<int>(pHook); break;
			case DATA_TYPE_UINT:		retval = GetReturnValue<unsigned int>(pHook); break;
			case DATA_TYPE_LONG:		retval = GetReturnValue<long>(pHook); break;
			case DATA_TYPE_ULONG:		retval = GetReturnValue<unsigned long>(pHook); break;
			case DATA_TYPE_LONG_LONG:	retval = GetReturnValue<long long>(pHook); break;
			case DATA_TYPE_ULONG_LONG:	retval = GetReturnValue<unsigned long long>(pHook); break;
			case DATA_TYPE_FLOAT:		retval = GetReturnValue<float>(pHook); break;
			case DATA_TYPE_DOUBLE:		retval = GetReturnValue<double>(pHook); break;
			case DATA_TYPE_POINTER:		retval = object(CPointer(pHook->GetReturnValue<Addr_t>())); break;
			case DATA_TYPE_STRING:		retval = GetReturnValue<const char *>(pHook); break;
			default: BOOST_RAISE_EXCEPTION(PyExc_TypeError, "Unknown type.");
		}
	}
	
	CStackData stackdata = CStackData(pHook);
	bool bOverride = false;
	for (std::list<object>::iterator it=callbacks.begin(); it != callbacks.end(); ++it)
	{
		BEGIN_BOOST_PY()
			object pyretval;
			if (eHookType == HOOKTYPE_PRE)
				pyretval = (*it)(stackdata);
			else
				pyretval = (*it)(stackdata, retval);

			if (!pyretval.is_none())
			{
				bOverride = true;
				switch(pHook->m_pCallingConvention->m_returnType)
				{
					case DATA_TYPE_VOID:		break;
					case DATA_TYPE_BOOL:		SetReturnValue<bool>(pHook, pyretval); break;
					case DATA_TYPE_CHAR:		SetReturnValue<char>(pHook, pyretval); break;
					case DATA_TYPE_UCHAR:		SetReturnValue<unsigned >(pHook, pyretval); break;
					case DATA_TYPE_SHORT:		SetReturnValue<short>(pHook, pyretval); break;
					case DATA_TYPE_USHORT:		SetReturnValue<unsigned short>(pHook, pyretval); break;
					case DATA_TYPE_INT:			SetReturnValue<int>(pHook, pyretval); break;
					case DATA_TYPE_UINT:		SetReturnValue<unsigned int>(pHook, pyretval); break;
					case DATA_TYPE_LONG:		SetReturnValue<long>(pHook, pyretval); break;
					case DATA_TYPE_ULONG:		SetReturnValue<unsigned long>(pHook, pyretval); break;
					case DATA_TYPE_LONG_LONG:	SetReturnValue<long long>(pHook, pyretval); break;
					case DATA_TYPE_ULONG_LONG:	SetReturnValue<unsigned long long>(pHook, pyretval); break;
					case DATA_TYPE_FLOAT:		SetReturnValue<float>(pHook, pyretval); break;
					case DATA_TYPE_DOUBLE:		SetReturnValue<double>(pHook, pyretval); break;
					case DATA_TYPE_POINTER:
					{
						pHook->SetReturnValue<Addr_t>(ExtractAddress(pyretval));
					} break;
					case DATA_TYPE_STRING:		SetReturnValue<const char*>(pHook, pyretval); break;
					default: BOOST_RAISE_EXCEPTION(PyExc_TypeError, "Unknown type.")
				}
			}
		END_BOOST_PY_NORET()
	}
	return bOverride;
}


// ============================================================================
// >> CStackData
// ============================================================================
CStackData::CStackData(CHook* pHook)
{
	m_pHook = pHook;
}

object CStackData::GetItem(unsigned int iIndex)
{
	if (iIndex >= (unsigned int) m_pHook->m_pCallingConvention->m_vecArgTypes.size())
		BOOST_RAISE_EXCEPTION(PyExc_IndexError, "Index out of range.")

	// Argument already cached?
	object retval;
	//object retval = m_mapCache[iIndex];
	//if (retval)
	//	return retval;

	switch(m_pHook->m_pCallingConvention->m_vecArgTypes[iIndex])
	{
		case DATA_TYPE_BOOL:		retval = GetArgument<bool>(m_pHook, iIndex); break;
		case DATA_TYPE_CHAR:		retval = GetArgument<char>(m_pHook, iIndex); break;
		case DATA_TYPE_UCHAR:		retval = GetArgument<unsigned char>(m_pHook, iIndex); break;
		case DATA_TYPE_SHORT:		retval = GetArgument<short>(m_pHook, iIndex); break;
		case DATA_TYPE_USHORT:		retval = GetArgument<unsigned short>(m_pHook, iIndex); break;
		case DATA_TYPE_INT:			retval = GetArgument<int>(m_pHook, iIndex); break;
		case DATA_TYPE_UINT:		retval = GetArgument<unsigned int>(m_pHook, iIndex); break;
		case DATA_TYPE_LONG:		retval = GetArgument<long>(m_pHook, iIndex); break;
		case DATA_TYPE_ULONG:		retval = GetArgument<unsigned long>(m_pHook, iIndex); break;
		case DATA_TYPE_LONG_LONG:	retval = GetArgument<long long>(m_pHook, iIndex); break;
		case DATA_TYPE_ULONG_LONG:	retval = GetArgument<unsigned long long>(m_pHook, iIndex); break;
		case DATA_TYPE_FLOAT:		retval = GetArgument<float>(m_pHook, iIndex); break;
		case DATA_TYPE_DOUBLE:		retval = GetArgument<double>(m_pHook, iIndex); break;
		case DATA_TYPE_POINTER:		retval = object(CPointer(m_pHook->GetArgument<Addr_t>(iIndex))); break;
		case DATA_TYPE_STRING:		retval = GetArgument<const char *>(m_pHook, iIndex); break;
		default: BOOST_RAISE_EXCEPTION(PyExc_TypeError, "Unknown type.") break;
	}
	//m_mapCache[iIndex] = retval;
	return retval;
}

void CStackData::SetItem(unsigned int iIndex, object value)
{
	if (iIndex >= (unsigned int) m_pHook->m_pCallingConvention->m_vecArgTypes.size())
		BOOST_RAISE_EXCEPTION(PyExc_IndexError, "Index out of range.")

	// Update cache
	//m_mapCache[iIndex] = value;
	switch(m_pHook->m_pCallingConvention->m_vecArgTypes[iIndex])
	{
		case DATA_TYPE_BOOL:		SetArgument<bool>(m_pHook, iIndex, value); break;
		case DATA_TYPE_CHAR:		SetArgument<char>(m_pHook, iIndex, value); break;
		case DATA_TYPE_UCHAR:		SetArgument<unsigned char>(m_pHook, iIndex, value); break;
		case DATA_TYPE_SHORT:		SetArgument<short>(m_pHook, iIndex, value); break;
		case DATA_TYPE_USHORT:		SetArgument<unsigned short>(m_pHook, iIndex, value); break;
		case DATA_TYPE_INT:			SetArgument<int>(m_pHook, iIndex, value); break;
		case DATA_TYPE_UINT:		SetArgument<unsigned int>(m_pHook, iIndex, value); break;
		case DATA_TYPE_LONG:		SetArgument<long>(m_pHook, iIndex, value); break;
		case DATA_TYPE_ULONG:		SetArgument<unsigned long>(m_pHook, iIndex, value); break;
		case DATA_TYPE_LONG_LONG:	SetArgument<long long>(m_pHook, iIndex, value); break;
		case DATA_TYPE_ULONG_LONG:	SetArgument<unsigned long long>(m_pHook, iIndex, value); break;
		case DATA_TYPE_FLOAT:		SetArgument<float>(m_pHook, iIndex, value); break;
		case DATA_TYPE_DOUBLE:		SetArgument<double>(m_pHook, iIndex, value); break;
		case DATA_TYPE_POINTER:
		{
			SetArgument<Addr_t>(m_pHook, iIndex, object(ExtractAddress(value)));
		} break;
		case DATA_TYPE_STRING:		SetArgument<const char *>(m_pHook, iIndex, value); break;
		default: BOOST_RAISE_EXCEPTION(PyExc_TypeError, "Unknown type.")
	}
}

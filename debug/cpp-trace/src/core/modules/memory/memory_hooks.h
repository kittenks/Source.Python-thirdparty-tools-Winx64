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

#ifndef MEMORY_HOOKS_H
#define MEMORY_HOOKS_H

//---------------------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------------------
#include <list>
#include <map>

#include "boost/python.hpp"
using namespace boost::python;

// DynamicHooks
#include "hook.h"

//---------------------------------------------------------------------------------
// Classes
//---------------------------------------------------------------------------------
class CStackData
{
public:
	CStackData(CHook* pHook);

	object		GetItem(unsigned int iIndex);
	void		SetItem(unsigned int iIndex, object value);

	CRegisters* GetRegisters()
	{ return m_pHook->GetRegisters(); }

	str	__repr__()
	{ return str(boost::python::tuple(ptr(this))); }

	void* GetReturnAddress()
	{
#ifdef SOURCEPYTHON_X86_64
		return m_pHook->GetCurrentReturnAddress();
#else
		void* pESP = m_pHook->GetRegisters()->m_esp->GetValue<void*>();
		if (m_pHook->m_RetAddr.count(pESP) == 0) {
			return NULL;
		}
		return m_pHook->m_RetAddr[pESP].back();
#endif
	}

	bool GetUsePreRegister()
	{
#ifdef SOURCEPYTHON_X86_64
		return m_pHook->GetUsePreRegisters();
#else
		return m_pHook->m_bUsePreRegisters;
#endif
	}

	void SetUsePreRegisters(bool value)
	{
#ifdef SOURCEPYTHON_X86_64
		m_pHook->SetUsePreRegisters(value);
#else
		m_pHook->m_bUsePreRegisters = value;
#endif
	}

protected:
	CHook*                m_pHook;
	std::map<int, object> m_mapCache;
};


//---------------------------------------------------------------------------------
// Functions
//---------------------------------------------------------------------------------
bool SP_HookHandler(HookType_t eHookType, CHook* pHook);

//---------------------------------------------------------------------------------
// Diagnostic: DynamicHooks convention lifecycle and liveness tracer.
// Added 2026-09-29. See the SP_HOOK_TRACE block in memory_hooks.cpp for why.
//
// These are temporary. They exist only to explain the crash at
// core.dll+0x48DFD2, and they are the reason to remove them is in that same
// block, not the reason they are here.
//---------------------------------------------------------------------------------

// Records one lifecycle event. event is a short fixed label ("handoff",
// "dtor-dtor", "deletehook") so the log can be read by eye without parsing.
// kind names the convention's flavour - "win64", "custom", "unknown" - because
// the two are owned by different rules: a built-in convention is a raw new that
// ~CFunction frees, a custom one is a boost::shared_ptr whose Deleter decides,
// and which of those two paths is live is the first thing to know about any
// given hand-off.
void SpHookTraceLifecycle(const char* event, const void* pFunc,
                          const void* pConv, bool bHooked,
                          const char* kind = "unknown");

// Records the liveness of every convention currently held by a live hook.
// reason is a short label naming what triggered it, so the last snapshot in the
// log can be attributed to a moment rather than guessed at.
void SpHookTraceSnapshot(const char* reason);

// Increments the dispatch counter the snapshot throttle is based on. Called
// from SP's hook callback, which is the most frequent point in core.dll that
// also has a CHook in hand.
void SpHookTraceTick(const char* reason);

// Records the engine's main thread id. Must be called from the plugin load
// entry, which is the only code guaranteed to be running on that thread.
//
// The hardware watchpoint verdict is meaningless without it: the crashing
// dispatch happens on this thread and nowhere else, and the aggregate
// "threads armed" count moves by a factor of seven between runs, so it cannot
// answer whether this particular thread was covered.
//
// unsigned long rather than DWORD: this header is included from translation
// units that do not include windows.h, and leaking a Windows type into a public
// header for one parameter is not worth it. On Windows the two are the same
// width, which is all that matters here.
void SpHookTraceSetMainThreadId(unsigned long id);

// Arms a hardware watchpoint on &pHook->m_pCallingConvention for the calling
// thread, immediately.
//
// Call this from the hook-creation path, not from a sampling thread. The hook
// that crashes is created and dispatched within a few milliseconds, which is
// shorter than one poll interval, so a watchpoint installed by polling arrives
// after its subject is gone - and a probe that arrives late reports "nothing
// happened" with exactly the same authority as one that was watching all along.
//
// The calling thread is the one that will dispatch, so arming only it is enough
// for the verdict and costs a few microseconds instead of a thread sweep.
void SpHookTraceArmHookNow(CHook* pHook);

extern bool g_HooksDisabled;

inline void SetHooksDisabled(bool value)
{
	g_HooksDisabled = value;
}

inline bool GetHooksDisabled()
{
	return g_HooksDisabled;
}

#endif // MEMORY_HOOKS_H

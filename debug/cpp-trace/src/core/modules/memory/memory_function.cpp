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
// DynCall
#include "dyncall.h"
#include "dyncall_signature.h"

// Memory
#include "memory_function.h"
#include "memory_utilities.h"
#include "memory_hooks.h"
#include "memory_wrap.h"

// DynamicHooks
// Windows x86-64 and Linux x86-64 are both 64-bit, so both take the x64
// backend, but their calling conventions are unrelated: Windows passes integer
// and SSE arguments by position into RCX/RDX/R8/R9 and XMM0-3, while SysV
// numbers the two register classes independently. The classes share an
// interface, so this is a choice of which one to instantiate.
#if defined(SOURCEPYTHON_X86_64) && defined(_WIN32)
#include "conventions/x64MsWin64.h"
#elif defined(SOURCEPYTHON_X86_64)
#include "conventions/x64GccSystemV.h"
#else
#include "conventions/x86MsCdecl.h"
#include "conventions/x86MsThiscall.h"
#include "conventions/x86MsStdcall.h"
#include "conventions/x86MsFastcall.h"
#include "conventions/x86GccCdecl.h"
#include "conventions/x86GccThiscall.h"
#endif

// Source.Python
#include "utilities/call_python.h"


// ============================================================================
// >> SP_CALL_TRACE
// ============================================================================
// A one-shot probe at the entry to CFunction::Call, added 2026-09-29.
//
// Why it is here. One of the six minidumps - the 04:42 one - was the first to
// contain the faulting thread's stack, and reading it gives a chain that ends
// at the fault:
//
//   core.dll+0x48C9B0   mov ecx, 0x20
//                        call 0x4D08C0        <- an allocator, 32 bytes
//                        mov rcx, [rsp+0x30]   <- what it returned
//                        call 0x48DB90        <- the fault is inside here
//   core.dll+0x48DB90   mov rax, [rsp+0xA0]   <- 0x19CB9987430
//                        mov rcx, [rsp+0xA8]   <- 0x19CBBC4CBB0
//                        mov [rax], rcx        <- writes 8 bytes through the first
//                        mov ecx, 0x350
//                        call 0x4D08C0         <- the same allocator, 0x350 bytes
//                        ...
//                        call qword ptr [rax+8]  <- the fault, 0x48DBF2
//
// The two addresses in the first two of those lines are in the Python heap,
// not in any module. So whatever is at 0x48DB90 is holding Python objects.
//
// Neither frame can be named. src/thirdparty/dyncall has headers and prebuilt
// libraries and no .c files at all, so both are inside libdyncall_s.lib as
// linked. Saying "0x48C9B0 is dyncall's VM code" is an inference from its
// shape, not something the tree can confirm, and this probe does not pretend
// otherwise - it records what SP actually hands to dyncall, so the next run
// either shows the sizes appearing or does not.
//
// It fires once and then costs a predictable bool test. A crash investigation
// that slows the server down invalidates its own timings, and this is a
// diagnostic, not a feature.
static void SpCallTrace(DCCallVM* vm, Addr_t addr, int arg_count)
{
	static bool done = false;
	if (done)
		return;
	done = true;

	// Everything here is inside a catch-all. A probe that can take the server
	// down is worse than no probe, and the run it is meant to explain has
	// already failed.
	try
	{
		// Everything here goes through the CPython C API rather than
		// boost::python's object::getattr, which does not exist - the binding
		// has no getattr and no operator/ either, so building a path out of
		// pathlib objects does not compile. Doing it in plain C avoids inventing
		// a boost::python API that is not there.
		//
		// The directory is taken from the already-imported sourcepython.paths
		// module, so the probe does not hardcode a second copy of the game path
		// that could drift from the real one.
		PyObject* paths = PyImport_ImportModule("paths");
		if (!paths)
		{
			PyErr_Clear();
			return;
		}
		PyObject* root = PyObject_GetAttrString(paths, "GAME_PATH");
		Py_DECREF(paths);
		if (!root)
		{
			PyErr_Clear();
			return;
		}
		PyObject* root_str = PyObject_Str(root);
		Py_DECREF(root);
		if (!root_str)
		{
			PyErr_Clear();
			return;
		}
		const char* root_chars = PyUnicode_AsUTF8(root_str);
		if (!root_chars)
		{
			Py_DECREF(root_str);
			PyErr_Clear();
			return;
		}

		char path[MAX_PATH];
		_snprintf_s(path, sizeof(path), _TRUNCATE, "%s/logs/source-python/sp_call_trace.txt",
			root_chars);
		Py_DECREF(root_str);

		FILE* handle = _tfopen(path, "a");
		if (!handle)
			return;

		fprintf(handle, "=== first CFunction::Call ===\n");
		fprintf(handle, "core.dll         0x%016llX\n",
			(unsigned long long)(uintptr_t)&SpCallTrace);
		fprintf(handle, "g_pCallVM        %p\n", (void*)vm);
		fprintf(handle, "target address   0x%016llX\n", (unsigned long long)addr);
		fprintf(handle, "argument count   %d\n", arg_count);
		fprintf(handle, "the dump showed allocations of 0x20 and 0x350\n");
		fflush(handle);
		fclose(handle);
	}
	catch (...)
	{
	}
}


// ============================================================================
// >> EXTERNALS
// ============================================================================
extern std::map<CHook *, std::map<HookType_t, std::list<object> > > g_mapCallbacks;


// ============================================================================
// >> GLOBAL VARIABLES
// ============================================================================
DCCallVM* g_pCallVM = dcNewCallVM(4096);


// ============================================================================
// >> GetDynCallConvention
// ============================================================================
int GetDynCallConvention(Convention_t eConv)
{
	switch (eConv)
	{
		case CONV_CUSTOM: return -1;
		case CONV_CDECL: return DC_CALL_C_DEFAULT;
		case CONV_THISCALL:
			#ifdef SOURCEPYTHON_X86_64
				return DC_CALL_C_DEFAULT;
			#else
			#ifdef _WIN32
				return DC_CALL_C_X86_WIN32_THIS_MS;
			#else
				return DC_CALL_C_X86_WIN32_THIS_GNU;
			#endif
			#endif
#ifdef _WIN32
		case CONV_STDCALL: return DC_CALL_C_X86_WIN32_STD;
		case CONV_FASTCALL: return DC_CALL_C_X86_WIN32_FAST_MS;
#endif
	}

	BOOST_RAISE_EXCEPTION(PyExc_ValueError, "Unsupported calling convention.")
	return -1;
}


// ============================================================================
// >> MakeDynamicHooksConvention
// ============================================================================
ICallingConvention* MakeDynamicHooksConvention(Convention_t eConv, std::vector<DataType_t> vecArgTypes, DataType_t returnType, int iAlignment)
{
	// On x86-64 there is only one calling convention per platform, so CDECL and
	// THISCALL both resolve to it. STDCALL and FASTCALL do not exist there at
	// all, which is why they are not listed: GetCallingConvention in
	// memory_calling_convention.h reports CONV_CDECL for every signature on
	// x86-64, and that is what arrives here.
#if defined(SOURCEPYTHON_X86_64) && defined(_WIN32)
	switch (eConv)
	{
	case CONV_CDECL:
	case CONV_THISCALL:
		return new x64MsWin64(vecArgTypes, returnType, iAlignment);
	}
#elif defined(SOURCEPYTHON_X86_64)
	switch (eConv)
	{
	case CONV_CDECL:
	case CONV_THISCALL:
		return new x64GccSystemV(vecArgTypes, returnType, iAlignment);
	}
#else
#ifdef _WIN32
	switch (eConv)
	{
	case CONV_CDECL: return new x86MsCdecl(vecArgTypes, returnType, iAlignment);
	case CONV_THISCALL: return new x86MsThiscall(vecArgTypes, returnType, iAlignment);
	case CONV_STDCALL: return new x86MsStdcall(vecArgTypes, returnType, iAlignment);
	case CONV_FASTCALL: return new x86MsFastcall(vecArgTypes, returnType, iAlignment);
	}
#else
	switch (eConv)
	{
	case CONV_CDECL: return new x86GccCdecl(vecArgTypes, returnType, iAlignment);
	case CONV_THISCALL: return new x86GccThiscall(vecArgTypes, returnType, iAlignment);
	}
#endif
#endif

	BOOST_RAISE_EXCEPTION(PyExc_ValueError, "Unsupported calling convention.")
	return NULL;
}


// ============================================================================
// >> CFunction
// ============================================================================
CFunction::CFunction(Addr_t ulAddr, object oCallingConvention, object oArgs, object oReturnType)
	:CPointer(ulAddr)
{
	// Step 1: Validate and convert the argument types
	m_tArgs = tuple(oArgs);

	// Step 2: Determine the return type/converter
	try
	{
		// If this line succeds...
		m_eReturnType = extract<DataType_t>(oReturnType);

		// ...no converter will be used
		m_oConverter = object();
	}
	catch( ... )
	{
		PyErr_Clear();

		// If this happens the return type is a converter for a pointer
		m_eReturnType = DATA_TYPE_POINTER;
		m_oConverter = oReturnType;
	}

	// Step 3: Determine the calling convention
	try
	{
		// If this line succeeds the user wants to create a function with the built-in calling conventions
		m_eCallingConvention = extract<Convention_t>(oCallingConvention);
		m_pCallingConvention = MakeDynamicHooksConvention(m_eCallingConvention, ObjectToDataTypeVector(m_tArgs), m_eReturnType);
		m_oCallingConvention = object();
	}
	catch( ... )
	{
		PyErr_Clear();

		// A custom calling convention will be used...
		m_eCallingConvention = CONV_CUSTOM;
		m_oCallingConvention = oCallingConvention(m_tArgs, m_eReturnType);
		m_pCallingConvention = extract<ICallingConvention*>(m_oCallingConvention);
	}

	// Step 4: Get the DynCall calling convention
	m_iCallingConvention = GetDynCallConvention(m_eCallingConvention);
}

CFunction::CFunction(Addr_t ulAddr, Convention_t eCallingConvention,
	int iCallingConvention, tuple tArgs, DataType_t eReturnType, object oConverter)
	:CPointer(ulAddr)
{
	m_eCallingConvention = eCallingConvention;
	m_iCallingConvention = iCallingConvention;
	m_pCallingConvention = NULL;
	m_oCallingConvention = object();

	m_tArgs = tArgs;
	m_eReturnType = eReturnType;
	m_oConverter = oConverter;
}

CFunction::CFunction(const CFunction& obj)
	:CPointer(obj)
{
	m_tArgs = obj.m_tArgs;
	m_eReturnType = obj.m_eReturnType;
	m_oConverter = obj.m_oConverter;

	m_eCallingConvention = obj.m_eCallingConvention;
	m_iCallingConvention = obj.m_iCallingConvention;

	if (m_eCallingConvention != CONV_CUSTOM)
	{
		m_pCallingConvention = MakeDynamicHooksConvention(m_eCallingConvention, ObjectToDataTypeVector(m_tArgs), m_eReturnType);
		m_oCallingConvention = object();
	}
	else
	{
		m_pCallingConvention = obj.m_pCallingConvention;
		m_oCallingConvention = obj.m_oCallingConvention;
	}
}

// Names a convention's flavour for the hook tracer. Only CONV_CUSTOM is spelled
// out; the built-ins are reported by number rather than by name, because the
// point of the field is to separate "owned by ~CFunction" from "owned by a
// shared_ptr deleter", and that distinction is custom versus everything else.
// Enumerating the built-in names would add a second thing to keep in step with
// the enum for no extra diagnostic value.
static const char* SpConvKindName(Convention_t eConv)
{
	static char buf[24];
	if (eConv == CONV_CUSTOM)
		return "custom";
	_snprintf_s(buf, sizeof(buf), _TRUNCATE, "type%d", (int) eConv);
	return buf;
}

CFunction::~CFunction()
{
	if (!m_pCallingConvention)
		return;

	if (m_eCallingConvention != CONV_CUSTOM)
	{
		// If we are using a built-in convention that is currently hooked, let's flag it as no longer hooked
		// so that we know we are not bound to a CFunction anymore and can be deleted.
		if (m_pCallingConvention->m_bHooked)
		{
			m_pCallingConvention->m_bHooked = false;

			// The convention is now unbound from any CFunction, but a hook may
			// still be holding it. That is the case this whole tracer exists to
			// watch for, so it is recorded rather than left to be inferred.
			SpHookTraceLifecycle("dtor-release", (const void *) m_ulAddr,
				(const void *) m_pCallingConvention, true,
				SpConvKindName(m_eCallingConvention));
		}
		// If the convention isn't flagged as hooked, then we need to take care of it.
		else
		{
			// This is the line that would leave a hook holding a dangling
			// pointer if a hook had taken this convention without the flag
			// being set. Whether any hook holds it is exactly what the log line
			// below lets a reader check.
			SpHookTraceLifecycle("dtor-DELETE", (const void *) m_ulAddr,
				(const void *) m_pCallingConvention, false,
				SpConvKindName(m_eCallingConvention));
			delete m_pCallingConvention;
		}
	}
	else
	{
		// A custom convention is not freed here at all. It is a
		// boost::shared_ptr whose Deleter in memory_wrap.h decides, and that
		// Deleter's only input is m_bHooked:
		//
		//   if (pThis->m_bHooked) return;   // DynamicHooks will take care of us
		//   delete pThis;
		//
		// so for the custom flavour m_bHooked is the entire ownership record.
		// This line does not change anything; it makes the branch visible in the
		// log, because a hook created through this path is protected by
		// something quite different from the one protecting a built-in.
		SpHookTraceLifecycle("dtor-custom", (const void *) m_ulAddr,
			(const void *) m_pCallingConvention,
			m_pCallingConvention->m_bHooked ? true : false,
			SpConvKindName(m_eCallingConvention));
	}

	m_pCallingConvention = NULL;
}

bool CFunction::IsCallable()
{
	return (m_eCallingConvention != CONV_CUSTOM) && (m_iCallingConvention != -1);
}

bool CFunction::IsHookable()
{
	return m_pCallingConvention != NULL;
}

bool CFunction::IsHooked()
{
	return GetHookManager()->FindHook((void *) m_ulAddr) != NULL;
}

CFunction* CFunction::GetTrampoline()
{
	CHook* pHook = GetHookManager()->FindHook((void *) m_ulAddr);
	if (!pHook)
		BOOST_RAISE_EXCEPTION(PyExc_ValueError, "Function was not hooked.")

	return new CFunction((Addr_t) pHook->m_pTrampoline, m_eCallingConvention,
		m_iCallingConvention, m_tArgs, m_eReturnType, m_oConverter);
}

template<class ReturnType, class Function>
ReturnType CallHelper(Function func, DCCallVM* vm, Addr_t addr)
{
	ReturnType result;
	TRY_SEGV()
		result = (ReturnType) func(vm, addr);
	EXCEPT_SEGV()
	return result;
}

void CallHelperVoid(DCCallVM* vm, Addr_t addr)
{
	TRY_SEGV()
		dcCallVoid(vm, addr);
	EXCEPT_SEGV()
}

object CFunction::Call(PyObject *args, PyObject *kw)
{
	if (!IsCallable())
		BOOST_RAISE_EXCEPTION(PyExc_ValueError, "Function is not callable.")

	Validate();
	if (PyTuple_GET_SIZE(args) - 1 != len(m_tArgs))
		BOOST_RAISE_EXCEPTION(PyExc_ValueError, "Number of passed arguments is not equal to the required number.")

	// Reset VM and set the calling convention
	dcReset(g_pCallVM);
	dcMode(g_pCallVM, m_iCallingConvention);

	// Fires once, before any argument is pushed. See SP_CALL_TRACE above for
	// what this is looking for.
	SpCallTrace(g_pCallVM, m_ulAddr, (int) len(m_tArgs));

	// Loop through all passed arguments and add them to the VM
	for(int i=1; i < PyTuple_GET_SIZE(args); i++)
	{
		PyObject *arg = PyTuple_GET_ITEM(args, i);
		switch(extract<DataType_t>(m_tArgs[i - 1]))
		{
			case DATA_TYPE_BOOL:		dcArgBool(g_pCallVM, extract<bool>(arg)); break;
			case DATA_TYPE_CHAR:		dcArgChar(g_pCallVM, extract<char>(arg)); break;
			case DATA_TYPE_UCHAR:		dcArgChar(g_pCallVM, extract<unsigned char>(arg)); break;
			case DATA_TYPE_SHORT:		dcArgShort(g_pCallVM, extract<short>(arg)); break;
			case DATA_TYPE_USHORT:		dcArgShort(g_pCallVM, extract<unsigned short>(arg)); break;
			case DATA_TYPE_INT:			dcArgInt(g_pCallVM, extract<int>(arg)); break;
			case DATA_TYPE_UINT:		dcArgInt(g_pCallVM, extract<unsigned int>(arg)); break;
			case DATA_TYPE_LONG:		dcArgLong(g_pCallVM, extract<long>(arg)); break;
			case DATA_TYPE_ULONG:		dcArgLong(g_pCallVM, extract<unsigned long>(arg)); break;
			case DATA_TYPE_LONG_LONG:	dcArgLongLong(g_pCallVM, extract<long long>(arg)); break;
			case DATA_TYPE_ULONG_LONG:	dcArgLongLong(g_pCallVM, extract<unsigned long long>(arg)); break;
			case DATA_TYPE_FLOAT:		dcArgFloat(g_pCallVM, extract<float>(arg)); break;
			case DATA_TYPE_DOUBLE:		dcArgDouble(g_pCallVM, extract<double>(arg)); break;
			case DATA_TYPE_POINTER:
			{
				Addr_t ulAddr = 0;
				if (arg != Py_None)
					ulAddr = ExtractAddress(object(handle<>(borrowed(arg))));

				dcArgPointer(g_pCallVM, ulAddr);
				break;
			}
			case DATA_TYPE_STRING:		dcArgPointer(g_pCallVM, (Addr_t) (void *) extract<char *>(arg)); break;
			default:					BOOST_RAISE_EXCEPTION(PyExc_ValueError, "Unknown argument type.")
		}
	}

	// Call the function
	switch(m_eReturnType)
	{
		case DATA_TYPE_VOID:		CallHelperVoid(g_pCallVM, m_ulAddr); break;
		case DATA_TYPE_BOOL:		return object(CallHelper<bool>(dcCallBool, g_pCallVM, m_ulAddr));
		case DATA_TYPE_CHAR:		return object(CallHelper<char>(dcCallChar, g_pCallVM, m_ulAddr));
		case DATA_TYPE_UCHAR:		return object(CallHelper<unsigned char>(dcCallChar, g_pCallVM, m_ulAddr));
		case DATA_TYPE_SHORT:		return object(CallHelper<short>(dcCallShort, g_pCallVM, m_ulAddr));
		case DATA_TYPE_USHORT:		return object(CallHelper<unsigned short>(dcCallShort, g_pCallVM, m_ulAddr));
		case DATA_TYPE_INT:			return object(CallHelper<int>(dcCallInt, g_pCallVM, m_ulAddr));
		case DATA_TYPE_UINT:		return object(CallHelper<unsigned int>(dcCallInt, g_pCallVM, m_ulAddr));
		case DATA_TYPE_LONG:		return object(CallHelper<long>(dcCallLong, g_pCallVM, m_ulAddr));
		case DATA_TYPE_ULONG:		return object(CallHelper<unsigned long>(dcCallLong, g_pCallVM, m_ulAddr));
		case DATA_TYPE_LONG_LONG:	return object(CallHelper<long long>(dcCallLongLong, g_pCallVM, m_ulAddr));
		case DATA_TYPE_ULONG_LONG:	return object(CallHelper<unsigned long long>(dcCallLongLong, g_pCallVM, m_ulAddr));
		case DATA_TYPE_FLOAT:		return object(CallHelper<float>(dcCallFloat, g_pCallVM, m_ulAddr));
		case DATA_TYPE_DOUBLE:		return object(CallHelper<double>(dcCallDouble, g_pCallVM, m_ulAddr));
		case DATA_TYPE_POINTER:
		{
			CPointer pPtr = CPointer(CallHelper<Addr_t>(dcCallPointer, g_pCallVM, m_ulAddr));
			if (!m_oConverter.is_none())
				return m_oConverter(pPtr);

			return object(pPtr);
		}
		case DATA_TYPE_STRING:		return object(CallHelper<const char *>(dcCallPointer, g_pCallVM, m_ulAddr));
		default:					BOOST_RAISE_EXCEPTION(PyExc_TypeError, "Unknown return type.")
	}
	return object();
}

object CFunction::CallTrampoline(PyObject *args, PyObject *kw)
{
	CHook* pHook = GetHookManager()->FindHook((void *) m_ulAddr);
	if (!pHook)
		BOOST_RAISE_EXCEPTION(PyExc_ValueError, "Function was not hooked.")

	return CFunction((Addr_t) pHook->m_pTrampoline, m_eCallingConvention,
		m_iCallingConvention, m_tArgs, m_eReturnType, m_oConverter).Call(args, kw);
}

object CFunction::SkipHooks(PyObject *args, PyObject *kw)
{
	CHook* pHook = GetHookManager()->FindHook((void *) m_ulAddr);
	if (pHook)
		return CFunction((Addr_t) pHook->m_pTrampoline, m_eCallingConvention,
			m_iCallingConvention, m_tArgs, m_eReturnType, m_oConverter).Call(args, kw);

	return Call(args, kw);
}

CHook* HookFunctionHelper(void* addr, ICallingConvention* pConv, Convention_t eConv)
{
	CHook* result;
	TRY_SEGV()
		result = GetHookManager()->HookFunction(addr, pConv);
	EXCEPT_SEGV()

	// Ownership hand-off, recorded explicitly.
	//
	// This is belt and braces, not the fix for anything. DynamicHooks already
	// does it: hook_x64.cpp ends its bridge setup with
	//
	//   m_bTargetPatched = true;
	//   m_pCallingConvention->m_bHooked = true;
	//
	// so by the time HookFunction returns, the convention is already flagged.
	// An earlier revision of this file carried a long comment claiming the flag
	// was never set anywhere, and a matching "fix" here. Both were wrong: the
	// claim was based on searching SP's tree, and src/thirdparty/DynamicHooks
	// ships headers and prebuilt libraries with no .cpp in it, so the assignment
	// that mattered was in the implementation compiled into DynamicHooks.lib and
	// was never in the repository to be found. Setting the flag here changed
	// nothing observable, which is what the evidence then said.
	//
	// The flag is still set, because it costs one store and it makes the
	// hand-off visible at this call site rather than depending on a library's
	// internals. It is not presented as fixing the crash at
	// core.dll+0x48DFD2, because it does not.
	//
	// Set only on success: if HookFunction fails, the convention must stay owned
	// by the CFunction so that its destructor frees it as it did before.
	if (result && pConv)
		pConv->m_bHooked = true;

	// Correlate this hand-off with the dtor line that follows it. If the log
	// ever shows the same address as both "handoff" and "dtor-DELETE", the
	// protocol above is not working and the hook is holding freed memory.
	SpHookTraceLifecycle(result ? "handoff" : "handoff-FAILED", addr, pConv,
		(result && pConv) ? pConv->m_bHooked : false, SpConvKindName(eConv));

	return result;
}

void CFunction::AddHook(HookType_t eType, PyObject* pCallable)
{
	if (!IsHookable())
		BOOST_RAISE_EXCEPTION(PyExc_ValueError, "Function is not hookable.")

	Validate();
	CHook* pHook = GetHookManager()->FindHook((void *) m_ulAddr);

	// Prepare arguments for log message
	str type = str(eType);
	const char* szType = extract<const char*>(type);

	str convention = str(m_eCallingConvention);
	const char* szConvention = extract<const char*>(convention);

	str args = str(m_tArgs);
	const char* szArgs = extract<const char*>(args);

	str return_type = str(m_eReturnType);
	const char* szReturnType = extract<const char*>(return_type);

	object oCallback = object(handle<>(borrowed(pCallable)));
	str callback = str(oCallback);
	const char* szCallback = extract<const char*>(callback);

	PythonLog(
		4,
		"Hooking function: type=%s, addr=%u, conv=%s, args=%s, rtype=%s, callback=%s",
		szType,
		m_ulAddr,
		szConvention,
		szArgs,
		szReturnType,
		szCallback
	);

	if (!pHook) {
		pHook = HookFunctionHelper((void *) m_ulAddr, m_pCallingConvention,
			m_eCallingConvention);

		// Reserve a Python reference for DynamicHooks.
		if (m_eCallingConvention == CONV_CUSTOM)
			Py_INCREF(m_oCallingConvention.ptr());
	}

	// Add the hook handler. If it's already added, it won't be added twice
	pHook->AddCallback(eType, (HookHandlerFn *) (void *) &SP_HookHandler);
	g_mapCallbacks[pHook][eType].push_back(object(handle<>(borrowed(pCallable))));
}

bool CFunction::AddHook(HookType_t eType, HookHandlerFn* pFunc)
{
	if (!IsHookable())
		return false;

	CHook* pHook = GetHookManager()->FindHook((void*) m_ulAddr);

	if (!pHook) {
		pHook = GetHookManager()->HookFunction((void*) m_ulAddr, m_pCallingConvention);

		if (!pHook)
			return false;

		// Ownership hand-off; see HookFunctionHelper for why the flag has to be
		// set here and why nothing used to set it.
		if (m_pCallingConvention)
			m_pCallingConvention->m_bHooked = true;

		SpHookTraceLifecycle("handoff-HF", (const void *) m_ulAddr,
			(const void *) m_pCallingConvention,
			m_pCallingConvention ? m_pCallingConvention->m_bHooked : false,
			SpConvKindName(m_eCallingConvention));

		// Watch CHook+0x18 from here on, on this thread, before returning to the
		// caller that is about to dispatch.
		//
		// Arming has to happen exactly here and not from the sampling poll: the
		// hook created above is the one the server dies on, and it dies within
		// milliseconds. A watchpoint installed by a 40 ms poll arrives after the
		// crash - two earlier rounds did exactly that and both produced a
		// confident, meaningless "no write occurred".
		SpHookTraceArmHookNow(pHook);

		// Reserve a Python reference for DynamicHooks.
		if (m_eCallingConvention == CONV_CUSTOM)
			Py_INCREF(m_oCallingConvention.ptr());
	}

	pHook->AddCallback(eType, pFunc);
	return true;
}

void CFunction::RemoveHook(HookType_t eType, PyObject* pCallable)
{
	Validate();
	CHook* pHook = GetHookManager()->FindHook((void *) m_ulAddr);
	if (!pHook)
		return;

	g_mapCallbacks[pHook][eType].remove(object(handle<>(borrowed(pCallable))));
}

void CFunction::DeleteHook()
{
	CHook* pHook = GetHookManager()->FindHook((void *) m_ulAddr);
	if (!pHook)
		return;

	g_mapCallbacks.erase(pHook);

	// Recorded before the pointer is NULLed below, because after that there is
	// nothing left to record. The delete in the else branch below is the other
	// place a convention this tracer knows about can be freed, so a log that
	// shows an address here after a "handoff" line is explaining a hook that
	// used it.
	SpHookTraceLifecycle("deletehook", (const void *) m_ulAddr,
		(const void *) pHook->m_pCallingConvention,
		pHook->m_pCallingConvention ? pHook->m_pCallingConvention->m_bHooked : false,
		SpConvKindName(m_eCallingConvention));

	ICallingConventionWrapper *pConv = dynamic_cast<ICallingConventionWrapper *>(pHook->m_pCallingConvention);
	if (pConv)
	{
		if (pConv->m_bHooked)
		{
			// Flag the convention as no longer hooked and being taken care of by DynamicHooks.
			pHook->m_pCallingConvention->m_bHooked = false;

			// Release the Python reference we reserved for DynamicHooks.
			PyObject *pOwner = detail::wrapper_base_::owner(pConv);
			if (pOwner && Py_REFCNT(pOwner))
				Py_DECREF(pOwner);
		}
	}
	else
	{
		// If we are using a built-in convention that is currently hooked, let's flag it as no longer hooked
		// so that we know we are not bound to a CHook anymore and can be deleted.
		if (pHook->m_pCallingConvention->m_bHooked)
			pHook->m_pCallingConvention->m_bHooked = false;
		// If we are a built-in convention bound to a CHook instance but not flagged as hooked anymore, then that
		// means we are no longer bound to a CFunction instance and can be safely deleted.
		else
			delete pHook->m_pCallingConvention;
	}

	// Set the calling convention to NULL, because DynamicHooks will delete it otherwise.
	pHook->m_pCallingConvention = NULL;
	GetHookManager()->UnhookFunction((void *) m_ulAddr);
}

/**
* =============================================================================
* DynamicHooks
* Linux System V AMD64 hook backend.
* =============================================================================
*/

#if defined(DYNAMICHOOKS_X86_64)

#include "hook.h"
#include "utilities.h"
#include "thirdparty/HDE64/hde64.h"

#include "x86.h"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <vector>

// -----------------------------------------------------------------------------
// Operating system layer.
//
// The rest of this file is architecture code and is the same on every OS: the
// HDE64 decode, the instruction relocation, the AsmJit-generated bridge and the
// absolute jump all work as written. Only four primitives differ, and they are
// the whole of the OS-specific surface:
//
//   PageSize()                  sysconf(_SC_PAGESIZE)     vs GetSystemInfo
//   Protect()                   mprotect                  vs VirtualProtect
//   FlushInstructions()         clear-cache builtin       vs FlushInstructionCache
//   AllocateExecutable[Near]()  mmap MAP_ANONYMOUS /
//                               MAP_FIXED_NOREPLACE      vs VirtualAlloc
//   ReleaseExecutable()         munmap                    vs VirtualFree
//
// AllocateExecutableNear has no direct counterpart; see the comment on it.
// -----------------------------------------------------------------------------
#ifdef _WIN32
#include <windows.h>

// PROT_READ / PROT_WRITE / PROT_EXEC are the Linux spelling, from
// <sys/mman.h>, and this file is compiled with that header only on the non-
// Windows side. Protect() below takes the protection as these bits and
// translates them to PAGE_EXECUTE_READ / PAGE_EXECUTE_READWRITE, which is what
// lets the Linux call sites read PROT_READ | PROT_WRITE | PROT_EXEC unchanged.
// Without these three the call sites themselves fail to compile on Windows, not
// just the function body.
//
// They are this file's private vocabulary: everything here is inside the
// anonymous namespace, so no Linux-flavoured macro escapes into a header, and
// the mprotect() branch still receives the same bits it always did.
#ifndef PROT_READ
#define PROT_READ   0x1
#endif
#ifndef PROT_WRITE
#define PROT_WRITE  0x2
#endif
#ifndef PROT_EXEC
#define PROT_EXEC   0x4
#endif
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

using namespace asmjit;
using namespace asmjit::x86;

namespace
{
	const size_t ABSOLUTE_JUMP_SIZE = 14;
	const size_t RELATIVE_JUMP_SIZE = 5;
	const size_t ENDBR64_SIZE = 4;
	const size_t MAX_PROLOGUE_SIZE = 32;

	// Microsoft x64 ABI: immediately before a "call", rsp must be 8 mod 16; the
	// "call" pushes the 8-byte return address so the callee enters at rsp 0 mod 16.
	// The caller must also leave 32 bytes (0x20) of shadow (home) space immediately
	// above the return address, into which an MSVC-compiled callee is free to spill
	// its four register arguments rcx/rdx/r8/r9. DispatchPre/DispatchPost do spill
	// them, so that 0x20 must be real, writable, and must not overlap the snapshot.
	//
	// Stack phase at the two call sites (this is the subtle part - getting it wrong
	// by 8 bytes crashes deterministically):
	//
	//  * The PRE bridge is reached by the inline detour, which is a "jmp" patched at
	//    the hooked function's first bytes. The function was entered by its caller's
	//    "call" (return address already pushed), and "jmp" pushes nothing, so the
	//    bridge's first instruction runs with rsp 0 mod 16 - the ordinary AFTER-call
	//    phase - with [rsp] holding the original return address. After
	//    "sub rsp, frameSize" (frameSize is 8 mod 16) rsp is 8 mod 16, which is
	//    ALREADY the phase required right before a "call".
	//
	//  * The POST bridge is reached by the original function's "ret", which has just
	//    popped the (rewritten) return address; it runs with rsp 8 mod 16, the phase
	//    of ordinary code in a caller. "sub rsp, frameSize" (frameSize is 0 mod 16)
	//    leaves rsp 8 mod 16 - again already the pre-"call" phase.
	//
	// Therefore the padding must be a multiple of 16 so it does NOT flip the phase:
	// exactly 0x20 (the shadow space). The "call" then pushes the return address into
	// the 8 bytes below that shadow and the callee enters aligned at rsp 0 mod 16.
	//
	// Two wrong values and how they crashed:
	//   - No padding: the phase happened to be right, but there was no shadow space,
	//     so the callee's home stores overwrote the first snapshot slots
	//     (rax/rbx/rcx/rdx): snapshot.rax got "this", snapshot.rcx got &snapshot.rsp,
	//     the hooked "this"/arguments read back as stack addresses and the restored
	//     frame jumped into the stack (DEP, rip == a stack address) - the original
	//     PlayerRunCommand crash.
	//   - 0x28 (shadow plus an extra 8 bytes): shadow was present, fixing the DEP
	//     crash, but the extra 8 flipped rsp to 0 mod 16 before the "call", so the
	//     callee entered misaligned by 8. MSVC then faulted on an aligned "movaps"
	//     to a stack slot deep in the callee (observed in fopen's _wsopen_nolock,
	//     STATUS_DATATYPE_MISALIGNMENT / access 0xFFFFFFFFFFFFFFFF).
	// 0x20 is the only value that provides the shadow AND preserves the phase.
	const size_t MSWIN64_CALL_PADDING = 0x20;

	struct alignas(16) X64Snapshot
	{
		uint64_t rax;
		uint64_t rbx;
		uint64_t rcx;
		uint64_t rdx;
		uint64_t rsi;
		uint64_t rdi;
		uint64_t rbp;
		uint64_t rsp;
		uint64_t r8;
		uint64_t r9;
		uint64_t r10;
		uint64_t r11;
		uint64_t r12;
		uint64_t r13;
		uint64_t r14;
		uint64_t r15;
		uint64_t rflags;
		uint64_t dispatchReturn;
		unsigned char xmm[16][16];
	};

	static_assert(sizeof(X64Snapshot) % 16 == 0,
		"The post-hook snapshot must preserve stack alignment.");

	struct X64Invocation
	{
		X64Invocation(CHook* pOwner, ICallingConvention* pConvention)
			: pHook(pOwner),
			  pPre(new CRegisters(pConvention->GetRegisters())),
			  pPost(new CRegisters(pConvention->GetRegisters())),
			  pReturnAddress(NULL)
		{
		}

		CHook* pHook;
		std::unique_ptr<CRegisters> pPre;
		std::unique_ptr<CRegisters> pPost;
		void* pReturnAddress;
	};

// The per-thread invocation state.
//
// The porting checklist suggests replacing __thread with __declspec(thread).
// That does not work here: MSVC forbids __declspec(thread) on a variable that
// has a dynamic initializer or a destructor, and the first of these three is a
// std::vector, which has both. C++ thread_local does support
// non-trivially-destructible types under MSVC, including inside a DLL, so it is
// kept. The other two would be acceptable either way, but splitting three
// related variables across two mechanisms would buy nothing.
	thread_local std::vector<std::unique_ptr<X64Invocation> > s_Invocations;
	thread_local X64Invocation* s_pCurrentInvocation = NULL;
	thread_local bool s_bUsePreRegisters = true;

	size_t PageSize()
	{
#ifdef _WIN32
		// GetSystemInfo is the documented way to get the page size. It is fixed
		// for the life of the process, so caching it in a function-local static
		// is correct on both platforms and keeps the call out of the hot path.
		static const size_t pageSize = []() {
			SYSTEM_INFO si;
			GetSystemInfo(&si);
			return static_cast<size_t>(si.dwPageSize);
		}();
#else
		static const size_t pageSize = static_cast<size_t>(sysconf(_SC_PAGESIZE));
#endif
		return pageSize;
	}

	uintptr_t PageAlign(uintptr_t address)
	{
		return address & ~(static_cast<uintptr_t>(PageSize()) - 1);
	}

	void Protect(void* pAddress, size_t size, int protection)
	{
		uintptr_t first = PageAlign(reinterpret_cast<uintptr_t>(pAddress));
		uintptr_t last = PageAlign(
			reinterpret_cast<uintptr_t>(pAddress) + size - 1);
#ifdef _WIN32
		// This is called with PROT_* bits, which is the Linux spelling, so the
		// protection is translated rather than passed through.
		//
		// The game's .text is normally PAGE_EXECUTE_READ, so writing to it
		// without this call is an access violation; the porting checklist calls
		// that the single most common first crash on Windows.
		DWORD dwOldProtect = 0;
		DWORD dwNewProtect = (protection & PROT_WRITE) ? PAGE_EXECUTE_READWRITE
			: PAGE_EXECUTE_READ;
		if (!VirtualProtect(reinterpret_cast<void*>(first),
			static_cast<SIZE_T>(last - first + PageSize()),
			dwNewProtect, &dwOldProtect))
		{
			throw std::runtime_error("Unable to change hook page protection.");
		}
#else
		if (mprotect(reinterpret_cast<void*>(first), last - first + PageSize(),
			protection) != 0)
		{
			throw std::runtime_error("Unable to change hook page protection.");
		}
#endif
	}

	void FlushInstructions(void* pAddress, size_t size)
	{
#ifdef _WIN32
		// Required on Windows. Without it the CPU can keep executing bytes that
		// were written after the instruction stream was cached, which shows up as
		// a hook that appears to install and then still runs the original code.
		if (!FlushInstructionCache(GetCurrentProcess(), pAddress,
			static_cast<SIZE_T>(size)))
		{
			throw std::runtime_error("Unable to flush the instruction cache.");
		}
#else
		char* pBegin = static_cast<char*>(pAddress);
		__builtin___clear_cache(pBegin, pBegin + size);
#endif
	}

	void WriteAbsoluteJump(unsigned char* pSource, const void* pDestination)
	{
		pSource[0] = 0xff;
		pSource[1] = 0x25;
		std::memset(pSource + 2, 0, 4);
		std::memcpy(pSource + 6, &pDestination, sizeof(pDestination));
	}

	void WriteEndbr64(unsigned char* pDestination)
	{
		static const unsigned char instruction[ENDBR64_SIZE] = {
			0xf3, 0x0f, 0x1e, 0xfa
		};
		std::memcpy(pDestination, instruction, sizeof(instruction));
	}

	bool FitsRelativeJump(const void* pSource, const void* pDestination)
	{
		intptr_t displacement = reinterpret_cast<const unsigned char*>(pDestination)
			- (reinterpret_cast<const unsigned char*>(pSource) + RELATIVE_JUMP_SIZE);
		return displacement >= INT32_MIN && displacement <= INT32_MAX;
	}

	void WriteRelativeJump(unsigned char* pSource, const void* pDestination)
	{
		intptr_t distance = reinterpret_cast<const unsigned char*>(pDestination)
			- (pSource + RELATIVE_JUMP_SIZE);
		if (distance < INT32_MIN || distance > INT32_MAX)
			throw std::runtime_error("Unable to encode a relative hook jump.");
		int32_t displacement = static_cast<int32_t>(distance);
		pSource[0] = 0xe9;
		std::memcpy(pSource + 1, &displacement, sizeof(displacement));
	}

	void* AllocateExecutable(size_t size)
	{
#ifdef _WIN32
		// MEM_COMMIT implies MEM_RESERVE, but both are named for symmetry with
		// the Linux call and with the relay path below.
		//
		// For a future reader: Windows 11 can refuse to make freshly allocated
		// memory executable and require a Dynamic Code opt-in through
		// SetProcessDynamicCodePolicy. It has not been needed here, but if a
		// machine refuses to run code written into allocated memory, that policy
		// is the first thing to check - the symptom is an access violation on the
		// first jump into the relay, not a failure to allocate.
		void* pMemory = VirtualAlloc(NULL, static_cast<SIZE_T>(size),
			MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!pMemory)
			throw std::bad_alloc();
		FlushInstructions(pMemory, size);
		return pMemory;
#else
		void* pMemory = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (pMemory == MAP_FAILED)
			throw std::bad_alloc();
		return pMemory;
#endif
	}

// The counterpart of AllocateExecutable and AllocateExecutableNear.
	void ReleaseExecutable(void* pMemory)
	{
		if (!pMemory)
			return;
#ifdef _WIN32
		// MEM_RELEASE takes the base address that was returned and a size of zero.
		VirtualFree(pMemory, 0, MEM_RELEASE);
#else
		// The size is not carried alongside the pointer, so the whole remaining
		// mapping is released. Both callers hold dedicated single-purpose blocks.
		munmap(pMemory, 0);
#endif
	}

	void* AllocateExecutableNear(void* pTarget, size_t size)
	{
#if defined(_WIN32) || defined(MAP_FIXED_NOREPLACE)
		const uintptr_t target = PageAlign(reinterpret_cast<uintptr_t>(pTarget));
		const uintptr_t step = PageSize() * 16;
		const uintptr_t limit = static_cast<uintptr_t>(INT32_MAX);

		for (uintptr_t distance = step; distance < limit; distance += step)
		{
			uintptr_t candidates[2] = {
				target >= distance ? target - distance : 0,
				target <= UINTPTR_MAX - distance ? target + distance : 0
			};
			for (size_t index = 0; index < 2; ++index)
			{
				if (!candidates[index])
					continue;
#ifdef _WIN32
				void* pMemory = VirtualAlloc(
					reinterpret_cast<void*>(candidates[index]), size,
					MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				if (!pMemory)
					continue;
				// The reservation may have landed somewhere other than where it was
				// asked for; only an exact match is usable, and anything else is
				// released before the next candidate is tried.
				if (reinterpret_cast<uintptr_t>(pMemory) == candidates[index]
					&& FitsRelativeJump(pTarget, pMemory))
				{
					return pMemory;
				}
				VirtualFree(pMemory, 0, MEM_RELEASE);
#else
				void* pMemory = mmap(
					reinterpret_cast<void*>(candidates[index]), size,
					PROT_READ | PROT_WRITE | PROT_EXEC,
					MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
				if (pMemory != MAP_FAILED && FitsRelativeJump(pTarget, pMemory))
					return pMemory;
				if (pMemory != MAP_FAILED)
					munmap(pMemory, size);
#endif
			}
		}
#endif
		throw std::runtime_error(
			"Unable to allocate an executable relay within relative-jump range.");
	}

	void SaveSnapshot(Assembler& a, int originalStackOffset)
	{
#define SAVE_GPR(name) a.mov(ptr(rsp, offsetof(X64Snapshot, name)), name)
		SAVE_GPR(rax); SAVE_GPR(rbx); SAVE_GPR(rcx); SAVE_GPR(rdx);
		SAVE_GPR(rsi); SAVE_GPR(rdi); SAVE_GPR(rbp);
		SAVE_GPR(r8); SAVE_GPR(r9); SAVE_GPR(r10); SAVE_GPR(r11);
		SAVE_GPR(r12); SAVE_GPR(r13); SAVE_GPR(r14); SAVE_GPR(r15);
#undef SAVE_GPR
		a.lea(r10, ptr(rsp, originalStackOffset));
		a.mov(ptr(rsp, offsetof(X64Snapshot, rsp)), r10);
		a.pushfq();
		a.pop(rax);
		a.mov(ptr(rsp, offsetof(X64Snapshot, rflags)), rax);

		const Xmm registers[] = {
			xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7,
			xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15
		};
		for (size_t index = 0; index < 16; ++index)
			a.movdqu(ptr(rsp, offsetof(X64Snapshot, xmm) + index * 16),
				registers[index]);
	}

	void RestoreSnapshot(Assembler& a)
	{
		const Xmm registers[] = {
			xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7,
			xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15
		};
		for (size_t index = 0; index < 16; ++index)
			a.movdqu(registers[index],
				ptr(rsp, offsetof(X64Snapshot, xmm) + index * 16));

#define RESTORE_GPR(name) a.mov(name, ptr(rsp, offsetof(X64Snapshot, name)))
		RESTORE_GPR(rbx); RESTORE_GPR(rcx); RESTORE_GPR(rdx);
		RESTORE_GPR(rsi); RESTORE_GPR(rdi); RESTORE_GPR(rbp);
		RESTORE_GPR(r8); RESTORE_GPR(r9); RESTORE_GPR(r10);
		RESTORE_GPR(r11); RESTORE_GPR(r12); RESTORE_GPR(r13);
		RESTORE_GPR(r14); RESTORE_GPR(r15);
		a.mov(rax, ptr(rsp, offsetof(X64Snapshot, rflags)));
		a.push(rax);
		a.popfq();
		RESTORE_GPR(rax);
#undef RESTORE_GPR
	}

	CRegister* RegisterFor(CRegisters* pRegisters, Register_t reg)
	{
		switch (reg)
		{
			case RAX: return pRegisters->m_rax;
			case RBX: return pRegisters->m_rbx;
			case RCX: return pRegisters->m_rcx;
			case RDX: return pRegisters->m_rdx;
			case RSI: return pRegisters->m_rsi;
			case RDI: return pRegisters->m_rdi;
			case RBP: return pRegisters->m_rbp;
			case RSP: return pRegisters->m_rsp;
			case R8: return pRegisters->m_r8;
			case R9: return pRegisters->m_r9;
			case R10: return pRegisters->m_r10;
			case R11: return pRegisters->m_r11;
			case R12: return pRegisters->m_r12;
			case R13: return pRegisters->m_r13;
			case R14: return pRegisters->m_r14;
			case R15: return pRegisters->m_r15;
			case XMM0: return pRegisters->m_xmm0;
			case XMM1: return pRegisters->m_xmm1;
			case XMM2: return pRegisters->m_xmm2;
			case XMM3: return pRegisters->m_xmm3;
			case XMM4: return pRegisters->m_xmm4;
			case XMM5: return pRegisters->m_xmm5;
			case XMM6: return pRegisters->m_xmm6;
			case XMM7: return pRegisters->m_xmm7;
			case XMM8: return pRegisters->m_xmm8;
			case XMM9: return pRegisters->m_xmm9;
			case XMM10: return pRegisters->m_xmm10;
			case XMM11: return pRegisters->m_xmm11;
			case XMM12: return pRegisters->m_xmm12;
			case XMM13: return pRegisters->m_xmm13;
			case XMM14: return pRegisters->m_xmm14;
			case XMM15: return pRegisters->m_xmm15;
			default: return NULL;
		}
	}
}

CHook::CHook(void* pFunc, ICallingConvention* pConvention)
	: m_pFunc(pFunc),
	  m_pCallingConvention(pConvention),
	  m_pBridge(NULL),
	  m_pTrampoline(NULL),
	  m_pRegistersPre(NULL),
	  m_pRegistersPost(NULL),
	  m_pNewRetAddr(NULL),
	  m_bUsePreRegisters(true),
	  m_iCopiedBytes(0),
	  m_iPatchBytes(0),
	  m_iTrampolineSize(0),
	  m_pRelay(NULL),
	  m_iRelaySize(0),
	  m_bTargetPatched(false)
{
	if (!pFunc || !pConvention)
		throw std::invalid_argument("A hook requires a function and convention.");

	std::memset(m_CopiedBytes, 0, sizeof(m_CopiedBytes));
	unsigned char* pTarget = static_cast<unsigned char*>(pFunc);
	bool shortTerminal = false;
	// A short terminal function (ends in ret before 14 bytes were copied) whose
	// trailing int3/nop padding is large enough to host a full 14-byte absolute
	// jump is patched with that distance-independent form, so no +/-2GB relay is
	// needed. Only when the padding is too short do we fall back to the near
	// relay + 5-byte relative jump (which fails on high-base modules).
	bool shortAbsolute = false;

	while (m_iCopiedBytes < ABSOLUTE_JUMP_SIZE)
	{
		hde64s instruction;
		hde64_disasm(pTarget + m_iCopiedBytes, &instruction);
		if (!instruction.len || (instruction.flags & F_ERROR))
			throw std::invalid_argument("Unable to decode the target prologue.");
		if (instruction.flags & F_RELATIVE)
			throw std::invalid_argument(
				"Relative control flow in the target prologue is unsupported.");
		if ((instruction.flags & F_MODRM) && instruction.modrm_mod == 0 &&
			instruction.modrm_rm == 5 && !instruction.p_67)
		{
			throw std::invalid_argument(
				"RIP-relative addressing in the target prologue is unsupported.");
		}
		if (instruction.opcode == 0xc3)
		{
			// The function ends in a plain near "ret" before enough bytes were
			// collected for the 14-byte absolute detour. Tiny one-instruction
			// setters hit this on x64, e.g. CServerGameDLL::SetServerHibernation
			// is "88 51 10 C3" (mov [rcx+0x10],dl ; ret) - only 4 bytes, shorter
			// even than the 5-byte relative jump. Route it through the near-relay
			// path below: the trampoline reproduces the whole function including
			// this ret, so there is no jump back to patch.
			m_iCopiedBytes += instruction.len;
			shortTerminal = true;
			break;
		}
		if (instruction.opcode == 0xc2)
		{
			// ret imm16 is never emitted under the Microsoft x64 ABI (the caller
			// cleans the stack), and the relay path returns through one plain
			// ret. Refuse it rather than mis-relocate it. The message carries the
			// actual target and its bytes so a wrong vtable index is diagnosable
			// from the Python warning alone.
			char hex[160];
			int pos = 0;
			for (int z = 0; z < 24; ++z)
				pos += snprintf(hex + pos, sizeof(hex) - pos,
					"%02X ", static_cast<unsigned>(pTarget[z]));
			char msg[256];
			snprintf(msg, sizeof(msg),
				"Terminating control flow (ret imm16) before the detour boundary; "
				"pFunc=%p copied=%zu first24: %s",
				static_cast<void*>(pTarget), static_cast<size_t>(m_iCopiedBytes), hex);
			throw std::invalid_argument(msg);
		}
		m_iCopiedBytes += instruction.len;
		if (m_iCopiedBytes > MAX_PROLOGUE_SIZE)
			throw std::invalid_argument("The target prologue is too large.");
	}

	if (shortTerminal)
	{
		// Prefer the 14-byte absolute detour: it reaches a bridge placed anywhere
		// in the 64-bit address space and allocates its trampoline anywhere too,
		// so no executable memory is needed inside a +/-2GB relative-jump window.
		// The 5-byte relative form below needs exactly that, but on a high-base
		// module (server.dll loads around 0x7FFD...) the window is packed with
		// module images and VirtualAlloc cannot place a relay there. It is safe to
		// overwrite the inter-function padding (MSVC int3 / nop) because it is
		// never executed; only require enough of it to fit the absolute jump.
		bool enoughPadding = true;
		for (size_t i = m_iCopiedBytes; i < ABSOLUTE_JUMP_SIZE; ++i)
		{
			unsigned char pad = pTarget[i];
			if (pad != 0xCC && pad != 0x90)
			{
				enoughPadding = false;
				break;
			}
		}
		if (enoughPadding)
		{
			shortAbsolute = true;
			m_iPatchBytes = ABSOLUTE_JUMP_SIZE;
		}
		else
		{
			m_iPatchBytes = (m_iCopiedBytes >= RELATIVE_JUMP_SIZE)
				? m_iCopiedBytes : RELATIVE_JUMP_SIZE;
			if (m_iCopiedBytes < RELATIVE_JUMP_SIZE)
			{
				for (size_t i = m_iCopiedBytes; i < RELATIVE_JUMP_SIZE; ++i)
				{
					unsigned char pad = pTarget[i];
					if (pad != 0xCC && pad != 0x90)
						throw std::invalid_argument(
							"Function ends before the detour boundary and is not "
							"followed by relocatable padding.");
				}
			}
		}
	}
	else
	{
		m_iPatchBytes = m_iCopiedBytes;
	}

	// Save every byte the detour will overwrite - the function body and, in the
	// short case, the borrowed padding bytes - so the destructor restores all of
	// them byte-for-byte.
	std::memcpy(m_CopiedBytes, pTarget, m_iPatchBytes);

	if (shortTerminal && !shortAbsolute)
	{
		m_iRelaySize = PageSize();
		m_pRelay = AllocateExecutableNear(pFunc, m_iRelaySize);
		if (!m_pRelay)
			throw std::runtime_error(
				"Unable to allocate a near relay for the detour.");
		m_pTrampoline = static_cast<unsigned char*>(m_pRelay) + 32;
		m_iTrampolineSize = ENDBR64_SIZE + m_iCopiedBytes;
		WriteEndbr64(static_cast<unsigned char*>(m_pTrampoline));
		// Only the function body (ending in ret) is reproduced, never the
		// borrowed padding. The ret returns through the bridge, so no jump back
		// to the target is emitted.
		std::memcpy(static_cast<unsigned char*>(m_pTrampoline) + ENDBR64_SIZE,
			m_CopiedBytes, m_iCopiedBytes);
	}
	else if (shortTerminal)
	{
		// Distance-independent form: the trampoline lives in ordinary allocated
		// executable memory (any address), holding ENDBR64 followed by the whole
		// tiny function body that ends in ret. The body's ret returns through the
		// bridge, so there is no jump back to the target.
		m_iTrampolineSize = ENDBR64_SIZE + m_iCopiedBytes;
		m_pTrampoline = AllocateExecutable(m_iTrampolineSize);
		WriteEndbr64(static_cast<unsigned char*>(m_pTrampoline));
		std::memcpy(static_cast<unsigned char*>(m_pTrampoline) + ENDBR64_SIZE,
			m_CopiedBytes, m_iCopiedBytes);
	}
	else
	{
		m_iTrampolineSize = ENDBR64_SIZE + m_iCopiedBytes + ABSOLUTE_JUMP_SIZE;
		m_pTrampoline = AllocateExecutable(m_iTrampolineSize);
		WriteEndbr64(static_cast<unsigned char*>(m_pTrampoline));
		std::memcpy(static_cast<unsigned char*>(m_pTrampoline) + ENDBR64_SIZE,
			m_CopiedBytes, m_iCopiedBytes);
		WriteAbsoluteJump(static_cast<unsigned char*>(m_pTrampoline) +
			ENDBR64_SIZE + m_iCopiedBytes, pTarget + m_iCopiedBytes);
	}

	if (!CreatePostCallback() || !CreateBridge())
		throw std::runtime_error("Unable to create the AMD64 hook bridge.");

	Protect(pTarget, m_iPatchBytes, PROT_READ | PROT_WRITE | PROT_EXEC);
	if (shortTerminal && !shortAbsolute)
	{
		WriteAbsoluteJump(static_cast<unsigned char*>(m_pRelay), m_pBridge);
		// 5-byte E9; for a sub-5-byte function its tail lands on the borrowed
		// padding bytes that were validated above.
		WriteRelativeJump(pTarget, m_pRelay);
		// If the function body was longer than 5 bytes, the unreachable tail
		// between the jump and the ret is made into NOPs for cleanliness.
		if (m_iCopiedBytes > RELATIVE_JUMP_SIZE)
			std::fill(pTarget + RELATIVE_JUMP_SIZE,
				pTarget + m_iCopiedBytes, static_cast<unsigned char>(0x90));
	}
	else
	{
		// Normal prologue, or a tiny terminal function with enough padding:
		// write a straight 14-byte absolute jump to the bridge. Any bytes left
		// between the jump and the copied boundary are made into NOPs.
		WriteAbsoluteJump(pTarget, m_pBridge);
		std::fill(pTarget + ABSOLUTE_JUMP_SIZE,
			pTarget + m_iPatchBytes, static_cast<unsigned char>(0x90));
	}
	FlushInstructions(pTarget, m_iPatchBytes);
	Protect(pTarget, m_iPatchBytes, PROT_READ | PROT_EXEC);
	m_bTargetPatched = true;
	m_pCallingConvention->m_bHooked = true;
}

CHook::~CHook()
{
	if (m_bTargetPatched)
	{
		Protect(m_pFunc, m_iPatchBytes, PROT_READ | PROT_WRITE | PROT_EXEC);
		std::memcpy(m_pFunc, m_CopiedBytes, m_iPatchBytes);
		FlushInstructions(m_pFunc, m_iPatchBytes);
		Protect(m_pFunc, m_iPatchBytes, PROT_READ | PROT_EXEC);
	}
	if (m_pBridge)
		m_asmjit_rt.release(m_pBridge);
	if (m_pNewRetAddr)
		m_asmjit_rt.release(m_pNewRetAddr);
	if (m_pRelay)
		ReleaseExecutable(m_pRelay);
	else if (m_pTrampoline)
		ReleaseExecutable(m_pTrampoline);
	delete m_pCallingConvention;
}

void CHook::AddCallback(HookType_t type, HookHandlerFn* pCallback)
{
	if (pCallback && !IsCallbackRegistered(type, pCallback))
		m_hookHandler[type].push_back(pCallback);
}

void CHook::RemoveCallback(HookType_t type, HookHandlerFn* pCallback)
{
	if (IsCallbackRegistered(type, pCallback))
		m_hookHandler[type].remove(pCallback);
}

bool CHook::IsCallbackRegistered(HookType_t type, HookHandlerFn* pCallback)
{
	std::list<HookHandlerFn*>& callbacks = m_hookHandler[type];
	return std::find(callbacks.begin(), callbacks.end(), pCallback) !=
		callbacks.end();
}

CRegisters* CHook::GetRegisters()
{
	if (!s_pCurrentInvocation)
		return NULL;
	return s_bUsePreRegisters ? s_pCurrentInvocation->pPre.get() :
		s_pCurrentInvocation->pPost.get();
}

bool CHook::GetUsePreRegisters()
{
	return s_bUsePreRegisters;
}

void CHook::SetUsePreRegisters(bool value)
{
	s_bUsePreRegisters = value;
}

void* CHook::GetCurrentReturnAddress()
{
	return s_pCurrentInvocation ? s_pCurrentInvocation->pReturnAddress : NULL;
}

bool CHook::HookHandler(HookType_t type)
{
	s_bUsePreRegisters = type == HOOKTYPE_PRE;
	bool overrideResult = false;
	std::list<HookHandlerFn*> callbacks = m_hookHandler[type];
	for (std::list<HookHandlerFn*>::iterator it = callbacks.begin();
		it != callbacks.end(); ++it)
	{
		if (reinterpret_cast<HookHandlerFn>(*it)(type, this))
			overrideResult = true;
	}
	return overrideResult;
}

// Entered from the JIT bridge through "a.call(rax)". Nothing thrown in here may
// propagate back into the bridge: on Windows x64 the unwinder walks .pdata, a
// JIT-generated bridge has no unwind record, and the result is std::terminate or
// a hard fault rather than anything diagnosable. For Source.Python this is the
// normal path, not an exotic one, because the callback is a Python callback.
//
// Note what the handler does NOT do: it does not pop s_Invocations. The pairing
// is push here, pop in DispatchPost, and the post bridge still runs after this
// returns. Popping here would make the post handler pop an entry that is no
// longer on top, and every later hook on the thread would then be matched
// against the wrong hook - a failure that surfaces far from its cause.
bool CHook::DispatchPre(CHook* pHook, void* pSnapshot, void* pStack)
{
	X64Snapshot* pProbe = static_cast<X64Snapshot*>(pSnapshot);
	const uint64_t t0rax = pProbe->rax, t0rcx = pProbe->rcx;

	std::unique_ptr<X64Invocation> invocation(
		new X64Invocation(pHook, pHook->m_pCallingConvention));
	// The bridge sets pStack to the hooked function's return-address slot (rsp at
	// function entry), so *pStack is the caller's return address - a code address.
	// It must never be the stack pointer itself; the post bridge returns through
	// this value.
	invocation->pReturnAddress = *static_cast<void**>(pStack);

	const uint64_t t1rax = pProbe->rax, t1rcx = pProbe->rcx;

	X64Invocation* pPrevious = s_pCurrentInvocation;
	bool previousUsePre = s_bUsePreRegisters;
	s_Invocations.push_back(std::move(invocation));
	s_pCurrentInvocation = s_Invocations.back().get();

	const uint64_t t2rax = pProbe->rax, t2rcx = pProbe->rcx;

	pHook->SnapshotToRegisters(pSnapshot, s_pCurrentInvocation->pPre.get(), false);

	const uint64_t t3rax = pProbe->rax, t3rcx = pProbe->rcx;

	// TEMPORARY DIAGNOSTIC - remove before this is considered finished.
	//
	// Taken after s_pCurrentInvocation is installed, so GetRegisters() resolves
	// exactly the way Source.Python's callback will resolve it, which makes
	// arg0 below the very value PrePlayerRunCommand is about to dereference.
	// All three stages of the argument's journey are on one line, for one
	// dispatch, because any two of them taken from different dispatches look
	// identical to a corrupted snapshot:
	//   snap.rcx  - what SaveSnapshot's "mov [rsp+10h], rcx" stored,
	//   m_rcx_val - what SnapshotToRegisters copied into the register buffer,
	//   arg0      - what GetArgumentPtr actually selects for index 0.
	// snap.rcx == m_rcx_val but arg0 != m_rcx_val means the argument lookup is
	// choosing the wrong register; all three equal means the snapshot itself is
	// wrong, which the bridge disassembly already says it is not.
	{
		X64Snapshot* pSnap = static_cast<X64Snapshot*>(pSnapshot);
		// HookHandler(HOOKTYPE_PRE) sets this to true before invoking the
		// callback; set it here too so the printed arg0 is not read against a
		// register set left over from an enclosing post-hook.
		s_bUsePreRegisters = true;
		FILE* fp = fopen("D:\\Counter-Strike-Source\\cstrike\\logs\\source-python\\sp_snap.txt", "a");
		if (fp) {
			CRegisters* pPre = s_pCurrentInvocation->pPre.get();
			void* pArg0Ptr = pHook->m_pCallingConvention
				? pHook->m_pCallingConvention->GetArgumentPtr(0, pPre)
				: NULL;
			fprintf(fp,
				"SNAP hook=%p pSnap=%p pStack=%p *pStack=%p "
				"snap.rax=%p snap.rcx=%p snap.r8=%p snap.rsp=%p "
				"m_rcx_addr=%p m_rcx_val=%p m_r8_val=%p "
				"arg0_ptr=%p arg0=%p off_rsp=%zu sizeof=%zu\n",
				(void*)pHook, pSnapshot, pStack,
				pStack ? *(void**)pStack : NULL,
				(void*)(size_t)pSnap->rax, (void*)(size_t)pSnap->rcx,
				(void*)(size_t)pSnap->r8, (void*)(size_t)pSnap->rsp,
				(pPre && pPre->m_rcx) ? (void*)pPre->m_rcx->m_pAddress : NULL,
				(pPre && pPre->m_rcx) ? (void*)(size_t)pPre->m_rcx->GetValue<uint64_t>() : NULL,
				(pPre && pPre->m_r8) ? (void*)(size_t)pPre->m_r8->GetValue<uint64_t>() : NULL,
				pArg0Ptr,
				pArg0Ptr ? (void*)(size_t)*(unsigned long long*)pArg0Ptr : NULL,
				offsetof(X64Snapshot, rsp), sizeof(X64Snapshot));
			fprintf(fp,
				"   T0(entry) rax=%p rcx=%p | T1(after inv+retaddr) rax=%p rcx=%p | "
				"T2(after push) rax=%p rcx=%p | T3(after SnapshotToReg) rax=%p rcx=%p\n",
				(void*)(size_t)t0rax, (void*)(size_t)t0rcx,
				(void*)(size_t)t1rax, (void*)(size_t)t1rcx,
				(void*)(size_t)t2rax, (void*)(size_t)t2rcx,
				(void*)(size_t)t3rax, (void*)(size_t)t3rcx);
			// TEMPORARY DIAGNOSTIC - remove before this is considered finished.
			// Dump the bridge bytes that actually executed for THIS dispatch.
			// pSnapshot is the bridge's frame after `sub rsp, frameSize`, and the
			// `call DispatchPre` that got us here pushed its return address at
			// pSnapshot-8.  That address sits a fixed distance past the
			// SaveSnapshot stores, so walking back from it to endbr64 recovers the
			// exact instructions that ran - which a disassembly of some other
			// run's bridge cannot do.  (*pStack is not usable for this: it names
			// the hooked function's own return slot in server.dll, not the bridge.)
			if (pSnapshot) {
				void* pRet = *reinterpret_cast<void**>(
					static_cast<char*>(pSnapshot) - sizeof(void*));
				unsigned char* pBridge = NULL;
				// The scan walks backwards through JIT memory that may sit on a
				// page boundary, and a diagnostic that takes the process down
				// would look exactly like the bug it is meant to isolate.
				// Verify both ends of the range are committed before reading.
				auto readable = [](const void* pAddr) -> bool {
					MEMORY_BASIC_INFORMATION mbi;
					return pAddr && VirtualQuery(pAddr, &mbi, sizeof(mbi)) ==
							sizeof(mbi) && (mbi.State & MEM_COMMIT) &&
							!(mbi.Protect & PAGE_GUARD);
				};
				if (pRet) {
					unsigned char* p = static_cast<unsigned char*>(pRet);
					if (readable(p) && readable(p - 0x200)) {
						for (int i = 0; i < 0x200; ++i, --p) {
							if (p[0] == 0xF3 && p[1] == 0x0F &&
								p[2] == 0x1E && p[3] == 0xFA) {
								pBridge = p;
								break;
							}
						}
					}
				}
				fprintf(fp, "   RET=%p bridge=%p\n", pRet, (void*)pBridge);
				if (pBridge) {
					fprintf(fp, "   BYTES ");
					for (int i = 0; i < 0x140; ++i)
						fprintf(fp, "%02X", pBridge[i]);
					fprintf(fp, "\n");
				}
			}
			fclose(fp);
		}
	}

	bool overrideResult = false;
	try
	{
		overrideResult = pHook->HookHandler(HOOKTYPE_PRE);
		pHook->RegistersToSnapshot(s_pCurrentInvocation->pPre.get(), pSnapshot, false);
	}
	catch (...)
	{
		// Swallowed deliberately, for the reason above. The snapshot is not
		// written back, so the callee keeps its own register state and
		// overrideResult stays false, meaning "carry on into the original".
	}

	s_pCurrentInvocation = pPrevious;
	s_bUsePreRegisters = previousUsePre;
	return overrideResult;
}

// Entered from the post bridge through "a.call(rax)", under the same
// no-exception-crosses-the-bridge rule as DispatchPre.
//
// pReturnAddress is read before the try rather than after the work, because
// pInvocation points into s_Invocations and the pop below invalidates it. In
// the original ordering that read was safe only because nothing between it and
// the pop could throw; now that the work is inside a try, hoisting it is what
// keeps it safe.
void* CHook::DispatchPost(CHook* pHook, void* pSnapshot, void* pStack)
{
	(void) pStack;
	if (s_Invocations.empty() || s_Invocations.back()->pHook != pHook)
		return NULL;

	X64Invocation* pPrevious = s_pCurrentInvocation;
	bool previousUsePre = s_bUsePreRegisters;
	X64Invocation* pInvocation = s_Invocations.back().get();
	void* pReturnAddress = pInvocation->pReturnAddress;
	try
	{
		pHook->CopyRegisters(pInvocation->pPre.get(), pInvocation->pPost.get());
		pHook->SnapshotToRegisters(pSnapshot, pInvocation->pPost.get(), true);
		s_pCurrentInvocation = pInvocation;
		pHook->HookHandler(HOOKTYPE_POST);
		pHook->RegistersToSnapshot(pInvocation->pPost.get(), pSnapshot, true);
	}
	catch (...)
	{
		// Swallowed, same reason as in DispatchPre. The snapshot is not written
		// back, so the return value the caller sees is the original one.
	}

	// Unconditional, and this is the pop that pairs with DispatchPre's push.
	s_Invocations.pop_back();
	s_pCurrentInvocation = pPrevious;
	s_bUsePreRegisters = previousUsePre;
	return pReturnAddress;
}

void CHook::SnapshotToRegisters(
	void* pRawSnapshot, CRegisters* pRegisters, bool bPost)
{
	X64Snapshot* pSnapshot = static_cast<X64Snapshot*>(pRawSnapshot);
#define SNAPSHOT_GPR(reg, field) \
	do { if (pRegisters->reg) pRegisters->reg->SetValue<uint64_t>(pSnapshot->field); } while (0)
	SNAPSHOT_GPR(m_rax, rax); SNAPSHOT_GPR(m_rbx, rbx);
	SNAPSHOT_GPR(m_rcx, rcx); SNAPSHOT_GPR(m_rdx, rdx);
	SNAPSHOT_GPR(m_rsi, rsi); SNAPSHOT_GPR(m_rdi, rdi);
	SNAPSHOT_GPR(m_rbp, rbp); SNAPSHOT_GPR(m_r8, r8);
	SNAPSHOT_GPR(m_r9, r9); SNAPSHOT_GPR(m_r10, r10);
	SNAPSHOT_GPR(m_r11, r11); SNAPSHOT_GPR(m_r12, r12);
	SNAPSHOT_GPR(m_r13, r13); SNAPSHOT_GPR(m_r14, r14);
	SNAPSHOT_GPR(m_r15, r15);
#undef SNAPSHOT_GPR
	if (pRegisters->m_rsp && !bPost)
		pRegisters->m_rsp->SetValue<uint64_t>(pSnapshot->rsp);

	CRegister* xmmRegisters[] = {
		pRegisters->m_xmm0, pRegisters->m_xmm1,
		pRegisters->m_xmm2, pRegisters->m_xmm3,
		pRegisters->m_xmm4, pRegisters->m_xmm5,
		pRegisters->m_xmm6, pRegisters->m_xmm7,
		pRegisters->m_xmm8, pRegisters->m_xmm9,
		pRegisters->m_xmm10, pRegisters->m_xmm11,
		pRegisters->m_xmm12, pRegisters->m_xmm13,
		pRegisters->m_xmm14, pRegisters->m_xmm15
	};
	for (size_t index = 0; index < 16; ++index)
		if (xmmRegisters[index])
			std::memcpy(xmmRegisters[index]->m_pAddress,
				pSnapshot->xmm[index], 16);
}

void CHook::RegistersToSnapshot(
	CRegisters* pRegisters, void* pRawSnapshot, bool bPost)
{
	(void) bPost;
	X64Snapshot* pSnapshot = static_cast<X64Snapshot*>(pRawSnapshot);
#define REGISTERS_GPR(reg, field) \
	do { if (pRegisters->reg) pSnapshot->field = pRegisters->reg->GetValue<uint64_t>(); } while (0)
	REGISTERS_GPR(m_rax, rax); REGISTERS_GPR(m_rbx, rbx);
	REGISTERS_GPR(m_rcx, rcx); REGISTERS_GPR(m_rdx, rdx);
	REGISTERS_GPR(m_rsi, rsi); REGISTERS_GPR(m_rdi, rdi);
	REGISTERS_GPR(m_rbp, rbp); REGISTERS_GPR(m_r8, r8);
	REGISTERS_GPR(m_r9, r9); REGISTERS_GPR(m_r10, r10);
	REGISTERS_GPR(m_r11, r11); REGISTERS_GPR(m_r12, r12);
	REGISTERS_GPR(m_r13, r13); REGISTERS_GPR(m_r14, r14);
	REGISTERS_GPR(m_r15, r15);
#undef REGISTERS_GPR

	CRegister* xmmRegisters[] = {
		pRegisters->m_xmm0, pRegisters->m_xmm1,
		pRegisters->m_xmm2, pRegisters->m_xmm3,
		pRegisters->m_xmm4, pRegisters->m_xmm5,
		pRegisters->m_xmm6, pRegisters->m_xmm7,
		pRegisters->m_xmm8, pRegisters->m_xmm9,
		pRegisters->m_xmm10, pRegisters->m_xmm11,
		pRegisters->m_xmm12, pRegisters->m_xmm13,
		pRegisters->m_xmm14, pRegisters->m_xmm15
	};
	for (size_t index = 0; index < 16; ++index)
		if (xmmRegisters[index])
			std::memcpy(pSnapshot->xmm[index],
				xmmRegisters[index]->m_pAddress, 16);
}

void CHook::CopyRegisters(CRegisters* pSource, CRegisters* pDestination)
{
	std::list<Register_t> registers = m_pCallingConvention->GetRegisters();
	for (std::list<Register_t>::iterator it = registers.begin();
		it != registers.end(); ++it)
	{
		CRegister* pFrom = RegisterFor(pSource, *it);
		CRegister* pTo = RegisterFor(pDestination, *it);
		if (pFrom && pTo)
			std::memcpy(pTo->m_pAddress, pFrom->m_pAddress,
				static_cast<size_t>(pFrom->m_iSize));
	}
}

bool CHook::CreateBridge()
{
	CodeHolder code;
	code.init(m_asmjit_rt.environment(), m_asmjit_rt.cpuFeatures());
	Assembler a(&code);
	const int frameSize = static_cast<int>(sizeof(X64Snapshot) + 8);
	Label overrideOriginal = a.newLabel();

	a.endbr64();
	a.sub(rsp, frameSize);
	SaveSnapshot(a, frameSize);
	// Microsoft x64 ABI: DispatchPre is an MSVC-compiled member function, so its
	// three parameters arrive in rcx/rdx/r8. Emitting rdi/rsi/rdx here is the
	// SysV assignment and delivers the engine's own rcx/rdx/r8 to the callee
	// instead, which is a deterministic wrong-pointer crash rather than a race.
	a.mov(rcx, imm(reinterpret_cast<uint64_t>(this)));
	a.mov(rdx, rsp);
	// pStack must point at the slot that currently holds the hooked function's
	// return address. After "sub rsp, frameSize" that slot is [rsp+frameSize]
	// (the snapshot's saved rsp is that same address), and it still contains the
	// caller's return address because the normal/override paths overwrite it only
	// AFTER DispatchPre returns; the function's stack arguments sit immediately
	// above the slot. DispatchPre reads the return address as *pStack, matching
	// the convention the 32-bit build uses.
	//
	// Passing &snapshot.rsp here instead made *pStack equal to the stack POINTER
	// (the address of the return slot) rather than the return address in it, so
	// pReturnAddress became a stack address and the post bridge's final "ret"
	// jumped onto the stack (fault rip == saved rsp). That was the run_command
	// crash that remained once the shadow-space/alignment bug was fixed.
	a.lea(r8, ptr(rsp, frameSize));
	a.mov(rax, imm(reinterpret_cast<uint64_t>(&CHook::DispatchPre)));
	// Reserve the callee's 32-byte shadow space WITHOUT changing the 8 mod 16
	// pre-call phase (0x20 is 0 mod 16; see MSWIN64_CALL_PADDING). rdx/r8 already
	// hold absolute addresses, so lowering rsp here does not disturb them. The
	// snapshot starts at the current rsp, which sits ABOVE this pad, so the
	// callee's home stores cannot reach it. The "call" pushes the return address
	// below this shadow.
	a.sub(rsp, static_cast<int>(MSWIN64_CALL_PADDING));
	a.call(rax);
	a.add(rsp, static_cast<int>(MSWIN64_CALL_PADDING));
	a.test(al, al);
	a.jnz(overrideOriginal);

	// Normal path: redirect the original return to the post bridge and tail
	// jump through the trampoline with the entry stack restored exactly.
	a.mov(r11, ptr(rsp, offsetof(X64Snapshot, rsp)));
	a.mov(r10, imm(reinterpret_cast<uint64_t>(m_pNewRetAddr)));
	a.mov(ptr(r11), r10);
	RestoreSnapshot(a);
	a.add(rsp, frameSize);
	a.mov(r10, imm(reinterpret_cast<uint64_t>(m_pTrampoline)));
	a.jmp(r10);

	// Override path: use the callback-provided return registers, then enter
	// the same post bridge without calling the original function.
	a.bind(overrideOriginal);
	a.mov(r11, ptr(rsp, offsetof(X64Snapshot, rsp)));
	a.mov(r10, imm(reinterpret_cast<uint64_t>(m_pNewRetAddr)));
	a.mov(ptr(r11), r10);
	RestoreSnapshot(a);
	a.add(rsp, frameSize);
	a.ret();

	return m_asmjit_rt.add(&m_pBridge, &code) == kErrorOk;
}

bool CHook::CreatePostCallback()
{
	CodeHolder code;
	code.init(m_asmjit_rt.environment(), m_asmjit_rt.cpuFeatures());
	Assembler a(&code);
	const int frameSize = static_cast<int>(sizeof(X64Snapshot));

	a.endbr64();
	a.sub(rsp, frameSize);
	SaveSnapshot(a, frameSize - static_cast<int>(sizeof(void*)));
	// Same Microsoft x64 ABI requirement as CreateBridge: DispatchPost has the
	// identical (CHook*, void*, void*) signature and is likewise MSVC-compiled.
	a.mov(rcx, imm(reinterpret_cast<uint64_t>(this)));
	a.mov(rdx, rsp);
	a.lea(r8, ptr(rsp, frameSize));
	a.mov(rax, imm(reinterpret_cast<uint64_t>(&CHook::DispatchPost)));
	// Same shadow-space/alignment requirement as CreateBridge. The post bridge is
	// reached by the original function's "ret", so it enters with rsp 8 mod 16;
	// "sub rsp, frameSize" (0 mod 16) keeps rsp 8 mod 16, and this 0x20 pad
	// (0 mod 16) preserves that pre-"call" phase so DispatchPost enters aligned.
	a.sub(rsp, static_cast<int>(MSWIN64_CALL_PADDING));
	a.call(rax);
	a.add(rsp, static_cast<int>(MSWIN64_CALL_PADDING));
	a.mov(ptr(rsp, offsetof(X64Snapshot, dispatchReturn)), rax);
	a.mov(r11, ptr(rsp, offsetof(X64Snapshot, dispatchReturn)));
	a.mov(ptr(rsp, frameSize - static_cast<int>(sizeof(void*))), r11);
	RestoreSnapshot(a);
	a.add(rsp, frameSize - static_cast<int>(sizeof(void*)));
	a.ret();

	return m_asmjit_rt.add(&m_pNewRetAddr, &code) == kErrorOk;
}

#endif // defined(DYNAMICHOOKS_X86_64)

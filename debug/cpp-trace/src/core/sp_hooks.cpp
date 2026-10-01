/**
* =============================================================================
* Source Python
* Copyright (C) 2012-2018 Source Python Development Team.  All rights reserved.
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

//---------------------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------------------
class CBasePlayer;

// Boost.Python
#include "boost/python.hpp"
using namespace boost::python;

// SDK
#include "edict.h"
#include "game/shared/shareddefs.h"
#include "game/shared/usercmd.h"

// Source.Python
#include "sp_hooks.h"
#include "utilities/conversions.h"
#include "utilities/call_python.h"
#include "modules/entities/entities_entity.h"
#include "modules/listeners/listeners_manager.h"
#include "modules/memory/memory_hooks.h"


//---------------------------------------------------------------------------------
// GLOBAL VARIABLES
//---------------------------------------------------------------------------------
std::vector<IEntityHook*> g_EntityHooks;


//---------------------------------------------------------------------------------
// ISimpleEntityHook
//---------------------------------------------------------------------------------
ISimpleEntityHook::ISimpleEntityHook(const char* func_name, HookHandlerFn* hook_handler, HookType_t hook_type)
{
	this->func_name = func_name;
	this->hook_handler = hook_handler;
	this->hook_type = hook_type;
}

bool ISimpleEntityHook::Initialize(CBaseEntity* pEntity)
{
	if (!Test(pEntity))
	{
		return false;
	}

	PythonLog(4, "Initializing core hook (%s)...", this->func_name);

	unsigned int index;
	if (!IndexFromBaseEntity(pEntity, index))
	{
		PythonLog(0, "Failed to convert the entity pointer to an index (%s)", this->func_name);
		return true;
	}

	CFunction* func = NULL;
	try
	{
		static object Entity = import("entities.entity").attr("Entity");

		object entity = Entity(index);
		func = extract<CFunction*>(entity.attr(this->func_name));
	}
	catch (...)
	{
		PyErr_Print();
		PyErr_Clear();

		PythonLog(0, "Failed to import entities.entity.Entity or to retrieve %s.", this->func_name);
		return true;
	}

	// The gamedata key this hook is for, on the same log the convention lifecycle
	// goes to. The hand-off line that follows records which function was hooked,
	// but "server.dll+0x3107A0" is only meaningful next to the name that produced
	// it, and the name is the thing that can be checked against a gamedata table.
	//
	// It is not in PythonLog because that call is at verbosity 4 and the server
	// runs at a lower level, so the one piece of identifying information this
	// path has never reached the log.
	SpHookTraceLifecycle("request", (const void *) func->m_ulAddr,
		(const void *) func->m_pCallingConvention,
		func->m_pCallingConvention ? func->m_pCallingConvention->m_bHooked : false,
		this->func_name);

	if (!func->AddHook(this->hook_type, this->hook_handler))
	{
		PythonLog(0, "Could not create a hook for %s.", this->func_name);
		return true;
	}

	PythonLog(3, "Core hook (%s) has been initialized.", this->func_name);
	return true;
}


//---------------------------------------------------------------------------------
// PlayerHook
//---------------------------------------------------------------------------------
PlayerHook::PlayerHook(const char* func_name, HookHandlerFn* hook_handler, HookType_t hook_type)
	:ISimpleEntityHook(func_name, hook_handler, hook_type)
{
}

bool PlayerHook::Test(CBaseEntity* pEntity)
{
	CBaseEntityWrapper* pWrapper = (CBaseEntityWrapper*) pEntity;
	return pWrapper->IsPlayer();
}


//---------------------------------------------------------------------------------
// FUNCTIONS
//---------------------------------------------------------------------------------
void InitHooks()
{
	CBaseEntity* pEntity = (CBaseEntity *) servertools->FirstEntity();
	while (pEntity)
	{
		InitHooks(pEntity);
		pEntity = (CBaseEntity *) servertools->NextEntity(pEntity);
	}
}

void InitHooks(CBaseEntity* pEntity)
{
	if (!pEntity)
		return;

	std::vector<IEntityHook*>::iterator it = g_EntityHooks.begin();
	while (it != g_EntityHooks.end())
	{
		IEntityHook* pHook = *it;

		if (pHook->Initialize(pEntity))
		{
			it = g_EntityHooks.erase(it);
			delete pHook;
		}
		else
		{
			++it;
		}
	}
}

//---------------------------------------------------------------------------------
// HOOKS
//---------------------------------------------------------------------------------
bool PrePlayerRunCommand(HookType_t hook_type, CHook* pHook)
{
	// Counted before every early return, including the "no listeners registered"
	// ones below, because the number being measured is how many times the engine
	// reached this hook - not how many times SP had work to do. A counter placed
	// after those returns would report zero for a server doing nothing, and zero
	// for a server that crashes on its first dispatch, and those are exactly the
	// two cases that must be told apart.
	//
	// Until this was wired up the dispatch count read zero for an entire run and
	// I took that to mean the crashing hook had never dispatched. It had not been
	// counted at all: the counter was on SP_HookHandler, and this is not the
	// callback the run_command hook uses.
	SpHookTraceTick("run_command");

	bool bUsePreRegister = false;
	bool bRestoreRegisterSelection = false;

	if (hook_type == HOOKTYPE_PRE) {
		GET_LISTENER_MANAGER(OnPlayerRunCommand, run_command_manager);
		GET_LISTENER_MANAGER(OnButtonStateChanged, button_state_manager);

		if (!run_command_manager->GetCount() && !button_state_manager->GetCount())
			return false;
	}
	else {
		GET_LISTENER_MANAGER(OnPlayerPostRunCommand, post_run_command_manager);

		if (!post_run_command_manager->GetCount())
			return false;

		// Arguments belong to the function-entry snapshot.  On x86-64 the
		// active register set is invocation-local, so changing the legacy
		// CHook member does not select the pre-hook registers.
#ifdef SOURCEPYTHON_X86_64
		bUsePreRegister = pHook->GetUsePreRegisters();
		pHook->SetUsePreRegisters(true);
#else
		bUsePreRegister = pHook->m_bUsePreRegisters;
		pHook->m_bUsePreRegisters = true;
#endif
		bRestoreRegisterSelection = true;
	}

	static object Player = import("players.entity").attr("Player");

	CBaseEntity* pEntity = pHook->GetArgument<CBaseEntity*>(0);

	// TEMPORARY DIAGNOSTIC - remove before this is considered finished.
	//
	// The engine's PlayerRunCommand always passes a valid CBaseEntity* in rcx, so
	// this value is either a plausible heap object with a vtable in server.dll, or
	// it is not.  There is no third possibility, which is why logging the pointer
	// settles whether the pre-entry register snapshot is corrupt or the fault is
	// downstream of it, without needing any struct offset.
	//
	// The virtual address is printed because ASLR moves it every run; what has to
	// be compared between runs is the SHAPE (heap vs module, aligned or not, and
	// what sits at offset 0), not the number.
	{
		FILE* fp = fopen("D:\\Counter-Strike-Source\\cstrike\\logs\\source-python\\sp_arg0.txt", "a");
		if (fp) {
			unsigned long long v = (unsigned long long)(size_t)pEntity;
			unsigned long long v0 = v ? *(unsigned long long*)pEntity : 0;
			fprintf(fp, "ARG0 pEntity=%p  [pEntity+0]=%p  hook=%p  type=%d\n",
				(void*)pEntity, (void*)(size_t)v0, (void*)pHook, (int)hook_type);
			fclose(fp);
		}
	}

	unsigned int index;
	if (!IndexFromBaseEntity(pEntity, index)) {
		if (bRestoreRegisterSelection) {
#ifdef SOURCEPYTHON_X86_64
			pHook->SetUsePreRegisters(bUsePreRegister);
#else
			pHook->m_bUsePreRegisters = bUsePreRegister;
#endif
		}
		return false;
	}
	
	// https://github.com/Source-Python-Dev-Team/Source.Python/issues/149
#if defined(ENGINE_BRANCH_TF2)
	CUserCmd cmd = *pHook->GetArgument<CUserCmd*>(1);
	CUserCmd* pCmd = &cmd;
#else
	CUserCmd* pCmd = pHook->GetArgument<CUserCmd*>(1);
#endif

	object player = Player(index);

	if (hook_type == HOOKTYPE_PRE) {
		CALL_LISTENERS(OnPlayerRunCommand, player, ptr(pCmd));

		GET_LISTENER_MANAGER(OnButtonStateChanged, button_state_manager);
		if (button_state_manager->GetCount())
		{
			CBaseEntityWrapper* pWrapper = (CBaseEntityWrapper*) pEntity;
			static int offset = pWrapper->FindDatamapPropertyOffset("m_nButtons");

			int buttons = pWrapper->GetDatamapPropertyByOffset<int>(offset);
			if (buttons != pCmd->buttons)
			{
				CALL_LISTENERS(OnButtonStateChanged, player, buttons, pCmd->buttons);
			}
		}
	}
	else {
		CALL_LISTENERS(OnPlayerPostRunCommand, player, ptr(pCmd));
	}

#if defined(ENGINE_BRANCH_TF2)
	CUserCmd* pRealCmd = pHook->GetArgument<CUserCmd*>(1);
	memcpy(pRealCmd, pCmd, sizeof(CUserCmd));
#endif

	if (bRestoreRegisterSelection) {
#ifdef SOURCEPYTHON_X86_64
		pHook->SetUsePreRegisters(bUsePreRegister);
#else
		pHook->m_bUsePreRegisters = bUsePreRegister;
#endif
	}

	return false;
}

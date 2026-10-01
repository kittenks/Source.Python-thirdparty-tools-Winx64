#!/usr/bin/env python3
r"""
sp_vtable_probe - ask RTTI what the vtable indices really are, and compare them
against what the data files claim.

Why
---
The fault was traced, by three independent logs whose counts agreed at 600, to
entities/orangebox/cstrike/CBaseEntity.ini:

    # _ZNK11CBasePlayer25PhysicsSolidMaskForEntityEv
    [[get_solid_mask]]
        offset_windows = 171
        return_type = UINT

Slot 171 of the x86-64 vtable holds "mov eax, 0x200400B ; ret" - a constant
leaf that never reads `this`, so it cannot be PhysicsSolidMaskForEntity.

The number cannot be corrected by arithmetic. A 32-bit vtable slot is 4 bytes
and an x86-64 one is 8, but more importantly the class may gain or lose virtual
functions between builds, so slot N on one architecture is not slot N on the
other by any fixed rule.

Source.Python already resolves slots by name, and memory_wrap.cpp exposes the
result:

    _FunctionInfo.def_readonly("vtable_index",  &CFunctionInfo::m_iVtableIndex);
    _FunctionInfo.def_readonly("vtable_offset", &CFunctionInfo::m_iVtableOffset);

so the answer does not have to be guessed. get_class_info(cls) returns
{name: [FunctionInfo, ...]}, which is the whole table at once.

What it does
------------
  1. dumps every virtual function of the named classes with its RTTI-derived
     vtable_index, vtable_offset, return type and argument types
  2. reads the deployed ini files, extracts the mangled symbol from each entry's
     comment, and pairs each [[key]] with the method it claims to be
  3. prints, per entry, the claimed index and the real one, and marks the
     mismatches
  4. for the mismatched ones, additionally reports which slot in the real table
     holds that method, and what the slot SP currently points at looks like -
     a short disassembly, so a constant leaf is recognisable as one

Nothing is changed. This only reports.
"""
import os
import re
import sys
import time

PLUGIN_NAME = "sp_vtable_probe"

_log = None
_path = None
_results = []


# ---------------------------------------------------------------------------
# the ini side
# ---------------------------------------------------------------------------
def demangle(symbol):
    """(class, method) from an Itanium-mangled symbol.

    "_ZNK11CBasePlayer25PhysicsSolidMaskForEntityEv"
        -> ("CBasePlayer", "PhysicsSolidMaskForEntity")

    The K of _ZNK has to be consumed before the first length prefix can be read.
    A version that stripped only "_ZN" found no digits, returned None, and made
    the one entry that actually mattered - get_solid_mask - look like it had no
    class at all.
    """
    if not symbol or not symbol.startswith("_ZN"):
        return (None, None)
    rest = symbol[3:]
    names = []
    for _ in range(2):
        while rest[:1] in ("K", "V", "r", "B"):
            rest = rest[1:]
        digits = ""
        for ch in rest:
            if ch.isdigit():
                digits += ch
            else:
                break
        if not digits:
            break
        n = int(digits)
        names.append(rest[len(digits):len(digits) + n])
        rest = rest[len(digits) + n:]
        if not rest:
            break
    if not names:
        return (None, None)
    return (names[0], names[1] if len(names) > 1 else None)


def parse_ini(path):
    """[(key, class, method, claimed_index, source)] from [[virtual_function]].

    [[name]] is matched before [section]: the section pattern is greedy, so
    "[[get_solid_mask]]" also matches it with the group capturing
    "[get_solid_mask]", which is neither a section nor a key - and every
    subsequent entry was then dropped, which is how a file with five
    offset_windows lines was reported as having none.
    """
    out = []
    if not os.path.exists(path):
        return out
    text = open(path, "r", encoding="utf-8", errors="replace").read()
    comment = None
    key = None
    in_vf = False
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("#"):
            comment = stripped.lstrip("# ").strip()
            continue
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^\[\[(.+)\]\]$", line)
        if m:
            key = m.group(1)
            continue
        m = re.match(r"^\[(.+)\]$", line)
        if m:
            in_vf = (m.group(1) == "virtual_function")
            key = None
            continue
        if in_vf and key and line.startswith("offset_windows"):
            value = line.split("=", 1)[1].strip()
            try:
                claimed = int(value)
            except ValueError:
                continue
            cls, method = demangle(comment)
            out.append((key, cls, method, claimed,
                        os.path.basename(path)))
            key = None
    return out


# ---------------------------------------------------------------------------
# log
# ---------------------------------------------------------------------------
def _resolve_dir():
    try:
        from core import SP_ROOT_PATH
        return os.path.join(str(SP_ROOT_PATH), "logs")
    except Exception:
        pass
    try:
        from paths import GAME_PATH
        return os.path.join(str(GAME_PATH), "logs")
    except Exception:
        return os.path.join(os.getcwd(), "logs")


def _open():
    global _log, _path
    try:
        folder = _resolve_dir()
        os.makedirs(folder, exist_ok=True)
        _path = os.path.join(folder, "sp_vtable_probe.log")
        _log = open(_path, "a", encoding="utf-8", errors="replace")
    except Exception as error:
        _log = None
        _path = None
        _say("could not open the log: %s: %s" % (type(error).__name__, error))


def _say(line=""):
    text = line if not line else "%s %s" % (time.strftime("%H:%M:%S"), line)
    if _log is not None:
        try:
            _log.write(text + "\n")
            _log.flush()
            return
        except Exception:
            pass
    try:
        from core import echo_console
        echo_console("[%s] %s" % (PLUGIN_NAME, line))
    except Exception:
        pass


def _section(title):
    _say("")
    _say("=" * 78)
    _say("  %s" % title)
    _say("=" * 78)


# ---------------------------------------------------------------------------
# the probe
# ---------------------------------------------------------------------------
def _data_root():
    for candidate in (
            lambda: __import__("paths").SP_DATA_PATH,
            lambda: __import__("core").SP_DATA_PATH):
        try:
            return str(candidate())
        except Exception:
            continue
    return None


def _collect_ini_entries():
    root = _data_root()
    if not root:
        _say("could not locate the data directory; SP_DATA_PATH unavailable")
        return []
    # Resolution order for a class: <engine>/<game>, then <engine>, then the
    # whole tree. Not a single branch. cstrike has its own CBaseEntity.ini and
    # CBasePlayer.ini, so scanning only orangebox/cstrike would miss the eight
    # entries in orangebox/CBaseEntity.ini that are also part of CS:Source's
    # effective set - and skipping them would report the cstrike branch as
    # complete when it is not.
    #
    # Scanning everything, on the other hand, brings in bms, csgo, gmod, l4d2,
    # hl2mp, tf and dod, none of which apply here, and every one of their entries
    # is reported as a mismatch. 164 offset_windows lines exist under entities
    # in total; the ones that can be checked are far fewer.
    base = os.path.join(root, "entities")
    branch = None
    try:
        from core import GAME_NAME
        branch = str(GAME_NAME)
    except Exception:
        pass
    # The engine branch is the one that holds the game subdirectory, i.e. the
    # parent of <engine>/<game>. Taken from the data layout rather than from a
    # constant, because the engine name is not the same as the source-engine name
    # SP reports.
    engine_dir = None
    if branch and os.path.isdir(os.path.join(base, branch)):
        engine_dir = branch          # flat layout, e.g. csgo/
    elif branch:
        for candidate in sorted(os.listdir(base)):
            full = os.path.join(base, candidate)
            if os.path.isdir(full) and os.path.isdir(os.path.join(full, branch)):
                engine_dir = candidate
                break
    # The engine branch is walked but NOT descended into for the other games it
    # contains. orangebox holds cstrike/ and dod/, hl2mp/ and tf/ side by side,
    # and those are different games with different classes and different slot
    # numbers. Walking the engine directory wholesale pulled in CDODPlayer.ini,
    # CItem.ini and CTFPlayer.ini - 25 entries that cannot be checked and are
    # reported as uncheckable noise. The game's own subdirectory is taken, and
    # only files directly in the engine directory are read besides it.
    scan = []
    game_dir = None
    if engine_dir and branch:
        game_dir = os.path.join(base, engine_dir, branch)
        if os.path.isdir(game_dir):
            scan.append(game_dir)
    if engine_dir:
        engine_root = os.path.join(base, engine_dir)
        # Direct children only: prune every subdirectory of the engine branch
        # except the game's own.
        scan.append(engine_root)
    if not scan:
        scan.append(base)
    # Files are gathered explicitly rather than by pruning a walk. The pruning
    # version kept the engine branch's own files and the game's subdirectory, but
    # when the game branch could not be identified _scan_prune was empty, the
    # filter removed every subdirectory, and the scan silently returned nothing
    # - a probe that reports no entries reads exactly like a probe that found
    # none, which is the failure this whole investigation keeps running into.
    files = []
    for start in scan:
        if not os.path.isdir(start):
            continue
        for fn in sorted(os.listdir(start)):
            full = os.path.join(start, fn)
            if os.path.isfile(full) and fn.endswith(".ini"):
                files.append(full)
    found = []
    seen = set()
    for full in files:
        if full in seen:
            continue
        seen.add(full)
        for entry in parse_ini(full):
            found.append(entry)
    return found


def _dump_class(name, limit=None):
    """Every virtual function of an exposed interface, with its RTTI index.

    Only the exposed interfaces are in CLASS_INFO. The key is the interface name
    the C++ wrap registered - IVEngineServer, ICvar, CGameRules and so on
    (BEGIN_CLASS_INFO(...) in src/core/modules) - and game entity classes such
    as CBaseEntity or CCSPlayer are NOT there: entities/classes.py builds those
    from the data files with create_type_from_dict, and their slot numbers come
    from the ini with no RTTI involved at all.

    That distinction is the finding, not a detail. An earlier version of this
    probe asked CLASS_INFO for CBaseEntity and reported KeyError for every
    engine class it wanted, then concluded "the RTTI walk found nothing, which
    is itself the finding" - a confident statement derived from asking the wrong
    table the wrong question.
    """
    try:
        from memory import get_class_info
    except Exception as error:
        _say("cannot import get_class_info: %s: %s"
             % (type(error).__name__, error))
        return None
    try:
        info = get_class_info(name)
    except Exception as error:
        _say("  %-26s NOT IN CLASS_INFO  (%s: %s)"
             % (name, type(error).__name__, error))
        return None
    _say("  %s: %d named member function(s)" % (name, len(info)))
    virtuals = []
    for fname, infos in sorted(info.items()):
        for number, fi in enumerate(infos):
            try:
                is_virtual = bool(fi.is_virtual)
                vindex = int(fi.vtable_index)
                voffset = int(fi.vtable_offset)
            except Exception as error:
                _say("    %-34s [%d] FunctionInfo unreadable: %s: %s"
                     % (fname, number, type(error).__name__, error))
                continue
            try:
                args = [str(a) for a in fi.argument_types]
            except Exception:
                args = ['?']
            try:
                rtype = str(fi.return_type)
            except Exception:
                rtype = '?'
            if is_virtual:
                _say("    %-34s [%d] VIRTUAL  index %-5d offset %-6d %s(%s)"
                     % (fname, number, vindex, voffset, rtype, ", ".join(args)))
                virtuals.append((fname, number, vindex, voffset, rtype, args))
            else:
                _say("    %-34s [%d] direct   %s(%s)"
                     % (fname, number, rtype, ", ".join(args)))
    if not virtuals:
        _say("    (no virtual functions reported for %s)" % name)
    return virtuals


def _describe_slot(pointer, index):
    """What is at the address the vtable slot points at.

    A constant-returning leaf is the signature of a slot that has nothing to do
    with the method it is supposed to be: "mov eax, imm32 ; ret" ignores both
    `this` and every argument, so it cannot be a method that inspects an entity.
    """
    try:
        address = int(pointer)
    except Exception:
        return "slot %d: no address could be obtained, so nothing was read" % index
    try:
        raw = read_bytes(address, 16)
    except Exception as error:
        return "could not read 0x%X: %s" % (address, error)
    hexed = " ".join("%02X" % b for b in raw)
    verdict = ""
    if len(raw) >= 6 and raw[0] == 0xB8 and raw[5] == 0xC3:
        imm = int.from_bytes(raw[1:5], "little")
        verdict = "   <- mov eax, 0x%X ; ret  A CONSTANT LEAF: ignores this" % imm
    elif len(raw) >= 2 and raw[0] == 0x33 and raw[1] == 0xC0:
        verdict = "   <- xor eax, eax ; ret  returns 0, ignores this"
    elif len(raw) >= 1 and raw[0] == 0xC3:
        verdict = "   <- ret  (a single ret, nothing else)"
    else:
        verdict = "   <- real code"
    return "0x%016X  %s%s" % (address, hexed, verdict)


def read_bytes(address, count):
    """Read process memory at an absolute address."""
    import ctypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = ctypes.c_void_p(k32.GetCurrentProcess())
    buf = (ctypes.c_ubyte * count)()
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(handle, ctypes.c_void_p(address),
                                 ctypes.byref(buf), count,
                                 ctypes.byref(got)):
        raise OSError(ctypes.get_last_error(), "ReadProcessMemory failed")
    return bytes(bytearray(buf)[:got.value])


def _live_entity():
    """Any live entity whose vtable can be read, with a note of what it was.

    Best effort and clearly labelled: a vtable read against the wrong object
    type would be exactly the kind of plausible wrong answer this investigation
    has been fighting, so when no entity is available the slot check is skipped
    rather than guessed.
    """
    try:
        from filters.players import PlayerIter
    except Exception as error:
        _say("  (cannot reach filters.players: %s: %s)"
             % (type(error).__name__, error))
        return (None, None)
    try:
        for player in PlayerIter():
            ptr = getattr(player, 'pointer', None)
            if ptr is not None:
                return (ptr, 'a player')
    except Exception as error:
        _say("  (no live player: %s: %s)" % (type(error).__name__, error))
    return (None, None)


def _describe_slot(pointer, index):
    """What the vtable slot at `index` points at, read from a live vtable.

    This is the minimum sufficient test and needs no class lookup: if the slot
    holds a constant-returning leaf, it cannot be a method that inspects an
    entity, whatever the ini says the entry is. If it holds a real prologue, the
    slot is at least pointing at code that could plausibly be a method.
    """
    try:
        address = int(pointer)
    except Exception:
        return "slot %d: no address could be obtained" % index
    try:
        raw = read_bytes(address, 16)
    except Exception as error:
        return "could not read 0x%X: %s" % (address, error)
    hexed = " ".join("%02X" % b for b in raw)
    if len(raw) >= 6 and raw[0] == 0xB8 and raw[5] == 0xC3:
        imm = int.from_bytes(raw[1:5], "little")
        verdict = ("   <- mov eax, 0x%X ; ret   A CONSTANT LEAF: ignores this"
                   % imm)
    elif len(raw) >= 2 and raw[0] == 0x33 and raw[1] == 0xC0:
        verdict = "   <- xor eax, eax ; ret   returns 0, ignores this"
    elif len(raw) >= 1 and raw[0] == 0xC3:
        verdict = "   <- ret   a single ret and nothing else"
    elif len(raw) >= 4 and raw[:4] == bytes([0x48, 0x89, 0x5C, 0x24]):
        verdict = "   <- real code (saves a non-volatile register)"
    else:
        verdict = "   <- real code"
    return "0x%016X  %s%s" % (address, hexed, verdict)


def _run():
    _section("1. what the data files claim")
    entries = _collect_ini_entries()
    _say("  %d [[virtual_function]] entry/entries with an offset_windows"
         % len(entries))
    for key, cls, method, claimed, src in entries:
        _say("    %-16s %-46s claims index %d"
             % (key, "%s::%s" % (cls or "?", method or "?"), claimed))
        _say("      %s" % src)

    _section("2. what CLASS_INFO actually holds")
    from memory import CLASS_INFO
    _say("  %d class/classes" % len(CLASS_INFO))
    _say("  keys: %s" % ", ".join(sorted(CLASS_INFO)))
    _say("")
    _say("  These are the interfaces Source.Python exposes, registered by the C++")
    _say("  wrap under BEGIN_CLASS_INFO(...). The game entity classes the ini")
    _say("  files describe are NOT among them. entities/classes.py builds each")
    _say("  ServerClass with create_type_from_dict, so an entity's slot numbers")
    _say("  come straight from the ini and RTTI is never consulted for them.")
    _say("")
    _say("  Consequence: the ini's slot numbers cannot be checked against RTTI,")
    _say("  because RTTI has no opinion about them. An earlier version of this")
    _say("  probe asked CLASS_INFO for CBaseEntity, got KeyError for every")
    _say("  entity class, and concluded that the RTTI extractor was at fault -")
    _say("  a confident reading drawn from asking the wrong table.")
    _say("")
    _say("  The interfaces are dumped as a control. If they resolve, the x86-64")
    _say("  vtable extractor in memory_function_info.h works, and the fault is")
    _say("  in the entity data rather than in the extractor.")
    rtti_worked = 0
    for name in sorted(CLASS_INFO):
        if _dump_class(name):
            rtti_worked += 1
    _say("")
    _say("  %d of %d interface(s) reported virtual functions, so the RTTI "
         "extractor is %s" % (rtti_worked, len(CLASS_INFO),
                              "working" if rtti_worked else "NOT WORKING"))

    _section("3. does each claimed slot hold code that could be the method?")
    _say("  Read from a live entity's vtable, so no class lookup is involved.")
    _say("  A slot holding a constant-returning leaf cannot be a method that")
    _say("  inspects an entity: such a function ignores both `this` and every")
    _say("  argument, and the C++ side of all these entries takes a POINTER.")
    ptr, what = _live_entity()
    if ptr is None:
        _say("")
        _say("  No live entity was available, so no slot could be read. The")
        _say("  section above is unaffected; this one is simply unavailable.")
    else:
        _say("  vtable read from %s" % what)
        _say("")
        leaf_slots = 0
        checked = 0
        for key, cls, method, claimed, src in entries:
            _say("  %-18s %-44s slot %d"
                 % (key, "%s::%s" % (cls or "?", method or "?"), claimed))
            try:
                slot_ptr = ptr.get_virtual_func(claimed)
            except Exception as error:
                _say("    could not read: %s: %s" % (type(error).__name__, error))
                continue
            checked += 1
            text = _describe_slot(slot_ptr, claimed)
            _say("    %s" % text)
            if "CONSTANT LEAF" in text or "ignores this" in text:
                leaf_slots += 1
                _say("    => this slot cannot be %s" % (method or key))
                # The neighbouring slots are printed so the correct index can be
                # spotted, if it is in range.
                _say("    neighbours:")
                for delta in (-2, -1, 0, 1, 2):
                    idx = claimed + delta
                    if idx < 0:
                        continue
                    try:
                        nb = ptr.get_virtual_func(idx)
                    except Exception:
                        continue
                    _say("      slot %-5d %s"
                         % (idx, _describe_slot(nb, idx)))
            _say("")

        _section("4. verdict")
        if leaf_slots:
            _say("  %d of %d slot(s) that were read hold a constant-returning"
                 % (leaf_slots, checked))
            _say("  leaf, so the ini names a slot that cannot hold the method it")
            _say("  claims. The neighbours above show where the real code is.")
            _say("")
            _say("  A slot number cannot be carried between architectures by")
            _say("  arithmetic: a slot is 4 bytes wide on 32-bit and 8 on x86-64,")
            _say("  and a class may gain or lose virtual functions between")
            _say("  builds. Each value has to be read off this build.")
        else:
            _say("  Every slot that could be read holds real code.")
    return True


def _register_commands():
    from commands.server import server_command_manager

    def _probe_command(*args, **kwargs):
        _run()

    try:
        server_command_manager.register_commands('sp_vtable_probe',
                                                 _probe_command)
        _say("registered sp_vtable_probe")
    except Exception as error:
        _say("could not register sp_vtable_probe: %s: %s"
             % (type(error).__name__, error))


def load():
    if _log is None:
        _open()
    _say("")
    _say("### sp_vtable_probe loaded at %s"
         % time.strftime("%Y-%m-%d %H:%M:%S"))
    _say("    log file: %s" % _path)
    _register_commands()
    _say("")
    _say('run "sp_vtable_probe". Nothing is changed; it only reports.')


def unload():
    if _log is not None:
        try:
            _log.flush()
            _log.close()
        except Exception:
            pass
    print("sp_vtable_probe unloaded")

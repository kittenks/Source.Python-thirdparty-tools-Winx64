#!/usr/bin/env python3
r"""
sp_addrguard - prove, on the live server, whether a function address survives
the trip from the vtable into the call.

Why this exists
---------------
sp_console told us the address the object holds:

    FAULT #1  function address 0x7FFA839877F0
    error   : RuntimeError: Access violation while executing address '2207807472'

2207807472 is 0x839877F0. The object holds the right address and the call
executes the low half of it. Everything upstream of the call is therefore
exonerated: the vtable index, the byte stride, the gamedata value and the
function body itself are all correct. What is wrong is the width of the
variable the address is handed to on its way into dyncall.

sp_stride was written to measure that, but it was never run, and it does not
compare against anything - it prints candidates and leaves the judgement to
the reader. This plugin states the judgement instead: for one vtable slot it
reads the truth with ctypes and asks Source.Python for the same address, then
reports whether they agree. Agreement is pass; disagreement is fail, and the
difference is printed so the truncation is visible rather than inferred.

What is measured, in order
--------------------------
  1. raw round trip   Pointer(big) -> int(). A 64-bit address handed to
                      Pointer must come back unchanged. This is checked first
                      because if it fails, every address in the process is
                      suspect and the rest of the report means nothing.
  2. this pointer     the entity address, and whether it is above 4 GB.
  3. vtable slot      eight bytes at vptr + index * 8, read with ctypes -
                      no Source.Python code involved, so this is the reference.
  4. SP's answer      ptr.make_virtual_function(index, ...) -> int().
  5. the call         only attempted when 3 and 4 agree, because calling a
                      truncated address is what crashes the server, and a
                      crash here would destroy the evidence rather than add
                      to it. When they disagree the call is skipped and the
                      report says so.

Repeating it
------------
    sp_addrguard        one pass
    sp_addrguard 3      three passes, each independently reported

Repeat it after rebuilding. The expected transition is:

    before: slot 171  MANUAL 0x7FFA839877F0  SP 0x00000000839877F0  FAIL
    after : slot 171  MANUAL 0x7FFA839877F0  SP 0x7FFA839877F0      PASS

Self test
---------
    sp_addrguard_selftest

Runs the comparison logic against synthetic values, including a deliberately
truncated one, without touching the game. Use it to confirm the plugin itself
detects what it claims to detect: a checker that cannot fail is not a checker.
"""
import ctypes
import os
import time

PLUGIN_NAME = "sp_addrguard"

# The slot the whole investigation has been about.
DEFAULT_INDEX = 171
# MASK_SOLID. PhysicsSolidMaskForEntity on CBaseEntity returns this constant.
EXPECTED_MASK_SOLID = 0x200400B

_log = None
_path = None


# ---------------------------------------------------------------------------
# logging
# ---------------------------------------------------------------------------
def _say(line=""):
    text = ("%s %s" % (time.strftime("%H:%M:%S"), line)) if line else ""
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


def _open():
    global _log, _path
    try:
        try:
            from core import SP_ROOT_PATH
            folder = os.path.join(str(SP_ROOT_PATH), "logs")
        except Exception:
            from paths import GAME_PATH
            folder = os.path.join(str(GAME_PATH), "logs")
        os.makedirs(folder, exist_ok=True)
        _path = os.path.join(folder, "sp_addrguard.log")
        _log = open(_path, "a", encoding="utf-8", errors="replace")
    except Exception as error:
        _log = None
        _path = None
        _say("could not open the log: %s: %s" % (type(error).__name__, error))


# ---------------------------------------------------------------------------
# raw memory, deliberately not via Source.Python
# ---------------------------------------------------------------------------
def read_pointer(address):
    """The eight bytes at an absolute address, as an int.

    ctypes.string_at dereferences inside this process, which is what we want:
    the reference value must not travel through any of the code under test.
    ReadProcessMemory is the fallback for an address that is not mapped, where
    a clean OSError beats an access violation.
    """
    try:
        return int.from_bytes(ctypes.string_at(ctypes.c_void_p(address), 8),
                              "little")
    except Exception:
        try:
            buf = (ctypes.c_char * 8)()
            read = ctypes.c_size_t(0)
            ok = ctypes.windll.kernel32.ReadProcessMemory(
                ctypes.windll.kernel32.GetCurrentProcess(),
                ctypes.c_void_p(address), buf, 8,
                ctypes.byref(read))
            if not ok or read.value != 8:
                raise OSError("ReadProcessMemory failed at 0x%X" % address)
            return int.from_bytes(bytes(buf), "little")
        except Exception as error:
            raise RuntimeError("cannot read 0x%X: %s" % (address, error))


def pointer_width():
    return ctypes.sizeof(ctypes.c_void_p) * 8


# ---------------------------------------------------------------------------
# the comparison - the whole point of the plugin
# ---------------------------------------------------------------------------
def compare(reference, candidate, width_bits=None):
    """Judge a candidate address against a reference address.

    Returns a dict so the self test can exercise this without a game.
    """
    width_bits = width_bits or pointer_width()
    mask = (1 << width_bits) - 1
    truncated = candidate == (reference & 0xFFFFFFFF)
    return {
        "reference": reference,
        "candidate": candidate,
        "equal": reference == candidate,
        "looks_truncated_to_32": bool(truncated and reference != candidate),
        "lost_high": (reference & mask) - candidate if reference != candidate
                     else 0,
    }


def _verdict(result):
    if result["equal"]:
        return "PASS"
    if result["looks_truncated_to_32"]:
        return "FAIL - address truncated to 32 bits"
    return "FAIL - address differs, cause unknown"


# ---------------------------------------------------------------------------
# one pass
# ---------------------------------------------------------------------------
def _find_any_entity():
    """The first entity we can get a pointer to, or None.

    Prefers a real player; falls back to the world entity, which exists on a
    running map and is enough for a vtable read.
    """
    try:
        from players.entity import Player
        from filters.players import PlayerIter
        for edict in PlayerIter():
            try:
                return Player(edict.index)
            except Exception:
                continue
    except Exception:
        pass
    try:
        from entities.entity import Entity
        return Entity(0)
    except Exception:
        return None


def run_once(index=DEFAULT_INDEX, verbose=True):
    from memory import Pointer, get_object_pointer, DataType, Convention

    report = {"index": index, "ok": False}

    # --- 1. raw round trip ---------------------------------------------
    probe = 0x7FFA00001000  # a plausible x64 module address; never dereferenced
    try:
        roundtrip = int(Pointer(probe))
    except Exception as error:
        _say("  Pointer(0x%X) raised %s: %s" % (probe, type(error).__name__,
                                                error))
        report["roundtrip"] = {"error": str(error)}
        roundtrip = None
    if roundtrip is not None:
        rr = compare(probe, roundtrip)
        report["roundtrip"] = rr
        _say("  1. raw round trip   in 0x%016X  out 0x%016X  %s"
             % (probe, roundtrip, _verdict(rr)))
        if not rr["equal"]:
            _say("     Pointer() loses the high half. Every address below is")
            _say("     unsound; stop here and fix Pointer first.")

    # --- 2/3/4. the vtable slot ----------------------------------------
    entity = _find_any_entity()
    if entity is None:
        _say("  no entity available - only the round trip was measured")
        return report
    try:
        this = int(get_object_pointer(entity))
    except Exception as error:
        _say("  get_object_pointer failed: %s: %s" % (type(error).__name__,
                                                      error))
        return report
    report["this"] = this
    _say("  2. this               0x%016X  %s"
         % (this, "above 4 GB" if this > 0xFFFFFFFF else "BELOW 4 GB"))

    # Which class is this? It decides whether slot 171 is PhysicsSolidMaskForEntity
    # at all. The player fallback gives CBasePlayer or CBaseEntity and slot 171 is
    # the right one. The Entity(0) fallback gives CWorld, whose data file carries
    # no [virtual_function] section at all, so its slot 171 is some other function
    # and a return value that is not MASK_SOLID would be ambiguous between "the
    # call failed" and "the slot was never get_solid_mask". Printing the class
    # removes that ambiguity.
    cname = None
    for probe in ("class_name",):
        try:
            cname = getattr(entity, probe, None)
            if cname is not None:
                cname = str(cname)
                break
        except Exception:
            cname = None
    if not cname:
        try:
            cname = str(type(entity).get_class_name())
        except Exception:
            cname = type(entity).__name__
    report["class_name"] = cname
    _say("     class              %s" % cname)
    if cname not in ("CBasePlayer", "CBaseEntity", "CCSPlayer", "CBaseCombatCharacter"):
        _say("     note: not a CBaseEntity descendant, so slot %d is not"
             % index)
        _say("     PhysicsSolidMaskForEntity on this object. A step 5 result")
        _say("     other than MASK_SOLID says nothing about the port.")

    try:
        vptr = read_pointer(this)
        manual = read_pointer(vptr + index * pointer_width() // 8)
    except Exception as error:
        _say("  3. vtable read failed: %s" % error)
        return report
    report["vptr"] = vptr
    report["slot_manual"] = manual
    _say("  3. slot %d (ctypes)  0x%016X   <- reference, no SP involved"
         % (index, manual))

    try:
        func = get_object_pointer(entity).make_virtual_function(
            index, Convention.THISCALL, (DataType.POINTER,), DataType.UINT)
        sp_addr = int(func)
    except Exception as error:
        _say("  4. make_virtual_function failed: %s: %s"
             % (type(error).__name__, error))
        return report
    report["slot_sp"] = sp_addr
    res = compare(manual, sp_addr)
    report["slot"] = res
    _say("  4. slot %d (SP)      0x%016X   %s"
         % (index, sp_addr, _verdict(res)))
    if not res["equal"]:
        _say("     lost 0x%X  (the high %d bits)"
             % (res["lost_high"], pointer_width() - 32))

    # --- 5. the call ----------------------------------------------------
    if not res["equal"]:
        _say("  5. call              SKIPPED - the address is already wrong;")
        _say("     calling it is what produced the access violations.")
        return report
    try:
        value = func(get_object_pointer(entity))
        report["returned"] = value
        note = ""
        if isinstance(value, int) and value == EXPECTED_MASK_SOLID:
            note = "  (== MASK_SOLID, as expected)"
        _say("  5. call              returned 0x%X%s"
             % (int(value), note))
        report["ok"] = True
    except Exception as error:
        report["call_error"] = str(error)
        _say("  5. call              %s: %s" % (type(error).__name__, error))

    return report


def run(times=1):
    for n in range(times):
        _say("")
        _say("=" * 74)
        _say("  sp_addrguard pass %d/%d   pointer width %d bits"
             % (n + 1, times, pointer_width()))
        _say("=" * 74)
        try:
            run_once()
        except Exception as error:
            import traceback
            _say("  pass failed: %s: %s" % (type(error).__name__, error))
            for line in traceback.format_exc().rstrip().splitlines()[-6:]:
                _say("    " + line)
    _say("")
    _say("  log file: %s" % _path)


# ---------------------------------------------------------------------------
# self test - does the checker actually detect a truncation?
# ---------------------------------------------------------------------------
def selftest():
    _say("")
    _say("  sp_addrguard self test (synthetic, touches no game memory)")
    cases = [
        ("unchanged", 0x7FFA839877F0, 0x7FFA839877F0, True),
        ("truncated", 0x7FFA839877F0, 0x839877F0, False),
        ("one bit off", 0x7FFA839877F0, 0x7FFA839877F1, False),
    ]
    failures = 0
    for name, ref, cand, want_equal in cases:
        res = compare(ref, cand, 64)
        ok = res["equal"] == want_equal
        failures += 0 if ok else 1
        _say("    %-12s ref 0x%016X  cand 0x%016X  %-38s %s"
             % (name, ref, cand, _verdict(res),
                "as expected" if ok else "UNEXPECTED"))
    _say("")
    _say("  self test: %s" % ("PASS" if failures == 0
                              else "%d UNEXPECTED" % failures))
    return failures == 0


# ---------------------------------------------------------------------------
def load():
    if _log is None:
        _open()
    _say("")
    _say("### sp_addrguard loaded at %s"
         % time.strftime("%Y-%m-%d %H:%M:%S"))
    _say("    log file: %s" % _path)
    _say("    pointer width: %d bits" % pointer_width())

    from commands.server import server_command_manager

    def _run(*args):
        times = 1
        for a in args:
            try:
                times = max(1, min(10, int(a)))
                break
            except (TypeError, ValueError):
                continue
        run(times)

    def _selftest(*args):
        selftest()

    for name, cb in (("sp_addrguard", _run),
                     ("sp_addrguard_selftest", _selftest)):
        try:
            server_command_manager.register_commands(name, cb)
            _say("registered %s" % name)
        except Exception as error:
            _say("could not register %s: %s: %s"
                 % (name, type(error).__name__, error))
    _say("")
    _say('run "sp_addrguard" for one pass, "sp_addrguard 3" for three,')
    _say('"sp_addrguard_selftest" to check the checker.')


def unload():
    if _log is not None:
        try:
            _log.flush()
            _log.close()
        except Exception:
            pass
    print("sp_addrguard unloaded")

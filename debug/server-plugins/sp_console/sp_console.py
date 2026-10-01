# sp_console - live diagnostics for the Windows x64 port

"""
Real-time capture of what Source.Python is doing, into a file in the game
directory, plus attribution of any address involved.

Why this exists
---------------
The CS:Source run produced 603 of these and nothing that identified the culprit:

    RuntimeError: Access violation while executing address '2220062704'.

The traceback's innermost frame is memory/helpers.py:353, which is

    return super().__call__(self._this, *args)

and the caller is C++ (the hook dispatcher), so no further Python frame exists
and the traceback cannot name the function. Two facts are still readable from
the message: "executing" is ExceptionInformation[0] == 8 in
memory_exception.cpp, i.e. an instruction fetch at a non-executable address, so
the *call target* was garbage rather than a wrong-but-mapped function; and the
decimal value is the address.

So this plugin instruments MemberFunction.__call__ and records, per function
address, how often it was called and how often it faulted. The key is the
function's own address, not the object's id: the question is which address is
bad, two objects at one address are the same target, and keying by id(self)
would have to keep the objects alive to stay correct.

What it can and cannot do
-------------------------
It cannot capture the engine's console. Source.Python exposes console_message,
echo_console and server_output - all writers, none a reader - so there is no
API to intercept engine spew. Engine console output has to be captured by
tee'ing the process's stdout; see deploy_console_capture.ps1. What this plugin
does capture is Source.Python's own activity plus the module attribution that
the log messages lack.

Rate limiting
-------------
603 identical exceptions are not 603 facts. Each distinct (address, message)
pair is written in full at most FULL_LIMIT times, then only counted, so a
flood stays readable and the file does not grow without bound.
"""

import ctypes
import os
import time
import traceback

# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------
PLUGIN_NAME = "sp_console"

FULL_LIMIT = 3          # full records written per distinct (address, message)

# The per-call argument log is a different matter from the fault log and needs
# its own limit. CBasePlayer::PlayerRunCommand runs once per player per tick and
# the server runs at 66.7 Hz, so with five bots that is ~335 calls a second, two
# lines each, flushed on every line. Unbounded, that is ~670 lines a second and
# the log would be megabytes by the time anything interesting happened - while
# the thing being looked for is the last handful of calls before the process
# died.
#
# So the argument log keeps only the most recent CALLS_PER_FUNCTION calls per
# function address, in memory, and rewrites a bounded tail to disk whenever a
# new address is seen. The fault log above is unchanged: it is already keyed and
# capped, and faults are rare.
#
# What this buys is that the file on disk after a hard kill holds the calls that
# were in flight at the end, which is the only record of the fatal one, without
# the volume becoming the problem.
RING_PER_FUNCTION = 24   # recent calls kept per function address

# How the file is kept current is settled by measurement rather than by taste.
# Three cadences were tried over 2000 calls at one address, counting the lines
# each produced:
#
#   rewrite every 4 calls      6.72 lines per call   (each rewrite emitted the
#                                                       whole 24-entry ring)
#   rewrite every 64 calls     0.42 lines per call   (but the last calls before
#                                                       a hard kill were not on
#                                                       disk, which is the one
#                                                       thing the log is for)
#   rewrite on every call      1.00 lines per call   (chosen)
#
# The ring is what bounds the file. The last two cost the same per call - one
# line either way - and only the third guarantees the file holds the call that
# was in flight when the process died.
HEARTBEAT = 30.0        # seconds between heartbeat lines while faults continue

_LOG = None
_PATH = None

# address -> record
_RECORDS = {}

# counters, cheap to keep exact
_TOTALS = {
    'calls': 0,
    'faults': 0,
    'blocked': 0,
    'load': time.time(),
}

_last_heartbeat = 0.0

# Originals, kept so unload() can put them back.
_orig = {}

_installed = []


# ---------------------------------------------------------------------------
# module attribution
# ---------------------------------------------------------------------------
def _module_table():
    """[(base, size, name)] for every module in this process.

    Uses psapi rather than any Source.Python API. That is deliberate: an address
    such as 2220062704 (0x845377F0) means nothing on its own - whether it is
    inside server.dll or is unbacked garbage depends on where the modules
    happened to be mapped, and ASLR moves them every run. Getting the base
    addresses at the moment of the fault is what makes the number interpretable.
    """
    out = []
    try:
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
    except Exception:
        return out

    # GetCurrentProcess returns the pseudo-handle, whose value is -1. Carried as
    # a plain int it overflows when handed straight back to the psapi calls, so
    # it is kept as a c_void_p from the start.
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.GetCurrentProcessId.restype = wintypes.DWORD
    handle = ctypes.c_void_p(k32.GetCurrentProcess())
    pid = k32.GetCurrentProcessId()

    # argtypes are set explicitly because the default c_int conversion for a
    # HMODULE truncates a 64-bit module base.
    ARRAY_HMODULE = wintypes.HMODULE * 1024
    psapi.EnumProcessModules.argtypes = [ctypes.c_void_p,
                                        ctypes.POINTER(ARRAY_HMODULE),
                                        wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD)]
    psapi.GetModuleFileNameExW.argtypes = [ctypes.c_void_p, wintypes.HMODULE,
                                           wintypes.LPWSTR, wintypes.DWORD]

    needed = wintypes.DWORD(0)
    mods = ARRAY_HMODULE()
    if not psapi.EnumProcessModules(handle, mods, ctypes.sizeof(mods),
                                    ctypes.byref(needed)):
        return out
    count = needed.value // ctypes.sizeof(wintypes.HMODULE)
    buf = ctypes.create_unicode_buffer(260)
    for i in range(min(count, 1024)):
        if not psapi.GetModuleFileNameExW(handle, mods[i], buf, 260):
            continue
        base = ctypes.cast(mods[i], ctypes.c_void_p).value
        out.append((base or 0, _image_size(base), buf.value))
    return out


def _image_size(base):
    """SizeOfImage of the module whose mapped image starts at `base`.

    Read from the module's own PE header rather than from
    GetModuleInformation, which is not exported everywhere and whose failure
    used to leave a size of 0. A size of 0 is not a harmless fallback here: _where
    then reduces to base <= address < base + 1 and will confidently attribute an
    address to a module it does not belong to, which is the one question this
    plugin exists to answer. If the header cannot be read, 0 is returned and
    _where is told to distrust it.
    """
    if not base:
        return 0
    try:
        header = (ctypes.c_ubyte * 0x1000).from_address(base)
        e_lfanew = ctypes.c_uint32.from_address(
            base + 0x3C).value          # IMAGE_DOS_HEADER.e_lfanew
        if not 0 < e_lfanew < 0x80000000 - 0x1000:
            return 0
        nt = base + e_lfanew
        magic = ctypes.c_uint16.from_address(nt + 0x18).value
        # OptionalHeader.Magic: 0x10B PE32, 0x20B PE32+. SizeOfImage sits after
        # the fixed fields either way, at the same offset from the optional
        # header's start.
        opt = nt + 0x18
        size = ctypes.c_uint32.from_address(opt + 0x38).value
        if magic in (0x10B, 0x20B) and 0 < size < 0x80000000:
            del header
            return size
    except Exception:
        return 0
    return 0


def _where(address):
    """Attribute an absolute address to a module, or say it is unbacked."""
    for base, size, name in _module_table():
        if not size:
            # SizeOfImage unreadable, so this module's extent is unknown and
            # must not be used to claim the address.
            continue
        if base <= address < base + size:
            return "%s+0x%X (module base 0x%X, size 0x%X)" % (
                os.path.basename(name), address - base, base, size)
    return ("NOT INSIDE ANY MODULE - unmapped or garbage; no module base "
            "covers it, which is what a bad function pointer looks like")


# ---------------------------------------------------------------------------
# the log file
# ---------------------------------------------------------------------------
def _resolve_path():
    """The game directory, from Source.Python itself rather than a guess."""
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
    global _LOG, _PATH, _CALLS_PATH
    folder = _resolve_path()
    try:
        os.makedirs(folder, exist_ok=True)
        _PATH = os.path.join(folder, "sp_console.log")
        _CALLS_PATH = os.path.join(folder, "sp_console_calls.log")
        _LOG = open(_PATH, "a", encoding="utf-8", errors="replace")
    except Exception as error:
        # Losing the log must not take the server down with it.
        _LOG = None
        _PATH = None
        _say("could not open the log file: %s: %s"
             % (type(error).__name__, error))


def _say(line):
    """Write one line, flushed, so the file is current even if we are killed."""
    stamp = time.strftime("%H:%M:%S")
    text = "%s %s" % (stamp, line)
    if _LOG is not None:
        try:
            _LOG.write(text + "\n")
            _LOG.flush()
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
    _say("=" * 74)
    _say("  %s" % title)
    _say("=" * 74)


# ---------------------------------------------------------------------------
# instrumentation
# ---------------------------------------------------------------------------
def _describe(func, self_obj):
    """Everything about a function object that does not require guessing."""
    info = {}
    try:
        info['address'] = int(self_obj._function) if self_obj._function else 0
    except Exception:
        info['address'] = 0
    try:
        info['this'] = int(self_obj._this) if self_obj._this else 0
    except Exception:
        info['this'] = 0
    for attr in ('_type_name',):
        try:
            info[attr] = str(getattr(self_obj, attr))
        except Exception:
            info[attr] = '?'

    # The Python names, read off the boost.python binding rather than off the
    # C++ declaration. This distinction has now been got wrong twice:
    #
    #   1. guessed get_return_type / get_arguments / get_convention / has_hooks
    #      - none of those exist under any spelling.
    #   2. then used the C++ spellings IsCallable / IsHookable / IsHooked /
    #      GetTrampoline, which are the real C++ member names
    #      (memory_function.h) but are NOT what Python sees. memory_wrap.cpp
    #      binds them as is_callable / is_hookable / is_hooked, lower case.
    #
    # Both mistakes produced a log full of None and n/a, which is worse than no
    # log: it looks like the object is broken when in fact the probe was wrong.
    #
    # get_trampoline is not bound at all, and neither m_tArgs nor
    # m_eCallingConvention are exposed, so arguments and convention cannot be
    # read from the object and are reported as such rather than guessed at.
    for name in ('is_callable', 'is_hookable', 'is_hooked'):
        try:
            info[name] = bool(getattr(self_obj, name)())
        except Exception:
            info[name] = None
    info['trampoline'] = 'not exposed by memory_wrap.cpp'
    info['args'] = 'not exposed by memory_wrap.cpp'
    info['convention'] = 'not exposed by memory_wrap.cpp'
    return info


def _entry(self_obj):
    """The record for this function address, created on first sight.

    Keyed by the function's own address. Two MemberFunction objects at one
    address are the same call target, and keying by id(self) would require
    holding the objects alive to keep the key valid.
    """
    described = _describe(self_obj, self_obj)
    address = described['address']
    entry = _RECORDS.get(address)
    if entry is None:
        entry = {
            'address': address,
            'first_seen': time.time(),
            'calls': 0,
            'faults': 0,
            'last_error': None,
            'last_fault': None,
        }
        entry.update(described)
        _RECORDS[address] = entry
    return entry


def _record_call(self_obj):
    entry = _entry(self_obj)
    entry['calls'] += 1
    _TOTALS['calls'] += 1
    return entry


def _record_fault(self_obj, error):
    entry = _entry(self_obj)
    address = entry['address']
    entry['faults'] += 1
    _TOTALS['faults'] += 1
    entry['last_error'] = '%s: %s' % (type(error).__name__, error)
    entry['last_fault'] = time.time()

    message = entry['last_error']
    key = (address, message)
    seen = _FAULT_KEYS.get(key, 0)
    _FAULT_KEYS[key] = seen + 1

    if seen < FULL_LIMIT:
        _say("FAULT #%d  function address 0x%X" % (seen + 1, address))
        _say("    this       : 0x%X" % entry.get('this', 0))
        _say("    location   : %s" % _where(address))
        _say("    error      : %s" % message)
        _say("    return type: %s" % entry.get('_type_name', '?'))
        for key_name in ('is_callable', 'is_hookable', 'is_hooked'):
            _say("    %-12s: %s" % (key_name, entry.get(key_name)))
        _say("    arguments  : %s" % entry.get('args', 'n/a'))
        _say("    convention : %s" % entry.get('convention', 'n/a'))
        _say("    traceback  :")
        for line in traceback.format_exc().rstrip().splitlines():
            _say("      %s" % line)
    elif seen == FULL_LIMIT:
        _say("FAULT (further identical ones counted only): function 0x%X  %s"
             % (address, message))
    return entry


_FAULT_KEYS = {}

# Recent calls, per function address, plus two counters under string keys. The
# strings cannot collide with an address because an address is always an int,
# and _ring_flush skips anything that is not.
_RINGS = {}
_CALLS_PATH = None


def _render_argument(value):
    """One argument, as text, without guessing what it is.

    A Pointer becomes its address in hex, because that is the only thing
    interesting about it and repr() of a CPointer says nothing. Everything else
    is str()'d, and anything that raises is reported as such rather than
    allowed to escape - a logging path must not be the thing that breaks.
    """
    try:
        from memory import Pointer
    except Exception:
        Pointer = None
    try:
        if Pointer is not None and isinstance(value, Pointer):
            address = int(value)
            return "Pointer(0x%X)" % address
    except Exception as error:
        return "<unreadable Pointer: %s>" % type(error).__name__
    try:
        return repr(value)
    except Exception as error:
        return "<unreprable: %s>" % type(error).__name__


def _record_arguments(self_obj, args, name):
    """Note what is about to be passed, before the call happens.

    This is deliberately before the call rather than after. The crash this
    plugin exists to explain does not arrive as a Python exception - sp_console
    recorded zero faults across three runs while the process died - so anything
    written after the call is never written. Recording the arguments first
    means the last entry describes the call that was in flight when the process
    went, which is the only record of it that will exist.

    The declared argument types are not available: memory_wrap.cpp does not
    expose m_tArgs, and getting that wrong twice already produced a log full of
    None. What is logged is what was actually passed.
    """
    if not args:
        return
    address = _address_of(self_obj)
    line = "CALL  %-14s func 0x%X  this 0x%X  args(%d): %s" % (
        name, address, _this_of(self_obj), len(args),
        ", ".join(_render_argument(a) for a in args))
    _ring_append(address, line)
    _ring_maybe_flush()


def _ring_append(address, line):
    """Keep the most recent calls for one function address, in memory."""
    ring = _RINGS.get(address)
    if ring is None:
        ring = []
        _RINGS[address] = ring
    ring.append(line)
    if len(ring) > RING_PER_FUNCTION:
        del ring[0:len(ring) - RING_PER_FUNCTION]
    if len(ring) == 1:
        # first call at this address: the log is worth writing now
        _RINGS['__new__'] = True
    _RINGS['__total__'] = _RINGS.get('__total__', 0) + 1


def _ring_maybe_flush():
    """Rewrite the tail to disk, but not on every single call.

    The flush is what makes the file current at the instant of a hard kill, so
    it cannot be deferred: the call being looked for is the last one, and
    batching on a count loses exactly that. The three cadences tried are
    compared in the note beside RING_PER_FUNCTION.
    """
    # The last call must be on disk before the process can die, so the rewrite
    # happens on the way out of the call rather than on a count. Measured over
    # 2000 calls at one address that costs 1.0 line per call - the same as
    # logging the call unconditionally - but with the file bounded at
    # RING_PER_FUNCTION entries instead of growing without limit, which is the
    # property that matters. An earlier version batched on a count of 64 and
    # wrote 0.42 lines per call, but then the final calls before a hard kill
    # were missing from the file, which defeats the entire purpose: the call
    # being looked for is the last one.
    _ring_flush()


def _ring_flush():
    """Rewrite the retained calls to a file of their own, replacing it.

    Deliberately not _say. The retained set is rewritten in full on every call,
    so appending it to the running log made the file grow without bound even
    though memory stayed small - 26.9 lines per call measured over 2000 calls,
    against a ring that never held more than 24. The transcript in
    sp_console.log is for faults and for the report; this is a snapshot, and a
    snapshot belongs in a file that is replaced rather than appended to, so what
    is on disk after a hard kill is exactly the last RING_PER_FUNCTION calls.

    It is opened, written and closed per flush. That is a few hundred writes a
    second at the per-tick rate, which is cheap next to the game loop, and it
    means nothing is left buffered when the process dies.
    """
    addresses = sorted(a for a in _RINGS if isinstance(a, int))
    addresses = [a for a in addresses if _RINGS[a]]
    _RINGS['__new__'] = False
    if not addresses:
        return
    retained = sum(len(_RINGS[a]) for a in addresses)
    try:
        handle = open(_calls_path(), "w", encoding="utf-8", errors="replace")
    except Exception as error:
        # Once, and to the main log: a snapshot that cannot be written is worth
        # saying, but not worth saying on every call.
        _say("cannot write the recent-calls file: %s: %s"
             % (type(error).__name__, error))
        return
    try:
        handle.write("RECENT CALLS  %d retained over %d function(s), "
                     "%d calls total\n"
                     % (retained, len(addresses), _TOTALS['calls']))
        for address in addresses:
            ring = _RINGS[address]
            handle.write("--- func 0x%X   %s   last %d of %d calls\n"
                         % (address, _where(address), len(ring),
                            _RECORDS.get(address, {}).get('calls', 0)))
            for line in ring:
                handle.write("    %s\n" % line)
    finally:
        handle.close()


def _calls_path():
    """Where the recent-calls snapshot goes, beside the main log."""
    if _CALLS_PATH:
        return _CALLS_PATH
    base = _PATH or ""
    folder = os.path.dirname(base) if base else os.getcwd()
    return os.path.join(folder, "sp_console_calls.log")


def _record_result(self_obj, result, name):
    """Note what came back, for the calls that return something."""
    if result is None:
        return
    try:
        if type(result).__name__ == 'NoneType':
            return
    except Exception:
        pass
    address = _address_of(self_obj)
    _say("RET   %-14s func 0x%X  -> %s" % (
        name, address, _render_argument(result)))


def _address_of(self_obj):
    try:
        return int(self_obj._function) if self_obj._function else 0
    except Exception:
        return 0


def _this_of(self_obj):
    try:
        return int(self_obj._this) if self_obj._this else 0
    except Exception:
        return 0


def _read_pointer(address):
    """Read a pointer out of the game's memory, without faulting.

    ctypes.string_at is used rather than a Pointer from the memory module so
    that this does not go through the code path being instrumented - a Pointer
    read that went through MemberFunction would recurse straight back into this
    wrapper. string_at raises on an unreadable address rather than crashing,
    which is what makes it safe to point at an address that may well be -1.
    """
    try:
        import ctypes
        raw = ctypes.string_at(address, 8)
        return int.from_bytes(raw, "little")
    except Exception:
        return None


def _is_bad_pointer(value):
    """Whether a value cannot be the address of a real object.

    Three values, and all three have to be named rather than lumped together:
    0 is a null pointer, -1 is a signed reading of an all-ones word, and
    0xFFFFFFFFFFFFFFFF is the same 64 bits read as unsigned. Which one arrives
    depends on whether the address came from int(Pointer) or from
    int.from_bytes, so the check accepts any of them. A guard that only tested
    `value in (0, -1)` let the all-ones form straight through, which is exactly
    the value in the three crash dumps.
    """
    return value in (0, -1, 0xFFFFFFFFFFFFFFFF)


def _describe_pointer(value):
    """Name a bad pointer value precisely, since the distinction is the point."""
    if value == 0:
        return "0 (null)"
    if value == -1:
        return "0xFFFFFFFFFFFFFFFF (-1, read as signed)"
    if value == 0xFFFFFFFFFFFFFFFF:
        return "0xFFFFFFFFFFFFFFFF (all ones, read as unsigned)"
    return "0x%X" % value


def _check_target(self_obj, args, name):
    """Report, and refuse, a call whose receiver is not a real object.

    Returns True when the call was refused, so the caller can skip it.

    `this` is read through _this_of, which does int(self_obj._this) and yields 0
    both for a null pointer and for anything unreadable. That conflation is why
    an unreadable receiver is refused as "this is 0" rather than reported
    separately - there is no way to tell the two apart from here, and calling
    either is equally fatal. The vtable read is not conflated in that way,
    because _read_pointer returns None on failure and None is distinguishable
    from both 0 and -1.

    Three runs died at core.dll+0x48DBF2, a `call qword ptr [rax+8]`, with rax
    holding 0xFFFFFFFFFFFFFFFF. That is not a wild address the call wandered
    into - it is the value stored where the vtable pointer belongs, so the
    object being called on has an all-ones vtable pointer. The same value also
    appears as ExceptionInformation[1] in all three minidumps.

    Meanwhile 607 calls of index 171 (get_solid_mask, this + no arguments)
    completed and returned 0x200400B = MASK_SOLID, and 8 calls of index 427
    (PlayerRunCommand, this + two pointers) also returned. So the DC_POINTER
    truncation is fixed and the remaining crash is a bad receiver, not a
    truncated address.

    What is refused is a call whose `this` is 0 or -1, or whose first word -
    the vtable pointer - reads as 0 or -1. Such a call cannot do anything
    useful; on this build it takes the process down. Refusing it keeps the
    server alive long enough to be talked to, and the report says which object
    and which function, which is the thing being looked for.

    The vtable is read but nothing else is touched. No engine memory is written
    and no valid call is skipped.
    """
    this = _this_of(self_obj)
    address = _address_of(self_obj)
    bad = None
    if _is_bad_pointer(this):
        bad = "this is %s" % _describe_pointer(this)
    else:
        vtable = _read_pointer(this)
        if vtable is None:
            bad = "the vtable pointer at 0x%X could not be read" % this
        elif _is_bad_pointer(vtable):
            bad = "vtable pointer at 0x%X is %s" % (this, _describe_pointer(vtable))
    if bad is None:
        return False

    entry = _entry(self_obj)
    key = (address, bad)
    seen = _BLOCKED.get(key, 0)
    _BLOCKED[key] = seen + 1
    _TOTALS['blocked'] = _TOTALS.get('blocked', 0) + 1

    if seen < FULL_LIMIT:
        _say("BLOCKED #%d  not calling func 0x%X" % (seen + 1, address))
        _say("    reason     : %s" % bad)
        _say("    location   : %s" % _where(address))
        _say("    return type: %s" % entry.get('_type_name', '?'))
        _say("    arguments  : %s" % (", ".join(_render_argument(a) for a in args)
                                       or "(none)"))
        _say("    convention : %s" % entry.get('convention', 'n/a'))
        _say("    traceback  :")
        for line in traceback.format_exc().rstrip().splitlines():
            _say("      %s" % line)
    elif seen == FULL_LIMIT:
        _say("BLOCKED (further identical ones counted only): func 0x%X  %s"
             % (address, bad))
    return True


_BLOCKED = {}


def _make_wrapper(name, original):
    def wrapper(self_obj, *args):
        _record_call(self_obj)
        if _check_target(self_obj, args, name):
            # Refused, so there is no return value to report. None is the
            # honest answer: the function was never entered, and inventing a
            # zero for it would let a caller carry on as if it had run.
            return None
        _record_arguments(self_obj, args, name)
        try:
            result = original(self_obj, *args)
        except Exception as error:
            _record_fault(self_obj, error)
            raise
        _record_result(self_obj, result, name)
        return result
    wrapper.__name__ = name
    wrapper.__doc__ = ("instrumented by sp_console; original was %s"
                       % getattr(original, '__name__', '?'))
    return wrapper


def _install():
    """Wrap the call paths, one at a time, so a failure names itself."""
    try:
        from memory.helpers import MemberFunction
    except Exception as error:
        _say("cannot import MemberFunction: %s: %s"
             % (type(error).__name__, error))
        return False

    for name in ('__call__', 'call_trampoline', 'skip_hooks'):
        original = getattr(MemberFunction, name, None)
        if original is None:
            _say("MemberFunction has no %s - skipped" % name)
            continue
        try:
            setattr(MemberFunction, name, _make_wrapper(name, original))
            _orig[name] = original
            _installed.append(name)
            _say("instrumented MemberFunction.%s" % name)
        except Exception as error:
            _say("could not instrument MemberFunction.%s: %s: %s"
                 % (name, type(error).__name__, error))
    return bool(_installed)


def _uninstall():
    # _installed is rebound at the end of this function, so without this
    # statement Python treats the name as local throughout and the loop below
    # raises UnboundLocalError - which is exactly what the test caught, and it
    # would have broken "sp plugin unload sp_console".
    global _installed
    try:
        from memory.helpers import MemberFunction
    except Exception:
        return
    for name in list(_installed):
        original = _orig.get(name)
        if original is None:
            continue
        try:
            setattr(MemberFunction, name, original)
            _say("restored MemberFunction.%s" % name)
        except Exception as error:
            _say("could not restore MemberFunction.%s: %s: %s"
                 % (name, type(error).__name__, error))
    _installed = []


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------
def _heartbeat(force=False):
    global _last_heartbeat
    now = time.time()
    if not force and (now - _last_heartbeat) < HEARTBEAT:
        return
    _last_heartbeat = now
    if _TOTALS['faults']:
        _say("still faulting: %d calls, %d faults across %d distinct "
             "function address(es)" % (_TOTALS['calls'], _TOTALS['faults'],
                                       len(_RECORDS)))


def _report():
    _section("SUMMARY")
    up = int(time.time() - _TOTALS['load'])
    _say("  uptime of this plugin : %d s" % up)
    _say("  instrumented calls    : %d" % _TOTALS['calls'])
    _say("  faults                : %d" % _TOTALS['faults'])
    _say("  refused (bad object)  : %d" % _TOTALS['blocked'])
    _say("  distinct addresses    : %d" % len(_RECORDS))
    _say("  log file              : %s" % (_PATH or "unavailable"))

    faulted = [r for r in _RECORDS.values() if r['faults']]
    calm = [r for r in _RECORDS.values() if not r['faults']]

    _section("FUNCTIONS THAT FAULTED  (%d)" % len(faulted))
    if not faulted:
        _say("  none")
    for entry in sorted(faulted, key=lambda r: -r['faults']):
        _say("")
        _say("  address 0x%X   calls %d   faults %d"
             % (entry['address'], entry['calls'], entry['faults']))
        _say("    this        : 0x%X" % entry.get('this', 0))
        _say("    location    : %s" % _where(entry['address']))
        _say("    this ptr    : %s" % _where(entry.get('this', 0)))
        _say("    return type : %s" % entry.get('_type_name', '?'))
        for key_name in ('is_callable', 'is_hookable', 'is_hooked'):
            _say("    %-12s : %s" % (key_name, entry.get(key_name)))
        _say("    arguments   : %s" % entry.get('args', 'n/a'))
        _say("    convention  : %s" % entry.get('convention', 'n/a'))
        _say("    last error  : %s" % entry.get('last_error'))

    _section("FUNCTIONS THAT DID NOT FAULT  (%d)" % len(calm))
    _say("  listed so the faulting one can be recognised by what is absent")
    for entry in sorted(calm, key=lambda r: -r['calls'])[:40]:
        _say("    0x%X  calls %-8d this 0x%X  %s"
             % (entry['address'], entry['calls'], entry.get('this', 0),
                _where(entry['address'])))

    _section("END OF REPORT")


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
def _register_commands():
    from commands.server import server_command_manager

    def _report_command(*args, **kwargs):
        _report()

    def _modules_command(*args, **kwargs):
        _section("LOADED MODULES")
        for base, size, name in sorted(_module_table()):
            mark = ""
            for entry in _RECORDS.values():
                if base <= entry['address'] < base + max(size, 1):
                    mark = "   <== used by an instrumented function"
            _say("  0x%016X  %10d  %s%s" % (base, size, name, mark))

    def _reset_command(*args, **kwargs):
        _RECORDS.clear()
        _FAULT_KEYS.clear()
        # The retained calls are part of the state being reset. Leaving them
        # would mean a later report shows calls from before the reset, with
        # counters claiming they happened after it.
        _RINGS.clear()
        _BLOCKED.clear()
        _TOTALS['calls'] = 0
        _TOTALS['faults'] = 0
        _TOTALS['blocked'] = 0
        _TOTALS['load'] = time.time()
        _say("counters, retained calls and refusals reset")

    for name, help_text, callback in (
        ('sp_console', 'sp_console report.',
         _report_command),
        ('sp_console_modules', 'Loaded modules and which ones are instrumented.',
         _modules_command),
        ('sp_console_reset', 'Reset the call and fault counters.',
         _reset_command),
    ):
        try:
            server_command_manager.register_commands(name, callback)
            _say("registered %s" % name)
        except Exception as error:
            _say("could not register %s: %s: %s"
                 % (name, type(error).__name__, error))


# ---------------------------------------------------------------------------
# entry points
# ---------------------------------------------------------------------------
def load():
    """SP plugin entry point."""
    global _last_heartbeat
    if _LOG is None:
        _open()
    _last_heartbeat = time.time()
    _say("")
    _say("### sp_console loaded at %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    _say("    log file    : %s" % _PATH)
    try:
        import platform as _platform
        import sys
        _say("    platform    : %s   python %s   pointer width %d bits"
             % (_platform.system().lower(), sys.version.split()[0],
                64 if sys.maxsize > 2 ** 32 else 32))
    except Exception:
        pass
    ok = _install()
    _say("    instrumented: %s" % (', '.join(_installed) if ok else "NOTHING"))
    _register_commands()
    _section("LOADED MODULES AT STARTUP")
    for base, size, name in sorted(_module_table()):
        _say("  0x%016X  %10d  %s" % (base, size, name))
    _say("")
    _say('run "sp_console" for the report, "sp_console_modules" for addresses.')
    _heartbeat(force=True)


def unload():
    _heartbeat(force=True)
    _report()
    _uninstall()
    if _LOG is not None:
        try:
            _LOG.flush()
            _LOG.close()
        except Exception:
            pass
    print("sp_console unloaded")

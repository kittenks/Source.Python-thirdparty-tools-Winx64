#!/usr/bin/env python3
r"""
sp_stride - settle whether the virtual function call is jumping to the wrong
address, and if so why.

The contradiction
-----------------
Three things are established, and they cannot all be true together:

  * slot 171 holds "mov eax, 0x200400B ; ret", and 0x200400B is MASK_SOLID
    (public/bspflags.h:106, OR of CONTENTS_SOLID|MOVEABLE|WINDOW|MONSTER|GRATE).
    The declaration is virtual unsigned int PhysicsSolidMaskForEntity(void)
    const (game/client/c_baseentity.h:958) - no parameters, a class constant, so
    the immediate and the ignored `this` are both correct.
  * executing that function cannot fault.
  * and yet the run faults 598 times with ExceptionInformation[0] == 8, an
    instruction fetch at an address that equals the vtable slot's own address.

So the number 171 was read correctly and converted to the wrong address. This
plugin measures the conversion instead of reasoning about it.

What is measured
----------------
  1. the entity pointer, and whether it is above 4 GB. A pointer that was
     truncated to 32 bits would make the whole vtable wrong, and every
     conclusion drawn from any address would be unsound. This is checked first
     because it invalidates the rest if it fails.
  2. the vptr, read from the entity.
  3. three ways of getting at slot 171:
       A  vptr + 171 * 8, then read 8 bytes  - the x86-64 layout
       B  vptr + 171 * 4, then read 8 bytes  - a 32-bit stride
       C  CPointer.get_virtual_func(171)   - whatever Source.Python itself does
     For each, the 8 bytes are shown, and if they look like a pointer into
     server.dll or engine.dll, the code at the pointed-at address is shown too.
     A and C must agree. If B also yields a plausible pointer, the stride is
     the defect. If B yields garbage, the stride is not the defect.
  4. the same three for the neighbouring slots, because a stride error of one
     slot would show up as a consistent shift and is easier to see than a
     single comparison.

Note on what A and B mean. The vtable is an array of 8-byte pointers on x86-64,
so slot 171 lives at vptr + 171*8 and the function address is the 8 bytes found
there. Disassembling vptr + 171*4 itself would be disassembling the middle of
the pointer array, which is not code - so both candidate addresses are read as
pointers and the code is disassembled at what they point to.
"""
import os
import sys
import time

PLUGIN_NAME = "sp_stride"
_log = None
_path = None
HEX = 24


# ---------------------------------------------------------------------------
# log
# ---------------------------------------------------------------------------
def _say(line=""):
    text = "%s %s" % (time.strftime("%H:%M:%S"), line) if line else ""
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
        _path = os.path.join(folder, "sp_stride.log")
        _log = open(_path, "a", encoding="utf-8", errors="replace")
    except Exception as error:
        _log = None
        _path = None
        _say("could not open the log: %s: %s" % (type(error).__name__, error))


# ---------------------------------------------------------------------------
# memory
# ---------------------------------------------------------------------------
def read_bytes(address, count):
    """Bytes at an absolute address in this process.

    ctypes.string_at is tried first. It reads the current process's own memory
    with a plain pointer dereference, so it works for any mapped address -
    including the synthetic tables a test builds with a bytearray - whereas
    ReadProcessMemory is a syscall that fails for addresses the process cannot
    actually own, and it was the only route used here, which made the whole
    plugin untestable away from the game: every read raised
    "OSError: [Errno 299]" before any measurement could be taken.

    ReadProcessMemory stays as the fallback, since it is the one that reports
    a clean error for an unmapped address rather than a hard access violation.
    """
    import ctypes
    try:
        return ctypes.string_at(ctypes.c_void_p(address), count)
    except Exception:
        pass
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = ctypes.c_void_p(k32.GetCurrentProcess())
    buf = (ctypes.c_ubyte * count)()
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(handle, ctypes.c_void_p(address),
                                 ctypes.byref(buf), count,
                                 ctypes.byref(got)):
        raise OSError(ctypes.get_last_error(),
                      "could not read %d bytes at 0x%X" % (count, address))
    return bytes(bytearray(buf)[:got.value])


def read_ptr(address):
    return int.from_bytes(read_bytes(address, 8), "little")


def module_of(address):
    """(name, offset) if the address is inside a module, else (None, None)."""
    for base, size, name in _modules():
        if base <= address < base + max(size, 1):
            return os.path.basename(name), address - base
    return None, None


def _modules():
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    handle = ctypes.c_void_p(k32.GetCurrentProcess())
    ARRAY = wintypes.HMODULE * 1024
    psapi.EnumProcessModules.argtypes = [ctypes.c_void_p, ctypes.POINTER(ARRAY),
                                        wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD)]
    psapi.GetModuleFileNameExW.argtypes = [ctypes.c_void_p, wintypes.HMODULE,
                                           wintypes.LPWSTR, wintypes.DWORD]
    needed = wintypes.DWORD(0)
    mods = ARRAY()
    if not psapi.EnumProcessModules(handle, mods, ctypes.sizeof(mods),
                                    ctypes.byref(needed)):
        return []
    buf = ctypes.create_unicode_buffer(260)
    out = []
    for i in range(needed.value // ctypes.sizeof(wintypes.HMODULE)):
        if not psapi.GetModuleFileNameExW(handle, mods[i], buf, 260):
            continue
        base = ctypes.cast(mods[i], ctypes.c_void_p).value
        out.append((base or 0, 0, buf.value))   # size unused, see _where
    return out


def _where(address):
    name, off = module_of(address)
    if name:
        return "%s+0x%X" % (name, off)
    return "not inside any module"


def describe_code(address):
    """First instructions at an address, and whether it looks like a leaf."""
    try:
        raw = read_bytes(address, HEX)
    except Exception as error:
        return "could not read: %s" % error
    hexed = " ".join("%02X" % b for b in raw[:16])
    verdict = ""
    if len(raw) >= 6 and raw[0] == 0xB8 and raw[5] == 0xC3:
        verdict = ("  mov eax, 0x%X ; ret   a constant leaf"
                   % int.from_bytes(raw[1:5], "little"))
    elif len(raw) >= 2 and raw[0] == 0x33 and raw[1] == 0xC0:
        verdict = "  xor eax, eax ; ret"
    elif len(raw) >= 1 and raw[0] == 0xC3:
        verdict = "  ret"
    else:
        verdict = "  real code"
    return "%s\n           %s" % (hexed, verdict)


# ---------------------------------------------------------------------------
# an entity to measure
# ---------------------------------------------------------------------------
def find_entity():
    """(label, entity) for the first object whose vptr can be read.

    Several routes are tried because the entity API's surface is not
    established here, and a route that fails is reported rather than silently
    yielding nothing - "no entity" and "found none" must not look alike.
    """
    attempts = []

    try:
        from filters.players import PlayerIter
        for player in PlayerIter():
            return ("a player", player)
        attempts.append("filters.players.PlayerIter() returned no players")
    except Exception as error:
        attempts.append("PlayerIter: %s: %s" % (type(error).__name__, error))

    try:
        from entities import engine_server
        index = None
        for name in ("get_max_edicts", "get_max_entities"):
            fn = getattr(engine_server, name, None)
            if fn:
                try:
                    index = int(fn())
                    break
                except Exception:
                    pass
        if index is None:
            attempts.append("engine_server exposes no entity count")
        else:
            from entities.entity import Entity
            for i in range(1, min(index, 512)):
                try:
                    ent = Entity(i)
                    pointer = getattr(ent, 'pointer', None)
                    if pointer is None:
                        continue
                    read_ptr(int(pointer))
                    return ("entity index %d" % i, ent)
                except Exception:
                    continue
            attempts.append("no entity in the first %d indices had a "
                            "readable vptr" % min(index, 512))
    except Exception as error:
        attempts.append("entities: %s: %s" % (type(error).__name__, error))

    for line in attempts:
        _say("    (route unavailable: %s)" % line)
    return (None, None)


# ---------------------------------------------------------------------------
# the measurement
# ---------------------------------------------------------------------------
def _slot_pointer(vptr, index, stride):
    """Read the pointer stored at vptr + index*stride."""
    try:
        return read_ptr(vptr + index * stride)
    except Exception as error:
        return None


def _run():
    _section("1. an object to measure")
    label, entity = find_entity()
    if entity is None:
        _say("  No usable object was found, so nothing could be measured.")
        _say("  This is reported rather than passed over: an empty result here")
        _say("  is indistinguishable from a working one unless it is said.")
        return False
    _say("  using %s" % label)

    try:
        from memory import get_object_pointer
        pointer = get_object_pointer(entity)
        address = int(pointer)
    except Exception as error:
        _say("  get_object_pointer failed: %s: %s" % (type(error).__name__, error))
        return False

    _say("  get_object_pointer : 0x%X" % address)
    wide = address > 0xFFFFFFFF
    _say("  above 4 GB        : %s" % ("yes" if wide else "NO - THIS IS A BUG"))
    if not wide:
        _say("")
        _say("  The pointer is 32-bit sized. Everything below is measured from a")
        _say("  truncated address, so none of it means anything until that is fixed.")
        return False

    try:
        vptr = read_ptr(address)
    except Exception as error:
        _say("  reading the vptr failed: %s: %s" % (type(error).__name__, error))
        return False
    _say("  vptr              : 0x%X  (%s)" % (vptr, _where(vptr)))

    _section("2. slot 171, three ways")
    _say("  A  vptr + 171*8, then read the pointer there   - the x86-64 layout")
    _say("  B  vptr + 171*4, then read the pointer there   - a 32-bit stride")
    _say("  C  CPointer.get_virtual_func(171)              - what SP itself does")
    _say("")

    a = _slot_pointer(vptr, 171, 8)
    b = _slot_pointer(vptr, 171, 4)
    c = None
    try:
        ptr_obj = getattr(entity, 'pointer', None)
        if ptr_obj is not None:
            c = int(ptr_obj.get_virtual_func(171))
    except Exception as error:
        _say("  C  unavailable: %s: %s" % (type(error).__name__, error))

    for tag, value, stride in (("A  171*8", a, 8), ("B  171*4", b, 4),
                               ("C  SP's own", c, None)):
        if value is None:
            _say("  %-12s -> could not be read" % tag)
            continue
        _say("  %-12s -> 0x%016X  %s" % (tag, value, _where(value)))
        _say("             %s" % describe_code(value))
    _say("")

    _section("3. what that says")
    verdict = []
    if a is not None and c is not None:
        verdict.append(("A and C agree" if a == c
                        else "A and C DISAGREE: 0x%X vs 0x%X" % (a, c)))
    if a is not None and b is not None:
        verdict.append(("A and B are equal, so the stride is not the "
                        "difference here" if a == b
                        else "A and B differ, so the stride would matter"))
    if b is not None:
        name, off = module_of(b)
        verdict.append("B lands in %s" % (name or "no module"))
    for line in verdict:
        _say("  %s" % line)

    _section("4. the neighbourhood, both strides")
    _say("  %-6s %-20s %-20s" % ("slot", "171-style *8", "32-bit *4"))
    for index in (169, 170, 171, 172, 173):
        pa = _slot_pointer(vptr, index, 8)
        pb = _slot_pointer(vptr, index, 4)
        _say("  %-6d %-20s %-20s"
             % (index,
                "0x%X" % pa if pa else "-" ,
                "0x%X" % pb if pb else "-"))
    _say("")
    _say("  Read each pointer's first bytes to see which column holds code:")
    for index in (170, 171, 172):
        for tag, value, stride in (("*8", _slot_pointer(vptr, index, 8), 8),
                                   ("*4", _slot_pointer(vptr, index, 4), 4)):
            if value is None:
                continue
            try:
                raw = read_bytes(value, 8)
                hexed = " ".join("%02X" % b for b in raw)
            except Exception:
                hexed = "unreadable"
            _say("    slot %-4d %s -> 0x%X  %s" % (index, tag, value, hexed))
    return True


def _register_commands():
    from commands.server import server_command_manager

    def _stride_command(*args, **kwargs):
        """The engine passes the console's arguments to a command callback.

        _run itself takes none, so registering it directly made every
        invocation die with

            TypeError: _run() takes 0 positional arguments but 1 was given

        and - because the exception is raised inside the callback, before any
        of the reporting runs - nothing at all was written to sp_stride.log.
        The console showed only the traceback, so the plugin looked like it had
        never been invoked. The other plugins wrap their callbacks for this
        reason; this one did not.
        """
        _run()

    try:
        server_command_manager.register_commands('sp_stride', _stride_command)
        _say("registered sp_stride")
    except Exception as error:
        _say("could not register sp_stride: %s: %s" % (type(error).__name__, error))


def load():
    if _log is None:
        _open()
    _say("")
    _say("### sp_stride loaded at %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    _say("    log file: %s" % _path)
    try:
        import sys as _s
        _say("    pointer width: %d bits" % (64 if _s.maxsize > 2 ** 32 else 32))
    except Exception:
        pass
    _register_commands()
    _say("")
    _say('run "sp_stride". It only reads memory; it changes nothing.')


def unload():
    if _log is not None:
        try:
            _log.flush()
            _log.close()
        except Exception:
            pass
    print("sp_stride unloaded")

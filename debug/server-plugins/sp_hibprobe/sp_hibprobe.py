#!/usr/bin/env python3
r"""
sp_hibprobe - one-shot: resolve CServerGameDLL::SetServerHibernation the same
way listeners.__init__ does, then dump the REAL target address, its module +
RVA, and the first bytes of the prologue so the "Terminating control flow
appears before the detour boundary" failure can be explained. Read-only.
"""
import ctypes
import os
import time

PLUGIN_NAME = "sp_hibprobe"


def read_bytes(address, count):
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = ctypes.c_void_p(k32.GetCurrentProcess())
    buf = (ctypes.c_ubyte * count)()
    got = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(address),
                               ctypes.byref(buf), count, ctypes.byref(got))
    if not ok:
        raise OSError(ctypes.get_last_error(), "ReadProcessMemory failed")
    return bytes(bytearray(buf)[:got.value])


def module_of(address):
    """(module file name, allocation base) for an address via VirtualQuery."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)

    class MBI(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", ctypes.c_ulong),
            ("__a", ctypes.c_ulong),
            ("RegionSize", ctypes.c_size_t),
            ("State", ctypes.c_ulong),
            ("Protect", ctypes.c_ulong),
            ("Type", ctypes.c_ulong),
            ("__b", ctypes.c_ulong),
        ]
    mbi = MBI()
    if not k32.VirtualQuery(ctypes.c_void_p(address), ctypes.byref(mbi),
                            ctypes.sizeof(mbi)):
        return ("?", 0)
    base = mbi.AllocationBase or mbi.BaseAddress
    buf = ctypes.create_unicode_buffer(2048)
    psapi.GetMappedFileNameW(k32.GetCurrentProcess(), ctypes.c_void_p(base),
                             buf, 2048)
    name = buf.value.replace("\\", "/").split("/")[-1] if buf.value else "?"
    return (name, base or 0)


def _log_path():
    try:
        from paths import LOG_PATH
        return str(LOG_PATH / "sp_hibprobe.log")
    except Exception:
        return os.path.join(os.getcwd(), "cstrike", "logs",
                            "source-python", "sp_hibprobe.log")


def run():
    out = []
    def say(s=""):
        out.append("%s %s" % (time.strftime("%H:%M:%S"), s))

    say("==== sp_hibprobe ====")
    try:
        from memory import (get_virtual_function, get_object_pointer,
                            get_function_info)
        from engines.server import server_game_dll
    except Exception as e:
        say("import failed %s: %s" % (type(e).__name__, e))
        _flush(out)
        return

    try:
        info = get_function_info(server_game_dll, "SetServerHibernation")
        say("is_virtual=%s vtable_index=%s vtable_offset=%s"
            % (info.is_virtual, info.vtable_index, info.vtable_offset))
        idx = int(info.vtable_index)

        obj = get_object_pointer(server_game_dll)
        say("object pointer = 0x%016X" % int(obj))
        # get_virtual_func(index) returns a Pointer to the slot's real target.
        slot = obj.get_virtual_func(idx)
        real = int(slot)
        mname, base = module_of(real)
        say("vtable[%d] -> 0x%016X  [%s+0x%X]"
            % (idx, real, mname, (real - base) if base else 0))

        raw = read_bytes(real, 48)
        say("prologue bytes:")
        for off in range(0, len(raw), 16):
            chunk = raw[off:off + 16]
            say("  +%02X  %s" % (off, " ".join("%02X" % b for b in chunk)))

        # Also report what the Function object resolves to and whether add_hook
        # (the detour build) raises here.
        f = get_virtual_function(server_game_dll, "SetServerHibernation")
        say("Function object = %r  f.address=0x%016X" % (f, int(f.address)))
    except Exception as e:
        say("ERROR %s: %s" % (type(e).__name__, e))
    _flush(out)


def _flush(out):
    try:
        path = _log_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8", errors="replace") as fh:
            fh.write("\n".join(out) + "\n")
    except Exception:
        pass
    try:
        from core import echo_console
        for line in out:
            echo_console("[%s] %s" % (PLUGIN_NAME, line))
    except Exception:
        pass


def load():
    run()


def unload():
    pass

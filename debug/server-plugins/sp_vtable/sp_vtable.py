#!/usr/bin/env python3
r"""
Record who reads a virtual-function property, and what index it asked for.

Why this exists
---------------
The faults are at vtable index 171, byte offset 1368, confirmed by walking the
contiguous pointer runs in .rdata. No [[virtual_function]] entry in the data
tree declares that offset, so the property being read is not one the ini
declares. That leaves the question the traceback cannot answer: which Python
code touches it.

The traceback in logs/sp_console.log stops at

    File ".../memory/helpers.py", line 353, in __call__
      return super().__call__(self._this, *args)

because the caller above that is C++ (the hook/call dispatcher). Instrumenting
__call__ - which is what sp_console does - therefore always reports from below
the interesting frame. The read happens higher up: TypeManager.virtual_function
returns a property whose fget constructs the MemberFunction and calls it. So the
fget is the frame worth wrapping.

How it works
------------
TypeManager.virtual_function is replaced with a wrapper that calls the original
to get the property, then returns a new property whose fget records the index,
the this pointer, and the Python stack before delegating to the original fget.
The original is otherwise untouched: same arguments, same return type, same
convention, same doc. If the wrapper cannot be installed the plugin says so
rather than silently doing nothing.

Every read is recorded, not just the failing one, because a property may be read
many times before it faults and the reader can differ between calls. Records are
keyed by index so a repeated read of the same slot is counted rather than
re-listed.
"""
import inspect
import os
import sys
import time
import traceback

PLUGIN_NAME = "sp_vtable"

# index -> record
_RECORDS = {}
# (index, site) -> times seen, so the same reader is not re-listed
_SEEN = {}

_log = None
_path = None
_original = None
_installed = False


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
        _path = os.path.join(folder, "sp_vtable.log")
        _log = open(_path, "a", encoding="utf-8", errors="replace")
    except Exception as error:
        _log = None
        _path = None
        _say("could not open the log: %s: %s" % (type(error).__name__, error))


def _say(line):
    text = "%s %s" % (time.strftime("%H:%M:%S"), line)
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


def _describe_site():
    """The Python frames above this plugin, which is what we actually want.

    Frames belonging to this file and to the memory package are dropped: they are
    the plumbing between the read and the call, and leaving them in would bury
    the reader.
    """
    out = []
    for frame in traceback.extract_stack()[:-1]:
        name = os.path.basename(frame.filename)
        if name == os.path.basename(__file__):
            continue
        if name in ("manager.py", "helpers.py", "__init__.py"):
            continue
        if "source-python" in frame.filename and "packages" in frame.filename:
            # A package frame that is not one of the two plumbing modules is
            # worth keeping: that is the caller.
            pass
        out.append("%s:%d in %s" % (name, frame.lineno, frame.name))
    return out[-8:]


def _make_fget(inner, index, args, return_type, convention):
    def fget(ptr):
        site = tuple(_describe_site())
        # The attribute name. Without it the report says "600 reads of index
        # 171" and nothing more, which does not identify anything actionable -
        # the whole point is to learn WHICH entity property is being read. The
        # name is not passed into virtual_function by the type manager, so it is
        # recovered from the frame below: entities._base.BaseEntity.__getattr__
        # holds the requested name in its local `attr` and calls __get__ on the
        # descriptor it looked up. Reading a frame local is the only way to get
        # it without changing the package, and it is guarded because the frame
        # may not be there.
        attr = None
        try:
            for frame in inspect.stack()[1:]:
                if frame.function == "__getattr__":
                    candidate = frame.frame.f_locals.get("attr")
                    if isinstance(candidate, str):
                        attr = candidate
                    break
        except Exception:
            attr = None
        entry = _RECORDS.get(index)
        if entry is None:
            entry = {
                'index': index,
                'byte_offset': index * 8,
                'args': [str(a) for a in (args or ())],
                'return_type': str(return_type),
                'convention': str(convention),
                'reads': 0,
                'first_site': site,
                'last_site': site,
                'sites': {},
                'attrs': {},
                'last_this': 0,
            }
            _RECORDS[index] = entry
            _say("")
            _say("NEW virtual function index %d  (byte offset %d)"
                 % (index, index * 8))
            _say("    return type : %s" % entry['return_type'])
            _say("    arguments   : %s" % (entry['args'] or "(none declared)"))
            _say("    convention  : %s" % entry['convention'])
        entry['reads'] += 1
        if attr is not None:
            entry['attrs'][attr] = entry['attrs'].get(attr, 0) + 1
        entry['last_site'] = site
        entry['sites'][site] = entry['sites'].get(site, 0) + 1
        try:
            entry['last_this'] = int(ptr)
        except Exception:
            try:
                entry['last_this'] = int(ptr.get_pointer())
            except Exception:
                entry['last_this'] = 0
        return inner(ptr)

    fget.__name__ = 'sp_vtable_fget'
    fget.__doc__ = getattr(inner, '__doc__', None)
    return fget


def _install():
    global _original, _installed
    try:
        from memory.manager import TypeManager
    except Exception as error:
        _say("cannot import TypeManager: %s: %s" % (type(error).__name__, error))
        return False
    if _original is not None:
        return True
    _original = TypeManager.virtual_function

    def wrapper(self, index, args=(), return_type=None, convention=None,
                doc=None):
        # No attempt is made to recover the attribute name from the calling
        # frame here. TypeManager.create_type_from_dict does
        # cls_dict[name] = self.virtual_function(*data), so the name is not
        # available as an argument and would have to be inferred from the
        # caller's locals before the assignment has happened - which cannot be
        # done reliably. The name is read where it genuinely exists instead: the
        # `attr` local of entities._base.BaseEntity.__getattr__, see _make_fget.
        prop = _original(self, index, args, return_type, convention, doc)
        try:
            inner = prop.fget
        except AttributeError:
            return prop
        return property(_make_fget(inner, index, args, return_type, convention),
                        None, None, doc)

    wrapper.__name__ = 'sp_vtable_virtual_function'
    wrapper.__doc__ = ("instrumented by %s; the original was %s"
                       % (PLUGIN_NAME, _original.__name__))
    try:
        TypeManager.virtual_function = wrapper
    except Exception as error:
        _say("cannot replace TypeManager.virtual_function: %s: %s"
             % (type(error).__name__, error))
        return False
    _installed = True
    return True


def _uninstall():
    global _original, _installed
    if not _installed:
        return
    try:
        from memory.manager import TypeManager
        TypeManager.virtual_function = _original
        _say("restored TypeManager.virtual_function")
    except Exception as error:
        _say("could not restore: %s: %s" % (type(error).__name__, error))
    _installed = False


def _report():
    _say("")
    _say("=" * 74)
    _say("  sp_vtable report: virtual function indices read")
    _say("=" * 74)
    if not _RECORDS:
        _say("  nothing was read")
        return
    _say("  %d distinct index/indices" % len(_RECORDS))
    for index in sorted(_RECORDS):
        e = _RECORDS[index]
        _say("")
        _say("  index %d   byte offset %d   reads %d"
             % (index, e['byte_offset'], e['reads']))
        _say("    return type : %s" % e['return_type'])
        _say("    arguments   : %s" % (e['args'] or "(none declared)"))
        _say("    convention  : %s" % e['convention'])
        _say("    last this   : 0x%X" % e['last_this'])
        if e.get('attrs'):
            _say("    entity attributes read through it:")
            for attr, count in sorted(e['attrs'].items(), key=lambda kv: -kv[1]):
                _say("      %6d x  %s" % (count, attr))
        else:
            _say("    entity attributes read through it: none captured")
            _say("      (the read did not come from an entity __getattr__ frame)")
        _say("    readers:")
        for site, count in sorted(e['sites'].items(), key=lambda kv: -kv[1]):
            _say("      %4d x  %s" % (count, " <- ".join(site[-3:])))


def _register_commands():
    from commands.server import server_command_manager

    def _report_command(*args, **kwargs):
        _report()

    def _reset_command(*args, **kwargs):
        _RECORDS.clear()
        _SEEN.clear()
        _say("counters reset")

    for name, callback in (('sp_vtable', _report_command),
                           ('sp_vtable_reset', _reset_command)):
        try:
            server_command_manager.register_commands(name, callback)
            _say("registered %s" % name)
        except Exception as error:
            _say("could not register %s: %s: %s"
                 % (name, type(error).__name__, error))


def load():
    if _log is None:
        _open()
    _say("")
    _say("### sp_vtable loaded at %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    _say("    log file: %s" % _path)
    ok = _install()
    _say("    instrumented: %s" % ("TypeManager.virtual_function"
                                   if ok else "NOTHING"))
    if not ok:
        _say("    Without this the fault's reader stays unidentified: the")
        _say("    traceback cannot show it because the frame above")
        _say("    memory/helpers.py:353 is C++.")
    _register_commands()
    _say("")
    _say('run "sp_vtable" for the report.')


def unload():
    _report()
    _uninstall()
    if _log is not None:
        try:
            _log.flush()
            _log.close()
        except Exception:
            pass
    print("sp_vtable unloaded")

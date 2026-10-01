"""Source.Python compatibility report for the game it is running in.

Why this exists
---------------
The Windows x86-64 port builds, links, and Source.Python loads. What is not known
is how much of Source.Python actually *works* on a given game build, and that
differs per platform for a reason unrelated to the C++ port.

Source.Python locates game code through byte signatures and symbol names in
addons/source-python/data/source-python/**/*.ini. Those identifiers are
architecture-specific, and memory/helpers.py:396 resolves them three levels deep:

    <key>_<platform>_<arch>   ->   <key>_<platform>   ->   <key>

so identifier_windows_x64 is already supported and no framework change is needed.
The data is simply not there: the 48 identifier_windows entries in the tree are
32-bit x86 and begin with x86-32 prologues such as

    identifier_windows = 55 8B EC 81 EC 40 01 00 00 8B C1 53

55 8B EC is push ebp; mov ebp, esp. The x86-64 equivalent is a REX-prefixed
sequence beginning 48 89, so those signatures cannot match on Win64. Porting the
code does not make 32-bit signatures valid.

That makes "which of these work" a measurement, and this plugin is the instrument.

Why nothing expensive runs at load time
---------------------------------------
The first version of this plugin called probe_signatures() from load(). Each
identifier miss triggers a full pattern scan of the 15 MB server.dll, several
dozen of those run back to back, and load() executes on the server's main
thread. The result was a dedicated server that looked frozen on its splash
screen. So:

  - load() does only cheap work: module imports, server state, listener
    registration. That is a few hundred milliseconds.
  - the signature scan runs only from the sp_compat_signatures command, and it
    reports elapsed time per identifier so a slow one is visible rather than
    looking like a hang.
  - sp_compat_signatures accepts a substring filter, so the working list can be
    built a few entries at a time instead of all at once.

Commands
--------
  sp_compat             cheap report: modules, engine, server state, listeners
  sp_compat_signatures  per-signature pass/fail, with a substring filter
  sp_compat_events      one-shot dump of the game's event list
  sp_compat_status      listener activity since load

Every probe is individually guarded. A plugin that raises is worse than one that
reports less, because the crash hides the measurements that did succeed.
"""

import io
import os
import re
import sys
import time
import traceback


# ---------------------------------------------------------------------------
# Log destination
# ---------------------------------------------------------------------------
# Derived from this file's location rather than from SP's paths module, so the
# report can still be written if the paths module is one of the things that
# failed. This file lives at
#     <game>/addons/source-python/plugins/sp_compat/sp_compat.py
# which is four levels below the game directory, not three.
_HERE = os.path.dirname(os.path.abspath(__file__))
_GAME_DIR = os.path.abspath(
    os.path.join(_HERE, os.pardir, os.pardir, os.pardir, os.pardir))
_LOG_PATH = os.path.join(_GAME_DIR, 'logs', 'sp-compat.log')


def _log(text=''):
    """Write one line to the log file and to the console.

    Append mode, flushed per line, so a report survives the server being killed
    part way through - which is how these runs usually end, since the test host
    does not have the memory to keep a TF2 map up indefinitely.
    """
    try:
        directory = os.path.dirname(_LOG_PATH)
        if not os.path.isdir(directory):
            os.makedirs(directory)
        with io.open(_LOG_PATH, 'a', encoding='utf-8') as handle:
            handle.write(text + '\n')
    except Exception as error:
        text = text + '   (log write failed: %s)' % error
    try:
        print('[sp_compat] ' + text)
    except Exception:
        pass


def _section(title):
    _log('')
    _log('=' * 78)
    _log(title)
    _log('=' * 78)


def _ok(label, detail=''):
    _log('  [ OK ] %-44s %s' % (label, detail))


def _fail(label, detail=''):
    _log('  [FAIL] %-44s %s' % (label, detail))


def _warn(label, detail=''):
    _log('  [WARN] %-44s %s' % (label, detail))


def _count(label, good, total, note=''):
    if total:
        pct = 100.0 * good / total
        tag = '[ OK ]' if good == total else '[PART]'
        _log('  %s %-44s %4d/%-4d  %5.1f%%  %s' % (tag, label, good, total, pct, note))
    else:
        _log('  [ -- ] %-44s (nothing to test)' % label)


# ---------------------------------------------------------------------------
# 1. module probe - cheap, safe to run at load
# ---------------------------------------------------------------------------
_MODULES = (
    'auth', 'commands', 'config', 'core', 'cvars', 'effects', 'engines',
    'entities', 'events', 'filters', 'hooks', 'listeners', 'memory', 'menus',
    'messages', 'players', 'plugins', 'settings', 'stringtables', 'studio',
    'translations', 'weapons',
)


def probe_modules():
    _section('1. MODULE IMPORTS')
    _log('  platform = %-10s python = %-8s pointer width = %d bits'
         % (sys.platform, sys.version.split()[0],
            64 if sys.maxsize > 2 ** 32 else 32))
    _log('')
    good = []
    for name in _MODULES:
        try:
            __import__(name)
            good.append(name)
            _ok(name)
        except Exception as error:
            _fail(name, '%s: %s' % (type(error).__name__, error))
    _log('')
    _count('modules importable', len(good), len(_MODULES))
    return good


# ---------------------------------------------------------------------------
# 2. engine and server state - cheap
# ---------------------------------------------------------------------------
def probe_engine():
    _section('2. ENGINE AND SERVER STATE')

    try:
        import core
        engine = getattr(core, 'SOURCE_ENGINE', '?')
        platform = getattr(core, 'PLATFORM', '?')
        arch = getattr(core, 'ARCHITECTURE', '?')
        _ok('SOURCE_ENGINE', str(engine))
        # If this pair is wrong, every signature lookup silently falls back to
        # the wrong key, so it is printed rather than assumed.
        _ok('ini resolution key', '%s_%s' % (platform, arch))
    except Exception as error:
        _fail('engine identity', '%s: %s' % (type(error).__name__, error))
        engine = platform = arch = None

    # The right import for the game binary. The Python package reaches it through
    # engines.server, not through the top-level entities module.
    try:
        from engines.server import server_game_dll
        _ok('server_game_dll', 'resolved, %s' % type(server_game_dll).__name__)
    except Exception as error:
        _fail('server_game_dll', '%s: %s' % (type(error).__name__, error))

    for cvar_name in ('sv_lan', 'hostname', 'sv_password', 'mp_gamemode',
                      'sv_cheats', 'num_players', 'maxplayers', 'sv_visible'):
        # cvar.find_base, not ConVar(name). ConVar(name) constructs, and
        # maxplayers is a ConCommand, so constructing it raised
        # "Failed to create ConVar("maxplayers") because a ConCommand with the
        # same name already exists". ICvar::FindCommandBase is documented as
        # finding the ConCommandBase of a server command OR a console variable,
        # which is what is wanted here for both kinds of name.
        try:
            from cvars import cvar
            found = cvar.find_base(cvar_name)
            if found is None:
                _warn(cvar_name, 'cvar.find_base returned nothing')
            else:
                _ok(cvar_name, repr(found.get_string()))
        except Exception as error:
            _warn(cvar_name, '%s: %s' % (type(error).__name__, error))

    # Map name, from the engine singleton rather than an entity lookup.
    for attempt in ('mapname', 'get_map_name'):
        try:
            from engines.server import server
            target = getattr(server, attempt, None)
            if callable(target):
                _ok('map (server.%s)' % attempt, repr(target()))
                break
            if target is not None:
                _ok('map (server.%s)' % attempt, repr(target))
                break
        except Exception as error:
            _warn('map via server.%s' % attempt, '%s: %s' % (type(error).__name__, error))

    # Player enumeration. The exact accessor is not known from the source, so
    # several are tried and whichever works is reported. A failed probe is
    # information too: it says the player layer is not reachable by that route.
    _probe_players()

    return engine, platform, arch


def _probe_players():
    """Try to enumerate connected players, reporting which route worked."""
    # filters.players.__all__ is ('get_default_filters', 'parse_filter',
    # 'PlayerIter'), and PlayerIter takes no arguments - it iterates every
    # player via PlayerGenerator. That is the supported route.
    #
    # The two routes this tried before did not exist: Server has no
    # get_all_players and no players attribute, and there is no AllPlayers
    # symbol anywhere in the package - filters/__init__.py is essentially empty,
    # so `filters.AllPlayers` resolved to something that was not a filter at all.
    # Guessing accessor names and reporting the failures was not useful, because
    # a failed probe says nothing about whether the player layer works.
    routes = (
        ('filters.players.PlayerIter()',
         lambda: __import__('filters.players', fromlist=['PlayerIter']).PlayerIter()),
        ('players.PlayerGenerator()',
         lambda: __import__('players', fromlist=['PlayerGenerator']).PlayerGenerator()),
    )
    for label, attempt in routes:
        try:
            result = attempt()
        except Exception as error:
            _warn('players via %s' % label, '%s: %s' % (type(error).__name__, error))
            continue
        try:
            items = list(result)
        except Exception as error:
            _warn('players via %s' % label,
                  'not iterable: %s: %s' % (type(error).__name__, error))
            continue
        _ok('players via %s' % label, '%d found' % len(items))
        for item in items[:16]:
            try:
                _log('           - %-24s userid %-5s %s'
                     % (item.name, item.userid,
                        'bot' if item.is_bot else 'human'))
            except Exception:
                _log('           - %r' % (item,))
        if len(items) > 16:
            _log('           ... and %d more' % (len(items) - 16))
        return items

    _warn('player enumeration', 'no known accessor worked; see the attempts above')
    return []


# ---------------------------------------------------------------------------
# 3. listeners - registered at load, observed later
# ---------------------------------------------------------------------------
_listener_hits = {}


def probe_listeners():
    _section('3. LISTENERS  (registered now, observed on later ticks)')
    try:
        import listeners
    except Exception as error:
        _fail('import listeners', '%s: %s' % (type(error).__name__, error))
        return

    wanted = ('OnTick', 'OnMapStart', 'OnServerActivate',
              'OnClientConnect', 'OnClientPutInServer', 'OnEntityCreated',
              'OnEntitySpawned', 'OnPlayerRunCommand', 'OnPlayerSay',
              'OnLevelInit', 'OnLevelShutdown', 'OnServerCommand')

    def make_handler(label):
        def handler(*args, **kwargs):
            _listener_hits[label] = _listener_hits.get(label, 0) + 1
        return handler

    seen = set()
    registered = 0
    for name in wanted:
        if name in seen or not hasattr(listeners, name):
            continue
        seen.add(name)
        _listener_hits.setdefault(name, 0)
        try:
            getattr(listeners, name)(make_handler(name))
            registered += 1
        except Exception as error:
            _fail('register ' + name, '%s: %s' % (type(error).__name__, error))
    _count('listeners registered', registered, len(seen))
    _log('  they report on the next sp_compat_status')


def report_listener_hits():
    _section('LISTENER ACTIVITY SINCE REGISTRATION')
    if not _listener_hits:
        _warn('listener activity', 'no listeners were registered')
        return
    fired = [k for k, v in _listener_hits.items() if v]
    _count('listeners that fired', len(fired), len(_listener_hits))
    for name in sorted(_listener_hits):
        count = _listener_hits[name]
        if count:
            _ok(name, 'fired %d time(s)' % count)
        else:
            _log('  [ -- ] %-44s never fired' % name)


# ---------------------------------------------------------------------------
# 4. the signature scan - expensive, therefore command-only
# ---------------------------------------------------------------------------
_INI_SECTION_RE = re.compile(r'^\s*\[\[(\w+)\]\]\s*$')
_INI_KEYVAL_RE = re.compile(r'^\s*(\w+)\s*=\s*(.+?)\s*$')

# Above this, the scan is presumed to be stuck and it stops and says so. A scan
# that silently runs for ten minutes is indistinguishable from a hung server.
_SCAN_BUDGET_SECONDS = 120.0


def _data_dir():
    for candidate in (
        os.path.join(_HERE, os.pardir, os.pardir, 'data', 'source-python'),
        os.path.join(_GAME_DIR, 'addons', 'source-python', 'data', 'source-python'),
    ):
        if os.path.isdir(candidate):
            return os.path.abspath(candidate)
    return None


def _engine_data_dir(data_dir, engine):
    """Pick the engine's data subdirectory the way Source.Python does."""
    if not engine:
        return data_dir
    for candidate in (os.path.join(data_dir, engine, 'orangebox'),
                      os.path.join(data_dir, engine)):
        if os.path.isdir(candidate):
            return candidate
    return data_dir


def probe_signatures(name_filter=''):
    """Resolve declared identifiers against the game binary, one at a time.

    Expensive by nature: a miss scans the whole binary. So it is only reachable
    from a command, it takes a substring filter to work through the list in
    pieces, it prints elapsed time per entry, and it stops on a wall-clock budget.
    """
    needle = (name_filter or '').strip().lower()
    _section('SIGNATURE SCAN%s'
             % ('   filter=%r' % name_filter if needle else '  (all entries)'))

    data_dir = _data_dir()
    if not data_dir:
        _fail('data directory', 'not found; cannot enumerate signatures')
        return

    import core
    platform = getattr(core, 'PLATFORM', '?')
    arch = getattr(core, 'ARCHITECTURE', '?')
    engine = getattr(core, 'SOURCE_ENGINE', None)
    key = 'identifier_%s_%s' % (platform, arch)

    try:
        from engines.server import server_game_dll
        binary = server_game_dll
        _ok('server game dll', 'resolved')
    except Exception as error:
        _fail('server game dll', '%s: %s' % (type(error).__name__, error))
        return

    engine_dir = _engine_data_dir(data_dir, engine)
    _ok('data directory', engine_dir)
    _ok('identifier key', key)
    _log('')

    started = time.time()
    per_kind = {'function': [0, 0], 'virtual_function': [0, 0]}
    resolved = []
    failed = []
    skipped_wrong_key = 0
    stopped_early = False

    for dirpath, _dirnames, filenames in os.walk(engine_dir):
        for filename in sorted(filenames):
            if not filename.endswith('.ini'):
                continue
            path = os.path.join(dirpath, filename)
            try:
                with io.open(path, 'r', encoding='utf-8', errors='replace') as fh:
                    lines = fh.read().split('\n')
            except Exception as error:
                _warn(os.path.basename(path), 'unreadable: %s' % error)
                continue

            current_section = None
            current_name = None
            for raw in lines:
                line = raw.split('#')[0]
                if not line.strip():
                    continue
                header = _INI_SECTION_RE.match(line)
                if header:
                    current_section = header.group(1)
                    current_name = None
                    continue
                if current_section is None:
                    continue
                pair = _INI_KEYVAL_RE.match(line)
                if not pair:
                    continue
                k, value = pair.group(1), pair.group(2)
                if k == 'identifier' or k.endswith('_identifier'):
                    current_name = value

                if k != key:
                    # This entry has no entry for the key we resolve, so it
                    # falls back to identifier_<platform> or identifier. Counting
                    # these is how we size the missing-data problem.
                    if k in ('identifier_%s' % platform, 'identifier'):
                        skipped_wrong_key += 1
                    continue
                if current_name is None:
                    current_name = value
                if needle and needle not in str(current_name).lower():
                    continue

                if time.time() - started > _SCAN_BUDGET_SECONDS:
                    stopped_early = True
                    break

                if current_section in per_kind:
                    per_kind[current_section][1] += 1
                entry_time = time.time()
                label = '%s :: %s' % (os.path.basename(path), current_name)
                try:
                    binary[current_name]
                    elapsed = time.time() - entry_time
                    if current_section in per_kind:
                        per_kind[current_section][0] += 1
                    resolved.append(label)
                    _log('  [ OK ] %-58s %6.0f ms' % (label[:58], elapsed * 1000))
                except Exception as error:
                    elapsed = time.time() - entry_time
                    failed.append((label, '%s' % (error,)))
                    _log('  [FAIL] %-58s %6.0f ms  %s'
                         % (label[:58], elapsed * 1000, str(error)[:60]))
            if stopped_early:
                break
        if stopped_early:
            break

    _log('')
    _count('plain functions resolved',
           per_kind['function'][0], per_kind['function'][1])
    _count('virtual functions resolved',
           per_kind['virtual_function'][0], per_kind['virtual_function'][1])
    _count('total resolved',
           per_kind['function'][0] + per_kind['virtual_function'][0],
           per_kind['function'][1] + per_kind['virtual_function'][1])
    _log('')
    _log('  entries that fall back to a %s-width key (no %s entry): %d'
         % (platform, key, skipped_wrong_key))
    _log('  elapsed: %.1f s' % (time.time() - started))
    if stopped_early:
        _warn('scan stopped early',
              'hit the %.0f s budget; rerun with a filter for the rest'
              % _SCAN_BUDGET_SECONDS)
    _log('  %d resolved, %d failed' % (len(resolved), len(failed)))
    return {'resolved': resolved, 'failed': failed,
            'per_kind': per_kind, 'fallback_entries': skipped_wrong_key}


# ---------------------------------------------------------------------------
# 5. event dump
# ---------------------------------------------------------------------------
def dump_events():
    _section('EVENT DUMP  (one-shot)')
    try:
        import events
    except Exception as error:
        _fail('import events', '%s: %s' % (type(error).__name__, error))
        return
    for attr in ('list_all', 'get_all', 'list', 'all'):
        candidate = getattr(events, attr, None)
        if callable(candidate):
            try:
                names = list(candidate())
                _ok('events.%s()' % attr, '%d event(s)' % len(names))
                for name in sorted(str(n) for n in names):
                    _log('    %s' % name)
                return names
            except Exception as error:
                _warn('events.%s()' % attr, '%s: %s' % (type(error).__name__, error))
    _warn('event enumeration', 'no list_all/get_all/list/all on the events module')
    _log('  what events does expose:')
    for name in sorted(dir(events)):
        if not name.startswith('_'):
            _log('    %s' % name)
    return []


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
def _register_commands():
    """Register the plugin's console commands.

    ConCommand comes from the C++ module and is exported no_init - constructing
    it raises "This class cannot be instantiated from Python". The constructible
    route is a command manager's register_commands, which is what the Python-side
    decorator classes call internally.

    It has to be the *server* manager, not the base class. _BaseCommandManager
    defines register_commands but not _get_command; that is supplied by the
    per-kind subclasses (_ServerCommandManager, _ClientCommandManager,
    _SayCommandManager). Calling register_commands on the base therefore fails
    with

        AttributeError: '_BaseCommandManager' object has no attribute '_get_command'

    which is what this plugin did until the CS:Source run, where all four of its
    commands failed to register and the report lost its signature scan entirely.
    """
    manager = None
    try:
        from commands.server import server_command_manager
        manager = server_command_manager
    except Exception as error:
        _fail('command manager unavailable',
              '%s: %s' % (type(error).__name__, error))

    if manager is None:
        return

    def register(name, help_text, callback):
        try:
            manager.register_commands(name, callback)
            _ok('registered %s' % name)
        except Exception as error:
            _fail('register %s' % name, '%s: %s' % (type(error).__name__, error))

    def _compat_command(*args, **kwargs):
        run_cheap_report()

    def _signatures_command(*args, **kwargs):
        # The engine hands the console arguments through, so a filter can be
        # typed: sp_compat_signatures fire_output
        needle = ''
        for value in (list(args) + list(kwargs.values())):
            if isinstance(value, (list, tuple)) and value:
                needle = str(value[0])
                break
            if isinstance(value, str) and value:
                needle = value
                break
        probe_signatures(needle)

    def _events_command(*args, **kwargs):
        dump_events()

    def _status_command(*args, **kwargs):
        report_listener_hits()

    register('sp_compat', 'Source.Python compatibility report.', _compat_command)
    register('sp_compat_signatures', 'Per-signature pass/fail scan.', _signatures_command)
    register('sp_compat_events', "Dump this game's event list.", _events_command)
    register('sp_compat_status', 'Listener activity since load.', _status_command)


# ---------------------------------------------------------------------------
# entry points
# ---------------------------------------------------------------------------
def run_cheap_report():
    _log('')
    _log('#' * 78)
    _log('# sp_compat report at %s' % time.strftime('%Y-%m-%d %H:%M:%S'))
    _log('# game dir %s' % _GAME_DIR)
    _log('# NOTE the signature scan is deliberately NOT part of this report.')
    _log('#      It scans the whole game binary per entry and blocks the server.')
    _log('#      Run "sp_compat_signatures [filter]" when you want it.')
    _log('#' * 78)
    probe_modules()
    probe_engine()
    probe_listeners()
    _section('END OF CHEAP REPORT')
    _log('  log file: %s' % _LOG_PATH)
    return True


def load():
    """SP plugin entry point. Kept cheap on purpose - see the module docstring."""
    _log('')
    _log('sp_compat loaded.')
    _register_commands()
    run_cheap_report()
    _log('')
    _log('next: "sp_compat_signatures" to measure the x64 signature situation.')


def unload():
    _log('sp_compat unloaded.')

# ../listeners/__init__.py

"""Provides listener based functionality."""

# =============================================================================
# >> IMPORTS
# =============================================================================
# Python Imports
import socket
from enum import IntEnum
from urllib.error import URLError

# Source.Python Imports
#   Core
from core import AutoUnload
from core import SOURCE_ENGINE
from core import PLATFORM
from core.settings import _core_settings
from core.version import get_last_successful_build_number
from core.version import is_unversioned
from core.version import VERSION
#   Cvars
from cvars import ConVar
#   Engines
from engines.server import server_game_dll
#   Entities
from entities import BaseEntityOutput
from entities.datamaps import Variant
from entities.helpers import find_output_name
#   Memory
from memory import get_virtual_function
#   Players
from players.constants import PlayerButtons
#   Loggers
from loggers import _sp_logger
#   Memory
from memory import get_virtual_function
from memory import make_object
from memory.hooks import PreHook


# =============================================================================
# >> FORWARD IMPORTS
# =============================================================================
# Source.Python Imports
#   Listeners
from _listeners import ListenerManager
from _listeners import on_client_active_listener_manager
from _listeners import on_client_connect_listener_manager
from _listeners import on_client_disconnect_listener_manager
from _listeners import on_client_fully_connect_listener_manager
from _listeners import on_client_put_in_server_listener_manager
from _listeners import on_client_settings_changed_listener_manager
from _listeners import on_convar_changed_listener_manager
from _listeners import on_level_init_listener_manager
from _listeners import on_level_shutdown_listener_manager
from _listeners import on_network_id_validated_listener_manager
from _listeners import on_edict_allocated_listener_manager
from _listeners import on_edict_freed_listener_manager
from _listeners import on_entity_pre_spawned_listener_manager
from _listeners import on_networked_entity_pre_spawned_listener_manager
from _listeners import on_entity_created_listener_manager
from _listeners import on_networked_entity_created_listener_manager
from _listeners import on_entity_spawned_listener_manager
from _listeners import on_networked_entity_spawned_listener_manager
from _listeners import on_entity_deleted_listener_manager
from _listeners import on_networked_entity_deleted_listener_manager
from _listeners import on_entity_collision_listener_manager
from _listeners import on_entity_transmit_listener_manager
from _listeners import on_data_loaded_listener_manager
from _listeners import on_combiner_pre_cache_listener_manager
from _listeners import on_data_unloaded_listener_manager
from _listeners import on_query_cvar_value_finished_listener_manager
from _listeners import on_server_activate_listener_manager
from _listeners import on_tick_listener_manager
from _listeners import on_server_output_listener_manager
from _listeners import on_player_collision_listener_manager
from _listeners import on_player_transmit_listener_manager
from _listeners import on_player_run_command_listener_manager
from _listeners import on_player_post_run_command_listener_manager
from _listeners import on_button_state_changed_listener_manager


# =============================================================================
# >> ALL DECLARATION
# =============================================================================
__all__ = ('ButtonStatus',
           'ListenerManager',
           'ListenerManagerDecorator',
           'OnClientActive',
           'OnClientConnect',
           'OnClientDisconnect',
           'OnClientFullyConnect',
           'OnClientPutInServer',
           'OnClientSettingsChanged',
           'OnCombinerPreCache',
           'OnConVarChanged',
           'OnDataLoaded',
           'OnDataUnloaded',
           'OnEdictAllocated',
           'OnEdictFreed',
           'OnEntityCreated',
           'OnNetworkedEntityCreated',
           'OnEntityDeleted',
           'OnNetworkedEntityDeleted',
           'OnEntityCollision',
           'OnEntityTransmit',
           'OnEntityOutput',
           'OnEntityOutputListenerManager',
           'OnEntityPreSpawned',
           'OnNetworkedEntityPreSpawned',
           'OnEntitySpawned',
           'OnNetworkedEntitySpawned',
           'OnLevelInit',
           'OnLevelShutdown',
           'OnLevelEnd',
           'OnNetworkidValidated',
           'OnButtonStateChanged',
           'OnPlayerCollision',
           'OnPlayerTransmit',
           'OnPlayerRunCommand',
           'OnPlayerPostRunCommand',
           'OnPluginLoaded',
           'OnPluginLoading',
           'OnPluginUnloaded',
           'OnPluginUnloading',
           'OnQueryCvarValueFinished',
           'OnServerActivate',
           'OnTick',
           'OnVersionUpdate',
           'OnServerOutput',
           'get_button_combination_status',
           'on_client_active_listener_manager',
           'on_client_connect_listener_manager',
           'on_client_disconnect_listener_manager',
           'on_client_fully_connect_listener_manager',
           'on_client_put_in_server_listener_manager',
           'on_client_settings_changed_listener_manager',
           'on_combiner_pre_cache_listener_manager',
           'on_convar_changed_listener_manager',
           'on_data_loaded_listener_manager',
           'on_data_unloaded_listener_manager',
           'on_edict_allocated_listener_manager',
           'on_edict_freed_listener_manager',
           'on_entity_created_listener_manager',
           'on_networked_entity_created_listener_manager',
           'on_entity_deleted_listener_manager',
           'on_networked_entity_deleted_listener_manager',
           'on_entity_collision_listener_manager',
           'on_entity_transmit_listener_manager',
           'on_entity_output_listener_manager',
           'on_entity_pre_spawned_listener_manager',
           'on_networked_entity_pre_spawned_listener_manager',
           'on_entity_spawned_listener_manager',
           'on_networked_entity_spawned_listener_manager',
           'on_level_end_listener_manager',
           'on_level_init_listener_manager',
           'on_level_shutdown_listener_manager',
           'on_network_id_validated_listener_manager',
           'on_plugin_loaded_manager',
           'on_plugin_loading_manager',
           'on_plugin_unloaded_manager',
           'on_plugin_unloading_manager',
           'on_query_cvar_value_finished_listener_manager',
           'on_server_activate_listener_manager',
           'on_tick_listener_manager',
           'on_version_update_listener_manager',
           'on_server_output_listener_manager',
           'on_player_collision_listener_manager',
           'on_player_transmit_listener_manager',
           'on_player_run_command_listener_manager',
           'on_button_state_changed_listener_manager',
           )


# =============================================================================
# >> GLOBAL VARIABLES
# =============================================================================
# Get the sp.listeners logger
listeners_logger = _sp_logger.listeners

on_version_update_listener_manager = ListenerManager()
on_plugin_loaded_manager = ListenerManager()
on_plugin_unloaded_manager = ListenerManager()
on_plugin_loading_manager = ListenerManager()
on_plugin_unloading_manager = ListenerManager()
on_level_end_listener_manager = ListenerManager()

_check_for_update = ConVar(
    'sp_check_for_update',
    _core_settings['VERSION_SETTINGS']['check_for_update'],
    'Enable/disable checking for version updates.', min_value=0, max_value=1)

_notify_on_update = ConVar(
    'sp_notify_on_update',
    _core_settings['VERSION_SETTINGS']['notify_on_update'],
    'Log a warning when a Source.Python update is available.' +
    ' Requires sp_check_for_update to be set to 1.',
    min_value=0, max_value=1)


# =============================================================================
# >> CLASSES
# =============================================================================
class ButtonStatus(IntEnum):
    """Indicate whether a button has been pressed or released."""

    RELEASED = 0
    PRESSED = 1


class ListenerManagerDecorator(AutoUnload):
    """Base decorator class used to register/unregister a listener."""

    def __init__(self, callback):
        """Store the callback and register the listener."""
        # Log the <instance>.__init__ message
        listeners_logger.log_debug(
            '{0}.__init__<{1}>'.format(self.name, callback))

        # Set the callback to None...
        self.callback = None

        # Is the callback callable?
        if not callable(callback):

            # Raise an error
            raise TypeError(
                "'" + type(callback).__name__ + "' object is not callable.")

        # Log the registering message
        listeners_logger.log_debug(
            '{0}.__init__ - Registering'.format(self.name))

        # Store the callback
        self.callback = callback

        # Register the listener
        self.manager.register_listener(self.callback)

    def __call__(self, *args):
        """Call the listener."""
        # Log the calling
        listeners_logger.log_debug(
            '{0}.__call__<{1}>'.format(self.name, args))

        # Call the listener
        return self.callback(*args)

    @property
    def name(self):
        """Return the class name of the instance."""
        return self.__class__.__name__

    @property
    def manager(self):
        """Return a :class:`ListenerManager` object."""
        raise NotImplementedError('Must be implemented by a subclass.')

    def _unload_instance(self):
        """Unregister the listener."""
        # Was the callback registered?
        if self.callback is None:
            return

        # Log the unregistering
        listeners_logger.log_debug(
            '{0}._unload_instance - Unregistering <{1}>'.format(
                self.name, self.callback))

        # Unregister the listener
        self.manager.unregister_listener(self.callback)


class OnClientActive(ListenerManagerDecorator):
    """Register/unregister a ClientActive listener."""

    manager = on_client_active_listener_manager


class OnClientConnect(ListenerManagerDecorator):
    """Register/unregister a ClientConnect listener."""

    manager = on_client_connect_listener_manager


class OnClientDisconnect(ListenerManagerDecorator):
    """Register/unregister a ClientDisconnect listener."""

    manager = on_client_disconnect_listener_manager


class OnClientFullyConnect(ListenerManagerDecorator):
    """Register/unregister a ClientFullyConnect listener."""

    manager = on_client_fully_connect_listener_manager


class OnClientPutInServer(ListenerManagerDecorator):
    """Register/unregister a ClientPutInServer listener."""

    manager = on_client_put_in_server_listener_manager


class OnClientSettingsChanged(ListenerManagerDecorator):
    """Register/unregister a ClientSettingsChanged listener."""

    manager = on_client_settings_changed_listener_manager


class OnEntityOutputListenerManager(ListenerManager):
    """Register/unregister an EntityOutput listener."""

    def initialize(self):
        """Called when the first callback is being registered."""
        # Get the fire_output method
        fire_output = BaseEntityOutput.fire_output

        # If the fire_output method is not implemented, exit the call
        if fire_output is NotImplemented:
            return

        # Register the hook on fire_output
        fire_output.add_pre_hook(_pre_fire_output)

    def finalize(self):
        """Called when the last callback is being unregistered."""
        # Get the fire_output method
        fire_output = BaseEntityOutput.fire_output

        # If the fire_output method is not implemented, exit the call
        if fire_output is NotImplemented:
            return

        # Unregister the hook on fire_output
        fire_output.remove_pre_hook(_pre_fire_output)

on_entity_output_listener_manager = OnEntityOutputListenerManager()


class OnEntityOutput(ListenerManagerDecorator):
    """Register/unregister an EntityOutput listener."""

    manager = on_entity_output_listener_manager


class OnLevelInit(ListenerManagerDecorator):
    """Register/unregister a LevelInit listener."""

    manager = on_level_init_listener_manager


class OnLevelShutdown(ListenerManagerDecorator):
    """Register/unregister a LevelShutdown listener."""

    manager = on_level_shutdown_listener_manager


class OnNetworkidValidated(ListenerManagerDecorator):
    """Register/unregister a NetworkidValidated listener."""

    manager = on_network_id_validated_listener_manager


class OnEdictAllocated(ListenerManagerDecorator):
    """Register/unregister an OnEdictAllocated listener."""

    manager = on_edict_allocated_listener_manager


class OnEdictFreed(ListenerManagerDecorator):
    """Register/unregister an OnEdictFreed listener."""

    manager = on_edict_freed_listener_manager


class OnEntityPreSpawned(ListenerManagerDecorator):
    """Register/unregister a OnEntityPreSpawned listener."""

    manager = on_entity_pre_spawned_listener_manager


class OnNetworkedEntityPreSpawned(ListenerManagerDecorator):
    """Register/unregister a OnNetworkedEntityPreSpawned listener."""

    manager = on_networked_entity_pre_spawned_listener_manager


class OnEntityCreated(ListenerManagerDecorator):
    """Register/unregister a OnEntityCreated listener."""

    manager = on_entity_created_listener_manager


class OnNetworkedEntityCreated(ListenerManagerDecorator):
    """Register/unregister a OnNetworkedEntityCreated listener."""

    manager = on_networked_entity_created_listener_manager


class OnEntitySpawned(ListenerManagerDecorator):
    """Register/unregister a OnEntitySpawned listener."""

    manager = on_entity_spawned_listener_manager


class OnNetworkedEntitySpawned(ListenerManagerDecorator):
    """Register/unregister a OnNetworkedEntitySpawned listener."""

    manager = on_networked_entity_spawned_listener_manager


class OnEntityDeleted(ListenerManagerDecorator):
    """Register/unregister a OnEntityDeleted listener."""

    manager = on_entity_deleted_listener_manager


class OnNetworkedEntityDeleted(ListenerManagerDecorator):
    """Register/unregister a OnNetworkedEntityDeleted listener."""

    manager = on_networked_entity_deleted_listener_manager


class OnEntityCollision(ListenerManagerDecorator):
    """Register/unregister a OnEntityCollision listener."""

    manager = on_entity_collision_listener_manager


class OnEntityTransmit(ListenerManagerDecorator):
    """Register/unregister a OnEntityTransmit listener."""

    manager = on_entity_transmit_listener_manager


class OnDataLoaded(ListenerManagerDecorator):
    """Register/unregister a OnDataLoaded listener."""

    manager = on_data_loaded_listener_manager


class OnCombinerPreCache(ListenerManagerDecorator):
    """Register/unregister a OnCombinerPreCache listener."""

    manager = on_combiner_pre_cache_listener_manager


class OnDataUnloaded(ListenerManagerDecorator):
    """Register/unregister a OnDataUnloaded listener."""

    manager = on_data_unloaded_listener_manager


class OnQueryCvarValueFinished(ListenerManagerDecorator):
    """Register/unregister an OnQueryCvarValueFinished listener."""

    manager = on_query_cvar_value_finished_listener_manager


class OnServerActivate(ListenerManagerDecorator):
    """Register/unregister a ServerActivate listener."""

    manager = on_server_activate_listener_manager


class OnTick(ListenerManagerDecorator):
    """Register/unregister a Tick listener."""

    manager = on_tick_listener_manager


class OnVersionUpdate(ListenerManagerDecorator):
    """Register/unregister a version update listener."""

    manager = on_version_update_listener_manager


class OnConVarChanged(ListenerManagerDecorator):
    """Register/unregister a ConVar listener."""

    manager = on_convar_changed_listener_manager


class OnPluginLoaded(ListenerManagerDecorator):
    """Register/unregister a plugin loaded listener."""

    manager = on_plugin_loaded_manager


class OnPluginLoading(ListenerManagerDecorator):
    """Register/unregister a plugin loading listener."""

    manager = on_plugin_loading_manager


class OnPluginUnloaded(ListenerManagerDecorator):
    """Register/unregister a plugin unloaded listener."""

    manager = on_plugin_unloaded_manager


class OnPluginUnloading(ListenerManagerDecorator):
    """Register/unregister a plugin unloading listener."""

    manager = on_plugin_unloading_manager


class OnLevelEnd(ListenerManagerDecorator):
    """Register/unregister a map end listener."""

    manager = on_level_end_listener_manager

    # Guard variable to ensure this listener gets called only once per map.
    _level_initialized = False


class OnPlayerCollision(ListenerManagerDecorator):
    """Register/unregister a OnPlayerCollision listener."""

    manager = on_player_collision_listener_manager


class OnPlayerTransmit(ListenerManagerDecorator):
    """Register/unregister a OnPlayerTransmit listener."""

    manager = on_player_transmit_listener_manager


class OnPlayerRunCommand(ListenerManagerDecorator):
    """Register/unregister a run command listener."""

    manager = on_player_run_command_listener_manager

class OnPlayerPostRunCommand(ListenerManagerDecorator):
    """Register/unregister a post run command listener."""

    manager = on_player_post_run_command_listener_manager

class OnButtonStateChanged(ListenerManagerDecorator):
    """Register/unregister a button state change listener."""

    manager = on_button_state_changed_listener_manager


class OnServerOutput(ListenerManagerDecorator):
    """Register/unregister a server output listener."""

    manager = on_server_output_listener_manager


# =============================================================================
# >> FUNCTIONS
# =============================================================================
def get_button_combination_status(old_buttons, new_buttons, combination):
    """Return the status of a button combination.

    :param PlayerButtons old_buttons:
        Previously pressed buttons.
    :param PlayerButtons new_buttons:
        Now pressed buttons.
    :param PlayerButtons combination:
        Button combination to check.
    :return:
        Return the status of the button combination. If the combination was
        neither pressed nor released, None will be returned.
    :rtype: ButtonStatus

    Example:

    .. code:: python

        @OnButtonStateChanged
        def on_buttons_state_changed(player, old_buttons, new_buttons):
            status = get_button_combination_status(old_buttons, new_buttons,
                PlayerButtons.ATTACK|PlayerButtons.JUMP)

            if status == ButtonStatus.PRESSED:
                SayText2(
                    '{} is jumping and attacking.'.format(player.name)).send()

            elif status == ButtonStatus.RELEASED:
                SayText2(
                    '{} stopped jumping and attacking at the same time.'.format(
                    player.name)).send()
    """
    previously_pressed = old_buttons & combination == combination
    now_pressed = new_buttons & combination == combination

    if not previously_pressed and now_pressed:
        return ButtonStatus.PRESSED

    elif previously_pressed and not now_pressed:
        return ButtonStatus.RELEASED

    return None


# =============================================================================
# >> CALLBACKS
# =============================================================================
@OnLevelInit
def _on_level_init(map_name):
    """Called when a new map gets initialized."""
    OnLevelEnd._level_initialized = True

    # Don't check if it's an unversioned build (dev version)
    if is_unversioned():
        return

    if not _check_for_update.get_int():
        return

    try:
        latest_version = get_last_successful_build_number()
    except (URLError, socket.timeout):
        return

    if VERSION >= latest_version:
        return

    if _notify_on_update.get_int():
        # TODO: Add translations
        listeners_logger.log_warning(
            'A new Source.Python version is available!')

    on_version_update_listener_manager.notify(VERSION, latest_version)


@OnLevelShutdown
def _on_level_shutdown():
    """Called on level end."""
    # Was no map initialized?
    if not OnLevelEnd._level_initialized:
        return

    # Notify all registred callbacks
    on_level_end_listener_manager.notify()

    # Make sure we don't get called more than once per map change
    OnLevelEnd._level_initialized = False


def _pre_fire_output(args):
    """Called when an output is about to be fired."""
    if not on_entity_output_listener_manager:
        return

    # Windows is a bit weird: the function takes 4 additional arguments...
    if PLATFORM == 'windows':
        args = (args[0],) + tuple(args)[5:]

    caller_ptr = args[3]
    if not caller_ptr:
        # If we don't know the caller, we won't be able to retrieve the
        # output name
        return

    # Done here to fix cyclic import...
    from entities.entity import BaseEntity
    caller = make_object(BaseEntity, caller_ptr)
    output_name = find_output_name(caller, args[0])
    if output_name is None:
        return None

    # Done here to fix cyclic import...
    from entities.entity import Entity
    if caller.is_networked():
        caller = make_object(Entity, caller_ptr)

    value_ptr = args[1]
    value = (value_ptr or None) and make_object(Variant, value_ptr)

    activator_ptr = args[2]
    activator = ((activator_ptr or None) and make_object(
        BaseEntity, activator_ptr))
    if activator is not None and activator.is_networked():
        activator = make_object(Entity, activator_ptr)

    delay = args[4]
    on_entity_output_listener_manager.notify(
        output_name, activator, caller, value, delay)


# ============================================================================
# >> Fix for issue #181.
# ============================================================================
# Get the function name to hook...
if SOURCE_ENGINE in ('bms', 'orangebox', 'gmod'):
    _hibernation_function_name = 'SetServerHibernation'
elif SOURCE_ENGINE in ('blade', 'csgo', 'l4d2'):
    _hibernation_function_name = 'ServerHibernationUpdate'
else:
    # To remind us to add newly supported engines...
    raise NotImplementedError('No hibernation function exposed.')

# ---------------------------------------------------------------------------
# 2026-09-29: both _disconnect_bots() call sites are now instrumented.
#
# The crash is at core.dll+0x48DBF2, inside C++, and has never arrived as a
# catchable Python exception - five runs, zero records from anything watching
# the Python level. So the question is which Python entry point is on the stack
# when it happens, and there are only two ways into _disconnect_bots().
#
# The hibernation hook was already removed for one run and the crash did not
# move: 04:29:42 "Server is hibernating", 04:29:43 the same exception at the
# same offset. That exonerates the hook and, with it, the argument-layout worry
# about stack_data[1] - there was no hook to pass any arguments. The suspicion
# moves to the other caller, OnLevelEnd, which is driven by an engine event and
# needs no hook at all.
#
# The log below is written with plain file I/O rather than through warnings or
# a plugin, for two reasons measured on the previous run: the warnings module's
# handler swallowed the bisect notice entirely, so its absence proved nothing;
# and a plugin log is not guaranteed to be flushed before the process dies.
# Appended and flushed per line, opened and closed each time, so a hard kill
# loses at most the last line.
# ---------------------------------------------------------------------------
# os, time and GAME_PATH are not imported at this module's top level, so they
# are imported here where they are used. GAME_PATH is a pathlib.Path, and the
# logs directory is where every other SP component already writes.
import os as _os
import time as _time
from paths import LOG_PATH as _LOG_PATH

# LOG_PATH is logs/source-python, which is where the main module's own logger
# writes and therefore the one directory guaranteed to exist. GAME_PATH would
# do, but LOG_PATH says what the file is for.
_HIB_LOG_PATH = str(_LOG_PATH / 'hib.txt')


def _hib_log(line):
    """One line to hib.txt, opened and flushed, or nothing if that fails.

    Failing to log must not take the server down, so everything here is guarded
    and the error is swallowed deliberately.
    """
    try:
        folder = _os.path.dirname(_HIB_LOG_PATH)
        if folder and not _os.path.isdir(folder):
            _os.makedirs(folder, exist_ok=True)
        with open(_HIB_LOG_PATH, 'a', encoding='utf-8', errors='replace') as handle:
            handle.write('%s %s\n' % (_time.strftime('%H:%M:%S'), line))
    except Exception:
        # Deliberately swallowed. A logger that can take the server down is worse
        # than no logger, and the run it is meant to explain is already a
        # failure; a missing line is a smaller loss than a second crash.
        pass


try:
    _hibernation_function = get_virtual_function(
        server_game_dll, _hibernation_function_name)

    # TEMPORARY DIAGNOSTIC: dump the runtime vtable and the resolved hibernation
    # target's raw bytes so the "Terminating control flow" detour failure can be
    # traced to the exact instruction. Pure Python (ctypes) - no core rebuild.
    try:
        import ctypes as _ctypes
        from memory import get_object_pointer as _get_obj_ptr

        def _rb(_addr, _n=24):
            try:
                return ' '.join('%02X' % _ctypes.c_ubyte.from_address(
                    int(_addr) + _i).value for _i in range(_n))
            except Exception as _e:
                return 'readfail:%s' % _e

        _po = _get_obj_ptr(server_game_dll)
        _this = int(_po)
        _vt = int(_po.get_pointer())
        _hib_log('HIBOBJ this=0x%X vtable=0x%X' % (_this, _vt))
        for _i in range(8):
            _slot = int(_ctypes.c_longlong.from_address(_vt + 8 * _i).value)
            _hib_log('HIBVT vt[%d]=0x%X bytes: %s' % (_i, _slot, _rb(_slot)))
        try:
            _fa = int(_hibernation_function.address)
            _hib_log('HIBFUNC Function.address=0x%X bytes: %s' % (_fa, _rb(_fa, 32)))
        except Exception as _e:
            _hib_log('HIBFUNC addr n/a: %s: %s' % (type(_e).__name__, _e))
    except Exception as error:
        _hib_log('HIB dump failed: %s: %s' % (type(error).__name__, error))

    # The decoration has to happen inside this try rather than in an else branch
    # after it. PreHook.__call__ runs the add_hook that actually drives
    # DynamicHooks, so applying the hook outside the try lets a detour failure
    # escape uncaught and take the whole main module down with it.
    #
    # This used to be masked. get_virtual_function failed first on Windows x86-64,
    # because the vtable-offset extractor only understood 32-bit x86 thunks and so
    # reported every virtual function as non-virtual; that failure was inside the
    # try and produced the intended warning. Once the extractor was fixed the
    # failure moved to add_hook, which sits outside, and the warning this block
    # exists to emit stopped being emitted.
    #
    # The value DynamicHooks raises for this is std::invalid_argument, which
    # Boost.Python surfaces as ValueError - already handled below.
    @PreHook(_hibernation_function)
    def _pre_hibernation_function(stack_data):
        """Called when the server is hibernating."""
        # Recorded before the guard, not after. If the guard is reading a value
        # that is not what it assumes, then whether it returns or falls through
        # is the decision being made, and the value that made it has to be in
        # the log either way. Logging only the fall-through path would make a
        # wrongly-true read look identical to a correctly-true one.
        try:
            _hib_log('hib len=%d s1=%r  raw=%r'
                     % (len(stack_data), stack_data[1], stack_data))
        except Exception as error:
            _hib_log('hib could not read stack_data: %s: %s'
                     % (type(error).__name__, error))

        if not stack_data[1]:
            _hib_log('hib guard returned, no bots touched')
            return

        # Disconnect all bots...
        _hib_log('hib guard PASSED, calling _disconnect_bots')
        _disconnect_bots()
        _hib_log('hib _disconnect_bots returned')

    _hib_log('HIB HOOK INSTALLED OK addr=0x%X'
             % int(_hibernation_function.address))
except Exception as error:
    import traceback as _tb
    _hib_log('HIB HOOK FAILED [%s]: %r' % (type(error).__name__, error))
    _hib_log('HIB TRACEBACK: '
             + _tb.format_exc().replace('\n', ' | '))
    from warnings import warn
    warn('Unable to install the hibernation hook: {0}'.format(error))


@OnLevelEnd
def _on_level_end():
    """Disconnect all bots on level end."""
    # The other way into _disconnect_bots(). It needs no hook - an engine event
    # drives it - so it was still live during the run that removed the
    # hibernation hook, and the crash did not move. Recording entry and exit
    # here tells us whether it is reached at all, and whether the crash happens
    # inside it rather than after it.
    _hib_log('level_end entered')
    _disconnect_bots()
    _hib_log('level_end _disconnect_bots returned')


def _disconnect_bots():
    """Disconnect all bots."""

    # Cyclic import...
    from filters.players import PlayerIter

    bots = list(PlayerIter('bot'))
    _hib_log('disconnect_bots: %d bot(s): %r'
             % (len(bots), [bot.index for bot in bots]))

    # Notify OnClientDisconnect listener for all bots...
    for bot in bots:
        _hib_log('disconnect_bots: notifying index %d' % bot.index)
        on_client_disconnect_listener_manager.notify(bot.index)
        _hib_log('disconnect_bots: notified index %d' % bot.index)

    _hib_log('disconnect_bots: done')

# sp_cmdchurn.py
# Diagnostic (NOT shipped in stable, NOT auto-loaded): aggressively churns
# server ConCommand registration/unregistration (plus a few ConVar creates)
# to stress the engine CCvar registration list and Source.Python's command
# object lifetime on Windows x86-64. Load manually: sp plugin load sp_cmdchurn
from commands.server import server_command_manager
from cvars import ConVar
from listeners import OnTick
import gc

BATCH = 40          # commands touched per round (half reused names, half unique)
ROUNDS = 400        # ~16k register/unregister cycles
TICK_EVERY = 100    # run a round roughly every 1.5s at 64 tick

state = {'tick': 0, 'round': 0, 'reg': 0, 'unreg': 0, 'hold': []}


def _make_cb(tag):
    def cb(cmd):
        pass
    cb.__name__ = 'cb_%s' % tag
    return cb


def _do_round():
    r = state['round']

    # Release the previous round's cross-frame held commands first.
    for name, cb in state['hold']:
        try:
            server_command_manager.unregister_commands(name, cb)
            state['unreg'] += 1
        except Exception as e:
            print('[sp_cmdchurn] held unreg error %s: %s' % (name, e))
    state['hold'] = []

    # Reused names: exercises CreateCommand's find-existing -> unregister old
    # -> new manager -> destructor/restore path.
    for j in range(BATCH // 2):
        name = 'sp_churn_reuse_%d' % j
        cb = _make_cb('r%d_%d' % (r, j))
        server_command_manager.register_commands(name, cb)
        state['reg'] += 1
        if j & 1:
            server_command_manager.unregister_commands(name, cb)
            state['unreg'] += 1
        else:
            state['hold'].append((name, cb))

    # Unique names: pure create/delete of fresh CServerCommandManager objects.
    base = r * BATCH
    for j in range(BATCH // 2):
        name = 'sp_churn_u_%d' % (base + j)
        cb = _make_cb('u%d' % (base + j))
        server_command_manager.register_commands(name, cb)
        state['reg'] += 1
        if j & 1:
            server_command_manager.unregister_commands(name, cb)
            state['unreg'] += 1
        else:
            state['hold'].append((name, cb))

    if r % 10 == 0:
        ConVar('sp_churn_cvar_%d' % (r // 10), str(r))

    if r % 25 == 0:
        gc.collect()
        print('[sp_cmdchurn] round=%d reg=%d unreg=%d held=%d'
              % (r, state['reg'], state['unreg'], len(state['hold'])))


@OnTick
def _on_tick():
    state['tick'] += 1
    if state['tick'] % TICK_EVERY:
        return
    if state['round'] >= ROUNDS:
        return
    _do_round()
    state['round'] += 1
    if state['round'] >= ROUNDS:
        print('[sp_cmdchurn] DONE reg=%d unreg=%d'
              % (state['reg'], state['unreg']))


def load():
    print('[sp_cmdchurn] loaded - beginning command register/unregister churn')


def unload():
    for name, cb in list(state['hold']):
        try:
            server_command_manager.unregister_commands(name, cb)
        except Exception:
            pass
    state['hold'] = []
    print('[sp_cmdchurn] unloaded')

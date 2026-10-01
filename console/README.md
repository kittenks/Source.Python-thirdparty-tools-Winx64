# console/

Helpers for driving a running `srcds` dedicated-server console during local
smoke tests.

## `console_input.ps1`

Injects one command line into a running dedicated-server console window using
`AttachConsole` + `WriteConsoleInputW` against `CONIN$`. It writes **input only**;
the server's stdout is left untouched (capture it separately with `-condebug`
or a redirected log).

```powershell
powershell -ExecutionPolicy Bypass -File console\console_input.ps1 `
    -ServerPid 12345 -Line "sp plugin load sp_hibprobe"
```

`-ServerPid` is the PID of `srcds_win64.exe`; `-Line` is the console command
(no trailing newline required - the script sends Enter itself). The script
prints the number of input records written. Negative return values encode a
Win32 failure stage:

| return | stage |
|---|---|
| `-100 - <err>` | `AttachConsole` failed (wrong PID, or not the same desktop session) |
| `-200 - <err>` | opening `CONIN$` failed |
| `-300 - <err>` | `WriteConsoleInputW` failed |

Run it from the same user/desktop session as the server. It is a local
test-automation aid and is not used by, nor copied into, the game packages.

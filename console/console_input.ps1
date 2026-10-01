# Inject a command line into a running srcds dedicated-server console window
# via AttachConsole + WriteConsoleInput (input only; stdout is untouched).
param(
    [Parameter(Mandatory=$true)][int]$ServerPid,
    [Parameter(Mandatory=$true)][string]$Line
)
Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;

public static class ConIn {
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool FreeConsole();
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool AttachConsole(uint pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr GetStdHandle(int n);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true, BestFitMapping=false)]
    static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool WriteConsoleInputW(
        IntPtr hConsoleInput, INPUT_RECORD[] lpBuffer, uint nLength, out uint lpNumberOfEventsWritten);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);

    [StructLayout(LayoutKind.Sequential)]
    struct KEY_EVENT_RECORD {
        [MarshalAs(UnmanagedType.Bool)] public bool bKeyDown;
        public ushort wRepeatCount;
        public ushort wVirtualKeyCode;
        public ushort wVirtualScanCode;
        public char UnicodeChar;
        public uint dwControlKeyState;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct INPUT_RECORD {
        public ushort EventType; // 1 = KEY_EVENT
        public KEY_EVENT_RECORD KeyEvent;
    }

    static INPUT_RECORD Key(char ch, bool down, ushort vk) {
        INPUT_RECORD r = new INPUT_RECORD();
        r.EventType = 1;
        r.KeyEvent.bKeyDown = down;
        r.KeyEvent.wRepeatCount = 1;
        r.KeyEvent.wVirtualKeyCode = vk;
        r.KeyEvent.UnicodeChar = ch;
        r.KeyEvent.dwControlKeyState = 0;
        return r;
    }

    public static int Send(uint pid, string line) {
        FreeConsole();
        if (!AttachConsole(pid)) { return -100 - Marshal.GetLastWin32Error(); }
        // The launching process may have a redirected (pipe) stdin, so open the
        // attached console's active input buffer explicitly via CONIN$.
        IntPtr h = CreateFileW("CONIN$", 0xC0000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (h == IntPtr.Zero || h == (IntPtr)(-1)) { return -200 - Marshal.GetLastWin32Error(); }

        List<INPUT_RECORD> recs = new List<INPUT_RECORD>();
        foreach (char ch in line) {
            recs.Add(Key(ch, true, 0));
            recs.Add(Key(ch, false, 0));
        }
        recs.Add(Key('\r', true, 0x0D));  // Enter
        recs.Add(Key('\r', false, 0x0D));

        uint written;
        bool ok = WriteConsoleInputW(h, recs.ToArray(), (uint)recs.Count, out written);
        int ec = Marshal.GetLastWin32Error();
        CloseHandle(h);
        if (!ok) { return -300 - ec; }
        return (int)written;
    }
}
'@
$n = [ConIn]::Send([uint32]$ServerPid, $Line)
"events written: $n  (line: $Line)"

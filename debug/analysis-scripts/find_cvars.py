import os, glob

dirs = [
    r"D:\Counter-Strike-Source\bin\x64",
    r"D:\Counter-Strike-Source\cstrike\bin\x64",
]
needles = [
    b"sv_hibernate_when_empty",
    b"hibernate_when_empty",
    b"sv_hibernate",
    b"bot_join_after_player",
    b"join_after_player",
    b"bot_quota_mode",
    b"bot_quota",
    b"bot_difficulty",
    b"bot_auto_vacate",
]

def context(data, idx, span=48):
    a = max(0, idx - span); b = min(len(data), idx + span)
    chunk = data[a:b]
    return ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)

files = []
for d in dirs:
    files += glob.glob(os.path.join(d, "*.dll"))
for t in sorted(set(files)):
    try:
        data = open(t, "rb").read()
    except Exception:
        continue
    hits = []
    for n in needles:
        start = 0
        while True:
            j = data.find(n, start)
            if j < 0:
                break
            hits.append((n.decode(), j, context(data, j)))
            start = j + 1
    if hits:
        print("=" * 70)
        print(os.path.basename(t))
        seen = set()
        for name, off, ctx in hits:
            key = (name, off)
            if key in seen:
                continue
            seen.add(key)
            print("  [FOUND] %-26s @0x%08X  ...%s..." % (name, off, ctx))

print("\n---- summary of presence ----")
allblob = b""
for t in files:
    try:
        allblob += open(t, "rb").read()
    except Exception:
        pass
for n in needles:
    print("  %-26s %s" % (n.decode(), "PRESENT" if n in allblob else "absent"))

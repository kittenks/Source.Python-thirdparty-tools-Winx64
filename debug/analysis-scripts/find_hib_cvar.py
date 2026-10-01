import re
t = r"D:\Counter-Strike-Source\bin\x64\engine.dll"
data = open(t, "rb").read()
pat = re.compile(rb"[\x20-\x7e]{3,}")
cvars = set()
word = re.compile(r"^(sv|host|mp|bot|net|sys|fps)_[a-z0-9_]{2,}$")
kw = re.compile(r"hib|sleep|idle|wake|tick|frame|pause|freeze|quota|think|stall|snooze|nap", re.I)
for m in pat.finditer(data):
    s = m.group().decode("ascii", "replace")
    if word.match(s):
        cvars.add(s)
print("--- cvars matching idle/sleep/hibernate/wake/tick etc ---")
for c in sorted(cvars):
    if kw.search(c):
        print("   ", c)
print("--- total sv_/host_/mp_/bot_ cvar-like strings:", len(cvars))
# Also dump any token containing 'hibernate' regardless of prefix
print("--- ALL tokens containing 'hibernat' ---")
for m in pat.finditer(data):
    s = m.group().decode("ascii", "replace")
    if "hibernat" in s.lower() and not s.startswith(("?", ".", "!")):
        print("   ", repr(s))

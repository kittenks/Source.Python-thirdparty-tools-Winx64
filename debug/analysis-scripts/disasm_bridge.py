import re
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

path = r"D:\Counter-Strike-Source\cstrike\logs\source-python\sp_snap.txt"
hexbytes = None
with open(path, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        if line.startswith("   BYTES "):
            hexbytes = line.split("BYTES ", 1)[1].strip()
            break

assert hexbytes, "no BYTES line found"
code = bytes.fromhex(hexbytes)
print("total bytes dumped:", len(code), "hex len", len(hexbytes))

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False

# bridge base as recorded
base = 0x00000212CE000280
count = 0
for ins in md.disasm(code, base):
    print(f"{ins.address-base:#05x}  {ins.bytes.hex():<24} {ins.mnemonic:<8} {ins.op_str}")
    count += 1
    if ins.mnemonic in ("jmp", "ret") and count > 20:
        # keep going a little but mark
        pass
    if count >= 70:
        break

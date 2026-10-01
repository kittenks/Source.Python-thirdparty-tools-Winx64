import sys, struct
from capstone import *

DLL = r"C:\Users\Administrator\Documents\GitHub\Source.Python\src\Builds\Windows\css-x64\Release\core.dll"
TARGET_RVA = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x566632
WINDOW_BACK = 0x600
WINDOW_FWD  = 0x60

data = open(DLL, "rb").read()
e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
coff = e_lfanew + 4
num_sec = struct.unpack_from("<H", data, coff+2)[0]
opt_size = struct.unpack_from("<H", data, coff+16)[0]
sec_tab = coff + 20 + opt_size
image_base = struct.unpack_from("<Q", data, coff+20+24)[0]  # ImageBase (PE32+ offset 24)

def rva_to_off(rva):
    for i in range(num_sec):
        s = sec_tab + i*40
        name = data[s:s+8].rstrip(b"\x00")
        vsz, va, rsz, raw = struct.unpack_from("<IIII", data, s+8)
        if va <= rva < va + max(vsz, rsz):
            return raw + (rva - va), name.decode(errors="replace"), va, raw
    return None, None, None, None

off, secname, sec_va, sec_raw = rva_to_off(TARGET_RVA)
print(f"ImageBase=0x{image_base:X} target RVA=0x{TARGET_RVA:X} section={secname} fileoff=0x{off:X}")

# Find a likely function start: nearest preceding ENDBR64 (F3 0F 1E FA) that
# follows CC padding or a RET/C3, scanning back up to WINDOW_BACK.
def is_endbr(buf, i):
    return buf[i:i+4] == b"\xF3\x0F\x1E\xFA"

start_rva = TARGET_RVA
scan = TARGET_RVA
lo = TARGET_RVA - WINDOW_BACK
cand = None
while scan > lo:
    o,_,_,_ = rva_to_off(scan)
    if o and is_endbr(data, o):
        prev = data[o-1]
        if prev in (0xCC, 0xC3):
            cand = scan
            break
    scan -= 1
if cand is not None:
    start_rva = cand
    print(f"likely function start RVA=0x{start_rva:X} (ENDBR64 after 0x{data[rva_to_off(start_rva)[0]-1]:02X})")
else:
    start_rva = TARGET_RVA - 0x40
    print("no ENDBR64 prologue found; disassembling from target-0x40")

start_off,_,_,_ = rva_to_off(start_rva)
end_rva = TARGET_RVA + WINDOW_FWD
end_off,_,_,_ = rva_to_off(end_rva)
code = data[start_off:end_off]

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False
for ins in md.disasm(code, image_base + start_rva):
    rva = ins.address - image_base
    mark = "  <<<< FAULT" if rva == TARGET_RVA else ""
    print(f"  core+0x{rva:06X}  {ins.bytes.hex():<22} {ins.mnemonic:<8} {ins.op_str}{mark}")
    if rva >= TARGET_RVA + 0x30:
        break

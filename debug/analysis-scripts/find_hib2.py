import struct
from capstone import *

DLL = r"D:\Counter-Strike-Source\cstrike\bin\x64\server.dll"
data = open(DLL, "rb").read()
e = struct.unpack_from("<I", data, 0x3C)[0]
coff = e + 4
num_sec = struct.unpack_from("<H", data, coff+2)[0]
opt_size = struct.unpack_from("<H", data, coff+16)[0]
sec_tab = coff + 20 + opt_size
image_base = struct.unpack_from("<Q", data, coff+20+24)[0]
secs = []
for i in range(num_sec):
    s = sec_tab + i*40
    name = data[s:s+8].rstrip(b"\x00").decode(errors="replace")
    vsz, va, rsz, raw = struct.unpack_from("<IIII", data, s+8)
    secs.append((name, va, vsz, raw, rsz))

def rva_to_off(rva):
    for n, va, vsz, raw, rsz in secs:
        if va <= rva < va + max(vsz, rsz):
            return raw + (rva - va)
    return None
def off_to_rva(off):
    for n, va, vsz, raw, rsz in secs:
        if raw <= off < raw + rsz:
            return va + (off - raw)
    return None
def sec_of(off):
    for n, va, vsz, raw, rsz in secs:
        if raw <= off < raw+rsz: return n
    return "?"
def find_all(needle, lo=0, hi=len(data)):
    out=[]; i=lo
    while True:
        j=data.find(needle,i,hi)
        if j<0: break
        out.append(j); i=j+1
    return out

SETTER_RVA = 0x1B52A0
SETTER_VA  = image_base + SETTER_RVA
COL_RVA    = 0x5E4388
md = Cs(CS_ARCH_X86, CS_MODE_64)

def disasm(rva, count=12, label=""):
    off=rva_to_off(rva)
    if off is None:
        print("      %s RVA=0x%X unmapped" % (label, rva)); return
    raw=data[off:off+48]
    print("      %s RVA=0x%X bytes=%s" % (label, rva, raw[:20].hex(' ')))
    n=0
    for ins in md.disasm(raw, image_base+rva):
        print("          0x%X: %-12s %s %s" % (ins.address-image_base, ins.bytes.hex(' '), ins.mnemonic, ins.op_str))
        n+=1
        if n>=count: break

print("=== all DWORD refs to COL RVA 0x%X (vtable[-1] candidates) ===" % COL_RVA)
for h in find_all(struct.pack("<I", COL_RVA)):
    print("  file 0x%X rva 0x%X sec %s  next16: %s" % (h, off_to_rva(h), sec_of(h), data[h+4:h+20].hex(' ')))

print()
print("=== all QWORD refs to setter VA 0x%X (the 88 51 10 C3 fn) ===" % SETTER_VA)
for h in find_all(struct.pack("<Q", SETTER_VA)):
    rva = off_to_rva(h)
    print("  slot file 0x%X rva 0x%X sec %s" % (h, rva, sec_of(h)))
    # assume 8-byte aligned vtable slot; walk back to the COL-ptr head
    # find nearest preceding DWORD == COL_RVA at (candidate_vt-4)
    # search backwards up to 0x400 bytes for a 4-byte COL ref that is 8-aligned relative
    for back in range(0, 0x600, 8):
        vt_off = h - back
        if vt_off-4 < 0: break
        if struct.unpack_from("<I", data, vt_off-4)[0] == COL_RVA:
            vt_rva = off_to_rva(vt_off)
            index = (h - vt_off)//8
            print("    => vtable head file 0x%X rva 0x%X ; setter is vt[%d]" % (vt_off, vt_rva, index))
            for i in range(0, 9):
                va = struct.unpack_from("<Q", data, vt_off+8*i)[0]
                fr = va-image_base
                tag = " <== SETTER" if va==SETTER_VA else ""
                print("       vt[%d] VA=0x%X RVA=0x%X%s" % (i, va, fr, tag))
            print("    --- disasm vt[1] (SP's SetServerHibernation target) ---")
            va1 = struct.unpack_from("<Q", data, vt_off+8)[0]
            disasm(va1-image_base, label="vt[1]")
            break

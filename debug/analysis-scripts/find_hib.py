import struct, re, sys
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

def sec_range(names):
    lo = hi = None
    for n, va, vsz, raw, rsz in secs:
        if n in names:
            a, b = raw, raw + rsz
            if lo is None or a < lo: lo = a
            if hi is None or b > hi: hi = b
    return lo, hi

print("image_base=0x%X sections=%s" % (image_base, [s[0] for s in secs]))

# 1) find RTTI type descriptors whose name contains ServerGameDLL
tds = []
for m in re.finditer(rb"\.\?AV[0-9A-Za-z_]*ServerGameDLL@@\x00", data):
    name = m.group(0).rstrip(b"\x00").decode(errors="replace")
    name_off = m.start()
    td_off = name_off - 16
    td_rva = off_to_rva(td_off)
    if td_rva is not None:
        tds.append((name, td_off, td_rva))
# also dump any name containing ServerGameDLL at all (broader)
if not tds:
    for m in re.finditer(rb"[A-Za-z0-9_@\.?]+ServerGameDLL[A-Za-z0-9_@]*", data):
        print("candidate string @0x%X: %r" % (m.start(), m.group(0)[:80]))
print("type descriptors:")
for n, o, r in tds:
    print("  TD rva=0x%X name=%s" % (r, n))

rdata_lo, rdata_hi = sec_range({".rdata", ".data", "_RDATA"})

def find_all(needle, lo, hi):
    out = []
    i = lo
    while True:
        j = data.find(needle, i, hi)
        if j < 0: break
        out.append(j); i = j + 1
    return out

md = Cs(CS_ARCH_X86, CS_MODE_64)

def disasm_func(func_rva, count=24, label=""):
    off = rva_to_off(func_rva)
    if off is None:
        print("    %s func rva=0x%X (unmapped)" % (label, func_rva)); return
    raw = data[off:off+64]
    print("    %s func RVA=0x%X  bytes: %s" % (label, func_rva, raw[:24].hex(' ')))
    n = 0
    for ins in md.disasm(raw, image_base + func_rva):
        print("        0x%X: %-10s %s %s" % (ins.address - image_base, ins.bytes.hex(' '), ins.mnemonic, ins.op_str))
        n += 1
        if n >= count: break

for name, td_off, td_rva in tds:
    # 2) COL.pTypeDescriptor is a DWORD RVA == td_rva; COL starts 12 bytes before
    for f in find_all(struct.pack("<I", td_rva), rdata_lo, rdata_hi):
        col_off = f - 12
        sig, doff, cdoff, ptd, pchd, pself = struct.unpack_from("<IIIIII", data, col_off)
        col_rva = off_to_rva(col_off)
        if sig != 1: continue
        if pself != col_rva: continue
        print("COL rva=0x%X sig=%d off=%d pTD=0x%X pSelf=0x%X" % (col_rva, sig, doff, ptd, pself))
        # 3) vtable[-1] = COL RVA (DWORD); vtable starts right after
        for q in find_all(struct.pack("<I", col_rva), rdata_lo, rdata_hi):
            if q == col_off + 20:
                continue  # COL.pSelf references the COL itself; not a vtable
            vt_off = q + 4   # x64 vtable[-1] is a 4-byte image-relative COL RVA
            vt_rva = off_to_rva(vt_off)
            if vt_rva is None: continue
            va0 = struct.unpack_from("<Q", data, vt_off)[0]
            if rva_to_off(va0 - image_base) is None:
                print("  candidate COL-ref at file 0x%X: vt[0] VA=0x%X not in .text, skip" % (q, va0)); continue
            print("  vtable RVA=0x%X (file 0x%X)" % (vt_rva, vt_off))
            for i in range(8):
                va = struct.unpack_from("<Q", data, vt_off + 8*i)[0]
                frva = va - image_base
                mark = " <== SetServerHibernation(index1)" if i == 1 else ""
                print("    vt[%d] VA=0x%X RVA=0x%X%s" % (i, va, frva, mark))
            disasm_func(struct.unpack_from("<Q", data, vt_off + 8*1)[0] - image_base, label="vt[1]")
            print("  --- neighbors ---")
            for i in (0,2,3):
                va = struct.unpack_from("<Q", data, vt_off + 8*i)[0]
                disasm_func(va - image_base, count=8, label="vt[%d]" % i)

# 4) search the documented setter bytes 88 51 10 C3 in .text
tlo, thi = sec_range({".text"})
hits = find_all(b"\x88\x51\x10\xC3", tlo, thi)
print("occurrences of 88 51 10 C3 (mov [rcx+0x10],dl; ret): %d" % len(hits))
for h in hits[:10]:
    print("   file 0x%X RVA 0x%X" % (h, off_to_rva(h)))

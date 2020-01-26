//
//  exploit.h
//  watchme
//
//  Created by Sem Voigtländer on 16/01/20.
//  Copyright © 2020 kernelprogrammer. All rights reserved.
//

#ifndef exploit_h
#define exploit_h

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <mach/mach.h>

#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>
#include <mach-o/swap.h>


typedef struct MachoSym {
    const char *Name;
    mach_vm_address_t Address;
} MachoSym;

typedef struct Macho64 {
    struct mach_header_64* hdr;
    bool swap;
    struct load_command** cmds;
    struct segment_command_64** segs;
    struct section_64** sects;
    struct MachoSym* syms;
} Macho64;

typedef struct Macho32 {
    struct mach_header* hdr;
    bool swap;
    struct load_command** cmds;
    struct segment_command_64** segs;
    struct section_64** sects;
    struct MachoSym* syms;
} Macho32;

typedef struct MachoProc {
    task_t task;
    pid_t pid;
    uid_t uid;
    gid_t gid;
    const char *name;
    struct Macho64** m64;
    struct Macho32** m32;
} MachoProc;

typedef struct ROPInstr {
    uint32_t instruction;
    struct ROPInstr* next;
} ROPInstr;

typedef struct ROPGadget {
    ROPInstr instructions;
    const char* name;
} ROPGadget;

typedef struct ROPChain {
    ROPGadget* gadgets;
    const char* name;
} ROPChain;

typedef uint64_t dyld_slide_t;
typedef mach_vm_address_t kern_addr_t;
typedef mach_vm_address_t uaddr_t;

extern kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
extern kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);

#endif /* exploit_h */

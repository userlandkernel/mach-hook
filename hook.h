#ifndef HOOK_H
#define HOOK_H

#include <stdio.h>
#include <mach/mach.h>
struct A64INSTr {
    uint32_t *instructions;
    uint64_t count;
};

extern kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
extern kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);

#endif

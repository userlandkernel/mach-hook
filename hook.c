/*
 * Copyright 2020 (c) Sem Voigtländer
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <string.h>
#include <dlfcn.h>
#include <fcntl.h>

#include <sys/utsname.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/mman.h>

#include <mach/mach.h>

#include "exploit.h"

dyld_slide_t g_dyldSlide = 0;

static inline
int string_compare(const char* s1, const char* s2)
{
    while (*s1 != '\0' && *s1 == *s2)
    {
        s1++;
        s2++;
    }
    return (*(unsigned char *) s1) - (*(unsigned char *) s2);
}

static inline struct dyld_all_image_infos* task_img_infos(task_t task) {
    
    kern_return_t ret = KERN_SUCCESS;
    
    struct task_dyld_info dyldInfo = {};
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    
    struct dyld_all_image_infos* infos = NULL;
    
    if(!MACH_PORT_VALID(task)) {
        fprintf(stderr, "Invalid task.\n");
        return NULL;
    }

    
    ret = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
    if(ret != KERN_SUCCESS) {
        fprintf(stderr, "task_info failed: %s.\n", mach_error_string(ret));
        return NULL;
    }

    if(sizeof(struct dyld_all_image_infos) > dyldInfo.all_image_info_size) {
        fprintf(stderr, "\tAll image info size mismatch.\n");
        return NULL;
    }
    
    if(mach_task_self() == task) {
        infos = (struct dyld_all_image_infos*)dyldInfo.all_image_info_addr;
    }
    else {
        infos = malloc((size_t)dyldInfo.all_image_info_size);
        mach_vm_size_t read = 0;
        ret = mach_vm_read_overwrite(task, dyldInfo.all_image_info_addr, dyldInfo.all_image_info_size, (mach_vm_address_t)infos, &read);
        if(ret != KERN_SUCCESS) {
            fprintf(stderr, "\tfailed reading all image info from remote process: %s.\n", mach_error_string(ret));
            infos = NULL;
        }
    }
    
    
    return infos;
}


static inline dyld_slide_t dyldSlide(void) {
    
    struct dyld_all_image_infos* infos = NULL;
    
    if(g_dyldSlide)
        return g_dyldSlide;
    
    infos = task_img_infos(mach_task_self());
    
    if(!infos) {
        return 0;
    }
    
    g_dyldSlide = infos->sharedCacheSlide;
    
    return g_dyldSlide;
}

kern_return_t mach_vm_strlen(task_t task, mach_vm_address_t address, mach_vm_size_t* len) {
    kern_return_t ret = KERN_SUCCESS;
    mach_vm_size_t read = 0;
    char c = 'X';
    while (c != '\0' && ret == KERN_SUCCESS) {
        ret = mach_vm_read_overwrite(task, address, 1, (mach_vm_address_t)&c, &read);
        len[0] = len[0] + 1;
        address++;
    }
    return ret;
}

char* mach_vm_string(task_t task, char* remotePtr) {
    kern_return_t ret = KERN_SUCCESS;
    mach_vm_size_t read = 0;
    mach_vm_size_t len = 0;
    ret = mach_vm_strlen(task, (mach_vm_address_t)remotePtr, &len);
    char *localstr = malloc((size_t)len);
    bzero(localstr, (size_t)len);
    ret = mach_vm_read_overwrite(task, (mach_vm_address_t)remotePtr, len, (mach_vm_address_t)localstr, &read);
    if(ret != KERN_SUCCESS) {
        if(localstr) {
            free(localstr);
            localstr = NULL;
        }
    }
    return localstr;
}

static void MachProcInit(MachoProc proc) {

    kern_return_t err = KERN_SUCCESS;
    struct dyld_all_image_infos* infos = NULL;
    struct dyld_image_info* image = NULL;
    Macho64* current64 = NULL;
    Macho32* current32 = NULL;
    
    proc.m64 = NULL;
    proc.m32 = NULL;
    proc.name = NULL;

    if(!MACH_PORT_VALID(proc.task)) {
        if(proc.pid == getpid()) {
            proc.task = mach_task_self();
        }
        else {
            err = task_for_pid(mach_task_self(), proc.pid, &proc.task);
            if(err != KERN_SUCCESS) {
                fprintf(stderr, "task_for_pid(%d) failed.\n", proc.pid);
                return;
            }
            
        }
    }

    printf("MACH_PROC_INIT\n");
    printf("\tpid: %d\n", proc.pid);
    printf("\ttask: %#x\n", proc.task);

    infos = task_img_infos(proc.task);

    if(!infos) {
        fprintf(stderr, "task_img_infos(%#x) failed.\n", proc.task);
    }
    
    printf("\tcount: %d images\n", infos->infoArrayCount);

    // Allocate array with N references to Macho's
    proc.m64 = malloc(sizeof(Macho64*) * infos->infoArrayCount);
    proc.m32 = malloc(sizeof(Macho32*) * infos->infoArrayCount);
    
    
    printf("\timages:\n\n");
    for(int i = 0; i < infos->infoArrayCount; ++i) {
        
        // Point to the next image
        if(proc.task == mach_task_self()) {
            image = (struct dyld_image_info*)((unsigned long)infos->infoArray + i);
        }
        else {
            mach_vm_size_t read = 0;
            image = malloc(sizeof(struct dyld_image_info));
            bzero(image, sizeof(struct dyld_image_info));
            err = mach_vm_read_overwrite(proc.task, (mach_vm_address_t)(infos->infoArray + i), sizeof(struct dyld_image_info), (mach_vm_address_t)image, &read);
            if(err != KERN_SUCCESS) {
                fprintf(stderr, "\tfailed reading image info from remote process: %s.\n", mach_error_string(err));
                free(image);
                image = NULL;
                return;
            }
        }

        // Optionally you can print the image path and modification date
        // That might be useful when you want to verify integrity of dynamic libraries
        if(proc.task == mach_task_self()) {
            printf("image #%d:\n\tPath: %s\n\tBase address: %#llx (local)\n", i, image->imageFilePath, (uint64_t)image->imageLoadAddress);
        }
        else {
            char* imageFilePath = mach_vm_string(proc.task, (char*)image->imageFilePath);
            if(!imageFilePath) {
                printf("image #%d:\n\tPath: %s\n\tBase address: %#llx (remote)\n", i, "unknown", (uint64_t)image->imageLoadAddress);
            } else {
                printf("image #%d:\n\tPath: %s\n\tBase address: %#llx (remote)\n", i, imageFilePath, (uint64_t)image->imageLoadAddress);
                free(imageFilePath); // FREE!!!
                imageFilePath = NULL;
            }
        }
        
        // Allocate the actual objects
        proc.m64[i] = malloc(sizeof(Macho64));
        proc.m32[i] = malloc(sizeof(Macho32));
        
        // Zero out the pointers etc
        bzero(proc.m64[i], sizeof(Macho64));
        bzero(proc.m32[i], sizeof(Macho32));
        
        if(proc.task == mach_task_self()) {
            
            // Point the header to the image addresses
            proc.m64[i]->hdr = (struct mach_header_64*)image->imageLoadAddress;
            proc.m32[i]->hdr = (struct mach_header*)image->imageLoadAddress;
            
            current64 = proc.m64[i];
            
            printf("\t\tmagic: %#x\n", current64->hdr->magic);
            
            // Check the magic and wether it'd need to be swapped
            if(current64->hdr->magic == 0xfeedfacf || current64->hdr->magic == 0xfeedface) {
                current64->swap = false;
            }
            else {
                current64->swap = false;
            }
            
            printf("\t\tendian: %s\n", current64->swap ? "little" : "big");
            
            // Now check whether its 64-bit or 32-bit
            if(current64->hdr->magic == 0xfeedfacf) {
                
                // Swap endianness if needed
                if(current64->swap) {
                    swap_mach_header_64(current64->hdr, 0);
                }
                
                proc.m64[i]->cmds = malloc(proc.m64[i]->hdr->ncmds * sizeof(struct load_command*));
                bzero(proc.m64[i]->cmds, proc.m64[i]->hdr->ncmds * sizeof(struct load_command*));
                
                struct symtab_command *symtab = NULL;
                struct segment_command_64 *LINKEDIT = NULL, *TEXT = NULL, *DATA = NULL;
                struct load_command* lc = (void*)proc.m64[i]->hdr + sizeof(struct mach_header_64);
                
                proc.m64[i]->segs = malloc(proc.m64[i]->hdr->ncmds * sizeof(struct segment_command_64*));
                
                for(int j = 0, k = 0; j < proc.m64[i]->hdr->ncmds; j++) {
                    
                    // Swap endianness if needed
                    if(current64->swap) {
                        swap_load_command(lc, 0);
                    }
                    
                    
                    // Check if it's a segment command
                    if (lc->cmd == LC_SEGMENT_64) {
                       
                        proc.m64[i]->segs[k] = (struct segment_command_64*)lc;
                        
                        // Swap endianess if needed
                        if(current64->swap) {
                            swap_segment_command_64(proc.m64[i]->segs[k], 0);
                        }
                        
                        printf("\t\tsegment: %s\n", proc.m64[i]->segs[k]->segname);
                        printf("\t\tcount: %d sections.\n", proc.m64[i]->segs[k]->nsects);
                        printf("\t\tregion: %#llx - %#llx / %#llx - %#llx prot: %d - %d\n", proc.m64[i]->segs[k]->fileoff, proc.m64[i]->segs[k]->fileoff + proc.m64[i]->segs[k]->filesize, proc.m64[i]->segs[k]->vmaddr, proc.m64[i]->segs[k]->vmaddr + proc.m64[i]->segs[k]->vmsize, proc.m64[i]->segs[k]->initprot, proc.m64[i]->segs[k]->maxprot);
                        
                        // Now go over the sections
                        for(int l = 0; l < proc.m64[i]->segs[k]->nsects; l++) {
                            
                        }
                        
                        k++; // increment segment index counter
                    }
                    else if (lc->cmd == LC_SYMTAB) {
                        symtab = (struct symtab_command*)lc;
                        printf("\tsymtab\n");
                        printf("\t\tcount: %d symbols.\n", symtab->nsyms);
                        
                    }
                    proc.m64[i]->cmds[j] = lc;
                    lc = (struct load_command *)((unsigned long)lc + lc->cmdsize);
                }
                
            }
            
        }
        
        else {
            
            // Allocate the header
            proc.m64[i]->hdr = malloc(sizeof(struct mach_header_64));
            proc.m32[i]->hdr = malloc(sizeof(struct mach_header));
            
            // Now copy the headers from the remote
            mach_vm_size_t outSize = 0;
            
            // First the 32-bit one
            err = mach_vm_read_overwrite(proc.task, (mach_vm_address_t)image->imageLoadAddress, sizeof(struct mach_header), (mach_vm_address_t)proc.m32[i]->hdr, &outSize);
            
            if(err != KERN_SUCCESS) {
                // Optionally print error message
                return;
            }
            
            // Then the 64-bit one
            err = mach_vm_read_overwrite(proc.task, (mach_vm_address_t)image->imageLoadAddress, sizeof(struct mach_header_64), (mach_vm_address_t)proc.m64[i]->hdr, &outSize);
            
            if(err != KERN_SUCCESS) {
                // Optionally print error message
                return;
            }
            
            current64 = proc.m64[i];
            
            printf("\t\tmagic: %#x\n", current64->hdr->magic);
            
            // Check the magic and wether it'd need to be swapped
            if(current64->hdr->magic == MH_MAGIC_64 || current64->hdr->magic == MH_MAGIC) {
                current64->swap = false;
            }
            else if(current64->hdr->magic == MH_CIGAM_64 || current64->hdr->magic == MH_CIGAM){
                current64->swap = false;
            }
            
            // Now check whether its 64-bit or 32-bit
            if(current64->hdr->magic == 0xfeedfacf) {
                
                // Lets say its safe to free and nullify the 32-bit version
                free(proc.m32[i]->hdr);
                proc.m32[i]->hdr = NULL;
                bzero(proc.m32[i], sizeof(Macho32));
                
                // Swap endianness if needed
                if(current64->swap) {
                    swap_mach_header_64(current64->hdr, 0);
                }
                
                // Allocate array of N references to load commands
                proc.m64[i]->cmds = malloc(sizeof(struct load_command*) * current64->hdr->ncmds);
                
                // Allocate array of N references to segments
                proc.m64[i]->segs = malloc(sizeof(struct segment_command_64*) * current64->hdr->ncmds);
                
                
                // Zero out the pointers for security reasons
                bzero(proc.m64[i]->cmds, sizeof(struct load_command*) * current64->hdr->ncmds);
                bzero(proc.m64[i]->segs, sizeof(struct segment_command_64*) * current64->hdr->ncmds);
                
                // Point to the load commands in the remote process
                mach_vm_address_t cmdaddr = (mach_vm_address_t)image->imageLoadAddress + sizeof(struct mach_header_64);
               
                struct symtab_command *symtab = malloc(sizeof(struct symtab_command));
                struct segment_command_64 *LINKEDIT = NULL, *TEXT = NULL, *TEXT_EXEC = NULL, *DATA = NULL;
                
                // Go over each load command
                for(int j = 0, k = 0; j < current64->hdr->ncmds; j++) {
                    
                    proc.m64[i]->cmds[j] = malloc(sizeof(struct load_command));
                    bzero(proc.m64[i]->cmds[j], sizeof(struct load_command));
                    
                    // Copy the load command to our process
                    err = mach_vm_read_overwrite(proc.task, cmdaddr, sizeof(struct load_command), (mach_vm_address_t)proc.m64[i]->cmds[j], &outSize);
                    
                    if(err != KERN_SUCCESS) {
                        fprintf(stderr, "Failed reading load command from remote process: %s\n", mach_error_string(err));
                        return;
                    }
                    
                    // Swap endianness if needed
                    if(current64->swap) {
                        swap_load_command(proc.m64[i]->cmds[j], 0);
                    }
                    
                    // Check if it's a segment command
                    if (proc.m64[i]->cmds[j]->cmd == LC_SEGMENT_64) {
                        
                        // Allocate a segment command
                        proc.m64[i]->segs[k] = malloc(sizeof(struct segment_command_64));
                        bzero(proc.m64[i]->segs[k], sizeof(struct segment_command_64));
                        
                        
                        // Copy the segment command to our process
                        err = mach_vm_read_overwrite(proc.task, cmdaddr, sizeof(struct segment_command_64), (mach_vm_address_t)proc.m64[i]->segs[k], &outSize);
                        
                        if(err != KERN_SUCCESS) {
                            // Optionally print error message
                            return;
                        }
                        
                        // Swap endianess if needed
                        if(current64->swap) {
                            swap_segment_command_64(proc.m64[i]->segs[k], 0);
                        }
                        
                        printf("\tsegment: %s\n", proc.m64[i]->segs[k]->segname);
                        printf("\t\tcount: %d sections.\n", proc.m64[i]->segs[k]->nsects);
                        printf("\t\t%#llx - %#llx / %#llx - %#llx prot: %d - %d\n", proc.m64[i]->segs[k]->fileoff, proc.m64[i]->segs[k]->fileoff + proc.m64[i]->segs[k]->filesize, proc.m64[i]->segs[k]->vmaddr, proc.m64[i]->segs[k]->vmaddr + proc.m64[i]->segs[k]->vmsize, proc.m64[i]->segs[k]->initprot, proc.m64[i]->segs[k]->maxprot);
                        
                        
                        if(string_compare("__DATA", proc.m64[i]->segs[k]->segname) == 0) {
                            DATA = proc.m64[i]->segs[k];
                        }
                        else if(string_compare("__TEXT", proc.m64[i]->segs[k]->segname) == 0) {
                            TEXT = proc.m64[i]->segs[k];
                        }
                        else if(string_compare("__LINKEDIT", proc.m64[i]->segs[k]->segname) == 0) {
                            LINKEDIT = proc.m64[i]->segs[k];
                        }
                        else if(string_compare("__TEXT_EXEC", proc.m64[i]->segs[k]->segname) == 0) {
                            TEXT_EXEC = proc.m64[i]->segs[k];
                        }
                        
                        // Now go over the sections
                        for(int l = 0; l < proc.m64[i]->segs[k]->nsects; l++) {
                            
                        }
                        
                        k++; // Increase the segment index counter

                    }
                    
                    else if (proc.m64[i]->cmds[j]->cmd == LC_SYMTAB) {
                        
                        bzero(symtab, sizeof(struct symtab_command));
                        
                        // Copy the symtab command to our process
                        err = mach_vm_read_overwrite(proc.task, cmdaddr, sizeof(struct symtab_command), (mach_vm_address_t)symtab, &outSize);
                        
                        if(err != KERN_SUCCESS) {
                            // Optionally print error message
                            return;
                        }
                        
                        printf("\tsymtab:\n");
                        printf("\t\tcount: %d symbols.\n", symtab->nsyms);
                        
                        // These segments are required to calculate the file slide
                        if (!LINKEDIT || !symtab || !TEXT) {
                            fprintf(stderr, "\t\tFailed to retrieve required segments for remote process\n");
                            continue;
                        }
                        
                        
                        mach_vm_address_t base = (mach_vm_address_t)image->imageLoadAddress;
                        
                        // Calculate the file slide
                        unsigned long fileSlide = (unsigned long)(LINKEDIT->vmaddr - TEXT->vmaddr - LINKEDIT->fileoff);
                        printf("\t\tfile slide: %#lx\n", fileSlide);
                        
                        // Calculate the string table offset
                        char* strtab = (char *)(base + fileSlide + symtab->stroff);
                        printf("\t\tstrtab addr: %#lx\n", (unsigned long)strtab);
                        
                        // Calculate the offset of and point to the first name list
                        struct nlist_64* nl = malloc(sizeof(struct nlist_64) * symtab->nsyms);
                        bzero(nl, sizeof(struct nlist_64));
                        mach_vm_size_t read = 0;
                        err = mach_vm_read_overwrite(proc.task, (mach_vm_address_t)(base + fileSlide + symtab->symoff), sizeof(struct nlist_64) * symtab->nsyms, (mach_vm_address_t)nl, &read);
                        
                        if(err != KERN_SUCCESS) {
                            fprintf(stderr, "\t\tFailed to get nlist from remote process: %s\n", mach_error_string(err));
                            if(nl) {
                                free(nl);
                                nl = NULL;
                            }
                            continue;
                        }
                        
                        printf("\t\tsymbols:\n");
                        // Walk over the namelists in the symbol table
                        for (int i=0; i < symtab->nsyms; i++) {
                            
                            // Retrieve the name / string in the current name list
                            char *namePtr = strtab + nl[i].n_un.n_strx;
                            char* name = mach_vm_string(proc.task, namePtr);
                            if(!name || !nl[i].n_value) {
                                continue;
                            }
                           printf("\t\t\t#define %s %#llx\n", name, nl[i].n_value + g_dyldSlide);
                        }
                    }
                    
                    cmdaddr = cmdaddr + proc.m64[i]->cmds[j]->cmdsize; // Move on to the next load command
                }
                
            }
        }
        printf("\n");
    }
    
    
    
}


/**
 * @brief Retrieves the base address of a loaded mach-o image in the memory
 * @param task Taskport of the process to look in
 * @param name Name of the framework or library to retrieve (without its .framework extension)
 * @return Base address of the framework or zero
 * @see FindSymbol
 */
static void* FindImage(mach_port_t task, const char *name)
{
    
    if(!MACH_PORT_VALID(task)) {
        return NULL;
    }
    uint32_t imageCount = 0;
    struct dyld_all_image_infos* infos = NULL;
    struct dyld_image_info* imageArray = NULL;
    struct dyld_image_info* image = NULL;
    
    infos = task_img_infos(task);
    
    if(!infos) {
        return NULL;
    }
    
    imageCount = infos->infoArrayCount;
    imageArray = (void*)infos->infoArray;
    
    
    // Foreach image in image array
    for (int i = 0; i < imageCount; ++i) {
        
        image = imageArray + i;
        
        if(!image)
            break;
        
        // Check if its the framework We're looking for
        if(strstr(image->imageFilePath, name)) {
            return (void*)image->imageLoadAddress;
        }
        
    }
    
    return NULL;
}




static uint64_t imageSlide(const struct mach_header_64* header) {
    unsigned long i;
    const struct segment_command_64 *sgp = (const struct segment_command_64 *)(header + 1);
    for (i = 0; i < header->ncmds; i++){
        if (sgp->cmd == LC_SEGMENT_64) {
            if (sgp->fileoff == 0  &&  sgp->filesize != 0) {
                return (uint64_t)header - (uint64_t)sgp->vmaddr;
            }
        }
        sgp = (const struct segment_command_64 *)((char *)sgp + sgp->cmdsize);
    }
    return 0;
}


/**
 * @brief Locates a symbol in the memory by its name in a given framework
 * @see FindFramework
 * @param base Base address of the framework to look in
 * @param symbol Name of the symbol to find
 * @return Pointer to symbol in memory (function pointer)
 */
static void* FindSymbol(mach_port_t task, void* base, char* symbol) {
    
    struct segment_command_64 *sc = NULL, *linkedit = NULL, *text = NULL;
    struct load_command *lc = NULL;
    struct symtab_command *symtab = NULL;
    struct nlist_64 *nl = NULL;
    char *strtab = NULL;
    
    if(!base || !symbol || !MACH_PORT_VALID(task)) {
        return NULL;
    }
    
    if( task == mach_task_self() ) {
        
        // Point to the first mach-o load command
        lc = (struct load_command *)(base + sizeof(struct mach_header_64));
        
        //Now walk over all load commands
        for (int i=0; i<((struct mach_header_64 *)base)->ncmds; i++) {
            
            // We found the symbol table
            if (lc->cmd == LC_SYMTAB) {
                symtab = (struct symtab_command *)lc; // Update our reference to it
            }
            
            // We found a segment
            else {
                sc = (struct segment_command_64 *)lc; // Cast to a segment
                char * segname = ((struct segment_command_64 *)lc)->segname; // Get its name
                
                // Now check if its a segment that we need
                if (string_compare(segname, "__LINKEDIT") == 0) {
                    linkedit = sc; // Update our reference to linkedit
                }
                else if (string_compare(segname, "__TEXT") == 0) {
                    text = sc; // Update our reference to text
                }
            }
            
            // Move on to the next load command
            lc = (struct load_command *)((unsigned long)lc + lc->cmdsize);
        }
        
        // These segments are required to calculate the file slide
        if (!linkedit || !symtab || !text) {
            return NULL;
        }
        
        // Calculate the file slide
        unsigned long fileSlide = (unsigned long)(linkedit->vmaddr - text->vmaddr - linkedit->fileoff);
        
        // Calculate the string table offset
        strtab = (char *)(base + fileSlide + symtab->stroff);
        
        // Calculate the offset of and point to the first name list
        nl = (struct nlist_64 *)(base + fileSlide + symtab->symoff);
        
        // Walk over the namelists in the symbol table
        for (int i=0; i < symtab->nsyms; i++) {
            
            // Retrieve the name / string in the current name list
            char *name = strtab + nl[i].n_un.n_strx;
            
            // Check if its the symbol we are looking for
            if (string_compare(name, symbol) == 0) {
                return (void*)(nl[i].n_value + g_dyldSlide);
            }
        }
        
    }
    else {
        printf("Remote processes are not supported (yet).\n");
    }
    
    return NULL;
}

/**
 * @brief Patches a symbol in the memory by its name in a given framework
 * @see FindFramework
 * @param base Base address of the framework to look in
 * @param symbol Name of the symbol to find
 * @param newAddr New address or offset to point to
 * @return Pointer to symbol in memory (function pointer)
 */
static void* PatchSym(mach_port_t task, void* base, char* symbol, uint64_t newAddr) {
    
    struct segment_command_64 *sc = NULL, *linkedit = NULL, *text = NULL;
    struct load_command *lc = NULL;
    struct symtab_command *symtab = NULL;
    struct nlist_64 *nl = NULL;
    char *strtab = NULL;
    
    if(!base || !symbol || !MACH_PORT_VALID(task)) {
        return NULL;
    }
    
    if( task == mach_task_self() ) {
        
        // Point to the first mach-o load command
        lc = (struct load_command *)(base + sizeof(struct mach_header_64));
        
        //Now walk over all load commands
        for (int i=0; i<((struct mach_header_64 *)base)->ncmds; i++) {
            
            // We found the symbol table
            if (lc->cmd == LC_SYMTAB) {
                symtab = (struct symtab_command *)lc; // Update our reference to it
            }
            
            // We found a segment
            else {
                sc = (struct segment_command_64 *)lc; // Cast to a segment
                char * segname = ((struct segment_command_64 *)lc)->segname; // Get its name
                
                // Now check if its a segment that we need
                if (string_compare(segname, "__LINKEDIT") == 0) {
                    linkedit = sc; // Update our reference to linkedit
                }
                else if (string_compare(segname, "__TEXT") == 0) {
                    text = sc; // Update our reference to text
                }
            }
            
            // Move on to the next load command
            lc = (struct load_command *)((unsigned long)lc + lc->cmdsize);
        }
        
        // These segments are required to calculate the file slide
        if (!linkedit || !symtab || !text) {
            return NULL;
        }
        
        // Calculate the file slide
        unsigned long fileSlide = (unsigned long)(linkedit->vmaddr - text->vmaddr - linkedit->fileoff);
        
        // Calculate the string table offset
        strtab = (char *)(base + fileSlide + symtab->stroff);
        
        // Calculate the offset of and point to the first name list
        nl = (struct nlist_64 *)(base + fileSlide + symtab->symoff);
        
        // Walk over the namelists in the symbol table
        for (int i=0; i < symtab->nsyms; i++) {
            
            // Retrieve the name / string in the current name list
            char *name = strtab + nl[i].n_un.n_strx;
            
            // Check if its the symbol we are looking for
            if (string_compare(name, symbol) == 0) {
                printf("Patching '%s' %#llx -> %#llx: ", symbol, nl[i].n_value, newAddr);
                mach_vm_size_t size = 0;
                kern_return_t err = KERN_SUCCESS;
                err = mach_vm_protect(task, (mach_vm_address_t)&nl[i], sizeof(struct nlist_64), TRUE, VM_PROT_DEFAULT);
                nl[i].n_value = newAddr;
                if(err != KERN_SUCCESS) {
                    printf("Failed.\n");
                } else {
                    printf("Success, patched %llu bytes\n", size);
                }
            }
        }
        
    }
    else {
        printf("Remote processes are not supported (yet).\n");
    }
    
    printf("Failed to find symbol '%s'.\n", symbol);
    
    return NULL;
}


void* GOTLookup(mach_port_t task, void *base, uint64_t value, uint64_t replacer) {
    struct segment_command_64 *sc = NULL, *linkedit = NULL, *text = NULL, *data = NULL;
    struct section_64 *got = NULL;
    struct load_command *lc = NULL;
    
    if(!base || !MACH_PORT_VALID(task)) {
        return NULL;
    }
    
    if( task == mach_task_self() ) {
        
        // Point to the first mach-o load command
        lc = (struct load_command *)(base + sizeof(struct mach_header_64));
        
        //Now walk over all load commands
        for (int i=0; i<((struct mach_header_64 *)base)->ncmds; i++) {
            
            sc = (struct segment_command_64 *)lc; // Cast to a segment
            char * segname = ((struct segment_command_64 *)lc)->segname; // Get its name
            
            // Now check if its a segment that we need
            if (string_compare(segname, "__LINKEDIT") == 0) {
                linkedit = sc; // Update our reference to linkedit
            }
            
            else if (string_compare(segname, "__TEXT") == 0) {
                text = sc; // Update our reference to text
            }
            
            else if (string_compare(segname, "__DATA") == 0) {
                data = sc; // Update our reference to data
            }
            
            // Move on to the next load command
            lc = (struct load_command *)((unsigned long)lc + lc->cmdsize);
        }
        
        // These segments are required to calculate the file slide
        if (!linkedit || !text) {
            return NULL;
        }
        
        struct section_64* sec = (struct section_64*)((uint64_t)data + sizeof(struct segment_command_64));
        
        for (uint32_t j = 0; j < data->nsects; j++) {
            
            if(string_compare(sec->sectname, "__got") == 0) {
                got = sec;
                break;
            }
        }
        
        if(!got) {
            return NULL;
        }
        
        printf("__DATA.%s @ %#llx\n", sec->sectname, sec->addr);
        for(int i = 0; i < got->size; i += sizeof(uint64_t)) {
            uint64_t* valPtr = (void*)(got->addr + i);
            if(*valPtr == value) {
                if(replacer != value) {
                    printf("__DATA.__got+%d %#llx -> %#llx\n", i, *valPtr, replacer);
                    *valPtr = replacer;
                }
                printf("__DATA.__got+%d: %#llx\n", i, *valPtr);
                return valPtr;
            }
            else {
                if(*valPtr)
                    printf("__DATA.__got+%d: %#llx\n", i, *valPtr);
            }
        }
        printf("Failed to find value in __GOT\n");
        return NULL;
    }
    else {
        printf("Remote processes are not supported (yet).\n");
    }
    printf("Failed to find __GOT\n");
    return NULL;
}


/**
 * Macro for assuring that a framework is retrieved
 * @param fwrk Name of the framework to be retrieved
 * @see FindFramework
 */
#define LOOKUP_FWRK(fwrk) {\
    fwrkptr = NULL;\
    fwrkptr = FindImage(mach_task_self(), fwrk);\
    if(!fwrkptr){\
        printf("Failed to find required framework %s\n", fwrk);\
        exit(1);\
    } else {\
        printf("%s @ %#llx\n", fwrk, (uint64_t)fwrkptr);\
    }\
}

/**
 * @brief Macro for assuring that a symbol is retrieved and updated on its corresponding function pointer
 * @param fp Function pointer to be updated
 * @param sym Name of the symbol to be retrieved
 * @see LOOKUP_FWRK
 * @see FindSymbol
 */
#define LINK_SYM(fp, sym) {\
    fp = FindSymbol(mach_task_self(), fwrkptr, sym);\
    if(!fp){\
        printf("Failed to find required symbol %s\n", sym);\
        exit(1);\
    }\
    else {\
        printf("%s @ %#llx\n", sym, (uint64_t)fp);\
    }\
}

/**
 * Macro for assuring that a framework is retrieved
 * @param fwrk Name of the framework to be retrieved
 * @see FindFramework
 */
#define LOOKUP_REMOTE_FWRK(task, fwrk) {\
    fwrkptr = NULL;\
    fwrkptr = FindImage(task, fwrk);\
    if(!fwrkptr){\
        printf("Failed to find required framework %s\n", fwrk);\
        exit(1);\
    } else {\
        printf("%s @ %#llx\n", fwrk, (uint64_t)fwrkptr);\
    }\
}

/**
 * @brief Macro for assuring that a symbol is retrieved and updated on its corresponding function pointer
 * @param fp Function pointer to be updated
 * @param sym Name of the symbol to be retrieved
 * @see LOOKUP_FWRK
 * @see FindSymbol
 */
#define LINK_REMOTE_SYM(task, fp, sym) {\
    fp = FindSymbol(task, fwrkptr, sym);\
    if(!fp){\
        printf("Failed to find required symbol %s\n", sym);\
        exit(1);\
    }\
    else {\
        printf("%s @ %#llx\n", sym, fp);\
    }\
}

void my_hook(char *fmt, ...) {
    puts("HEHEHEHEHE!\n");
}

int main(int argc, char *argv[]) {
    
    MachoProc ourProc = {};
    ourProc.task = MACH_PORT_NULL;
    ourProc.pid = atoi(argv[1]);
    MachProcInit(ourProc);
    void* fwrkptr = NULL;
    void (*my_puts)(char *str);
    LOOKUP_FWRK("libsystem_c");
    LINK_SYM(my_puts, "_puts");
    GOTLookup(mach_task_self(), fwrkptr, 0x7fff742a4680, 0x4141414141);
    //	my_puts("Hello world from my_puts!\n");
//    PatchSym(mach_task_self(), fwrkptr, "_puts", (uint64_t)my_hook);
    puts("If you can read this then puts did not get hooked!\n");
    
    return 0;
}

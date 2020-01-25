/*
 * Copyright 2020 (c) Sem Voigtländer
 */#include <stdio.h>
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

#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>

#include <mach/mach.h>

struct A64INSTr {
    uint32_t *instructions;
    uint64_t count;
};

extern kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
extern kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);

uint64_t g_dyldSlide = 0;

static inline int string_compare(const char* s1, const char* s2)
{
    while (*s1 != '\0' && *s1 == *s2)
    {
        s1++;
        s2++;
    }
    return (*(unsigned char *) s1) - (*(unsigned char *) s2);
}

/**
 * @brief Retrieves the base address of a loaded mach-o image in the memory
 * @param task Taskport of the process to look in
 * @param name Name of the framework or library to retrieve (without its .framework extension)
 * @return Base address of the framework or zero
 * @see FindSymbol
 */
static void *FindImage(mach_port_t task, const char *name)
{
    kern_return_t ret = KERN_SUCCESS;
    
    struct task_dyld_info dyldInfo = {};
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    
    struct dyld_all_image_infos* infos = NULL;
    uint32_t imageCount = 0;
    
    struct dyld_image_info* imageArray = NULL;
    
    if(!MACH_PORT_VALID(task)) {
        return NULL;
    }
    
    ret = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
    if(ret != KERN_SUCCESS) {
        return NULL;
    }
    
    // Get image arrays, size and address
    mach_vm_address_t imageInfos = dyldInfo.all_image_info_addr;
    infos = (void*)imageInfos;
    
    if(!infos) {
        return NULL;
    }
    
    imageCount = infos->infoArrayCount;
    imageArray = (void*)infos->infoArray;
    struct dyld_image_info* image = NULL;
    
    // Foreach image in image array
    for (int i = 0; i < imageCount; ++i) {
        
        image = imageArray + i;
        
        if(!image) {
            break;
        }
        
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

static uint64_t dyldSlide(void) {
    
    kern_return_t ret = KERN_SUCCESS;
    
    struct task_dyld_info dyldInfo = {};
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    
    struct dyld_all_image_infos* infos = NULL;
    
    if (g_dyldSlide) {
        return g_dyldSlide;
    }
    
    ret = task_info(mach_task_self(),TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
    
    if (ret != KERN_SUCCESS) {
        return 0;
    }
    
    // Get image array's size and address
    mach_vm_address_t imageInfos = dyldInfo.all_image_info_addr;
    infos = (void*)imageInfos;
    
    if(!infos) {
        return 0;
    }
    
    g_dyldSlide = infos->sharedCacheSlide;
    
    return infos->sharedCacheSlide;
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
        unsigned long fileSlide = linkedit->vmaddr - text->vmaddr - linkedit->fileoff;
        
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
        unsigned long fileSlide = linkedit->vmaddr - text->vmaddr - linkedit->fileoff;
        
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
                err = mach_vm_protect(task, &nl[i], sizeof(struct nlist_64), TRUE, VM_PROT_DEFAULT);
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
    struct section_64 *got = NULL, *_text = NULL;
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
        
        // Calculate the file slide
        unsigned long fileSlide = linkedit->vmaddr - text->vmaddr - linkedit->fileoff;
        
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
        for(int i = 0; i < got->size; i+=sizeof(uint64_t)) {
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

void* A64Lookup(mach_port_t task, void* base, struct A64INSTr instructions){
    struct segment_command_64 *sc = NULL, *linkedit = NULL, *text = NULL, *data = NULL;
    struct section_64 *got = NULL, *_text = NULL;
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
        
        // Calculate the file slide
        unsigned long fileSlide = linkedit->vmaddr - text->vmaddr - linkedit->fileoff;
        
        struct section_64* sec = (struct section_64*)((uint64_t)text + sizeof(struct segment_command_64));
        
        for (uint32_t j = 0; j < data->nsects; j++) {
            
            if(string_compare(sec->sectname, "text") == 0) {
                _text = sec;
                break;
            }
        }
        
        if(!_text) {
            return NULL;
        }
        
        void* ptr = memmem((void*)_text->addr, _text->size, (void*)instructions.instructions, instructions.count * sizeof(uint32_t));
        return ptr;
        
    }
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
    
    void* fwrkptr = NULL;
    void (*my_puts)(char *str);
    LOOKUP_FWRK("libsystem_c");
    LINK_SYM(my_puts, "_puts");
    GOTLookup(mach_task_self(), fwrkptr, 0x7fff742a4680, 0x4141414141);
    //	my_puts("Hello world from my_puts!\n");
    PatchSym(mach_task_self(), fwrkptr, "_puts", (uint64_t)my_hook);
    puts("If you can read this then puts did not get hooked!\n");
    
    return 0;
}

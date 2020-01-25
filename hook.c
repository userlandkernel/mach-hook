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

#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>

#include <mach/mach.h>

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
		kern_return_t err = mach_vm_read_overwrite(task, (mach_vm_address_t)&nl[i].n_value, sizeof(uint64_t), (mach_vm_address_t)&newAddr, &size);
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


/**
 * Macro for assuring that a framework is retrieved
 * @param fwrk Name of the framework to be retrieved
 * @see FindFramework
*/
#define REQUIRE_FWRK(fwrk) {\
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
 * @see REQUIRE_FWRK
 * @see FindSymbol
*/
#define REQUIRE_SYM(fp, sym) {\
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
#define REQUIRE_REMOTE_FWRK(task, fwrk) {\
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
 * @see REQUIRE_FWRK
 * @see FindSymbol
*/
#define REQUIRE_REMOTE_SYM(task, fp, sym) {\
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
	REQUIRE_FWRK("libsystem_c");
	REQUIRE_SYM(my_puts, "_puts");
//	my_puts("Hello world from my_puts!\n");
	PatchSym(mach_task_self(), fwrkptr, "_puts", (uint64_t)my_hook);
	puts("If you can read this then puts did not get hooked!\n");

	return 0;
}

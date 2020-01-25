# mach-hook
- A minimalistic patchtool for mach-o files in current and remote processes.  

## What is it
Attempts to provide a simple hooking interface for userland processes.  
Attempts to simplify programming with private symbols.  
Attempts to make return oriented programming a bit easier by letting you find ROP gadgets in memory.  
May be a disassembler one day.  
May also aid in patching the kernel one day.  


## Features
- Finding symbols in symtab
- Finding and patching symbol imports in the global offset table
- 

## Planned support
- Finding and patching symbol references in the data segment / section
- Supporting more platforms
- Supporting kernel_task and kernel extensions

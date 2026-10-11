/*
 * COFF Loader Project
 * -------------------
 * This is a re-implementation of a COFF loader, with a BOF compatibility layer
 * it's meant to provide functional example of loading a COFF file in memory
 * and maybe be useful.
 */
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#if defined(_WIN32)
#include <windows.h>
#include "beacon_compatibility.h"
#endif

#include "COFFLoader.h"

 /* Enable or disable debug output if testing or adding new relocation types */
#ifdef DEBUG
#define DEBUG_PRINT(x, ...) printf(x, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(x, ...)
#endif

/* Defining symbols for the OS version, will try to define anything that is
 * different between the arch versions by specifying them here. */
#if defined(__x86_64__) || defined(_WIN64)
#define PREPENDSYMBOLVALUE "__imp_"
#else
#define PREPENDSYMBOLVALUE "__imp__"
#endif

#define COFFLOADER_RETURN_VAL_IF(expr, val, fmt, ...) if ((expr)) { DEBUG_PRINT(fmt, ##__VA_ARGS__); return val; }
#define MEDUSA_MAX_COFF_SIZE (2 * 1024 * 1024)
#define MEDUSA_MAX_SECTIONS 96
#define MEDUSA_MAX_SYMBOLS 131072
#define MEDUSA_MAX_MODULES 64

#ifdef _WIN32
static HMODULE loadedModules[MEDUSA_MAX_MODULES] = {0};
static size_t loadedModuleCount = 0;
#endif

unsigned char* unhexlify(unsigned char* value, int *outlen) {
    unsigned char* retval = NULL;
    char byteval[3] = { 0 };
    unsigned int counter = 0;
    int counter2 = 0;
    char character = 0;
    if (value == NULL) {
        return NULL;
    }
    DEBUG_PRINT("Unhexlify Strlen: %lu\n", (long unsigned int)strlen((char*)value));
    if (strlen((char*)value) % 2 != 0) {
        DEBUG_PRINT("Either value is NULL, or the hexlified string isn't valid\n");
        goto errcase;
    }

    retval = calloc(strlen((char*)value) + 1, 1);
    if (retval == NULL) {
        goto errcase;
    }

    counter2 = 0;
    for (counter = 0; counter < strlen((char*)value); counter += 2) {
        memcpy(byteval, value + counter, 2);
        character = (char)strtol(byteval, NULL, 16);
        memcpy(retval + counter2, &character, 1);
        counter2++;
    }
    *outlen = counter2;

errcase:
    return retval;
}



/* Helper to just get the contents of a file, used for testing. Real
 * implementations of this in an agent would use the tasking from the
 * C2 server for this */
unsigned char* getContents(char* filepath, uint32_t* outsize) {
    FILE *fin = NULL;
    uint32_t fsize = 0;
    size_t readsize = 0;
    unsigned char* buffer = NULL;
    unsigned char* tempbuffer = NULL;

    fin = fopen(filepath, "rb");
    if (fin == NULL) {
        return NULL;
    }
    fseek(fin, 0, SEEK_END);
    fsize = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    tempbuffer = calloc(fsize, 1);
    if (tempbuffer == NULL) {
        fclose(fin);
        return NULL;
    }
    memset(tempbuffer, 0, fsize);
    readsize = fread(tempbuffer, 1, fsize, fin);

    fclose(fin);
    buffer = calloc(readsize, 1);
    if (buffer == NULL) {
        free(tempbuffer);
        return NULL;
    }
    memset(buffer, 0, readsize);
    memcpy(buffer, tempbuffer, readsize - 1);
    free(tempbuffer);
    *outsize = fsize;
    return buffer;
}

static BOOL starts_with(const char* string, const char* substring) {
    if (string == NULL || substring == NULL) return FALSE;
    return strncmp(string, substring, strlen(substring)) == 0;
}

/* Helper function to process a symbol string, determine what function and
 * library its from, and return the right function pointer. Will need to
 * implement in the loading of the beacon internal functions, or any other
 * internal functions you want to have available. */
void* process_symbol(char* symbolstring) {
    void* functionaddress = NULL;
    char localcopy[1024] = { 0 };
    char* locallib = NULL;
    char* localfunc = NULL;
#if defined(_WIN32)    
    int tempcounter = 0;
    HMODULE llHandle = NULL;
#endif

    if (symbolstring == NULL || strnlen(symbolstring, sizeof(localcopy)) == sizeof(localcopy)) return NULL;
    strncpy(localcopy, symbolstring, sizeof(localcopy) - 1);
    if (starts_with(symbolstring, PREPENDSYMBOLVALUE"Beacon") || starts_with(symbolstring, PREPENDSYMBOLVALUE"toWideChar") ||
        starts_with(symbolstring, PREPENDSYMBOLVALUE"GetProcAddress") || starts_with(symbolstring, PREPENDSYMBOLVALUE"LoadLibraryA") ||
        starts_with(symbolstring, PREPENDSYMBOLVALUE"GetModuleHandleA") || starts_with(symbolstring, PREPENDSYMBOLVALUE"FreeLibrary") ||
        starts_with(symbolstring, "__C_specific_handler")) {
        if(strcmp(symbolstring, "__C_specific_handler") == 0)
        {
            localfunc = symbolstring;
            return InternalFunctions[29][1];
        }
        else
        {
            localfunc = symbolstring + strlen(PREPENDSYMBOLVALUE);
        }
        DEBUG_PRINT("\t\tInternalFunction: %s\n", localfunc);
        /* TODO: Get internal symbol here and set to functionaddress, then
         * return the pointer to the internal function*/
#if defined(_WIN32)
        for (tempcounter = 0; tempcounter < 30; tempcounter++) {
            if (InternalFunctions[tempcounter][0] != NULL) {
                if (strcmp(localfunc, (char*)(InternalFunctions[tempcounter][0])) == 0) {
                    functionaddress = (void*)InternalFunctions[tempcounter][1];
                    return functionaddress;
                }
            }
        }
#endif
    }
    else if (strncmp(symbolstring, PREPENDSYMBOLVALUE, strlen(PREPENDSYMBOLVALUE)) == 0) {
        DEBUG_PRINT("\t\tYep its an external symbol\n");
        locallib = localcopy + strlen(PREPENDSYMBOLVALUE);

        locallib = strtok(locallib, "$");
        localfunc = strtok(NULL, "$");
        if (locallib == NULL || localfunc == NULL) return NULL;
        DEBUG_PRINT("\t\tLibrary: %s\n", locallib);
        localfunc = strtok(localfunc, "@");
        DEBUG_PRINT("\t\tFunction: %s\n", localfunc);
        /* Resolve the symbols here, and set the functionpointervalue */
#if defined(_WIN32)
        if (strpbrk(locallib, "\\/:") != NULL || strlen(locallib) == 0 || strlen(locallib) > 64) return NULL;
        llHandle = GetModuleHandleA(locallib);
        if (llHandle == NULL) {
            llHandle = LoadLibraryExA(locallib, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
            if (llHandle != NULL) {
                if (loadedModuleCount >= MEDUSA_MAX_MODULES) { FreeLibrary(llHandle); return NULL; }
                loadedModules[loadedModuleCount++] = llHandle;
            }
        }
        DEBUG_PRINT("\t\tHandle: 0x%lx\n", llHandle);
        functionaddress = GetProcAddress(llHandle, localfunc);
        DEBUG_PRINT("\t\tProcAddress: 0x%p\n", functionaddress);
#endif
    }
    return functionaddress;
}

static bool coff_symbol_is_defined(struct coff_sym *symbol) {
    return symbol->SectionNumber > 0;
}

static bool coff_symbol_is_external(struct coff_sym *symbol) {
    return symbol->StorageClass == IMAGE_SYM_CLASS_EXTERNAL
        || symbol->StorageClass == IMAGE_SYM_CLASS_EXTERNAL_DEF;
}

/* Just a generic runner for testing, this is pretty much just a reference
 * implementation, return values will need to be checked, more relocation
 * types need to be handled, and needs to have different arguments for use
 * in any agent. */
int RunCOFF(char* functionname, unsigned char* coff_data, uint32_t filesize, unsigned char* argumentdata, int argumentSize) {
    coff_sect_t *coff_sect_ptr = NULL;
    coff_reloc_t *coff_reloc_ptr = NULL;
    int retcode = 0;
    int counter = 0;
    int reloccount = 0;
    unsigned int tempcounter = 0;
    char *symbol_name = NULL;
    int foundEntry = 0;

    BeaconResetOutput();
    loadedModuleCount = 0;

    COFFLOADER_RETURN_VAL_IF(functionname == NULL, 1, "Function name is NULL\n");
    COFFLOADER_RETURN_VAL_IF(coff_data == NULL, 1, "Can't execute NULL\n");
    COFFLOADER_RETURN_VAL_IF(filesize == 0, 1, "COFF file size is 0\n");
    COFFLOADER_RETURN_VAL_IF(filesize < sizeof(struct coff_file_header), 1,
            "COFF file size too small for a COFF file header\n");
    COFFLOADER_RETURN_VAL_IF(filesize > MEDUSA_MAX_COFF_SIZE, 1, "COFF file too large\n");

    struct coff_file_header *coff_header_ptr = (struct coff_file_header*)coff_data;
    COFFLOADER_RETURN_VAL_IF(coff_header_ptr->Machine != MACHINETYPE_AMD64, 1, "Unsupported machine\n");
    COFFLOADER_RETURN_VAL_IF(coff_header_ptr->NumberOfSections == 0 || coff_header_ptr->NumberOfSections > MEDUSA_MAX_SECTIONS,
            1, "Invalid section count\n");
    COFFLOADER_RETURN_VAL_IF(coff_header_ptr->SizeOfOptionalHeader != 0, 1, "Optional header is unsupported\n");
    COFFLOADER_RETURN_VAL_IF(filesize < sizeof(coff_file_header_t) + (size_t)coff_header_ptr->NumberOfSections * sizeof(coff_sect_t),
            1, "Section headers exceed file size\n");
    COFFLOADER_RETURN_VAL_IF(coff_header_ptr->NumberOfSymbols == 0 || coff_header_ptr->NumberOfSymbols > MEDUSA_MAX_SYMBOLS,
            1, "Invalid symbol count\n");

    COFFLOADER_RETURN_VAL_IF(coff_header_ptr->PointerToSymbolTable < sizeof(struct coff_file_header),
            1, "COFF symbol table offset is inside the file header\n");
    COFFLOADER_RETURN_VAL_IF(filesize < coff_header_ptr->PointerToSymbolTable, 1,
            "COFF symbol table offset exceeds file size\n");

    // Byte index of the strtab/end of symtab
    size_t coff_strtab_index = (size_t)coff_header_ptr->PointerToSymbolTable +
        (size_t)coff_header_ptr->NumberOfSymbols * sizeof(struct coff_sym);

    COFFLOADER_RETURN_VAL_IF(filesize < coff_strtab_index, 1, "COFF symbol table exceeds COFF file size\n");
    COFFLOADER_RETURN_VAL_IF(filesize < coff_strtab_index + sizeof(uint32_t), 1,
            "COFF string table offset exceeds COFF file size\n");

    uint32_t coff_strtab_size = *(uint32_t*)(coff_data + coff_strtab_index);
    COFFLOADER_RETURN_VAL_IF(coff_strtab_size < sizeof(uint32_t), 1, "Invalid string table size\n");

    COFFLOADER_RETURN_VAL_IF(filesize < coff_strtab_index + coff_strtab_size, 1,
            "COFF string table exceeds COFF file size\n");
    COFFLOADER_RETURN_VAL_IF(filesize != coff_strtab_index + coff_strtab_size, 1,
            "COFF file contains extraneous data\n");

    struct coff_sym *coff_sym_ptr = (struct coff_sym*)(coff_data + coff_header_ptr->PointerToSymbolTable);

#ifdef _WIN32
    void* funcptrlocation = NULL;
    size_t offsetvalue = 0;
#endif
    char* entryfuncname = functionname;
#if defined(__x86_64__) || defined(_WIN64)
#ifdef _WIN32
    uint64_t longoffsetvalue = 0;
#endif
#else
    /* Set the input function name to match the 32 bit version */
    entryfuncname = calloc(strlen(functionname) + 2, 1);
    if (entryfuncname == NULL) {
        return 1;
    }
    (void)sprintf(entryfuncname, "_%s", functionname);
#endif
    HMODULE kern = GetModuleHandleA("kernel32.dll");
    InternalFunctions[29][1] = (unsigned char *) GetProcAddress(kern, "__C_specific_handler");
    DEBUG_PRINT("found address of %x\n", InternalFunctions[29][1]);
#ifdef _WIN32
    /* NOTE: I just picked a size, look to see what is max/normal. */
    char** sectionMapping = NULL;
    size_t *sectionSize = NULL;
    void(*foo)(char* in, unsigned long datalen);
    void **functionMapping = NULL;
    int functionMappingCount = 0;
    int relocationCount = 0;
#endif
    /* Buffer to hold the symbol short name if the symbol has no trailing NULL byte */
    char symbol_shortname_buffer[9] = {0};

    DEBUG_PRINT("Machine 0x%X\n", coff_header_ptr->Machine);
    DEBUG_PRINT("Number of sections: %d\n", coff_header_ptr->NumberOfSections);
    DEBUG_PRINT("TimeDateStamp : %X\n", coff_header_ptr->TimeDateStamp);
    DEBUG_PRINT("PointerToSymbolTable : 0x%X\n", coff_header_ptr->PointerToSymbolTable);
    DEBUG_PRINT("NumberOfSymbols: %u\n", coff_header_ptr->NumberOfSymbols);
    DEBUG_PRINT("OptionalHeaderSize: %d\n", coff_header_ptr->SizeOfOptionalHeader);
    DEBUG_PRINT("Characteristics: %d\n", coff_header_ptr->Characteristics);
    DEBUG_PRINT("\n");
    /* Actually allocate an array to keep track of the sections */
    sectionMapping = (char**)calloc(sizeof(char*)*(coff_header_ptr->NumberOfSections+1), 1);
    sectionSize = (size_t*)calloc(sizeof(size_t)*(coff_header_ptr->NumberOfSections+1), 1);
    if (sectionMapping == NULL || sectionSize == NULL){
        DEBUG_PRINT("Failed to allocate sectionMapping\n");
        goto cleanup;
    }

    /* Handle the allocation and copying of the sections we're going to use
     * for right now I'm just VirtualAlloc'ing memory, this can be changed to
     * other methods, but leaving that up to the person implementing it. */
    for (counter = 0; counter < coff_header_ptr->NumberOfSections; counter++) {
        coff_sect_ptr = (coff_sect_t*)(coff_data + sizeof(coff_file_header_t) + (sizeof(coff_sect_t) * counter));
        DEBUG_PRINT("Name: %s\n", coff_sect_ptr->Name);
        DEBUG_PRINT("VirtualSize: 0x%X\n", coff_sect_ptr->VirtualSize);
        DEBUG_PRINT("VirtualAddress: 0x%X\n", coff_sect_ptr->VirtualAddress);
        DEBUG_PRINT("SizeOfRawData: 0x%X\n", coff_sect_ptr->SizeOfRawData);
        DEBUG_PRINT("PointerToRelocations: 0x%X\n", coff_sect_ptr->PointerToRelocations);
        DEBUG_PRINT("PointerToRawData: 0x%X\n", coff_sect_ptr->PointerToRawData);
        DEBUG_PRINT("NumberOfRelocations: %d\n", coff_sect_ptr->NumberOfRelocations);
        if (coff_sect_ptr->SizeOfRawData > MEDUSA_MAX_COFF_SIZE || coff_sect_ptr->VirtualSize > MEDUSA_MAX_COFF_SIZE ||
            (coff_sect_ptr->PointerToRawData != 0 && (coff_sect_ptr->PointerToRawData > filesize ||
             coff_sect_ptr->SizeOfRawData > filesize - coff_sect_ptr->PointerToRawData)) ||
            (coff_sect_ptr->NumberOfRelocations != 0 && (coff_sect_ptr->PointerToRelocations > filesize ||
             (size_t)coff_sect_ptr->NumberOfRelocations * sizeof(coff_reloc_t) > filesize - coff_sect_ptr->PointerToRelocations))) {
            retcode = 1;
            goto cleanup;
        }
        if (relocationCount > INT_MAX - coff_sect_ptr->NumberOfRelocations) { retcode = 1; goto cleanup; }
        relocationCount += coff_sect_ptr->NumberOfRelocations;
        /* NOTE: When changing the memory loading information of the loader,
         * you'll want to use this field and the defines from the Section
         * Flags table of Microsofts page, some defined in COFFLoader.h */
        DEBUG_PRINT("Characteristics: %x\n", coff_sect_ptr->Characteristics);
#ifdef _WIN32
        DEBUG_PRINT("Allocating 0x%x bytes\n", coff_sect_ptr->VirtualSize);
        /* NOTE: Might want to allocate as PAGE_READWRITE and VirtualProtect
         * before execution to either PAGE_READWRITE or PAGE_EXECUTE_READ
         * depending on the Section Characteristics. Parse them all again
         * before running and set the memory permissions. */
        sectionSize[counter] = coff_sect_ptr->SizeOfRawData > coff_sect_ptr->VirtualSize ? coff_sect_ptr->SizeOfRawData : coff_sect_ptr->VirtualSize;
        if (sectionSize[counter] == 0) sectionSize[counter] = 1;
        sectionMapping[counter] = VirtualAlloc(NULL, sectionSize[counter], MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
        if (sectionMapping[counter] == NULL) {
            DEBUG_PRINT("Failed to allocate memory\n");
        }
        DEBUG_PRINT("Allocated section %d at %p\n", counter, sectionMapping[counter]);
        if (coff_sect_ptr->PointerToRawData != 0){
            memcpy(sectionMapping[counter], coff_data + coff_sect_ptr->PointerToRawData, coff_sect_ptr->SizeOfRawData);
        }
        else{
        memset(sectionMapping[counter], 0, sectionSize[counter]);
        }
#endif
    }
    DEBUG_PRINT("Total Relocations: %d\n", relocationCount);
    /* Allocate and setup the GOT for functions, same here as above. */
    /* Actually allocate enough for worst case every relocation, may not be needed, but hey better safe than sorry */
#ifdef _WIN32
#ifdef _WIN64
    functionMapping = (void **)VirtualAlloc(NULL, (relocationCount ? relocationCount : 1)*sizeof(void*), MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
#else
    functionMapping = (void **)VirtualAlloc(NULL, (relocationCount ? relocationCount : 1)*sizeof(void*), MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
#endif
    if (functionMapping == NULL){
        DEBUG_PRINT("Failed to allocate functionMapping\n");
        goto cleanup;
    }
#endif

    /* Start parsing the relocations, and *hopefully* handle them correctly. */
    for (counter = 0; counter < coff_header_ptr->NumberOfSections; counter++) {
        DEBUG_PRINT("Doing Relocations of section: %d\n", counter);
        coff_sect_ptr = (coff_sect_t*)(coff_data + sizeof(coff_file_header_t) + (sizeof(coff_sect_t) * counter));
        coff_reloc_ptr = (coff_reloc_t*)(coff_data + coff_sect_ptr->PointerToRelocations);
        for (reloccount = 0; reloccount < coff_sect_ptr->NumberOfRelocations; reloccount++) {
            DEBUG_PRINT("\tVirtualAddress: 0x%X\n", coff_reloc_ptr->VirtualAddress);
            DEBUG_PRINT("\tSymbolTableIndex: 0x%X\n", coff_reloc_ptr->SymbolTableIndex);
            DEBUG_PRINT("\tType: 0x%X\n", coff_reloc_ptr->Type);
            if (coff_reloc_ptr->SymbolTableIndex >= coff_header_ptr->NumberOfSymbols) { retcode = 1; goto cleanup; }
            {
                size_t relocationWidth = coff_reloc_ptr->Type == IMAGE_REL_AMD64_ADDR64 ? 8 : 4;
                if (coff_reloc_ptr->VirtualAddress > sectionSize[counter] ||
                    relocationWidth > sectionSize[counter] - coff_reloc_ptr->VirtualAddress) { retcode = 1; goto cleanup; }
            }

            /* Check if the symbol name is a long symbol name */
            if (coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.value[0] == 0) {
                /* Long symbol name from the string table */

                uint32_t nameOffset = coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.value[1];
                if (nameOffset < 4 || nameOffset >= coff_strtab_size) { retcode = 1; goto cleanup; }
                symbol_name = ((char*)(coff_sym_ptr + coff_header_ptr->NumberOfSymbols)) + nameOffset;
                if (memchr(symbol_name, 0, coff_strtab_size - nameOffset) == NULL) { retcode = 1; goto cleanup; }

            } else {
                /* Short symbol name */

                /* If the short symbol name is 8 bytes in length, it is not NULL
                 * terminated. Copy it to a temporary buffer to add the NULL terminator. */
                if (coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.Name[7] != '\0') {
                    strncpy_s(
                        symbol_shortname_buffer,
                        sizeof(symbol_shortname_buffer),
                        &coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.Name[0],
                        sizeof(coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.Name)
                    );

                    symbol_name = symbol_shortname_buffer;
                } else {
                    symbol_name = &coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.Name[0];
                }
            }

            DEBUG_PRINT("\tSymNamePtr: %p\n", symbol_name);
            DEBUG_PRINT("\tSymName: %s\n", symbol_name);
            DEBUG_PRINT("\tSectionNumber: 0x%X\n", coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber);

            /* Check if the target symbol is a local symbol or an external undefined symbol
             * and resolve it */
            if (coff_symbol_is_defined(&coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex])) {
                if (coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber > coff_header_ptr->NumberOfSections ||
                    coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value >= sectionSize[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1]) {
                    retcode = 1; goto cleanup;
                }
                /* Locally defined symbol. Find the mapped address. */
                funcptrlocation = sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1];

                funcptrlocation = (void *)((char *)funcptrlocation + coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value);
            } else if (coff_symbol_is_external(&coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex])
                    && coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value == 0) {
                /* Imported symbol. Resolve it and map it in */
                funcptrlocation = process_symbol(symbol_name);
                if (funcptrlocation == NULL) {
                    DEBUG_PRINT("Failed resolving imported symbol '%s'\n", symbol_name);
                    retcode = 1;
                    goto cleanup;
                }

                /* Map the imported symbol address to the local import table */
                functionMapping[functionMappingCount] = funcptrlocation;

                /* Get the address of the imported symbol mapped in the local import 
                 * table for the relocation target */
                funcptrlocation = &functionMapping[functionMappingCount];

                /* Increment the number of mapped imported functions */
                functionMappingCount += 1;

            } else {
                /* Relocation to an undefined symbol */
                DEBUG_PRINT("Relocation %d in section index %d references undefined symbol %s\n", reloccount, counter, symbol_name);
                retcode = 1;
                goto cleanup;
            }

#ifdef _WIN32
#ifdef _WIN64
            /* Type == 1 relocation is the 64-bit VA of the relocation target */
            if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_ADDR64) {
                memcpy(&longoffsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(uint64_t));
                DEBUG_PRINT("\tReadin longOffsetValue : 0x%llX\n", longoffsetvalue);
                longoffsetvalue += (uint64_t)funcptrlocation;
                DEBUG_PRINT("\tModified longOffsetValue : 0x%llX Base Address: %p\n", longoffsetvalue, funcptrlocation);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &longoffsetvalue, sizeof(uint64_t));
            }
            /* This is Type == 3 relocation code */
            else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_ADDR32NB) {
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\tReadin OffsetValue : 0x%0X\n", offsetvalue);
                DEBUG_PRINT("\t\tReferenced Section: 0x%X\n", sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] + offsetvalue);
                DEBUG_PRINT("\t\tEnd of Relocation Bytes: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4);
                if (((char*)(sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] + offsetvalue) - (char*)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4)) > 0xffffffff) {
                    DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                    retcode = 1;
                    goto cleanup;
                }
                offsetvalue = ((char*)(sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] + offsetvalue) - (char*)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4));
                offsetvalue += coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value;
                DEBUG_PRINT("\tSetting 0x%p to OffsetValue: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }
            /* This is Type == 4 relocation code, this is either a relocation to a global
             * or imported symbol */
            else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32) {
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);

                if (llabs((long long)funcptrlocation - (long long)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4)) > UINT_MAX) {
                    DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                    goto cleanup;
                }

                offsetvalue += ((size_t)funcptrlocation - ((size_t)sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4));
                DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }
            else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32_1) {
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);

                if (llabs((long long)funcptrlocation - (long long)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 1)) > UINT_MAX) {
                    DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                    retcode = 1;
                    goto cleanup;
                }

                offsetvalue += (size_t)funcptrlocation - ((size_t)sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 1);
                DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }

            else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32_2) {
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);

                if (llabs((long long)funcptrlocation - (long long)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 2)) > UINT_MAX) {
                    DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                    retcode = 1;
                    goto cleanup;
                }

                offsetvalue += (size_t)funcptrlocation - ((size_t)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 2));
                DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }

            else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32_3) {
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);

                if (llabs((long long)funcptrlocation - (long long)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 3)) > UINT_MAX) {
                    DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                    retcode = 1;
                    goto cleanup;
                }

                offsetvalue += (size_t)funcptrlocation - ((size_t)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 3));
                DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }

            else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32_4) {
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);

                if (llabs((long long)funcptrlocation - (long long)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 4)) > UINT_MAX) {
                    DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                    retcode = 1;
                    goto cleanup;
                }

                offsetvalue += (size_t)funcptrlocation - ((size_t)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 4));
                DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }
            else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32_5) {
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);

                if (llabs((long long)funcptrlocation - (long long)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 5)) > UINT_MAX) {
                    DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                    retcode = 1;
                    goto cleanup;
                }

                offsetvalue += (size_t)funcptrlocation - ((size_t)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 5));
                DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }

            else if (coff_reloc_ptr->Type != IMAGE_REL_AMD64_ABSOLUTE) {
                DEBUG_PRINT("No code for relocation type: %d\n", coff_reloc_ptr->Type);
                retcode = 1;
                goto cleanup;
            }

            if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_ADDR32NB &&
                coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber <= 0) { retcode = 1; goto cleanup; }
#else
            /* This is Type == IMAGE_REL_I386_DIR32 relocation code */
            if (coff_reloc_ptr->Type == IMAGE_REL_I386_DIR32){
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\tReadin OffsetValue : 0x%0X\n", offsetvalue);
                offsetvalue = (uint32_t)funcptrlocation + offsetvalue;
                DEBUG_PRINT("\tSetting 0x%p to: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }
            else if (coff_reloc_ptr->Type == IMAGE_REL_I386_REL32){
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\tReadin OffsetValue : 0x%0X\n", offsetvalue);
                offsetvalue += (uint32_t)funcptrlocation - (uint32_t)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4);
                DEBUG_PRINT("\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }
#endif //WIN64 statement close
#endif //WIN32 statement close

            DEBUG_PRINT("\tValueNumber: 0x%X\n", coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value);
            DEBUG_PRINT("\tSectionNumber: 0x%X\n", coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber);
            coff_reloc_ptr += 1;
            DEBUG_PRINT("\n");
        }
        DEBUG_PRINT("\n");
    }

    /* Sections are writable only while relocating; switch to least privilege before execution. */
    for (counter = 0; counter < coff_header_ptr->NumberOfSections; counter++) {
        DWORD oldProtect = 0;
        DWORD finalProtect = PAGE_READONLY;
        coff_sect_ptr = (coff_sect_t*)(coff_data + sizeof(coff_file_header_t) + sizeof(coff_sect_t) * counter);
        if (coff_sect_ptr->Characteristics & IMAGE_SCN_MEM_EXECUTE) finalProtect = PAGE_EXECUTE_READ;
        else if (coff_sect_ptr->Characteristics & IMAGE_SCN_MEM_WRITE) finalProtect = PAGE_READWRITE;
        if (!VirtualProtect(sectionMapping[counter], sectionSize[counter], finalProtect, &oldProtect)) { retcode = 1; goto cleanup; }
        if (finalProtect == PAGE_EXECUTE_READ)
            FlushInstructionCache(GetCurrentProcess(), sectionMapping[counter], sectionSize[counter]);
    }
    {
        DWORD oldProtect = 0;
        if (!VirtualProtect(functionMapping, (relocationCount ? relocationCount : 1) * sizeof(void*), PAGE_READONLY, &oldProtect)) {
            retcode = 1; goto cleanup;
        }
    }

    /* Some debugging code to see what the sections look like in memory */
#if DEBUG
#ifdef _WIN32
    for (tempcounter = 0; tempcounter < coff_header_ptr->NumberOfSections; tempcounter++) {
        DEBUG_PRINT("Section: %u\n", tempcounter);
        if (sectionMapping[tempcounter] != NULL) {
            DEBUG_PRINT("\t");
            for (counter = 0; counter < sectionSize[tempcounter]; counter++) {
                DEBUG_PRINT("%02X ", (uint8_t)(sectionMapping[tempcounter][counter]));
            }
            DEBUG_PRINT("\n");
        }
    }
#endif
#endif

    DEBUG_PRINT("Symbols:\n");
    for (tempcounter = 0; tempcounter < coff_header_ptr->NumberOfSymbols; tempcounter++) {
        DEBUG_PRINT("\t%s: Section: %d, Value: 0x%X\n", coff_sym_ptr[tempcounter].first.Name, coff_sym_ptr[tempcounter].SectionNumber, coff_sym_ptr[tempcounter].Value);
        symbol_name = NULL;
        if (coff_sym_ptr[tempcounter].first.value[0] == 0) {
            uint32_t nameOffset = coff_sym_ptr[tempcounter].first.value[1];
            if (nameOffset >= 4 && nameOffset < coff_strtab_size &&
                memchr((char*)(coff_sym_ptr + coff_header_ptr->NumberOfSymbols) + nameOffset, 0,
                       coff_strtab_size - nameOffset) != NULL)
                symbol_name = (char*)(coff_sym_ptr + coff_header_ptr->NumberOfSymbols) + nameOffset;
        } else if (coff_sym_ptr[tempcounter].first.Name[7] != '\0') {
            memcpy(symbol_shortname_buffer, coff_sym_ptr[tempcounter].first.Name, 8);
            symbol_shortname_buffer[8] = 0;
            symbol_name = symbol_shortname_buffer;
        } else symbol_name = coff_sym_ptr[tempcounter].first.Name;
        if (symbol_name != NULL && strcmp(symbol_name, entryfuncname) == 0 &&
            coff_sym_ptr[tempcounter].SectionNumber > 0 &&
            coff_sym_ptr[tempcounter].SectionNumber <= coff_header_ptr->NumberOfSections &&
            coff_sym_ptr[tempcounter].Value < sectionSize[coff_sym_ptr[tempcounter].SectionNumber - 1]) {
            DEBUG_PRINT("\t\tFound entry!\n");
            foundEntry = 1;
#ifdef _WIN32
            /* So for some reason VS 2017 doesn't like this, but char* casting works, so just going to do that */
#ifdef _MSC_VER
            foo = (void(__cdecl*)(char*, unsigned long))(sectionMapping[coff_sym_ptr[tempcounter].SectionNumber - 1] + coff_sym_ptr[tempcounter].Value);
#else
            foo = (void(*)(char *, unsigned long))(sectionMapping[coff_sym_ptr[tempcounter].SectionNumber - 1] + coff_sym_ptr[tempcounter].Value);
#endif
            //sectionMapping[coff_sym_ptr[tempcounter].SectionNumber-1][coff_sym_ptr[tempcounter].Value+7] = '\xcc';
            DEBUG_PRINT("Trying to run: %p\n", foo);
            foo((char*)argumentdata, argumentSize);
#endif
        }
    }
    DEBUG_PRINT("Back\n");
    if (!foundEntry) retcode = 1;

    /* Cleanup the allocated memory */
#ifdef _WIN32
    cleanup :
            /* Avoid leaving a BOF-acquired token active on an exception-free return. */
            BeaconRevertToken();
            if (sectionMapping){
                for (tempcounter = 0; tempcounter < coff_header_ptr->NumberOfSections; tempcounter++) {
                    if (sectionMapping[tempcounter]) {
                        VirtualFree(sectionMapping[tempcounter], 0, MEM_RELEASE);
                    }
                }
                free(sectionMapping);
                sectionMapping = NULL;
            }
            if (sectionSize){
                free(sectionSize);
                sectionSize = NULL;
            }
            if (functionMapping){
                VirtualFree(functionMapping, 0, MEM_RELEASE);
            }
            while (loadedModuleCount > 0) {
                FreeLibrary(loadedModules[--loadedModuleCount]);
                loadedModules[loadedModuleCount] = NULL;
            }
#endif
            if (entryfuncname && entryfuncname != functionname){
                free(entryfuncname);
            }

            DEBUG_PRINT("Returning\n");
            return retcode;
}

#ifdef COFF_STANDALONE
int main(int argc, char* argv[]) {
    char* coff_data = NULL;
    unsigned char* arguments = NULL;
    int argumentSize = 0;
#ifdef _WIN32
    char* outdata = NULL;
    int outdataSize = 0;
#endif
    uint32_t filesize = 0;
    int checkcode = 0;
    if (argc < 3) {
        printf("ERROR: %s go /path/to/object/file.o (arguments)\n", argv[0]);
        return 1;
    }

    coff_data = (char*)getContents(argv[2], &filesize);
    if (coff_data == NULL) {
        return 1;
    }
    printf("Got contents of COFF file\n");
    arguments = unhexlify((unsigned char*)argv[3], &argumentSize);
    printf("Running/Parsing the COFF file\n");
    checkcode = RunCOFF(argv[1], (unsigned char*)coff_data, filesize, arguments, argumentSize);
    if (checkcode == 0) {
#ifdef _WIN32
        printf("Ran/parsed the coff\n");
        outdata = BeaconGetOutputData(&outdataSize);
        if (outdata != NULL) {

            printf("Outdata Below:\n\n%s\n", outdata);
        }
#endif
    }
    else {
        printf("Failed to run/parse the COFF file\n");
    }
    if (coff_data) {
        free(coff_data);
    }
    return 0;
}

#endif

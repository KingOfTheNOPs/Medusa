/*
 * Cobalt Strike 4.X BOF compatibility layer
 * -----------------------------------------
 * The whole point of these files are to allow beacon object files built for CS
 * to run fine inside of other tools without recompiling.
 *
 * Built off of the beacon.h file provided to build for CS.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#ifdef _WIN32
#include <windows.h>

#include "beacon_compatibility.h"

#define MEDUSA_MAX_BUFFER (2 * 1024 * 1024)
#define DEFAULTPROCESSNAME "rundll32.exe"
#ifdef _WIN64
#define X86PATH "SysWOW64"
#define X64PATH "System32"
#else
#define X86PATH "System32"
#define X64PATH "sysnative"
#endif


 /* Data Parsing */
unsigned char* InternalFunctions[30][2] = {
    {(unsigned char*)"BeaconDataParse", (unsigned char*)BeaconDataParse},
    {(unsigned char*)"BeaconDataInt", (unsigned char*)BeaconDataInt},
    {(unsigned char*)"BeaconDataShort", (unsigned char*)BeaconDataShort},
    {(unsigned char*)"BeaconDataLength", (unsigned char*)BeaconDataLength},
    {(unsigned char*)"BeaconDataExtract", (unsigned char*)BeaconDataExtract},
    {(unsigned char*)"BeaconFormatAlloc", (unsigned char*)BeaconFormatAlloc},
    {(unsigned char*)"BeaconFormatReset", (unsigned char*)BeaconFormatReset},
    {(unsigned char*)"BeaconFormatFree", (unsigned char*)BeaconFormatFree},
    {(unsigned char*)"BeaconFormatAppend", (unsigned char*)BeaconFormatAppend},
    {(unsigned char*)"BeaconFormatPrintf", (unsigned char*)BeaconFormatPrintf},
    {(unsigned char*)"BeaconFormatToString", (unsigned char*)BeaconFormatToString},
    {(unsigned char*)"BeaconFormatInt", (unsigned char*)BeaconFormatInt},
    {(unsigned char*)"BeaconPrintf", (unsigned char*)BeaconPrintf},
    {(unsigned char*)"BeaconOutput", (unsigned char*)BeaconOutput},
    {(unsigned char*)"BeaconUseToken", (unsigned char*)BeaconUseToken},
    {(unsigned char*)"BeaconRevertToken", (unsigned char*)BeaconRevertToken},
    {(unsigned char*)"BeaconIsAdmin", (unsigned char*)BeaconIsAdmin},
    {(unsigned char*)"BeaconGetSpawnTo", (unsigned char*)BeaconGetSpawnTo},
    {(unsigned char*)"BeaconSpawnTemporaryProcess", (unsigned char*)BeaconSpawnTemporaryProcess},
    {(unsigned char*)"BeaconInjectProcess", (unsigned char*)BeaconInjectProcess},
    {(unsigned char*)"BeaconInjectTemporaryProcess", (unsigned char*)BeaconInjectTemporaryProcess},
    {(unsigned char*)"BeaconCleanupProcess", (unsigned char*)BeaconCleanupProcess},
    {(unsigned char*)"toWideChar", (unsigned char*)toWideChar},
    {(unsigned char*)"LoadLibraryA", (unsigned char*)LoadLibraryA},
    {(unsigned char*)"GetProcAddress", (unsigned char*)GetProcAddress},
    {(unsigned char*)"GetModuleHandleA", (unsigned char*)GetModuleHandleA},
    {(unsigned char*)"FreeLibrary", (unsigned char*)FreeLibrary},
    {(unsigned char*)"__C_specific_handler", NULL}

};

uint32_t swap_endianess(uint32_t indata) {
    uint32_t testint = 0xaabbccdd;
    uint32_t outint = indata;
    if (((unsigned char*)&testint)[0] == 0xdd) {
        ((unsigned char*)&outint)[0] = ((unsigned char*)&indata)[3];
        ((unsigned char*)&outint)[1] = ((unsigned char*)&indata)[2];
        ((unsigned char*)&outint)[2] = ((unsigned char*)&indata)[1];
        ((unsigned char*)&outint)[3] = ((unsigned char*)&indata)[0];
    }
    return outint;
}

char* beacon_compatibility_output = NULL;
int beacon_compatibility_size = 0;
int beacon_compatibility_offset = 0;

void BeaconDataParse(datap* parser, char* buffer, int size) {
    if (parser == NULL || buffer == NULL) {
        return;
    }

    if (size < 4 || size > MEDUSA_MAX_BUFFER) {
        memset(parser, 0, sizeof(*parser));
        return;
    }
    parser->original = buffer;
    parser->buffer = buffer;
    parser->length = size - 4;
    parser->size = size - 4;
    parser->buffer += 4;
    return;
}

int BeaconDataInt(datap* parser) {
    if (parser == NULL) {
        return 0;
    }

    int32_t fourbyteint = 0;
    if (parser->length < 4) {
        return 0;
    }
    memcpy(&fourbyteint, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    return (int)fourbyteint;
}

short BeaconDataShort(datap* parser) {
    if (parser == NULL) {
        return 0;
    }

    int16_t retvalue = 0;
    if (parser->length < 2) {
        return 0;
    }
    memcpy(&retvalue, parser->buffer, 2);
    parser->buffer += 2;
    parser->length -= 2;
    return (short)retvalue;
}

int BeaconDataLength(datap* parser) {
    if (parser == NULL) {
        return 0;
    }

    return parser->length;
}

char* BeaconDataExtract(datap* parser, int* size) {
    if (size != NULL) *size = 0;
    if (parser == NULL) {
        return NULL;
    }

    uint32_t length = 0;
    char* outdata = NULL;
    /*Length prefixed binary blob, going to assume uint32_t for this.*/
    if (parser->length < 4) {
        return NULL;
    }
    memcpy(&length, parser->buffer, 4);
    parser->buffer += 4;

    outdata = parser->buffer;
    if (outdata == NULL) {
        return NULL;
    }
    parser->length -= 4;
    if (length > (uint32_t)parser->length) {
        return NULL;
    }
    parser->length -= length;
    parser->buffer += length;
    if (size != NULL && outdata != NULL) {
        *size = length;
    }
    return outdata;
}

/* format API */

void BeaconFormatAlloc(formatp* format, int maxsz) {
    if (format == NULL) {
        return;
    }
    memset(format, 0, sizeof(*format));
    if (maxsz <= 0 || maxsz > MEDUSA_MAX_BUFFER) return;

    format->original = calloc(maxsz, 1);
    format->buffer = format->original;
    format->length = 0;
    format->size = maxsz;
    return;
}

void BeaconFormatReset(formatp* format) {
    if (format == NULL) {
        return;
    }

    if (format->original == NULL || format->size <= 0) {
        return;
    }
    memset(format->original, 0, format->size);
    format->buffer = format->original;
    format->length = 0;
    return;
}

void BeaconFormatFree(formatp* format) {
    if (format == NULL) {
        return;
    }
    if (format->original) {
        free(format->original);
        format->original = NULL;
    }
    format->buffer = NULL;
    format->length = 0;
    format->size = 0;
    return;
}

void BeaconFormatAppend(formatp* format, char* text, int len) {
    if (format == NULL || text == NULL || len < 0 || format->buffer == NULL ||
        len > format->size - format->length) {
        return;
    }

    memcpy(format->buffer, text, len);
    format->buffer += len;
    format->length += len;
    return;
}

void BeaconFormatPrintf(formatp* format, char* fmt, ...) {
    if (format == NULL || fmt == NULL) {
        return;
    }

    /*Take format string, and sprintf it into here*/
    va_list args;
    int length = 0;

    va_start(args, fmt);
    length = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    if (length < 0 || format->buffer == NULL || length + 1 > format->size - format->length) {
        return;
    }

    va_start(args, fmt);
    (void)vsnprintf(format->buffer, length + 1, fmt, args);
    va_end(args);
    format->length += length;
    format->buffer += length;
    return;
}


char* BeaconFormatToString(formatp* format, int* size) {
    if (format == NULL || size == NULL) {
        return NULL;
    }

    *size = format->length;
    return format->original;
}

void BeaconFormatInt(formatp* format, int value) {
    if (format == NULL) {
        return;
    }

    uint32_t indata = value;
    uint32_t outdata = 0;
    if (format->length + 4 > format->size) {
        return;
    }
    outdata = swap_endianess(indata);
    memcpy(format->buffer, &outdata, 4);
    format->length += 4;
    format->buffer += 4;
    return;
}

/* Main output functions */

void BeaconPrintf(int type, char* fmt, ...) {
    if (fmt == NULL) {
        return;
    }

    /* Change to maintain internal buffer, and return after done running. */
    int length = 0;
    char* tempptr = NULL;
    va_list args;

    va_start(args, fmt);
    length = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    if (length < 0 || length > MEDUSA_MAX_BUFFER - beacon_compatibility_size - 1) {
        return;
    }
    tempptr = realloc(beacon_compatibility_output, beacon_compatibility_size + length + 1);
    if (tempptr == NULL) {
        return;
    }
    beacon_compatibility_output = tempptr;
    memset(beacon_compatibility_output + beacon_compatibility_offset, 0, length + 1);
    va_start(args, fmt);
    length = vsnprintf(beacon_compatibility_output + beacon_compatibility_offset, length +1, fmt, args);
    beacon_compatibility_size += length;
    beacon_compatibility_offset += length;
    va_end(args);
    return;
}

void BeaconOutput(int type, char* data, int len) {
    if (data == NULL || len < 0 || len > MEDUSA_MAX_BUFFER - beacon_compatibility_size - 1) {
        return;
    }

    char* tempptr = NULL;
    tempptr = realloc(beacon_compatibility_output, beacon_compatibility_size + len + 1);
    if (tempptr == NULL) {
        return;
    }
    beacon_compatibility_output = tempptr;
    memset(beacon_compatibility_output + beacon_compatibility_offset, 0, len + 1);
    memcpy(beacon_compatibility_output + beacon_compatibility_offset, data, len);
    beacon_compatibility_size += len;
    beacon_compatibility_offset += len;
    return;
}

/* Token Functions */

BOOL BeaconUseToken(HANDLE token) {
    return SetThreadToken(NULL, token);
}

void BeaconRevertToken(void) {
    if (!RevertToSelf()) {
#ifdef DEBUG
        printf("RevertToSelf Failed!\n");
#endif
    }
    return;
}

BOOL BeaconIsAdmin(void) {
    BYTE sidBuffer[SECURITY_MAX_SID_SIZE] = {0};
    DWORD sidSize = sizeof(sidBuffer);
    BOOL isMember = FALSE;
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, sidBuffer, &sidSize)) return FALSE;
    if (!CheckTokenMembership(NULL, sidBuffer, &isMember)) return FALSE;
    return isMember;
}

/* Injection/spawning related stuffs
 *
 * These functions are basic place holders, and if implemented into something
 * real should be just calling internal functions for your tools. */
void BeaconGetSpawnTo(BOOL x86, char* buffer, int length) {
    if (buffer != NULL && length > 0) memset(buffer, 0, length);
}

BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO * sInfo, PROCESS_INFORMATION * pInfo) {
    if (pInfo != NULL) memset(pInfo, 0, sizeof(*pInfo));
    return FALSE;
}

void BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char * arg, int a_len) {
    /* Leaving this to be implemented by people needing/wanting it */
    return;
}

void BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len) {
    /* Leaving this to be implemented by people needing/wanting it */
    return;
}

void BeaconCleanupProcess(PROCESS_INFORMATION* pInfo) {
    if (pInfo != NULL) {
        if (pInfo->hThread) (void)CloseHandle(pInfo->hThread);
        if (pInfo->hProcess) (void)CloseHandle(pInfo->hProcess);
    }
    return;
}

BOOL toWideChar(char* src, wchar_t* dst, int max) {
    if (max < sizeof(wchar_t))
        return FALSE;
    return MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, src, -1, dst, max / sizeof(wchar_t));
}

char* BeaconGetOutputData(int *outsize) {
    if (outsize == NULL) {
        return NULL;
    }

    char* outdata = beacon_compatibility_output;
    *outsize = beacon_compatibility_size;
    beacon_compatibility_output = NULL;
    beacon_compatibility_size = 0;
    beacon_compatibility_offset = 0;
    return outdata;
}

void BeaconResetOutput(void) {
    free(beacon_compatibility_output);
    beacon_compatibility_output = NULL;
    beacon_compatibility_size = 0;
    beacon_compatibility_offset = 0;
}

void BeaconFreeOutputData(char *output) {
    free(output);
}

#endif

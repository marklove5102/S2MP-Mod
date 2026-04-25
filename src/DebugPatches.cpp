///////////////////////////////////////////
//         Debug Patches
//	Patching some anti-tamper stuff
////////////////////////////////////////////
#include "pch.h"
#include "Arxan.hpp"
#include <winternl.h>

#pragma intrinsic(_ReturnAddress)

#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004
#define ThreadHideFromDebugger 0x11

std::string DebugPatches::conLabel = "DP";
uintptr_t DebugPatches::base = (uintptr_t)GetModuleHandle(NULL) + 0x1000;
///////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef NTSTATUS(WINAPI* NtUserBuildHwndList_t)(HDESK hdesk, HWND hwndParent, BOOL fChildren, BOOL fOwner, DWORD dwThreadId, UINT cHwndMax, HWND* phwnd, PUINT pcHwndNeeded);
NtUserBuildHwndList_t fpNtUserBuildHwndList = nullptr;

typedef BOOL(WINAPI* CheckRemoteDebuggerPresent_t)(HANDLE hProcess, PBOOL pbDebuggerPresent);
CheckRemoteDebuggerPresent_t fpCheckRemoteDebuggerPresent = nullptr;

typedef NTSTATUS(WINAPI* NtCreateThreadEx_t)(OUT PHANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes, IN HANDLE ProcessHandle, IN PVOID StartRoutine, IN PVOID Argument, IN ULONG CreateFlags, IN SIZE_T ZeroBits, IN SIZE_T StackSize, IN SIZE_T MaximumStackSize, IN PVOID AttributeList);
NtCreateThreadEx_t fpNtCreateThreadEx = nullptr;

typedef NTSTATUS(WINAPI* NtSetInformationThread_t)(HANDLE ThreadHandle, THREAD_INFORMATION_CLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
NtSetInformationThread_t fpNtSetInformationThread = nullptr;

typedef NTSTATUS(WINAPI* NtQueryInformationThread_t)(HANDLE ThreadHandle, THREAD_INFORMATION_CLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
NtQueryInformationThread_t fpNtQueryInformationThread = nullptr;

NTSTATUS WINAPI HookedNtUserBuildHwndList(HDESK hdesk, HWND hwndParent, BOOL fChildren, BOOL fOwner, DWORD dwThreadId, UINT cHwndMax, HWND* phwnd, PUINT pcHwndNeeded) {
    NTSTATUS result = fpNtUserBuildHwndList(hdesk, hwndParent, fChildren, fOwner, dwThreadId, cHwndMax, phwnd, pcHwndNeeded);

    if (NT_SUCCESS(result) && pcHwndNeeded) {
        *pcHwndNeeded = 0;
    }

    return result;
}

void bypassHwndChecks() {
    HMODULE hUser32 = LoadLibraryA("win32u.dll");
    if (!hUser32) {
        Console::print("Failed to load win32u.dll");
        return;
    }

    FARPROC pFunc = GetProcAddress(hUser32, "NtUserBuildHwndList");
    if (!pFunc) {
        Console::print("Failed to get address of NtUserBuildHwndList");
        return;
    }

    if (MH_CreateHook(pFunc, &HookedNtUserBuildHwndList, reinterpret_cast<LPVOID*>(&fpNtUserBuildHwndList)) != MH_OK) {
        Console::print("Failed to create hook");
        return;
    }

    if (MH_EnableHook(pFunc) != MH_OK) {
        Console::print("Failed to enable hook");
        return;
    }
}

using NtClose_t = NTSTATUS(NTAPI*)(HANDLE);
using NtQueryInformationProcess_t = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
NtClose_t fpNtClose = nullptr;
NtQueryInformationProcess_t fpNtQueryInformationProcess = nullptr;

typedef NTSTATUS(NTAPI* PNTQUERYOBJECT)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
PNTQUERYOBJECT pNtQueryObject = nullptr;


NTSTATUS NTAPI HookedNtClose(HANDLE handle) {
    if (pNtQueryObject) {
        char info[16] = { 0 };
        if (pNtQueryObject(handle, (OBJECT_INFORMATION_CLASS)4, &info, 2, nullptr) >= 0 && (uint64_t)handle != 0x12345) {
            return fpNtClose(handle);
        }
    }
    return STATUS_INVALID_HANDLE;
}
#ifndef ProcessDebugPort
#define ProcessDebugPort 7
#endif 

#ifndef ProcessDebugObjectHandle
#define ProcessDebugObjectHandle 30
#endif 

#ifndef ProcessDebugFlags
#define ProcessDebugFlags 31
#endif 
using fnNtQueryInformationProcess = NTSTATUS(WINAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG); 
fnNtQueryInformationProcess oNtQueryInformationProcess = nullptr;

NTSTATUS WINAPI HookedNtQueryInformationProcess(HANDLE handle, PROCESSINFOCLASS info_class, PVOID info, ULONG info_length, PULONG ret_length) {
    const NTSTATUS status = oNtQueryInformationProcess(handle, info_class, info, info_length, ret_length);

    if (NT_SUCCESS(status)) {
        if (info_class == ProcessBasicInformation) {
            static DWORD explorer_pid = 0;
            if (!explorer_pid) {
                HWND shell_window = GetShellWindow();
                GetWindowThreadProcessId(shell_window, &explorer_pid);
            }

            reinterpret_cast<PPROCESS_BASIC_INFORMATION>(info)->Reserved3 =
                reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(explorer_pid));
        }
        else if (info_class == ProcessDebugObjectHandle) {
            *reinterpret_cast<HANDLE*>(info) = nullptr;
            return STATUS_PORT_NOT_SET; // 0xC0000353
        }
        else if (info_class == ProcessDebugPort) {
            *reinterpret_cast<HANDLE*>(info) = nullptr;
        }
        else if (info_class == 31 /* ProcessDebugFlags */) {
            *reinterpret_cast<ULONG*>(info) = 1;
        }
    }

    return status;
}


BOOL WINAPI HookedCheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent) {
    BOOL result = fpCheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent);
    if (pbDebuggerPresent != nullptr) {
        if (pbDebuggerPresent) {
            Console::labelPrint(DebugPatches::conLabel, "CheckRemoteDebuggerPresent called");
        }
        *pbDebuggerPresent = FALSE;
    }

    return result;
}

NTSTATUS WINAPI HookedNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
    SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList) {
    //remove HIDE_FROM_DEBUGGER flag
    if (CreateFlags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER) {
        CreateFlags &= ~THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
        Console::labelPrint(DebugPatches::conLabel, "Stripped THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER from thread creation");
    }

    return fpNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

void bypassHiddenThreadCreation() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        Console::print("Failed to get handle for ntdll.dll");
        return;
    }

    FARPROC pFunc = GetProcAddress(hNtdll, "NtCreateThreadEx");
    if (!pFunc) {
        Console::print("Failed to get address of NtCreateThreadEx");
        return;
    }

    if (MH_CreateHook(pFunc, &HookedNtCreateThreadEx, reinterpret_cast<LPVOID*>(&fpNtCreateThreadEx)) != MH_OK) {
        Console::print("Failed to create hook for NtCreateThreadEx");
        return;
    }

    if (MH_EnableHook(pFunc) != MH_OK) {
        Console::print("Failed to enable hook for NtCreateThreadEx");
        return;
    }
}
NTSTATUS WINAPI HookedNtSetInformationThread(HANDLE ThreadHandle, THREAD_INFORMATION_CLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength) {
    if (ThreadInformationClass == (THREAD_INFORMATION_CLASS)ThreadHideFromDebugger) {
        return 0; //success
    }

    return fpNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

void bypassThreadHideFromDebugger() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        Console::print("Failed to get handle for ntdll.dll");
        return;
    }

    FARPROC pFunc = GetProcAddress(hNtdll, "NtSetInformationThread");
    if (!pFunc) {
        Console::print("Failed to get address of NtSetInformationThread");
        return;
    }

    if (MH_CreateHook(pFunc, &HookedNtSetInformationThread, reinterpret_cast<LPVOID*>(&fpNtSetInformationThread)) != MH_OK) {
        Console::print("Failed to create hook for NtSetInformationThread");
        return;
    }

    if (MH_EnableHook(pFunc) != MH_OK) {
        Console::print("Failed to enable hook for NtSetInformationThread");
        return;
    }
}

void hookNtClose() {
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (hNtDll) {
        pNtQueryObject = (PNTQUERYOBJECT)GetProcAddress(hNtDll, "NtQueryObject");
        if (!pNtQueryObject) {
            Console::print("Failed to resolve NtQueryObject");
            return;
        }
        MH_CreateHook(GetProcAddress(hNtDll, "NtClose"), HookedNtClose, reinterpret_cast<LPVOID*>(&fpNtClose));
    }
    MH_EnableHook(MH_ALL_HOOKS);
}

void clearHWBP(void) {
    CONTEXT ctx{};
    ZeroMemory(&ctx, sizeof(CONTEXT));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE thread = GetCurrentThread();
    if (thread != NULL) {
        GetThreadContext(thread, &ctx);
        ctx.Dr0 = 0;
        ctx.Dr1 = 0;
        ctx.Dr2 = 0;
        ctx.Dr3 = 0;
        ctx.Dr6 = 0;
        ctx.Dr7 = 0;
        SetThreadContext(thread, &ctx);
    }
}

NTSTATUS WINAPI HookedNtQueryInformationThread(HANDLE ThreadHandle, THREAD_INFORMATION_CLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength) {
    if (ThreadInformationClass == (THREAD_INFORMATION_CLASS)ThreadHideFromDebugger) {
        Console::print("Blocked NtQueryInformationThread(ThreadHideFromDebugger)");
        return 0xC00000BB; //STATUS_NOT_SUPPORTED
    }

    return fpNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
}

void bypassThreadQueryHideFromDebugger() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        Console::print("Failed to get handle for ntdll.dll");
        return;
    }

    FARPROC pFunc = GetProcAddress(hNtdll, "NtQueryInformationThread");
    if (!pFunc) {
        Console::print("Failed to get address of NtQueryInformationThread");
        return;
    }

    if (MH_CreateHook(pFunc, &HookedNtQueryInformationThread, reinterpret_cast<LPVOID*>(&fpNtQueryInformationThread)) != MH_OK) {
        Console::print("Failed to create hook for NtQueryInformationThread");
        return;
    }

    if (MH_EnableHook(pFunc) != MH_OK) {
        Console::print("Failed to enable hook for NtQueryInformationThread");
        return;
    }
}

void hookNtQueryInformationProcess() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        Console::print("Failed to get handle for ntdll.dll");
        return;
    }

    FARPROC pFunc = GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!pFunc) {
        Console::print("Failed to get address of NtQueryInformationProcess");
        return;
    }

    if (MH_CreateHook(pFunc, &HookedNtQueryInformationProcess, reinterpret_cast<LPVOID*>(&oNtQueryInformationProcess)) != MH_OK) {
        Console::print("Failed to create hook for NtQueryInformationProcess");
        return;
    }

    if (MH_EnableHook(pFunc) != MH_OK) {
        Console::print("Failed to enable hook for NtQueryInformationProcess");
        return;
    }
}

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
NtQuerySystemInformation_t fpNtQuerySystemInformation = nullptr;
typedef NTSTATUS(NTAPI* NtQueryObject_t)(HANDLE Handle, ULONG ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
#define SystemExtendedHandleInformation 64
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

std::wstring toLower(std::wstring s) {
    for (auto& c : s) {
        c = (wchar_t)towlower(c);
    }
    return s;
}


bool containsSubstring(const std::wstring& text, const std::wstring& sub, bool caseInsensitive) {
    if (caseInsensitive) {
        return toLower(text).find(toLower(sub)) != std::wstring::npos;
    }

    return text.find(sub) != std::wstring::npos;
}


size_t closeCurrentProcessMutantsContaining(const std::wstring& substring, bool caseInsensitive = true, bool dryRun = false) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        return 0;
    }
    
    NtQueryObject_t NtQueryObject = (NtQueryObject_t)GetProcAddress(ntdll, "NtQueryObject");

    if (!fpNtQuerySystemInformation || !NtQueryObject) {
        return 0;
    }

    DWORD currentPid = GetCurrentProcessId();
    ULONG handleInfoSize = 0x10000;
    std::vector<BYTE> handleInfoBuffer(handleInfoSize);

    NTSTATUS status;

    while (true) {
        status = fpNtQuerySystemInformation(SystemExtendedHandleInformation, handleInfoBuffer.data(), handleInfoSize, &handleInfoSize);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            handleInfoSize *= 2;
            handleInfoBuffer.resize(handleInfoSize);
            continue;
        }

        break;
    }

    if (!NT_SUCCESS(status)) {
        return 0;
    }

    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(handleInfoBuffer.data());

    size_t closedCount = 0;

    for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; i++) {
        auto& entry = handleInfo->Handles[i];

        if ((DWORD)entry.UniqueProcessId != currentPid) {
            continue;
        }

        HANDLE h = reinterpret_cast<HANDLE>(entry.HandleValue);
        BYTE typeBuffer[0x1000] = {};
        ULONG returnLength = 0;

        status = NtQueryObject(h, ObjectTypeInformation, typeBuffer, sizeof(typeBuffer), &returnLength);

        if (!NT_SUCCESS(status)) {
            continue;
        }

        UNICODE_STRING* typeName = reinterpret_cast<UNICODE_STRING*>(typeBuffer);

        if (!typeName->Buffer || typeName->Length == 0) {
            continue;
        }

        std::wstring type(typeName->Buffer, typeName->Length / sizeof(wchar_t));

        if (type != L"Mutant") {
            continue;
        }

        ULONG nameBufferSize = 0x1000;
        std::vector<BYTE> nameBuffer(nameBufferSize);

        status = NtQueryObject(h, ObjectNameInformation, nameBuffer.data(), nameBufferSize, &returnLength);

        if (status == STATUS_INFO_LENGTH_MISMATCH || returnLength > nameBufferSize) {
            nameBufferSize = returnLength;
            nameBuffer.resize(nameBufferSize);

            status = NtQueryObject(h, ObjectNameInformation, nameBuffer.data(), nameBufferSize, &returnLength);
        }

        if (!NT_SUCCESS(status)) {
            continue;
        }

        UNICODE_STRING* objectName = reinterpret_cast<UNICODE_STRING*>(nameBuffer.data());

        if (!objectName->Buffer || objectName->Length == 0) {
            continue;
        }

        std::wstring name(objectName->Buffer, objectName->Length / sizeof(wchar_t));

        if (!containsSubstring(name, substring, caseInsensitive)) {
            continue;
        }


        if (!dryRun) {
            if (CloseHandle(h)) {
                closedCount++;
            }
        }
    }

    return closedCount;
}

void freeIdaMutants() {
    //game would hold the mutex for ida module handles, forcing ida to fail to load lol
    size_t closedIda = closeCurrentProcessMutantsContaining(L"IDA ", true, false); //very needed
    size_t closeMisc = closeCurrentProcessMutantsContaining(L"WilStaging_02", true, false); //idk but looked sus
    closeMisc += closeCurrentProcessMutantsContaining(L"WilError_03", true, false); //idk but looked sus
    DEV_PRINTF("Closed %zu IDA Mutants", closedIda);
    DEV_PRINTF("Closed %zu Misc Mutants", closeMisc);
}


typedef _CLIENT_ID* R_PCLIENT_ID; //ffs

typedef NTSTATUS(NTAPI* NtOpenProcess_t)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, R_PCLIENT_ID ClientId);
NtOpenProcess_t fpNtOpenProcess = nullptr;

//prevent the steam must be running error from us blocking the processes
bool isSteamProcessId_Nt(DWORD pid) {
    if (!fpNtOpenProcess || pid == 0) {
        return false;
    }

    HANDLE hProc = nullptr;

    _CLIENT_ID cid{};
    cid.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid));
    cid.UniqueThread = nullptr;

    OBJECT_ATTRIBUTES oa{};
    InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);

    NTSTATUS status = fpNtOpenProcess(&hProc, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid);

    if (status < 0 || !hProc) {
        return false;
    }

    bool result = false;

    wchar_t path[MAX_PATH]{};
    DWORD size = MAX_PATH;

    if (QueryFullProcessImageNameW(hProc, 0, path, &size)){
        const wchar_t* name = wcsrchr(path, L'\\');
        name = name ? name + 1 : path;

        if (_wcsicmp(name, L"steam.exe") == 0)
            result = true;
    }

    CloseHandle(hProc);
    return result;
}


NTSTATUS NtOpenProcess_hookfunc(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, R_PCLIENT_ID ClientId) {
    if (ProcessHandle) {
        *ProcessHandle = nullptr;
    }

    if (!fpNtOpenProcess || !ClientId || !ClientId->UniqueProcess) {
        return STATUS_ACCESS_DENIED;
    }

    DWORD pid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(ClientId->UniqueProcess));

    if (!isSteamProcessId_Nt(pid)) {
        return STATUS_ACCESS_DENIED;
    }

    return fpNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

void disableProgramScans() {
    //NtOpenProcess 
    HMODULE dll = GetModuleHandleA("ntdll.dll");
    if (!dll) {
        return;
    }
    FARPROC pFunc = GetProcAddress(dll, "NtOpenProcess");
    if (!pFunc) {
        Console::print("Failed to get address of NtOpenProcess");
        return;
    }
    
    if (MH_CreateHook(pFunc, &NtOpenProcess_hookfunc, reinterpret_cast<LPVOID*>(&fpNtOpenProcess)) != MH_OK) {
        Console::print("Failed to create hook for NtOpenProcess");
        return;
    }
    
    if (MH_EnableHook(pFunc) != MH_OK) {
        Console::print("Failed to enable hook for NtOpenProcess");
        return;
    }
}


typedef BOOLEAN(NTAPI* RtlEqualUnicodeString_t)(PUNICODE_STRING, PUNICODE_STRING, BOOLEAN);
RtlEqualUnicodeString_t fpRtlEqualUnicodeString = nullptr;
void myRtlInitUnicodeString(PUNICODE_STRING dst, PCWSTR src) {
    if (!src) {
        dst->Length = 0;
        dst->MaximumLength = 0;
        dst->Buffer = NULL;
        return;
    }

    size_t len = wcslen(src) * sizeof(WCHAR);

    dst->Length = (USHORT)len;
    dst->MaximumLength = (USHORT)(len + sizeof(WCHAR));
    dst->Buffer = (PWSTR)src;
}
__kernel_entry NTSTATUS NtQuerySystemInformation_hookfunc(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    NTSTATUS status = fpNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    if (!NT_SUCCESS(status) || SystemInformationClass != SystemProcessInformation || SystemInformation == NULL) {
        return status;
    }

    const wchar_t* blockedProcesses[] = {
        L"OLLYDBG.exe",
        L"x32dbg.exe",
        L"x64dbg.exe",
        L"x96dbg.exe",
        L"windbg.exe",
        L"dnSpy.exe",
        L"HxD.exe",
        L"ida.exe", //weirdly the ida ones arent needed.
        L"ida64.exe",
        L"ImmunityDebugger.exe",
        L"Scylla_x64.exe",
        L"Scylla_x86.exe",
        L"OllyDumpEx_SA32.exe",
        L"OllyDumpEx_SA64.exe",
        L"apimonitor-x64.exe",
        L"apimonitor-x86.exe",
        L"cheatengine-x86_64.exe",
        L"Cheat Engine.exe",
        L"cheatengine-x86_64-SSE4-AVX2.exe",
        L"cheatengine-i386.exe",
    };
    const size_t numBlockedProcesses = sizeof(blockedProcesses) / sizeof(blockedProcesses[0]);

    PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
    PSYSTEM_PROCESS_INFORMATION prevSpi = NULL;

    while (true) {
        bool blockedName = false;

        if (spi->ImageName.Buffer && spi->ImageName.Length > 0) {
            UNICODE_STRING name = spi->ImageName;
            for (size_t i = 0; i < numBlockedProcesses; i++) {
                UNICODE_STRING blocked;
                myRtlInitUnicodeString(&blocked, blockedProcesses[i]);

                if (fpRtlEqualUnicodeString(&name, &blocked, TRUE)) {
                    blockedName = true;
                    //DEV_PRINTF("Blocked-name process observed: PID=%lu | Name=%.*ls", (DWORD)(ULONG_PTR)spi->UniqueProcessId, spi->ImageName.Length / sizeof(WCHAR), spi->ImageName.Buffer);
                    break;
                }
            }

            if (blockedName) {
                if (prevSpi == NULL) {
                    if (spi->NextEntryOffset == 0) {
                        RtlZeroMemory(SystemInformation, SystemInformationLength);
                        if (ReturnLength) {
                            *ReturnLength = 0;
                        }
                        return status;
                    }
                    else {
                        PSYSTEM_PROCESS_INFORMATION nextSpi = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)spi + spi->NextEntryOffset);
                        ULONG moveSize = SystemInformationLength - spi->NextEntryOffset;
                        RtlMoveMemory(SystemInformation, nextSpi, moveSize);
                        if (ReturnLength) {
                            *ReturnLength -= spi->NextEntryOffset;
                        }
                        spi = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
                        prevSpi = NULL;
                        continue;
                    }
                }
                else {
                    if (spi->NextEntryOffset == 0) {
                        prevSpi->NextEntryOffset = 0;
                        if (ReturnLength) {
                            *ReturnLength -= (ULONG)((BYTE*)spi - (BYTE*)prevSpi);
                        }
                        break;
                    }
                    else {
                        PSYSTEM_PROCESS_INFORMATION nextSpi = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)spi + spi->NextEntryOffset);
                        ULONG skipSize = spi->NextEntryOffset;
                        prevSpi->NextEntryOffset += skipSize;
                        if (ReturnLength) {
                            *ReturnLength -= skipSize;
                        }
                        spi = nextSpi;
                        continue;
                    }
                }
            }
        }

        prevSpi = spi;

        if (spi->NextEntryOffset == 0) {
            break;
        }

        spi = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)spi + spi->NextEntryOffset);
    }

    return status;
}



void patchProcessNameChecks() {
    //NtQuerySystemInformation 

    fpRtlEqualUnicodeString = (RtlEqualUnicodeString_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlEqualUnicodeString");
    HMODULE dll = GetModuleHandleA("ntdll.dll");
    if (!dll) {
        return;
    }
    FARPROC pFunc = GetProcAddress(dll, "NtQuerySystemInformation");
    if (!pFunc) {
        Console::print("Failed to get address of NtQuerySystemInformation");
        return;
    }

    if (MH_CreateHook(pFunc, &NtQuerySystemInformation_hookfunc, reinterpret_cast<LPVOID*>(&fpNtQuerySystemInformation)) != MH_OK) {
        Console::print("Failed to create hook for NtQuerySystemInformation");
        return;
    }

    if (MH_EnableHook(pFunc) != MH_OK) {
        Console::print("Failed to enable hook for NtQuerySystemInformation");
        return;
    }
}

//run from dll main to get pre unpacking hooks set
void DebugPatches::earlyInit() {
    MH_Initialize();
    patchProcessNameChecks();// run this first cuz of shared fpNtQuerySystemInformation usage
    freeIdaMutants(); //works, but how can we prevent it from ever happening
    disableProgramScans();
    bypassHwndChecks();
    hookNtQueryInformationProcess();
    bypassHiddenThreadCreation();
    bypassThreadHideFromDebugger();
    bypassThreadQueryHideFromDebugger();
}

void DebugPatches::init() {
    DEV_INIT_PRINT();
    freeIdaMutants(); //works, but how can we prevent it from ever happening
    hookNtClose();
    clearHWBP();
}
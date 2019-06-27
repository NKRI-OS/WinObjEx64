/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       PLUGIN_DEF.H
*
*  VERSION:     1.00
*
*  DATE:        23 June 2019
*
*  Common header file for the plugin subsystem definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

typedef BOOL(CALLBACK *pfnReadSystemMemoryEx)(
    _In_ ULONG_PTR Address,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG NumberOfBytesRead);

typedef UCHAR(CALLBACK *pfnGetInstructionLength)(
    _In_ PVOID ptrCode,
    _Out_ PULONG ptrFlags);

typedef PVOID(*PMEMALLOCROUTINE)(
    _In_ SIZE_T NumberOfBytes);

typedef BOOL(*PMEMFREEROUTINE)(
    _In_ PVOID Memory);

typedef PVOID(*pfnGetSystemInfoEx)(
    _In_ ULONG SystemInformationClass,
    _Out_opt_ PULONG ReturnLength,
    _In_ PMEMALLOCROUTINE MemAllocRoutine,
    _In_ PMEMFREEROUTINE MemFreeRoutine);

typedef PVOID(*pfnFindModuleEntryByName)(
    _In_ PVOID pModulesList,
    _In_ LPCSTR ModuleName);

typedef ULONG(*pfnFindModuleEntryByAddress)(
    _In_ PVOID pModulesList,
    _In_ PVOID Address);

typedef BOOL(*pfnFindModuleNameByAddress)(
    _In_ PVOID pModulesList,
    _In_ PVOID Address,
    _Inout_	LPWSTR Buffer,
    _In_ DWORD ccBuffer);

typedef struct _WINOBJEX_PARAM_BLOCK {
    HWND ParentWindow;
    HINSTANCE hInstance;
    RTL_OSVERSIONINFOW osver;
    pfnReadSystemMemoryEx ReadSystemMemoryEx;
    pfnGetInstructionLength GetInstructionLength;
    pfnGetSystemInfoEx GetSystemInfoEx;
    pfnFindModuleEntryByName FindModuleEntryByName;
    pfnFindModuleEntryByAddress FindModuleEntryByAddress;
    pfnFindModuleNameByAddress FindModuleNameByAddress;
} WINOBJEX_PARAM_BLOCK, *PWINOBJEX_PARAM_BLOCK;

typedef NTSTATUS(CALLBACK *pfnStartPlugin)(
    _In_ PWINOBJEX_PARAM_BLOCK ParamBlock
    );

typedef void(CALLBACK *pfnStopPlugin)(
    VOID
    );

typedef struct _WINOBJEX_PLUGIN {
    BOOLEAN NeedAdmin;
    BOOLEAN NeedDriver;
    BOOLEAN SupportWine;
    BOOLEAN Reserved;
    WORD MajorVersion;
    WORD MinorVersion;
    WCHAR Description[64];
    pfnStartPlugin StartPlugin;
    pfnStopPlugin StopPlugin;
} WINOBJEX_PLUGIN, *PWINOBJEX_PLUGIN;

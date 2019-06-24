/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       PLUGINMNGR.H
*
*  VERSION:     1.80
*
*  DATE:        22 June 2019
*
*  Common header file for the plugin manager.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define WINOBJEX_PLUGIN_EXPORT "PluginInit"
#define ID_MENU_PLUGINS       60000
#define WINOBJEX_MAX_PLUGINS  ID_MENU_PLUGINS + 20

typedef BOOL(CALLBACK *pfnReadSystemMemoryEx)(
    _In_ ULONG_PTR Address,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG NumberOfBytesRead);

typedef UCHAR (CALLBACK *pfnGetInstructionLength)(
    _In_ PVOID ptrCode,
    _Out_ PULONG ptrFlags);

typedef struct _WINOBJEX_PARAM_BLOCK {
    HWND ParentWindow;
    RTL_OSVERSIONINFOW osver;
    pfnReadSystemMemoryEx ReadSystemMemoryEx;
    pfnGetInstructionLength GetInstructionLength;
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

typedef struct _WINOBJEX_PLUGIN_INTERNAL {
    LIST_ENTRY ListEntry;
    UINT Id;
    WINOBJEX_PLUGIN Plugin;
} WINOBJEX_PLUGIN_INTERNAL, *PWINOBJEX_PLUGIN_INTERNAL;

typedef BOOLEAN(CALLBACK *pfnPluginInit)(
    _Out_ PWINOBJEX_PLUGIN PluginData
    );

VOID PluginManagerCreate(_In_ HWND MainWindow);
VOID PluginManagerDestroy();
WINOBJEX_PLUGIN_INTERNAL *PluginManagerGetEntryById(
    _In_ UINT Id);

VOID PluginManagerProcessEntry(
    _In_ HWND ParentWindow,
    _In_ UINT Id);

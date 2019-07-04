/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       PLUGMNGR.C
*
*  VERSION:     1.80
*
*  DATE:        02 July 2019
*
*  Plugin manager.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

LIST_ENTRY g_PluginsListHead;
volatile UINT g_PluginCount = ID_MENU_PLUGINS;

/*
* PluginManagerWorkerThread
*
* Purpose:
*
* Worker thread for building list of available plugins.
*
*/
DWORD WINAPI PluginManagerWorkerThread(
    _In_ PVOID Parameter
)
{
    HWND MainWindow = (HWND)Parameter;
    BOOL MenuInitialized = FALSE;

    WCHAR szSearchDirectory[1024];
    WCHAR szPluginPath[1024];
    DWORD dwSize;

    SIZE_T Length;
    HANDLE hFile;
    WIN32_FIND_DATA fdata;

    HMENU hMainMenu = GetMenu(MainWindow), hPluginMenu = NULL;
    MENUITEMINFO MenuItem;

    WINOBJEX_PLUGIN_INTERNAL *PluginEntry;
    pfnPluginInit PluginInit;
    HMODULE hPlugin;

    InitializeListHead(&g_PluginsListHead);

    //
    // Query working directory.
    //
    RtlSecureZeroMemory(szSearchDirectory, sizeof(szSearchDirectory));
    dwSize = GetCurrentDirectory(MAX_PATH, szSearchDirectory);
    if ((dwSize == 0) || (dwSize > MAX_PATH))
        ExitThread((DWORD)-1);

    _strcat(szSearchDirectory, TEXT("\\plugins\\"));

    //
    // Build plugin path.
    //
    RtlSecureZeroMemory(szPluginPath, sizeof(szPluginPath));
    _strcpy(szPluginPath, szSearchDirectory);
    _strcat(szSearchDirectory, TEXT("*.dll"));

    Length = _strlen(szPluginPath);

    //
    // Look for dlls in the plugin subdirectory.
    //
    hFile = FindFirstFileEx(szSearchDirectory, FindExInfoBasic, &fdata, FindExSearchNameMatch, NULL, 0);
    if (hFile != INVALID_HANDLE_VALUE) {
        do {
            if (g_PluginCount >= WINOBJEX_MAX_PLUGINS)
                break;

            szPluginPath[Length] = 0;
            _strcat(szPluginPath, fdata.cFileName);

            //
            // Load library and query plugin export.
            //
            hPlugin = LoadLibraryEx(szPluginPath, NULL, 0);
            if (hPlugin) {
                PluginInit = (pfnPluginInit)GetProcAddress(hPlugin, WINOBJEX_PLUGIN_EXPORT);
                if (PluginInit) {

                    PluginEntry = (WINOBJEX_PLUGIN_INTERNAL*)supHeapAlloc(sizeof(WINOBJEX_PLUGIN_INTERNAL));
                    if (PluginEntry) {

                        //
                        // Initialize plugin and initialize main menu entry if not initialized.
                        //
                        if (PluginInit(&PluginEntry->Plugin)) {
                            InsertHeadList(&g_PluginsListHead, &PluginEntry->ListEntry);
                            PluginEntry->Id = g_PluginCount;
                            InterlockedAdd((PLONG)&g_PluginCount, 1);

                            if (MenuInitialized == FALSE) {

                                hPluginMenu = CreatePopupMenu();
                                if (hPluginMenu) {

                                    RtlSecureZeroMemory(&MenuItem, sizeof(MenuItem));
                                    MenuItem.cbSize = sizeof(MenuItem);
                                    MenuItem.fMask = MIIM_SUBMENU | MIIM_STRING;
                                    MenuItem.dwTypeData = TEXT("Plugins");
                                    MenuItem.hSubMenu = hPluginMenu;

                                    MenuInitialized = InsertMenuItem(hMainMenu,
                                        GetMenuItemCount(hMainMenu) - 1,
                                        TRUE,
                                        &MenuItem);

                                    if (MenuInitialized)
                                        DrawMenuBar(MainWindow);

                                }
                            }

                            //
                            // Add menu entry.
                            //
                            if ((MenuInitialized) && (hPluginMenu)) {

                                RtlSecureZeroMemory(&MenuItem, sizeof(MenuItem));
                                MenuItem.cbSize = sizeof(MenuItem);
                                MenuItem.fMask = MIIM_STRING | MIIM_ID;
                                MenuItem.dwTypeData = PluginEntry->Plugin.Description;

                                //
                                // Associate menu entry id with plugin id for further searches.
                                //
                                MenuItem.wID = PluginEntry->Id;

                                InsertMenuItem(hPluginMenu,
                                    PluginEntry->Id,
                                    FALSE,
                                    &MenuItem);

                            }

                        }
                        else {
                            supHeapFree(PluginEntry);
                        }
                    }
                }
                else {
                    FreeLibrary(hPlugin);
                }
            }
        } while (FindNextFile(hFile, &fdata));
        FindClose(hFile);
    }

    ExitThread(0);
}

/*
* PluginManagerCreate
*
* Purpose:
*
* Create list of available plugins.
*
*/
VOID PluginManagerCreate(
    _In_ HWND MainWindow
)
{
    DWORD ThreadId;

    HANDLE hThread = CreateThread(NULL,
        0,
        (LPTHREAD_START_ROUTINE)PluginManagerWorkerThread,
        (PVOID)MainWindow,
        0,
        &ThreadId);

    if (hThread) CloseHandle(hThread);
}

/*
* PluginManagerDestroy
*
* Purpose:
*
* Destroy list of available plugins.
*
*/
VOID PluginManagerDestroy()
{
    PLIST_ENTRY Head, Next;
    WINOBJEX_PLUGIN_INTERNAL *PluginEntry;

    Head = &g_PluginsListHead;
    Next = Head->Flink;
    while ((Next != NULL) && (Next != Head)) {
        PluginEntry = CONTAINING_RECORD(Next, WINOBJEX_PLUGIN_INTERNAL, ListEntry);
        Next = Next->Flink;

        __try {
            PluginEntry->Plugin.StopPlugin();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            ;
        }
        supHeapFree(PluginEntry);
    }
}

/*
* PluginManagerGetEntryById
*
* Purpose:
*
* Lookup entry in plugins list by plugin id.
*
*/
WINOBJEX_PLUGIN_INTERNAL *PluginManagerGetEntryById(
    _In_ UINT Id
)
{
    PLIST_ENTRY Head, Next;
    WINOBJEX_PLUGIN_INTERNAL *PluginEntry;

    Head = &g_PluginsListHead;
    Next = Head->Flink;
    while ((Next != NULL) && (Next != Head)) {
        PluginEntry = CONTAINING_RECORD(Next, WINOBJEX_PLUGIN_INTERNAL, ListEntry);
        if (PluginEntry->Id == Id) {
            return PluginEntry;
        }
        Next = Next->Flink;
    }

    return NULL;
}

/*
* PluginManagerProcessEntry
*
* Purpose:
*
* Execute plugin code by plugin id.
*
*/
VOID PluginManagerProcessEntry(
    _In_ HWND ParentWindow,
    _In_ UINT Id
)
{
    NTSTATUS Status;
    WINOBJEX_PLUGIN_INTERNAL *PluginEntry;

    WINOBJEX_PARAM_BLOCK ParamBlock;

    __try {
        PluginEntry = PluginManagerGetEntryById(Id);
        if (PluginEntry) {

            //
            // Check plugin requirements.
            //

            if (g_WinObj.IsWine && PluginEntry->Plugin.SupportWine == FALSE) {
                MessageBox(ParentWindow, TEXT("This plugin does not support Wine"), PROGRAM_NAME, MB_ICONINFORMATION);
                return;
            }

            if (PluginEntry->Plugin.NeedAdmin && g_kdctx.IsFullAdmin == FALSE) {
                MessageBox(ParentWindow, TEXT("This plugin require administrator privileges"), PROGRAM_NAME, MB_ICONINFORMATION);
                return;
            }

            if (PluginEntry->Plugin.NeedDriver && g_kdctx.drvOpenLoadStatus != ERROR_SUCCESS) {
                MessageBox(ParentWindow, TEXT("This plugin require driver usage to run"), PROGRAM_NAME, MB_ICONINFORMATION);
                return;
            }
            
            RtlSecureZeroMemory(&ParamBlock, sizeof(ParamBlock));
            ParamBlock.ParentWindow = ParentWindow;
            ParamBlock.hInstance = g_WinObj.hInstance;
            ParamBlock.SystemRangeStart = g_kdctx.SystemRangeStart;

            //
            // Function pointers.
            // 
            // System
            //
            ParamBlock.GetSystemInfoEx = (pfnGetSystemInfoEx)&supGetSystemInfoEx;
            ParamBlock.ReadSystemMemoryEx = (pfnReadSystemMemoryEx)&kdReadSystemMemoryEx;
            ParamBlock.GetInstructionLength = (pfnGetInstructionLength)&kdGetInstructionLength;
            ParamBlock.FindModuleEntryByName = (pfnFindModuleEntryByName)&supFindModuleEntryByName;
            ParamBlock.FindModuleEntryByAddress = (pfnFindModuleEntryByAddress)&supFindModuleEntryByAddress;
            ParamBlock.FindModuleNameByAddress = (pfnFindModuleNameByAddress)&supFindModuleNameByAddress;
            //
            // UI related functions.
            //
            ParamBlock.uiGetMaxCompareTwoFixedStrings = (pfnuiGetMaxCompareTwoFixedStrings)&supGetMaxCompareTwoFixedStrings;
            ParamBlock.uiGetMaxOfTwoU64FromHex = (pfnuiGetMaxOfTwoU64FromHex)&supGetMaxOfTwoU64FromHex;
            ParamBlock.uiCopyTreeListSubItemValue = (pfnuiCopyTreeListSubItemValue)&supCopyTreeListSubItemValue;
            ParamBlock.uiCopyListViewSubItemValue = (pfnuiCopyListViewSubItemValue)&supCopyListViewSubItemValue;

            RtlCopyMemory(&ParamBlock.osver, &g_WinObj.osver, sizeof(RTL_OSVERSIONINFOW));

            Status = PluginEntry->Plugin.StartPlugin(&ParamBlock);

            if (NT_SUCCESS(Status)) {
                DbgPrint("Plugin->StartPlugin success\r\n");
            }
            else {
                DbgPrint("Plugin->StartPluin error %lx\r\n", Status);
            }

        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("Plugin catch exception %lx\r\n", GetExceptionCode());
    }
}

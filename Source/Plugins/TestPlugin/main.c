/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       MAIN.H
*
*  VERSION:     1.00
*
*  DATE:        22 June 2019
*
*  WinObjEx64 example and test plugin.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include <Windows.h>
#include <strsafe.h>

#pragma warning(push)
#pragma warning(disable: 4005)
#include <ntstatus.h>
#pragma warning(pop)
#include "ntos.h"
#include "plugin_def.h"

BOOL g_StopPlugin = FALSE;
HANDLE g_hThread = NULL;
WINOBJEX_PARAM_BLOCK g_ParamBlock;

/*
* PluginThread
*
* Purpose:
*
* Plugin payload thread.
*
*/
DWORD WINAPI PluginThread(
    _In_ PVOID Parameter
)
{
    UNREFERENCED_PARAMETER(Parameter);
   
    while (g_StopPlugin != TRUE) {

        Sleep(500);
        DbgPrint("Plugin is active, ParamBlock->ParentWindow %lx\r\n", g_ParamBlock.ParentWindow);

    }

    ExitThread(0);
}

/*
* StartPlugin
*
* Purpose:
*
* Run actual plugin code in dedicated thread.
*
*/
NTSTATUS CALLBACK StartPlugin(
    _In_ PWINOBJEX_PARAM_BLOCK ParamBlock
    )
{
    DWORD ThreadId;

    DbgPrint("StartPlugin called from thread 0x%lx\r\n", GetCurrentThreadId());
    MessageBox(GetDesktopWindow(), TEXT("This is message from test plugin"), TEXT("TestPlugin"), MB_ICONINFORMATION);

    RtlCopyMemory(&g_ParamBlock, ParamBlock, sizeof(WINOBJEX_PARAM_BLOCK));
    g_StopPlugin = FALSE;
    g_hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PluginThread, (PVOID)NULL, 0, &ThreadId);
    if (g_hThread) {
        return STATUS_SUCCESS;
    }
    else {
        return STATUS_UNSUCCESSFUL;
    }

}

/*
* StopPlugin
*
* Purpose:
*
* Stop plugin execution.
*
*/
void CALLBACK StopPlugin(
    VOID
)
{
    DbgPrint("StopPlugin called from thread 0x%lx\r\n", GetCurrentThreadId());

    if (g_hThread) {
        InterlockedExchange((PLONG)&g_StopPlugin, 1);
        if (WaitForSingleObject(g_hThread, 1000) == WAIT_TIMEOUT) {
            DbgPrint("Wait timeout, terminating plugin thread, g_hTread = %lx\r\n", g_hThread);
            TerminateThread(g_hThread, 0);
        }
        else {
            DbgPrint("Wait success, plugin thread stoped, g_Thread = %lx\r\n", g_hThread);
        }
        CloseHandle(g_hThread);
        g_hThread = NULL;
    }
}

/*
* PluginInit
*
* Purpose:
*
* Initialize plugin information for WinObjEx64.
*
*/
BOOLEAN CALLBACK PluginInit(
    _Out_ PWINOBJEX_PLUGIN PluginData
)
{
    __try {
        //
        // Set plugin name to be displayed in WinObjEx64 UI.
        //
        StringCbCopy(PluginData->Description, 32, TEXT("TestPlugin"));

        //
        // Setup start/stop plugin callbacks.
        //
        PluginData->StartPlugin = (pfnStartPlugin)&StartPlugin;
        PluginData->StopPlugin = (pfnStopPlugin)&StopPlugin;

        //
        // Setup permisions.
        //
        PluginData->NeedAdmin = FALSE;
        PluginData->SupportWine = TRUE;
        PluginData->NeedDriver = FALSE;

        PluginData->Reserved = 0;

        PluginData->MajorVersion = 1;
        PluginData->MinorVersion = 0;

        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("PluginInit exception thrown %lx\r\n", GetExceptionCode());
        return FALSE;
    }
}

/*
* DllMain
*
* Purpose:
*
* Dummy dll entrypoint.
*
*/
BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    lpvReserved
)
{
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}

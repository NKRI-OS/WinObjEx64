/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       MAIN.H
*
*  VERSION:     1.00
*
*  DATE:        23 June 2019
*
*  WinObjEx64 Sonar plugin.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

HINSTANCE g_ThisDLL;
BOOL g_PluginQuit = FALSE;

int  y_splitter_pos = 300, y_capture_pos = 0, y_splitter_max = 0;

SONARCONTEXT g_ctx;

/*
* ListProtocols
*
* Purpose:
*
* Query ndisProtocolList and output it.
*
*/
VOID ListProtocols()
{
    ULONG_PTR ndisProtocolList = QueryProtocolList();

    if (ndisProtocolList == 0) {

        MessageBox(g_ctx.MainWindow, 
            TEXT("Could not query ndisProtocolList variable address, abort."), 
            SONAR_WNDTITLE, 
            MB_ICONERROR);

        return;
    }



}

/*
* OnResize
*
* Purpose:
*
* Main window WM_SIZE handler.
*
*/
VOID OnResize(
    _In_ HWND hwndDlg
)
{
    RECT r, szr;

    RtlSecureZeroMemory(&r, sizeof(RECT));
    RtlSecureZeroMemory(&szr, sizeof(RECT));

    SendMessage(g_ctx.StatusBar, WM_SIZE, 0, 0);

    GetClientRect(hwndDlg, &r);
    GetClientRect(g_ctx.StatusBar, &szr);
    y_splitter_max = r.bottom - Y_SPLITTER_MIN;

    SetWindowPos(g_ctx.TreeList, 0,
        0, 0,
        r.right,
        y_splitter_pos,
        SWP_NOOWNERZORDER);

    SetWindowPos(g_ctx.ListView, 0,
        0, y_splitter_pos + Y_SPLITTER_SIZE,
        r.right,
        r.bottom - y_splitter_pos - Y_SPLITTER_SIZE - szr.bottom,
        SWP_NOOWNERZORDER);
}

/*
* MainWindowProc
*
* Purpose:
*
* Main window procedure.
*
*/
LRESULT CALLBACK MainWindowProc(
    _In_ HWND hwnd,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    INT dy;

    switch (uMsg) {

    case WM_COMMAND:
        if (LOWORD(wParam) == IDCANCEL)
            SendMessage(hwnd, WM_CLOSE, 0, 0);
        break;

    case WM_SIZE:
        OnResize(hwnd);
        break;

    case WM_LBUTTONUP:
        ReleaseCapture();
        break;

    case WM_LBUTTONDOWN:
        SetCapture(hwnd);
        y_capture_pos = (int)(short)HIWORD(lParam);
        break;

    case WM_GETMINMAXINFO:
        if (lParam) {
            ((PMINMAXINFO)lParam)->ptMinTrackSize.x = 400;
            ((PMINMAXINFO)lParam)->ptMinTrackSize.y = 256;
        }
        break;


    case WM_MOUSEMOVE:

        if (wParam & MK_LBUTTON) {
            dy = (int)(short)HIWORD(lParam) - y_capture_pos;
            if (dy != 0) {
                y_capture_pos = (int)(short)HIWORD(lParam);
                y_splitter_pos += dy;
                if (y_splitter_pos < Y_SPLITTER_MIN)
                {
                    y_splitter_pos = Y_SPLITTER_MIN;
                    y_capture_pos = Y_SPLITTER_MIN;
                }

                if (y_splitter_pos > y_splitter_max)
                {
                    y_splitter_pos = y_splitter_max;
                    y_capture_pos = y_splitter_max;
                }
                SendMessage(hwnd, WM_SIZE, 0, 0);
            }
        }
        break;

    case WM_CLOSE:
        PostQuitMessage(0);
        break;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

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
    LONG_PTR    wndStyles;
    HWND        MainWindow;
    WNDCLASSEX  wincls;
    HDITEM      hdritem;
    LVCOLUMN    col;

    INITCOMMONCONTROLSEX  icc;

    BOOL rv;
    MSG msg1;

    WINOBJEX_PARAM_BLOCK *ParamBlock = (WINOBJEX_PARAM_BLOCK *)Parameter;

    do {


        icc.dwSize = sizeof(INITCOMMONCONTROLSEX);
        icc.dwICC = ICC_TREEVIEW_CLASSES | ICC_BAR_CLASSES | ICC_LISTVIEW_CLASSES;
        if (!InitCommonControlsEx(&icc))
            break;

        //
        // Create main window and it components.
        //
        if (g_ctx.ClassAtom == 0) {

            RtlSecureZeroMemory(&wincls, sizeof(wincls));
            wincls.cbSize = sizeof(WNDCLASSEX);
            wincls.lpfnWndProc = &MainWindowProc;
            wincls.hInstance = g_ThisDLL;
            wincls.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
            wincls.lpszClassName = SONAR_WNDCLASS;
            wincls.hCursor = (HCURSOR)LoadImage(NULL, MAKEINTRESOURCE(OCR_SIZENS), IMAGE_CURSOR, 0, 0, LR_SHARED);

            wincls.hIcon = (HICON)LoadImage(
                ParamBlock->hInstance,
                MAKEINTRESOURCE(WINOBJEX64_ICON_MAIN),
                IMAGE_ICON,
                0,
                0,
                LR_SHARED);

            g_ctx.ClassAtom = RegisterClassEx(&wincls);
            if (g_ctx.ClassAtom == 0)
                break;
        }

        //
        // Create main window.
        //
        MainWindow = CreateWindowEx(
            0,
            MAKEINTATOM(g_ctx.ClassAtom),
            SONAR_WNDTITLE,
            WS_VISIBLE | WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            800,
            600,
            NULL,
            NULL,
            g_ThisDLL,
            NULL);

        if (MainWindow == 0)
            break;

        g_ctx.MainWindow = MainWindow;

        //
        // Status Bar window.
        //
        g_ctx.StatusBar = CreateWindowEx(
            0,
            STATUSCLASSNAME,
            NULL,
            WS_VISIBLE | WS_CHILD,
            0,
            0,
            0,
            0,
            MainWindow,
            NULL,
            g_ThisDLL,
            NULL);

        if (g_ctx.StatusBar == 0)
            break;

        //
        // TreeList window.
        //
        g_ctx.TreeList = CreateWindowEx(WS_EX_CLIENTEDGE, WC_TREELIST, NULL,
            WS_VISIBLE | WS_CHILD | TLSTYLE_LINKLINES | TLSTYLE_COLAUTOEXPAND | WS_TABSTOP,
            0, 0, 768, 256, MainWindow, NULL, NULL, NULL);

        if (g_ctx.TreeList == 0)
            break;

        //
        // ListView window.
        //
        g_ctx.ListView = CreateWindowEx(WS_EX_CLIENTEDGE, WC_LISTVIEW, NULL,
            WS_VISIBLE | WS_CHILD | WS_TABSTOP |
            LVS_AUTOARRANGE | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL,
            0, 0, 0, 0, MainWindow, NULL, NULL, NULL);

        if (g_ctx.ListView == 0)
            break;

        //
        // Init listview.
        //
        ListView_SetExtendedListViewStyle(g_ctx.ListView,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_LABELTIP | LVS_EX_DOUBLEBUFFER);
        SetWindowTheme(g_ctx.ListView, TEXT("Explorer"), NULL);

        RtlSecureZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER;
        col.iSubItem++;
        col.pszText = TEXT("Value");
        col.fmt = LVCFMT_LEFT;
        col.cx = 300;
        ListView_InsertColumn(g_ctx.ListView, col.iSubItem, &col);

        col.fmt = LVCFMT_LEFT;
        col.iSubItem++;
        col.pszText = TEXT("Address");
        col.iOrder++;
        col.cx = 130;
        ListView_InsertColumn(g_ctx.ListView, col.iSubItem, &col);

        //
        // Init treelist.
        //
        RtlSecureZeroMemory(&hdritem, sizeof(hdritem));
        hdritem.mask = HDI_FORMAT | HDI_TEXT | HDI_WIDTH;
        hdritem.fmt = HDF_LEFT | HDF_BITMAP_ON_RIGHT | HDF_STRING;
        hdritem.cxy = 300;
        hdritem.pszText = TEXT("Protocol");
        TreeList_InsertHeaderItem(g_ctx.TreeList, 0, &hdritem);

        hdritem.cxy = 130;
        hdritem.pszText = TEXT("Object");
        TreeList_InsertHeaderItem(g_ctx.TreeList, 1, &hdritem);

        wndStyles = GetWindowLongPtr(g_ctx.TreeList, GWL_STYLE);
        SetWindowLongPtr(g_ctx.TreeList, GWL_STYLE, wndStyles | TLSTYLE_LINKLINES);
        SetWindowTheme(g_ctx.TreeList, TEXT("Explorer"), NULL);

        OnResize(MainWindow);

        ListProtocols();
        SetFocus(g_ctx.TreeList);

        do {
            rv = GetMessage(&msg1, NULL, 0, 0);

            if (rv == -1)
                break;

            if (IsDialogMessage(MainWindow, &msg1))
                continue;

            TranslateMessage(&msg1);
            DispatchMessage(&msg1);

        } while ((rv != 0) || (g_PluginQuit));

    } while (FALSE);

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

    RtlSecureZeroMemory(&g_ctx, sizeof(g_ctx));

    g_ctx.PluginHeap = HeapCreate(0, 0, 0);
    if (g_ctx.PluginHeap == NULL)
        return STATUS_HEAP_CORRUPTION;

    HeapSetInformation(g_ctx.PluginHeap, HeapEnableTerminationOnCorruption, NULL, 0);

    RtlCopyMemory(&g_ctx.ParamBlock, ParamBlock, sizeof(WINOBJEX_PARAM_BLOCK));

    g_ctx.WorkerThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PluginThread, (PVOID)&g_ctx.ParamBlock, 0, &ThreadId);
    if (g_ctx.WorkerThread) {
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
    if (g_ctx.WorkerThread) {
        InterlockedExchange((PLONG)&g_PluginQuit, 1);
        if (WaitForSingleObject(g_ctx.WorkerThread, 1000) == WAIT_TIMEOUT) {
            TerminateThread(g_ctx.WorkerThread, 0);
        }
        CloseHandle(g_ctx.WorkerThread);
        g_ctx.WorkerThread = NULL;

        if (g_ctx.ClassAtom)
            UnregisterClass(MAKEINTATOM(g_ctx.ClassAtom), g_ThisDLL);

        HeapDestroy(g_ctx.PluginHeap);
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
        StringCbCopy(PluginData->Description, _countof(PluginData->Description), TEXT("NDIS Protocol List"));

        //
        // Setup start/stop plugin callbacks.
        //
        PluginData->StartPlugin = (pfnStartPlugin)&StartPlugin;
        PluginData->StopPlugin = (pfnStopPlugin)&StopPlugin;

        //
        // Setup permisions.
        //
        PluginData->NeedAdmin = TRUE;
        PluginData->SupportWine = FALSE;
        PluginData->NeedDriver = TRUE;

        PluginData->Reserved = 0;

        PluginData->MajorVersion = 1;
        PluginData->MinorVersion = 0;

        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("PluginInit exception thrown %lx", GetExceptionCode());
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
        g_ThisDLL = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}

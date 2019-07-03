/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       MAIN.H
*
*  VERSION:     1.00
*
*  DATE:        01 July 2019
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

#define SHOW_ERROR(error) MessageBox(g_ctx.MainWindow, (error), SONAR_WNDTITLE, MB_ICONERROR);

/*
* TreeListAddItem
*
* Purpose:
*
* Insert new treelist item.
*
*/
HTREEITEM TreeListAddItem(
    _In_ HWND TreeList,
    _In_opt_ HTREEITEM hParent,
    _In_ UINT mask,
    _In_ UINT state,
    _In_ UINT stateMask,
    _In_opt_ LPWSTR pszText,
    _In_opt_ PVOID subitems
)
{
    TVINSERTSTRUCT  tvitem;
    PTL_SUBITEMS    si = (PTL_SUBITEMS)subitems;

    RtlSecureZeroMemory(&tvitem, sizeof(tvitem));
    tvitem.hParent = hParent;
    tvitem.item.mask = mask;
    tvitem.item.state = state;
    tvitem.item.stateMask = stateMask;
    tvitem.item.pszText = pszText;
    tvitem.hInsertAfter = TVI_LAST;
    return TreeList_InsertTreeItem(TreeList, &tvitem, si);
}

/*
* ListOpenQueue
*
* Purpose:
*
* Output NDIS_OPEN_BLOCK queue to the treelist.
*
*/
VOID ListOpenQueue(
    _In_ HTREEITEM hTreeRootItem,
    _In_ ULONG_PTR OpenQueueAddress
)
{
    ULONG_PTR ProtocolNextOpen = OpenQueueAddress;

    NDIS_OPEN_BLOCK_COMPATIBLE OpenBlock;

    WCHAR szBuffer[100];
    TL_SUBITEMS_FIXED subitems;

    do {
        RtlSecureZeroMemory(&OpenBlock, sizeof(OpenBlock));
        if (!ReadAndConvertOpenBlock(ProtocolNextOpen, &OpenBlock, NULL)) {
            SHOW_ERROR(TEXT("Could not read open block, abort."));
            return;
        }

        RtlSecureZeroMemory(&subitems, sizeof(subitems));
        subitems.UserParam = (PVOID)NdisObjectTypeOpenBlock;
        StringCchPrintf(szBuffer, 32, TEXT("0x%llX"), ProtocolNextOpen);
        subitems.Count = 2;
        subitems.Text[0] = szBuffer;
        subitems.Text[1] = TEXT("");

        TreeListAddItem(
            g_ctx.TreeList,
            hTreeRootItem,
            TVIF_TEXT | TVIF_STATE,
            TVIS_EXPANDED,
            TVIS_EXPANDED,
            TEXT("NDIS_OPEN_BLOCK"),
            &subitems);

        ProtocolNextOpen = (ULONG_PTR)OpenBlock.ProtocolNextOpen;

    } while (ProtocolNextOpen != 0);
}

/*
* AddProtocolToTreeList
*
* Purpose:
*
* Output NDIS_PROTOCOL_BLOCK to the treelist.
*
*/
VOID AddProtocolToTreeList(
    _In_ NDIS_PROTOCOL_BLOCK_COMPATIBLE *ProtoBlock,
    _In_ ULONG_PTR ProtocolAddress
)
{
    PWCHAR lpProtocolName = NULL, lpImageName = NULL;
    UNICODE_STRING *usTemp;

    TL_SUBITEMS_FIXED subitems;
    HTREEITEM hTreeItem = NULL;

    WCHAR szBuffer[32];

    usTemp = &ProtoBlock->Name;

    lpProtocolName = (PWCHAR)DumpUnicodeString((ULONG_PTR)usTemp->Buffer,
        usTemp->Length,
        usTemp->MaximumLength,
        FALSE);

    if (lpProtocolName) {
        RtlSecureZeroMemory(&subitems, sizeof(subitems));
        subitems.UserParam = (PVOID)NdisObjectTypeProtocolBlock;
        StringCchPrintf(szBuffer, 32, TEXT("0x%llX"), ProtocolAddress);
        subitems.Count = 2;
        subitems.Text[0] = szBuffer;

        if (ProtoBlock->ImageName.Length == 0) {
            subitems.Text[1] = TEXT("");
        }
        else {

            usTemp = &ProtoBlock->ImageName;
            lpImageName = (PWCHAR)DumpUnicodeString((ULONG_PTR)usTemp->Buffer,
                usTemp->Length,
                usTemp->MaximumLength,
                FALSE);

            if (lpImageName) {
                subitems.Text[1] = lpImageName;
            }
            else {
                subitems.Text[1] = TEXT("Unknown image");
            }
        }

        hTreeItem = TreeListAddItem(
            g_ctx.TreeList,
            NULL,
            TVIF_TEXT | TVIF_STATE,
            TVIS_EXPANDED,
            TVIS_EXPANDED,
            lpProtocolName,
            &subitems);

        if (lpImageName)
            HeapMemoryFree(lpImageName);


        if ((ULONG_PTR)ProtoBlock->OpenQueue > g_ctx.ParamBlock.SystemRangeStart) {
            ListOpenQueue(hTreeItem, (ULONG_PTR)ProtoBlock->OpenQueue);
        }

        HeapMemoryFree(lpProtocolName);
    }

}

/*
* ListProtocols
*
* Purpose:
*
* Query ndisProtocolList and output it.
*
*/
VOID ListProtocols(
    _In_ BOOL bRefresh
)
{
    ULONG NextProtocolOffset;

    NDIS_PROTOCOL_BLOCK_COMPATIBLE ProtoBlock;

    ULONG_PTR ndisProtocolList = QueryProtocolList();
    ULONG_PTR ProtocolBlockAddress = 0;

    if (bRefresh) {
        ListView_DeleteAllItems(g_ctx.ListView);
        TreeList_ClearTree(g_ctx.TreeList);
    }

    if (ndisProtocolList == 0) {
        SHOW_ERROR(TEXT("Could not query ndisProtocolList variable address, abort."));
        return;
    }

    //
    // Read head and skip it.
    //
    NextProtocolOffset = GetNextProtocolOffset(g_ctx.ParamBlock.osver.dwBuildNumber);
    ProtocolBlockAddress = (ULONG_PTR)ndisProtocolList - NextProtocolOffset;
    RtlSecureZeroMemory(&ProtoBlock, sizeof(ProtoBlock));
    if (!ReadAndConvertProtocolBlock(ProtocolBlockAddress, &ProtoBlock, NULL)) {
        SHOW_ERROR(TEXT("Could not read protocol block, abort."));
        return;
    }

    ProtocolBlockAddress = (ULONG_PTR)ProtoBlock.NextProtocol;

    //
    // Walk protocol list.
    //
    do {
        RtlSecureZeroMemory(&ProtoBlock, sizeof(ProtoBlock));
        if (!ReadAndConvertProtocolBlock(ProtocolBlockAddress, &ProtoBlock, NULL)) {
            SHOW_ERROR(TEXT("Could not read protocol block, abort."));
            return;
        }

        AddProtocolToTreeList(&ProtoBlock, ProtocolBlockAddress);

        ProtocolBlockAddress = (ULONG_PTR)ProtoBlock.NextProtocol;

    } while (ProtocolBlockAddress != 0);
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
* ListViewCompareFunc
*
* Purpose:
*
* ListView comparer function.
*
*/
INT CALLBACK ListViewCompareFunc(
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort
)
{
    INT nResult;

    switch (lParamSort) {

    case 0: //text value

        nResult = g_ctx.ParamBlock.uiGetMaxCompareTwoFixedStrings(g_ctx.ListView,
            lParam1,
            lParam2,
            lParamSort,
            g_ctx.bInverseSort);

        break;

    default: // address

        nResult = g_ctx.ParamBlock.uiGetMaxOfTwoU64FromHex(g_ctx.ListView,
            lParam1,
            lParam2,
            lParamSort,
            g_ctx.bInverseSort);

        break;
    }

    return nResult;
}

/*
* GetNdisObjectInformationFromList
*
* Purpose:
*
* Return NDIS object type and address (converted from text) from treelist item.
*
*/
BOOLEAN GetNdisObjectInformationFromList(
    _In_ HTREEITEM hTreeItem,
    _Out_ NDIS_OBJECT_TYPE *NdisObjectType,
    _Out_ PULONG_PTR ObjectAddress
)
{
    TVITEMEX itemex;
    PWCHAR lpAddressField;
    TL_SUBITEMS_FIXED *subitems = NULL;

    *NdisObjectType = NdisObjectTypeInvalid;
    *ObjectAddress = 0ull;

    SIZE_T Length;

    RtlSecureZeroMemory(&itemex, sizeof(itemex));

    itemex.hItem = hTreeItem;
    if (TreeList_GetTreeItem(g_ctx.TreeList, &itemex, &subitems))
        if (subitems) {
            if (subitems->Text[0]) {
                *NdisObjectType = (NDIS_OBJECT_TYPE)(ULONG_PTR)subitems->UserParam;
                Length = _strlen(subitems->Text[0]);
                if (Length > 2) {
                    lpAddressField = subitems->Text[0];
                    *ObjectAddress = hextou64(&lpAddressField[2]);
                }
                return TRUE;
            }
        }

    return FALSE;
}

/*
* ConvertToUnicode
*
* Purpose:
*
* Convert module name to unicode.
*
* N.B.
* If function succeeded - use RtlFreeUnicodeString to release allocated unicode string.
*
*/
NTSTATUS ConvertToUnicode(
    _In_ LPSTR AnsiString,
    _Out_ PUNICODE_STRING UnicodeString)
{
    ANSI_STRING ansiString;

    RtlInitString(&ansiString, AnsiString);
    return RtlAnsiStringToUnicodeString(UnicodeString, &ansiString, TRUE);
}

/*
* xxxDumpProtocolBlock
*
* Purpose:
*
* Add item to list view.
*
*/
VOID xxxDumpProtocolBlock(
    _In_ LPWSTR lpszItem,
    _In_ LPWSTR lpszValue,
    _In_ LPWSTR lpszAdditionalInfo
)
{
    INT itemIndex;
    LVITEM lvItem;

    RtlSecureZeroMemory(&lvItem, sizeof(lvItem));
    lvItem.mask = LVIF_TEXT | LVIF_IMAGE;
    lvItem.iSubItem = 0;
    lvItem.iItem = MAXINT;
    lvItem.iImage = I_IMAGENONE;
    lvItem.pszText = lpszItem;
    itemIndex = ListView_InsertItem(g_ctx.ListView, &lvItem);

    lvItem.pszText = lpszValue;
    lvItem.iSubItem = 1;
    lvItem.iItem = itemIndex;
    ListView_SetItem(g_ctx.ListView, &lvItem);

    if (lpszAdditionalInfo) {
        lvItem.pszText = lpszAdditionalInfo;
    }
    else {
        lvItem.pszText = TEXT("");
    }
    lvItem.iSubItem = 2;
    lvItem.iItem = itemIndex;
    ListView_SetItem(g_ctx.ListView, &lvItem);
}

/*
* DumpHandlers
*
* Purpose:
*
* Output handlers with associated names.
*
*/
VOID DumpHandlers(
    _In_ PVOID *Handlers,
    _In_ UINT Count,
    _In_ LPWSTR *Names,
    RTL_PROCESS_MODULES *pModulesList
)
{
    BOOL ConvertNeedFree = FALSE;
    ULONG moduleIndex;
    PWSTR pAssociatedModule = NULL;

    WCHAR szBuffer[64];
    UNICODE_STRING usConvert;

    PRTL_PROCESS_MODULE_INFORMATION pModule;

    UINT i;
    for (i = 0; i < Count; i++) {
        if ((ULONG_PTR)Handlers[i] > g_ctx.ParamBlock.SystemRangeStart) {

            StringCchPrintf(szBuffer, 64, TEXT("0x%llX"), Handlers[i]);

            moduleIndex = g_ctx.ParamBlock.FindModuleEntryByAddress(pModulesList, Handlers[i]);
            if ((moduleIndex != 0xFFFFFFFF) && (moduleIndex < pModulesList->NumberOfModules)) {

                pModule = &pModulesList->Modules[moduleIndex];
                if (NT_SUCCESS(ConvertToUnicode((LPSTR)&pModule->FullPathName, &usConvert))) {
                    pAssociatedModule = usConvert.Buffer;
                    ConvertNeedFree = TRUE;
                }
                else {
                    pAssociatedModule = TEXT("Unknown Module");
                }

            }
            else {
                pAssociatedModule = TEXT(""); //could be any garbage pointer.
            }

            xxxDumpProtocolBlock(Names[i], szBuffer, pAssociatedModule);

            if (ConvertNeedFree) {
                RtlFreeUnicodeString(&usConvert);
                ConvertNeedFree = FALSE;
            }
        }

    }
}

/*
* DumpProtocolInfo
*
* Purpose:
*
* Read NDIS_PROTOCOL_BLOCK from memory and output it information.
*
*/
VOID DumpProtocolInfo(
    _In_ ULONG_PTR ProtocolAddress
)
{
    PWCHAR DumpedString;
    NDIS_PROTOCOL_BLOCK_COMPATIBLE ProtoBlock;
    WCHAR szBuffer[64];

    RTL_PROCESS_MODULES *pModulesList = NULL;

    PVOID ProtocolHandlers[_countof(g_lpszProtocolBlockHandlers)];

    ListView_DeleteAllItems(g_ctx.ListView);

    pModulesList = g_ctx.ParamBlock.GetSystemInfoEx(SystemModuleInformation, NULL, HeapMemoryAlloc, HeapMemoryFree);
    if (pModulesList == NULL)
        return;

    DbgPrint("NDIS_PROTOCOL_BLOCK %llX\r\n", ProtocolAddress);

    //
    // Dump protocol block from kernel.
    //
    RtlSecureZeroMemory(&ProtoBlock, sizeof(ProtoBlock));
    if (!ReadAndConvertProtocolBlock(ProtocolAddress, &ProtoBlock, NULL)) {
        HeapMemoryFree(pModulesList);
        return;
    }

    //
    // Output protocol version.
    //
    StringCchPrintf(szBuffer, 64, TEXT("%lu.%lu"), ProtoBlock.MajorNdisVersion, ProtoBlock.MinorNdisVersion);
    xxxDumpProtocolBlock(TEXT("NDIS Version"), szBuffer, NULL);

    //
    // Output driver version if set.
    //
    if (ProtoBlock.MajorDriverVersion) {
        StringCchPrintf(szBuffer, 64, TEXT("%lu.%lu"), ProtoBlock.MajorDriverVersion, ProtoBlock.MinorDriverVersion);
        xxxDumpProtocolBlock(TEXT("Driver Version"), szBuffer, NULL);
    }

    //
    // Read and output BindDeviceName UNICODE_STRING.
    //
    DumpedString = DumpUnicodeString((ULONG_PTR)ProtoBlock.BindDeviceName, 0, 0, TRUE);
    if (DumpedString) {
        StringCchPrintf(szBuffer, 64, TEXT("0x%llX"), (ULONG_PTR)ProtoBlock.BindDeviceName);
        xxxDumpProtocolBlock(TEXT("BindDeviceName"), szBuffer, DumpedString);
        HeapMemoryFree(DumpedString);
    }

    //
    // Read and output RootDeviceName UNICODE_STRING.
    //
    DumpedString = DumpUnicodeString((ULONG_PTR)ProtoBlock.RootDeviceName, 0, 0, TRUE);
    if (DumpedString) {
        StringCchPrintf(szBuffer, 64, TEXT("0x%llX"), (ULONG_PTR)ProtoBlock.RootDeviceName);
        xxxDumpProtocolBlock(TEXT("RootDeviceName"), szBuffer, DumpedString);
        HeapMemoryFree(DumpedString);
    }

    //
    // List Handlers.
    //
    RtlCopyMemory(ProtocolHandlers, &ProtoBlock.BindAdapterHandlerEx, sizeof(ProtocolHandlers));

    DumpHandlers(ProtocolHandlers, _countof(ProtocolHandlers), g_lpszProtocolBlockHandlers, pModulesList);

    HeapMemoryFree(pModulesList);
}

/*
* DumpProtocolInfo
*
* Purpose:
*
* Read NDIS_OPEN_BLOCK from memory and output it information.
*
*/
VOID DumpOpenBlockInfo(
    _In_ ULONG_PTR OpenBlockAddress
)
{
    PWCHAR DumpedString;
    NDIS_OPEN_BLOCK_COMPATIBLE OpenBlock;
    WCHAR szBuffer[64];

    RTL_PROCESS_MODULES *pModulesList = NULL;

    PVOID OpenBlockHandlers[_countof(g_lpszOpenBlockHandlers)];

    ListView_DeleteAllItems(g_ctx.ListView);

    DbgPrint("NDIS_OPEN_BLOCK %llX\r\n", OpenBlockAddress);

    //
    // Allocate loaded modules list.
    //
    pModulesList = g_ctx.ParamBlock.GetSystemInfoEx(SystemModuleInformation, NULL, HeapMemoryAlloc, HeapMemoryFree);
    if (pModulesList == NULL)
        return;

    //
    // Dump open block from kernel.
    //
    RtlSecureZeroMemory(&OpenBlock, sizeof(OpenBlock));
    if (!ReadAndConvertOpenBlock(OpenBlockAddress, &OpenBlock, NULL)) {
        HeapMemoryFree(pModulesList);
        return;
    }

    //
    // Read and output BindDeviceName UNICODE_STRING.
    //
    DumpedString = DumpUnicodeString((ULONG_PTR)OpenBlock.BindDeviceName, 0, 0, TRUE);
    if (DumpedString) {
        StringCchPrintf(szBuffer, 64, TEXT("0x%llX"), (ULONG_PTR)OpenBlock.BindDeviceName);
        xxxDumpProtocolBlock(TEXT("BindDeviceName"), szBuffer, DumpedString);
        HeapMemoryFree(DumpedString);
    }

    //
    // Read and output RootDeviceName UNICODE_STRING.
    //
    DumpedString = DumpUnicodeString((ULONG_PTR)OpenBlock.RootDeviceName, 0, 0, TRUE);
    if (DumpedString) {
        StringCchPrintf(szBuffer, 64, TEXT("0x%llX"), (ULONG_PTR)OpenBlock.RootDeviceName);
        xxxDumpProtocolBlock(TEXT("RootDeviceName"), szBuffer, DumpedString);
        HeapMemoryFree(DumpedString);
    }

    //
    // List Handlers.
    //
    RtlCopyMemory(OpenBlockHandlers, &OpenBlock.NextSendHandler, sizeof(OpenBlockHandlers));

    DumpHandlers(OpenBlockHandlers, _countof(OpenBlockHandlers), g_lpszOpenBlockHandlers, pModulesList);
    HeapMemoryFree(pModulesList);
}

/*
* OnNotify
*
* Purpose:
*
* WM_NOTIFY handler.
*
*/
VOID OnNotify(
    _In_ HWND hwnd,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    INT             i, SortColumn, ImageIndex;
    ULONG_PTR       ObjectAddress;
    HWND            TreeControl;
    LVCOLUMN        col;
    LPNMHDR         hdr = (LPNMHDR)lParam;
    LPNMTREEVIEW    lpnmTreeView;

    NDIS_OBJECT_TYPE NdisObjectType;

    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(wParam);

    TreeControl = (HWND)TreeList_GetTreeControlWindow(g_ctx.TreeList);

    if (hdr->hwndFrom == TreeControl) {

        switch (hdr->code) {

        case TVN_SELCHANGED:

            lpnmTreeView = (LPNMTREEVIEW)lParam;
            if (lpnmTreeView) {
                ObjectAddress = 0ull;
                if (GetNdisObjectInformationFromList(lpnmTreeView->itemNew.hItem,
                    &NdisObjectType,
                    &ObjectAddress))
                {
                    switch (NdisObjectType) {
                    case NdisObjectTypeProtocolBlock:
                        DumpProtocolInfo(ObjectAddress);
                        break;
                    case NdisObjectTypeOpenBlock:
                        DumpOpenBlockInfo(ObjectAddress);
                        break;
                    default:
                        break;

                    }
                }
            }
            break;

        default:
            break;
        }

    }
    else if (hdr->hwndFrom == g_ctx.ListView) {

        switch (hdr->code) {

        case LVN_COLUMNCLICK:
            g_ctx.bInverseSort = !g_ctx.bInverseSort;
            SortColumn = ((NMLISTVIEW *)lParam)->iSubItem;

            ListView_SortItemsEx(g_ctx.ListView, &ListViewCompareFunc, SortColumn);

            ImageIndex = ImageList_GetImageCount(g_ctx.ImageList);
            if (g_ctx.bInverseSort)
                ImageIndex -= 2;
            else
                ImageIndex -= 1;

            RtlSecureZeroMemory(&col, sizeof(col));
            col.mask = LVCF_IMAGE;

            for (i = 0; i < g_ctx.lvColumnCount; i++) {
                if (i == SortColumn) {
                    col.iImage = ImageIndex;
                }
                else {
                    col.iImage = I_IMAGENONE;
                }
                ListView_SetColumn(g_ctx.ListView, i, &col);
            }

            break;

        default:
            break;
        }

    }
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

    case WM_NOTIFY:
        OnNotify(hwnd, wParam, lParam);
        break;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

/*
* FreeGlobalResources
*
* Purpose:
*
* Plugin memory deallocation routine.
*
*/
VOID FreeGlobalResources()
{
    if (g_ctx.ClassAtom) {
        UnregisterClass(MAKEINTATOM(g_ctx.ClassAtom), g_ThisDLL);
        g_ctx.ClassAtom = 0;
    }

    if (g_ctx.ImageList) {
        ImageList_Destroy(g_ctx.ImageList);
        g_ctx.ImageList = 0;
    }

    if (g_ctx.PluginHeap) {
        HeapDestroy(g_ctx.PluginHeap);
        g_ctx.PluginHeap = NULL;
    }
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
    HICON       hIcon;
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

        ListView_SetExtendedListViewStyle(g_ctx.ListView,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_LABELTIP | LVS_EX_DOUBLEBUFFER);

        //
        // Image list for sorting column images.
        //
        g_ctx.ImageList = ImageList_Create(
            16,
            16,
            ILC_COLOR32 | ILC_MASK,
            2,
            2);

        hIcon = (HICON)LoadImage(g_ThisDLL, MAKEINTRESOURCE(IDI_ICON_SORT_UP), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
        if (hIcon) {
            ImageList_ReplaceIcon(g_ctx.ImageList, -1, hIcon);
            DestroyIcon(hIcon);
        }
        hIcon = (HICON)LoadImage(g_ThisDLL, MAKEINTRESOURCE(IDI_ICON_SORT_DOWN), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
        if (hIcon) {
            ImageList_ReplaceIcon(g_ctx.ImageList, -1, hIcon);
            DestroyIcon(hIcon);
        }
        ListView_SetImageList(g_ctx.ListView, g_ctx.ImageList, LVSIL_SMALL);

        //
        // Init listview columns.
        //

        RtlSecureZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
        col.iSubItem++;
        col.pszText = TEXT("Item");
        col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
        col.cx = 300;
        if (g_ctx.ImageList) {
            col.iImage = ImageList_GetImageCount(g_ctx.ImageList) - 1;
        }
        else {
            col.iImage = I_IMAGENONE;
        }
        ListView_InsertColumn(g_ctx.ListView, col.iSubItem, &col);

        col.fmt = LVCFMT_LEFT;
        col.iSubItem++;
        col.pszText = TEXT("Value");
        col.iOrder++;
        col.cx = 300;
        col.iImage = I_IMAGENONE;
        ListView_InsertColumn(g_ctx.ListView, col.iSubItem, &col);

        col.fmt = LVCFMT_LEFT;
        col.iSubItem++;
        col.pszText = TEXT("Additional Info");
        col.iOrder++;
        col.cx = 300;
        col.iImage = I_IMAGENONE;
        ListView_InsertColumn(g_ctx.ListView, col.iSubItem, &col);

        //
        // Remember column count.
        //
        g_ctx.lvColumnCount = 3;

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

        hdritem.cxy = 2000;
        hdritem.pszText = TEXT("Additional Information");
        TreeList_InsertHeaderItem(g_ctx.TreeList, 2, &hdritem);

        wndStyles = GetWindowLongPtr(g_ctx.TreeList, GWL_STYLE);
        SetWindowLongPtr(g_ctx.TreeList, GWL_STYLE, wndStyles | TLSTYLE_LINKLINES);

        SetWindowTheme(g_ctx.TreeList, TEXT("Explorer"), NULL);
        SetWindowTheme(g_ctx.ListView, TEXT("Explorer"), NULL);

        OnResize(MainWindow);

        ListProtocols(FALSE);

        TreeView_SelectItem(g_ctx.TreeList, TreeView_GetRoot(g_ctx.TreeList));
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

    FreeGlobalResources();

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
        return STATUS_MEMORY_NOT_ALLOCATED;

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

        FreeGlobalResources();
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
        // Setup permissions.
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

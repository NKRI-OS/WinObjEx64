/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       QUERY.C
*
*  VERSION:     1.00
*
*  DATE:        30 June 2019
*
*  Query NDIS specific data.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*

Generic search pattern

NdisDeregisterProtocol

7601
48 8B 3D 46 B9 FA FF                                            mov     rdi, cs:ndisProtocolList
9200
48 8B 3D 9A 1F FB FF                                            mov     rdi, cs:ndisProtocolList
9600
48 8B 3D 7A EF F9 FF                                            mov     rdi, cs:ndisProtocolList
10240
48 8B 3D FA 1D F9 FF                                            mov     rdi, cs:ndisProtocolList
10586
48 8B 3D 1A 62 F9 FF                                            mov     rdi, cs:ndisProtocolList
14393
48 8B 3D 4A 44 F9 FF                                            mov     rdi, cs:ndisProtocolList
15063
48 8B 3D 32 F4 F8 FF                                            mov     rdi, cs:ndisProtocolList
16299
48 8B 3D 6A BC F8 FF                                            mov     rdi, cs:ndisProtocolList
17134
48 8B 3D 9A AF F8 FF                                            mov     rdi, cs:ndisProtocolList
17763
48 8B 3D C4 7F F8 FF                                            mov     rdi, cs:ndisProtocolList
18362
48 8B 3D A2 CE FA FF                                            mov     rdi, cs:ndisProtocolList
18912
48 8B 3D BA 92 FA FF                                            mov     rdi, cs:ndisProtocolList

*/

#define HDE_F_ERROR 0x00001000

PROTOCOL_BLOCK_VERSIONS g_ProtocolBlock;
OPEN_BLOCK_VERSIONS g_OpenBlock;

PVOID HeapMemoryAlloc(_In_ SIZE_T Size)
{
    return HeapAlloc(g_ctx.PluginHeap, HEAP_ZERO_MEMORY, Size);
}

BOOL HeapMemoryFree(_In_ PVOID Memory)
{
    return HeapFree(g_ctx.PluginHeap, 0, Memory);
}

/*
* AddressInImage
*
* Purpose:
*
* Test if given address in range of image.
*
*/
BOOL AddressInImage(
    _In_ PVOID Address,
    _In_ PVOID ImageBase,
    _In_ ULONG ImageSize
)
{
    return IN_REGION(Address,
        ImageBase,
        ImageSize);
}

/*
* QueryProtocolList
*
* Purpose:
*
* Return kernel address of ndis!ndisProtocolList global variable.
*
*/
ULONG_PTR QueryProtocolList()
{
    UCHAR       Length;
    LONG        Rel = 0;
    ULONG       Index, DisasmFlags;
    ULONG_PTR   Address = 0, Result = 0;
    HMODULE     hModule = NULL;
    PBYTE       ptrCode;

    PRTL_PROCESS_MODULES            miSpace = NULL;
    PRTL_PROCESS_MODULE_INFORMATION NdisModule;
    WCHAR                           szBuffer[MAX_PATH * 2];

    do {

        //
        // Query NDIS.sys base
        //
        miSpace = g_ctx.ParamBlock.GetSystemInfoEx(SystemModuleInformation, NULL,
            (PMEMALLOCROUTINE)HeapMemoryAlloc,
            (PMEMFREEROUTINE)HeapMemoryFree);

        if (miSpace == NULL)
            break;

        if (miSpace->NumberOfModules == 0)
            break;

        NdisModule = g_ctx.ParamBlock.FindModuleEntryByName((PVOID)miSpace, "ndis.sys");
        if (NdisModule == NULL)
            break;

        //
        // Preload NDIS.sys
        //
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

        StringCchPrintf(szBuffer, sizeof(szBuffer),
            TEXT("%s\\system32\\drivers\\ndis.sys"),
            USER_SHARED_DATA->NtSystemRoot);

        hModule = LoadLibraryEx(szBuffer, NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (hModule == NULL)
            break;

        //
        // Match pattern scan from NdisDeregisterProtocol.
        //
        ptrCode = (PBYTE)GetProcAddress(hModule, "NdisDeregisterProtocol");
        if (ptrCode == NULL)
            break;

        Index = 0;
        do {
            DisasmFlags = 0;
            Length = g_ctx.ParamBlock.GetInstructionLength((void*)(ptrCode + Index), &DisasmFlags);
            if (DisasmFlags &  HDE_F_ERROR)
                break;

            if (Length == 7) {

                if ((ptrCode[Index] == 0x48) &&
                    (ptrCode[Index + 1] == 0x8B) &&
                    (ptrCode[Index + 2] == 0x3D))
                {
                    Rel = *(PLONG)(ptrCode + Index + 3);
                    break;
                }
            }
            Index += Length;

        } while (Index < 256);

        if (Rel == 0)
            break;

        Address = (ULONG_PTR)ptrCode + Index + Length + Rel;
        Address = (ULONG_PTR)NdisModule->ImageBase + Address - (ULONG_PTR)hModule;

        if (!AddressInImage((PVOID)Address, NdisModule->ImageBase, NdisModule->ImageSize))
            break;

        Result = Address;

    } while (FALSE);

    if (hModule) FreeLibrary(hModule);
    if (miSpace) HeapMemoryFree(miSpace);

    DbgPrint("QueryProtocolList %llx\r\n", Result);

    return Result;
}

/*
* DumpObjectWithSpecifiedSize
*
* Purpose:
*
* Return dumped object version aware.
*
* Use HeapFree to free returned buffer.
*
*/
PVOID DumpObjectWithSpecifiedSize(
    _In_ ULONG_PTR ObjectAddress,
    _In_ ULONG ObjectSize,
    _In_ ULONG ObjectVersion,
    _Out_ PULONG ReadSize,
    _Out_ PULONG ReadVersion
)
{
    PVOID ObjectBuffer = NULL;
    ULONG BufferSize = ALIGN_UP_BY(ObjectSize, PAGE_SIZE);

    if (ReadSize) *ReadSize = 0;
    if (ReadVersion) *ReadVersion = 0;

    ObjectBuffer = HeapAlloc(g_ctx.PluginHeap, HEAP_ZERO_MEMORY, BufferSize);
    if (ObjectBuffer == NULL) {
        return NULL;
    }

    if (!g_ctx.ParamBlock.ReadSystemMemoryEx(
        ObjectAddress,
        ObjectBuffer,
        (ULONG)ObjectSize,
        NULL))
    {
        HeapFree(g_ctx.PluginHeap, 0, ObjectBuffer);
        return NULL;
    }

    if (ReadSize)
        *ReadSize = ObjectSize;
    if (ReadVersion)
        *ReadVersion = ObjectVersion;

    return ObjectBuffer;
}

/*
* DumpProtocolBlockVersionAware
*
* Purpose:
*
* Return dumped NDIS_PROTOCOL_BLOCK version aware.
*
* Use HeapFree to free returned buffer.
*
*/
PVOID DumpProtocolBlockVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version)
{
    ULONG ObjectSize = 0;
    ULONG ObjectVersion = 0;

    //assume failure
    if (Size) *Size = 0;
    if (Version) *Version = 0;

    switch (g_ctx.ParamBlock.osver.dwBuildNumber) {
    case 7601:
        ObjectSize = sizeof(NDIS_PROTOCOL_BLOCK_7601);
        ObjectVersion = 1;
        break;

    case 9200:
        ObjectSize = sizeof(NDIS_PROTOCOL_BLOCK_9200);
        ObjectVersion = 2;
        break;

    case 9600:
    case 10240:
    case 10586:
    case 14393:
    case 15063:
    case 16299:
    case 17134:
        ObjectSize = sizeof(NDIS_PROTOCOL_BLOCK_9600_17134);
        ObjectVersion = 3;
        break;
    case 17763:
        ObjectSize = sizeof(NDIS_PROTOCOL_BLOCK_17763);
        ObjectVersion = 4;
        break;
    case 18362:
        ObjectSize = sizeof(NDIS_PROTOCOL_BLOCK_18362);
        ObjectVersion = 5;
        break;
    default:
        break;

    }

    return DumpObjectWithSpecifiedSize(ObjectAddress,
        ObjectSize,
        ObjectVersion,
        Size,
        Version);
}

/*
* DumpOpenBlockVersionAware
*
* Purpose:
*
* Return dumped NDIS_OPEN_BLOCK version aware.
*
* Use HeapFree to free returned buffer.
*
*/
PVOID DumpOpenBlockVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version)
{
    ULONG ObjectSize = 0;
    ULONG ObjectVersion = 0;

    //assume failure
    if (Size) *Size = 0;
    if (Version) *Version = 0;

    switch (g_ctx.ParamBlock.osver.dwBuildNumber) {
    case 7601:
        ObjectSize = sizeof(NDIS_OPEN_BLOCK_7601);
        ObjectVersion = 1;
        break;
    case 9200:
        ObjectSize = sizeof(NDIS_OPEN_BLOCK_9200);
        ObjectVersion = 2;
        break;
    case 9600:
    case 10240:
    case 10586:
        ObjectSize = sizeof(NDIS_OPEN_BLOCK_9600_10586);
        ObjectVersion = 3;
    case 14393:
    case 15063:
    case 16299:
    case 17134:
        ObjectSize = sizeof(NDIS_OPEN_BLOCK_14393_17134);
        ObjectVersion = 4;
        break;
    case 17763:
    case 18362:
        ObjectSize = sizeof(NDIS_OPEN_BLOCK_17763_18362);
        ObjectVersion = 5;
        break;

    default:
        break;
    }

    return DumpObjectWithSpecifiedSize(ObjectAddress,
        ObjectSize,
        ObjectVersion,
        Size,
        Version);
}

/*
* DumpUnicodeString
*
* Purpose:
*
* Read UNICODE_STRING buffer from kernel.
*
* Use HeapFree to free returned buffer.
*
*/
PVOID DumpUnicodeString(
    _In_ ULONG_PTR Address,
    _In_ WORD Length,
    _In_ WORD MaximumLength,
    _In_ BOOLEAN IsPtr)
{
    ULONG readBytes;
    PVOID DumpedString = NULL;
    UNICODE_STRING tempString;

    if (Address <= g_ctx.ParamBlock.SystemRangeStart)
        return NULL;

    RtlSecureZeroMemory(&tempString, sizeof(tempString));

    if (IsPtr) { //given address is pointer to the string

        if (g_ctx.ParamBlock.ReadSystemMemoryEx(Address,
            &tempString,
            sizeof(UNICODE_STRING),
            &readBytes))
        {
            if (readBytes != sizeof(UNICODE_STRING)) {
                return NULL;
            }
        }

    }
    else {
        tempString.Buffer = (PWCHAR)Address;
        tempString.Length = Length;
        tempString.MaximumLength = MaximumLength;
    }

    if (tempString.Length == 0 && tempString.MaximumLength == 0)
        return NULL;

    DumpedString = (PVOID)HeapAlloc(g_ctx.PluginHeap, HEAP_ZERO_MEMORY, tempString.Length + MAX_PATH);
    if (DumpedString) {
        if (g_ctx.ParamBlock.ReadSystemMemoryEx((ULONG_PTR)tempString.Buffer,
            DumpedString,
            tempString.Length,
            &readBytes))
        {
            if (readBytes != tempString.Length) {
                HeapFree(g_ctx.PluginHeap, 0, DumpedString);
                return NULL;
            }
        }

    }

    return DumpedString;
}

/*
* GetNextProtocol
*
* Purpose:
*
* Query next NDIS_PROTOCOL_BLOCK address.
*
*/
ULONG_PTR GetNextProtocol(
    _In_ ULONG ObjectVersion
)
{
    ULONG_PTR NextProtocol = 0;

    switch (ObjectVersion) {

    case 1:
        NextProtocol = (ULONG_PTR)g_ProtocolBlock.u1.Versions.v1->NextProtocol;
        break;
    case 2:
        NextProtocol = (ULONG_PTR)g_ProtocolBlock.u1.Versions.v2->NextProtocol;
        break;
    case 3:
        NextProtocol = (ULONG_PTR)g_ProtocolBlock.u1.Versions.v3->NextProtocol;
        break;
    case 4:
        NextProtocol = (ULONG_PTR)g_ProtocolBlock.u1.Versions.v4->NextProtocol;
        break;
    case 5:
        NextProtocol = (ULONG_PTR)g_ProtocolBlock.u1.Versions.v5->NextProtocol;
        break;

    default:
        NextProtocol = 0;
        break;
    }

    return NextProtocol;
}

/*
* GetNextProtocolOffset
*
* Purpose:
*
* Return offset of NextProtocol structure field (structure version specific).
*
*/
ULONG GetNextProtocolOffset(
    _In_ ULONG WindowsVersion
)
{
    ULONG Offset = 0;

    switch (WindowsVersion) {

    case 7601:
        Offset = FIELD_OFFSET(NDIS_PROTOCOL_BLOCK_7601, NextProtocol);
        break;
    case 9200:
        Offset = FIELD_OFFSET(NDIS_PROTOCOL_BLOCK_9200, NextProtocol);
        break;
    case 9600:
    case 10240:
    case 10586:
    case 14393:
    case 15063:
    case 16299:
    case 17134:
        Offset = FIELD_OFFSET(NDIS_PROTOCOL_BLOCK_9600_17134, NextProtocol);
        break;
    case 17763:
        Offset = FIELD_OFFSET(NDIS_PROTOCOL_BLOCK_17763, NextProtocol);
        break;
    case 18362:
        Offset = FIELD_OFFSET(NDIS_PROTOCOL_BLOCK_18362, NextProtocol);
        break;

    default:
        Offset = 0;
        break;
    }

    return Offset;
}

/*
* CreateCompatibleProtocolBlock
*
* Purpose:
*
* Build compatible protocol block for easy work with it.
*
*/
BOOL CreateCompatibleProtocolBlock(
    _In_ ULONG ObjectVersion,
    _Out_ NDIS_PROTOCOL_BLOCK_COMPATIBLE *ProtoBlock)
{
    switch (ObjectVersion) {

    case 1:
        RtlCopyMemory(&ProtoBlock->Name, &g_ProtocolBlock.u1.Versions.v1->Name, sizeof(UNICODE_STRING));
        RtlCopyMemory(&ProtoBlock->ImageName, &g_ProtocolBlock.u1.Versions.v1->ImageName, sizeof(UNICODE_STRING));
        ProtoBlock->OpenQueue = g_ProtocolBlock.u1.Versions.v1->OpenQueue;
        ProtoBlock->NextProtocol = g_ProtocolBlock.u1.Versions.v1->NextProtocol;

        ProtoBlock->MajorDriverVersion = g_ProtocolBlock.u1.Versions.v1->MajorDriverVersion;
        ProtoBlock->MajorNdisVersion = g_ProtocolBlock.u1.Versions.v1->MajorNdisVersion;
        ProtoBlock->MinorDriverVersion = g_ProtocolBlock.u1.Versions.v1->MinorDriverVersion;
        ProtoBlock->MinorNdisVersion = g_ProtocolBlock.u1.Versions.v1->MinorNdisVersion;

        ProtoBlock->AllocateSharedMemoryHandler = g_ProtocolBlock.u1.Versions.v1->AllocateSharedMemoryHandler;
        ProtoBlock->BindAdapterHandler = g_ProtocolBlock.u1.Versions.v1->BindAdapterHandler;
        ProtoBlock->BindAdapterHandlerEx = g_ProtocolBlock.u1.Versions.v1->BindAdapterHandlerEx;
        ProtoBlock->BindDeviceName = g_ProtocolBlock.u1.Versions.v1->BindDeviceName;
        ProtoBlock->CloseAdapterCompleteHandler = g_ProtocolBlock.u1.Versions.v1->CloseAdapterCompleteHandler;
        ProtoBlock->CloseAdapterCompleteHandlerEx = g_ProtocolBlock.u1.Versions.v1->CloseAdapterCompleteHandlerEx;
        ProtoBlock->CoAfRegisterNotifyHandler = g_ProtocolBlock.u1.Versions.v1->CoAfRegisterNotifyHandler;
        ProtoBlock->CoReceiveNetBufferListsHandler = g_ProtocolBlock.u1.Versions.v1->CoReceiveNetBufferListsHandler;
        ProtoBlock->CoReceivePacketHandler = g_ProtocolBlock.u1.Versions.v1->CoReceivePacketHandler;
        ProtoBlock->CoSendCompleteHandler = g_ProtocolBlock.u1.Versions.v1->CoSendCompleteHandler;
        ProtoBlock->CoSendNetBufferListsCompleteHandler = g_ProtocolBlock.u1.Versions.v1->CoSendNetBufferListsCompleteHandler;
        ProtoBlock->CoStatusHandler = g_ProtocolBlock.u1.Versions.v1->u3.CoStatusHandler;
        ProtoBlock->DirectOidRequestCompleteHandler = g_ProtocolBlock.u1.Versions.v1->DirectOidRequestCompleteHandler;
        ProtoBlock->FreeSharedMemoryHandler = g_ProtocolBlock.u1.Versions.v1->FreeSharedMemoryHandler;
        ProtoBlock->IndicateOffloadEventHandler = g_ProtocolBlock.u1.Versions.v1->IndicateOffloadEventHandler;
        ProtoBlock->InitiateOffloadCompleteHandler = g_ProtocolBlock.u1.Versions.v1->InitiateOffloadCompleteHandler;
        ProtoBlock->InvalidateOffloadCompleteHandler = g_ProtocolBlock.u1.Versions.v1->InvalidateOffloadCompleteHandler;
        ProtoBlock->OidRequestCompleteHandler = g_ProtocolBlock.u1.Versions.v1->OidRequestCompleteHandler;
        ProtoBlock->OpenAdapterCompleteHandler = g_ProtocolBlock.u1.Versions.v1->OpenAdapterCompleteHandler;
        ProtoBlock->OpenAdapterCompleteHandlerEx = g_ProtocolBlock.u1.Versions.v1->OpenAdapterCompleteHandlerEx;
        ProtoBlock->PnPEventHandler = g_ProtocolBlock.u1.Versions.v1->u1.PnPEventHandler;
        ProtoBlock->QueryOffloadCompleteHandler = g_ProtocolBlock.u1.Versions.v1->QueryOffloadCompleteHandler;
        ProtoBlock->ReceiveCompleteHandler = g_ProtocolBlock.u1.Versions.v1->ReceiveCompleteHandler;
        ProtoBlock->ReceiveHandler = g_ProtocolBlock.u1.Versions.v1->u6.ReceiveHandler;
        ProtoBlock->ReceiveNetBufferListsHandler = g_ProtocolBlock.u1.Versions.v1->ReceiveNetBufferListsHandler;
        ProtoBlock->ReceivePacketHandler = g_ProtocolBlock.u1.Versions.v1->ReceivePacketHandler;
        ProtoBlock->RequestCompleteHandler = g_ProtocolBlock.u1.Versions.v1->RequestCompleteHandler;
        ProtoBlock->ResetCompleteHandler = g_ProtocolBlock.u1.Versions.v1->ResetCompleteHandler;
        ProtoBlock->RootDeviceName = g_ProtocolBlock.u1.Versions.v1->RootDeviceName;
        ProtoBlock->SendCompleteHandler = g_ProtocolBlock.u1.Versions.v1->u4.SendCompleteHandler;
        ProtoBlock->SendNetBufferListsCompleteHandler = g_ProtocolBlock.u1.Versions.v1->SendNetBufferListsCompleteHandler;
        ProtoBlock->StatusCompleteHandler = g_ProtocolBlock.u1.Versions.v1->StatusCompleteHandler;
        ProtoBlock->StatusHandler = g_ProtocolBlock.u1.Versions.v1->u2.StatusHandler;
        ProtoBlock->TcpOffloadDisconnectCompleteHandler = g_ProtocolBlock.u1.Versions.v1->TcpOffloadDisconnectCompleteHandler;
        ProtoBlock->TcpOffloadEventHandler = g_ProtocolBlock.u1.Versions.v1->TcpOffloadEventHandler;
        ProtoBlock->TcpOffloadForwardCompleteHandler = g_ProtocolBlock.u1.Versions.v1->TcpOffloadForwardCompleteHandler;
        ProtoBlock->TcpOffloadReceiveCompleteHandler = g_ProtocolBlock.u1.Versions.v1->TcpOffloadReceiveCompleteHandler;
        ProtoBlock->TcpOffloadReceiveIndicateHandler = g_ProtocolBlock.u1.Versions.v1->TcpOffloadReceiveIndicateHandler;
        ProtoBlock->TcpOffloadSendCompleteHandler = g_ProtocolBlock.u1.Versions.v1->TcpOffloadSendCompleteHandler;
        ProtoBlock->TerminateOffloadCompleteHandler = g_ProtocolBlock.u1.Versions.v1->TerminateOffloadCompleteHandler;
        ProtoBlock->TransferDataCompleteHandler = g_ProtocolBlock.u1.Versions.v1->u5.TransferDataCompleteHandler;
        ProtoBlock->UnbindAdapterHandler = g_ProtocolBlock.u1.Versions.v1->UnbindAdapterHandler;
        ProtoBlock->UnbindAdapterHandlerEx = g_ProtocolBlock.u1.Versions.v1->UnbindAdapterHandlerEx;
        ProtoBlock->UninstallHandler = g_ProtocolBlock.u1.Versions.v1->UninstallHandler;
        ProtoBlock->UnloadHandler = g_ProtocolBlock.u1.Versions.v1->UnloadHandler;
        ProtoBlock->UpdateOffloadCompleteHandler = g_ProtocolBlock.u1.Versions.v1->UpdateOffloadCompleteHandler;
        break;

    case 2:
        RtlCopyMemory(&ProtoBlock->Name, &g_ProtocolBlock.u1.Versions.v2->Name, sizeof(UNICODE_STRING));
        RtlCopyMemory(&ProtoBlock->ImageName, &g_ProtocolBlock.u1.Versions.v2->ImageName, sizeof(UNICODE_STRING));
        ProtoBlock->OpenQueue = g_ProtocolBlock.u1.Versions.v2->OpenQueue;
        ProtoBlock->NextProtocol = g_ProtocolBlock.u1.Versions.v2->NextProtocol;

        ProtoBlock->MajorDriverVersion = g_ProtocolBlock.u1.Versions.v2->MajorDriverVersion;
        ProtoBlock->MajorNdisVersion = g_ProtocolBlock.u1.Versions.v2->MajorNdisVersion;
        ProtoBlock->MinorDriverVersion = g_ProtocolBlock.u1.Versions.v2->MinorDriverVersion;
        ProtoBlock->MinorNdisVersion = g_ProtocolBlock.u1.Versions.v2->MinorNdisVersion;

        ProtoBlock->AllocateSharedMemoryHandler = g_ProtocolBlock.u1.Versions.v2->AllocateSharedMemoryHandler;
        ProtoBlock->BindAdapterHandler = g_ProtocolBlock.u1.Versions.v2->BindAdapterHandler;
        ProtoBlock->BindAdapterHandlerEx = g_ProtocolBlock.u1.Versions.v2->BindAdapterHandlerEx;
        ProtoBlock->BindDeviceName = g_ProtocolBlock.u1.Versions.v2->BindDeviceName;
        ProtoBlock->CloseAdapterCompleteHandler = g_ProtocolBlock.u1.Versions.v2->CloseAdapterCompleteHandler;
        ProtoBlock->CloseAdapterCompleteHandlerEx = g_ProtocolBlock.u1.Versions.v2->CloseAdapterCompleteHandlerEx;
        ProtoBlock->CoAfRegisterNotifyHandler = g_ProtocolBlock.u1.Versions.v2->CoAfRegisterNotifyHandler;
        ProtoBlock->CoReceiveNetBufferListsHandler = g_ProtocolBlock.u1.Versions.v2->CoReceiveNetBufferListsHandler;
        ProtoBlock->CoReceivePacketHandler = g_ProtocolBlock.u1.Versions.v2->CoReceivePacketHandler;
        ProtoBlock->CoSendCompleteHandler = g_ProtocolBlock.u1.Versions.v2->CoSendCompleteHandler;
        ProtoBlock->CoSendNetBufferListsCompleteHandler = g_ProtocolBlock.u1.Versions.v2->CoSendNetBufferListsCompleteHandler;
        ProtoBlock->CoStatusHandler = g_ProtocolBlock.u1.Versions.v2->u3.CoStatusHandler;
        ProtoBlock->DirectOidRequestCompleteHandler = g_ProtocolBlock.u1.Versions.v2->DirectOidRequestCompleteHandler;
        ProtoBlock->FreeSharedMemoryHandler = g_ProtocolBlock.u1.Versions.v2->FreeSharedMemoryHandler;
        ProtoBlock->IndicateOffloadEventHandler = g_ProtocolBlock.u1.Versions.v2->IndicateOffloadEventHandler;
        ProtoBlock->InitiateOffloadCompleteHandler = g_ProtocolBlock.u1.Versions.v2->InitiateOffloadCompleteHandler;
        ProtoBlock->InvalidateOffloadCompleteHandler = g_ProtocolBlock.u1.Versions.v2->InvalidateOffloadCompleteHandler;
        ProtoBlock->OidRequestCompleteHandler = g_ProtocolBlock.u1.Versions.v2->OidRequestCompleteHandler;
        ProtoBlock->OpenAdapterCompleteHandler = g_ProtocolBlock.u1.Versions.v2->OpenAdapterCompleteHandler;
        ProtoBlock->OpenAdapterCompleteHandlerEx = g_ProtocolBlock.u1.Versions.v2->OpenAdapterCompleteHandlerEx;
        ProtoBlock->PnPEventHandler = g_ProtocolBlock.u1.Versions.v2->u1.PnPEventHandler;
        ProtoBlock->QueryOffloadCompleteHandler = g_ProtocolBlock.u1.Versions.v2->QueryOffloadCompleteHandler;
        ProtoBlock->ReceiveCompleteHandler = g_ProtocolBlock.u1.Versions.v2->ReceiveCompleteHandler;
        ProtoBlock->ReceiveHandler = g_ProtocolBlock.u1.Versions.v2->u6.ReceiveHandler;
        ProtoBlock->ReceiveNetBufferListsHandler = g_ProtocolBlock.u1.Versions.v2->ReceiveNetBufferListsHandler;
        ProtoBlock->ReceivePacketHandler = g_ProtocolBlock.u1.Versions.v2->ReceivePacketHandler;
        ProtoBlock->RequestCompleteHandler = g_ProtocolBlock.u1.Versions.v2->RequestCompleteHandler;
        ProtoBlock->ResetCompleteHandler = g_ProtocolBlock.u1.Versions.v2->ResetCompleteHandler;
        ProtoBlock->RootDeviceName = g_ProtocolBlock.u1.Versions.v2->RootDeviceName;
        ProtoBlock->SendCompleteHandler = g_ProtocolBlock.u1.Versions.v2->u4.SendCompleteHandler;
        ProtoBlock->SendNetBufferListsCompleteHandler = g_ProtocolBlock.u1.Versions.v2->SendNetBufferListsCompleteHandler;
        ProtoBlock->StatusCompleteHandler = g_ProtocolBlock.u1.Versions.v2->StatusCompleteHandler;
        ProtoBlock->StatusHandler = g_ProtocolBlock.u1.Versions.v2->u2.StatusHandler;
        ProtoBlock->TcpOffloadDisconnectCompleteHandler = g_ProtocolBlock.u1.Versions.v2->TcpOffloadDisconnectCompleteHandler;
        ProtoBlock->TcpOffloadEventHandler = g_ProtocolBlock.u1.Versions.v2->TcpOffloadEventHandler;
        ProtoBlock->TcpOffloadForwardCompleteHandler = g_ProtocolBlock.u1.Versions.v2->TcpOffloadForwardCompleteHandler;
        ProtoBlock->TcpOffloadReceiveCompleteHandler = g_ProtocolBlock.u1.Versions.v2->TcpOffloadReceiveCompleteHandler;
        ProtoBlock->TcpOffloadReceiveIndicateHandler = g_ProtocolBlock.u1.Versions.v2->TcpOffloadReceiveIndicateHandler;
        ProtoBlock->TcpOffloadSendCompleteHandler = g_ProtocolBlock.u1.Versions.v2->TcpOffloadSendCompleteHandler;
        ProtoBlock->TerminateOffloadCompleteHandler = g_ProtocolBlock.u1.Versions.v2->TerminateOffloadCompleteHandler;
        ProtoBlock->TransferDataCompleteHandler = g_ProtocolBlock.u1.Versions.v2->u5.TransferDataCompleteHandler;
        ProtoBlock->UnbindAdapterHandler = g_ProtocolBlock.u1.Versions.v2->UnbindAdapterHandler;
        ProtoBlock->UnbindAdapterHandlerEx = g_ProtocolBlock.u1.Versions.v2->UnbindAdapterHandlerEx;
        ProtoBlock->UninstallHandler = g_ProtocolBlock.u1.Versions.v2->UninstallHandler;
        ProtoBlock->UnloadHandler = g_ProtocolBlock.u1.Versions.v2->UnloadHandler;
        ProtoBlock->UpdateOffloadCompleteHandler = g_ProtocolBlock.u1.Versions.v2->UpdateOffloadCompleteHandler;
        break;

    case 3:
        RtlCopyMemory(&ProtoBlock->Name, &g_ProtocolBlock.u1.Versions.v3->Name, sizeof(UNICODE_STRING));
        RtlCopyMemory(&ProtoBlock->ImageName, &g_ProtocolBlock.u1.Versions.v3->ImageName, sizeof(UNICODE_STRING));
        ProtoBlock->OpenQueue = g_ProtocolBlock.u1.Versions.v3->OpenQueue;
        ProtoBlock->NextProtocol = g_ProtocolBlock.u1.Versions.v3->NextProtocol;

        ProtoBlock->MajorDriverVersion = g_ProtocolBlock.u1.Versions.v3->MajorDriverVersion;
        ProtoBlock->MajorNdisVersion = g_ProtocolBlock.u1.Versions.v3->MajorNdisVersion;
        ProtoBlock->MinorDriverVersion = g_ProtocolBlock.u1.Versions.v3->MinorDriverVersion;
        ProtoBlock->MinorNdisVersion = g_ProtocolBlock.u1.Versions.v3->MinorNdisVersion;

        ProtoBlock->AllocateSharedMemoryHandler = g_ProtocolBlock.u1.Versions.v3->AllocateSharedMemoryHandler;
        ProtoBlock->BindAdapterHandler = g_ProtocolBlock.u1.Versions.v3->BindAdapterHandler;
        ProtoBlock->BindAdapterHandlerEx = g_ProtocolBlock.u1.Versions.v3->BindAdapterHandlerEx;
        ProtoBlock->BindDeviceName = g_ProtocolBlock.u1.Versions.v3->BindDeviceName;
        ProtoBlock->CloseAdapterCompleteHandler = g_ProtocolBlock.u1.Versions.v3->CloseAdapterCompleteHandler;
        ProtoBlock->CloseAdapterCompleteHandlerEx = g_ProtocolBlock.u1.Versions.v3->CloseAdapterCompleteHandlerEx;
        ProtoBlock->CoAfRegisterNotifyHandler = g_ProtocolBlock.u1.Versions.v3->CoAfRegisterNotifyHandler;
        ProtoBlock->CoReceiveNetBufferListsHandler = g_ProtocolBlock.u1.Versions.v3->CoReceiveNetBufferListsHandler;
        ProtoBlock->CoReceivePacketHandler = g_ProtocolBlock.u1.Versions.v3->CoReceivePacketHandler;
        ProtoBlock->CoSendCompleteHandler = g_ProtocolBlock.u1.Versions.v3->CoSendCompleteHandler;
        ProtoBlock->CoSendNetBufferListsCompleteHandler = g_ProtocolBlock.u1.Versions.v3->CoSendNetBufferListsCompleteHandler;
        ProtoBlock->CoStatusHandler = g_ProtocolBlock.u1.Versions.v3->u3.CoStatusHandler;
        ProtoBlock->DirectOidRequestCompleteHandler = g_ProtocolBlock.u1.Versions.v3->DirectOidRequestCompleteHandler;
        ProtoBlock->FreeSharedMemoryHandler = g_ProtocolBlock.u1.Versions.v3->FreeSharedMemoryHandler;
        ProtoBlock->IndicateOffloadEventHandler = g_ProtocolBlock.u1.Versions.v3->IndicateOffloadEventHandler;
        ProtoBlock->InitiateOffloadCompleteHandler = g_ProtocolBlock.u1.Versions.v3->InitiateOffloadCompleteHandler;
        ProtoBlock->InvalidateOffloadCompleteHandler = g_ProtocolBlock.u1.Versions.v3->InvalidateOffloadCompleteHandler;
        ProtoBlock->OidRequestCompleteHandler = g_ProtocolBlock.u1.Versions.v3->OidRequestCompleteHandler;
        ProtoBlock->OpenAdapterCompleteHandler = g_ProtocolBlock.u1.Versions.v3->OpenAdapterCompleteHandler;
        ProtoBlock->OpenAdapterCompleteHandlerEx = g_ProtocolBlock.u1.Versions.v3->OpenAdapterCompleteHandlerEx;
        ProtoBlock->PnPEventHandler = g_ProtocolBlock.u1.Versions.v3->u1.PnPEventHandler;
        ProtoBlock->QueryOffloadCompleteHandler = g_ProtocolBlock.u1.Versions.v3->QueryOffloadCompleteHandler;
        ProtoBlock->ReceiveCompleteHandler = g_ProtocolBlock.u1.Versions.v3->ReceiveCompleteHandler;
        ProtoBlock->ReceiveHandler = g_ProtocolBlock.u1.Versions.v3->u6.ReceiveHandler;
        ProtoBlock->ReceiveNetBufferListsHandler = g_ProtocolBlock.u1.Versions.v3->ReceiveNetBufferListsHandler;
        ProtoBlock->ReceivePacketHandler = g_ProtocolBlock.u1.Versions.v3->ReceivePacketHandler;
        ProtoBlock->RequestCompleteHandler = g_ProtocolBlock.u1.Versions.v3->RequestCompleteHandler;
        ProtoBlock->ResetCompleteHandler = g_ProtocolBlock.u1.Versions.v3->ResetCompleteHandler;
        ProtoBlock->RootDeviceName = g_ProtocolBlock.u1.Versions.v3->RootDeviceName;
        ProtoBlock->SendCompleteHandler = g_ProtocolBlock.u1.Versions.v3->u4.SendCompleteHandler;
        ProtoBlock->SendNetBufferListsCompleteHandler = g_ProtocolBlock.u1.Versions.v3->SendNetBufferListsCompleteHandler;
        ProtoBlock->StatusCompleteHandler = g_ProtocolBlock.u1.Versions.v3->StatusCompleteHandler;
        ProtoBlock->StatusHandler = g_ProtocolBlock.u1.Versions.v3->u2.StatusHandler;
        ProtoBlock->TcpOffloadDisconnectCompleteHandler = g_ProtocolBlock.u1.Versions.v3->TcpOffloadDisconnectCompleteHandler;
        ProtoBlock->TcpOffloadEventHandler = g_ProtocolBlock.u1.Versions.v3->TcpOffloadEventHandler;
        ProtoBlock->TcpOffloadForwardCompleteHandler = g_ProtocolBlock.u1.Versions.v3->TcpOffloadForwardCompleteHandler;
        ProtoBlock->TcpOffloadReceiveCompleteHandler = g_ProtocolBlock.u1.Versions.v3->TcpOffloadReceiveCompleteHandler;
        ProtoBlock->TcpOffloadReceiveIndicateHandler = g_ProtocolBlock.u1.Versions.v3->TcpOffloadReceiveIndicateHandler;
        ProtoBlock->TcpOffloadSendCompleteHandler = g_ProtocolBlock.u1.Versions.v3->TcpOffloadSendCompleteHandler;
        ProtoBlock->TerminateOffloadCompleteHandler = g_ProtocolBlock.u1.Versions.v3->TerminateOffloadCompleteHandler;
        ProtoBlock->TransferDataCompleteHandler = g_ProtocolBlock.u1.Versions.v3->u5.TransferDataCompleteHandler;
        ProtoBlock->UnbindAdapterHandler = g_ProtocolBlock.u1.Versions.v3->UnbindAdapterHandler;
        ProtoBlock->UnbindAdapterHandlerEx = g_ProtocolBlock.u1.Versions.v3->UnbindAdapterHandlerEx;
        ProtoBlock->UninstallHandler = g_ProtocolBlock.u1.Versions.v3->UninstallHandler;
        ProtoBlock->UnloadHandler = g_ProtocolBlock.u1.Versions.v3->UnloadHandler;
        ProtoBlock->UpdateOffloadCompleteHandler = g_ProtocolBlock.u1.Versions.v3->UpdateOffloadCompleteHandler;
        break;

    case 4:
        RtlCopyMemory(&ProtoBlock->Name, &g_ProtocolBlock.u1.Versions.v4->Name, sizeof(UNICODE_STRING));
        RtlCopyMemory(&ProtoBlock->ImageName, &g_ProtocolBlock.u1.Versions.v4->ImageName, sizeof(UNICODE_STRING));
        ProtoBlock->OpenQueue = g_ProtocolBlock.u1.Versions.v4->OpenQueue;
        ProtoBlock->NextProtocol = g_ProtocolBlock.u1.Versions.v4->NextProtocol;

        ProtoBlock->MajorDriverVersion = g_ProtocolBlock.u1.Versions.v4->MajorDriverVersion;
        ProtoBlock->MajorNdisVersion = g_ProtocolBlock.u1.Versions.v4->MajorNdisVersion;
        ProtoBlock->MinorDriverVersion = g_ProtocolBlock.u1.Versions.v4->MinorDriverVersion;
        ProtoBlock->MinorNdisVersion = g_ProtocolBlock.u1.Versions.v4->MinorNdisVersion;

        ProtoBlock->AllocateSharedMemoryHandler = g_ProtocolBlock.u1.Versions.v4->AllocateSharedMemoryHandler;
        ProtoBlock->BindAdapterHandler = g_ProtocolBlock.u1.Versions.v4->BindAdapterHandler;
        ProtoBlock->BindAdapterHandlerEx = g_ProtocolBlock.u1.Versions.v4->BindAdapterHandlerEx;
        ProtoBlock->BindDeviceName = g_ProtocolBlock.u1.Versions.v4->BindDeviceName;
        ProtoBlock->CloseAdapterCompleteHandler = g_ProtocolBlock.u1.Versions.v4->CloseAdapterCompleteHandler;
        ProtoBlock->CloseAdapterCompleteHandlerEx = g_ProtocolBlock.u1.Versions.v4->CloseAdapterCompleteHandlerEx;
        ProtoBlock->CoAfRegisterNotifyHandler = g_ProtocolBlock.u1.Versions.v4->CoAfRegisterNotifyHandler;
        ProtoBlock->CoReceiveNetBufferListsHandler = g_ProtocolBlock.u1.Versions.v4->CoReceiveNetBufferListsHandler;
        ProtoBlock->CoReceivePacketHandler = g_ProtocolBlock.u1.Versions.v4->CoReceivePacketHandler;
        ProtoBlock->CoSendCompleteHandler = g_ProtocolBlock.u1.Versions.v4->CoSendCompleteHandler;
        ProtoBlock->CoSendNetBufferListsCompleteHandler = g_ProtocolBlock.u1.Versions.v4->CoSendNetBufferListsCompleteHandler;
        ProtoBlock->CoStatusHandler = g_ProtocolBlock.u1.Versions.v4->u3.CoStatusHandler;
        ProtoBlock->DirectOidRequestCompleteHandler = g_ProtocolBlock.u1.Versions.v4->DirectOidRequestCompleteHandler;
        ProtoBlock->FreeSharedMemoryHandler = g_ProtocolBlock.u1.Versions.v4->FreeSharedMemoryHandler;
        ProtoBlock->OidRequestCompleteHandler = g_ProtocolBlock.u1.Versions.v4->OidRequestCompleteHandler;
        ProtoBlock->OpenAdapterCompleteHandler = g_ProtocolBlock.u1.Versions.v4->OpenAdapterCompleteHandler;
        ProtoBlock->OpenAdapterCompleteHandlerEx = g_ProtocolBlock.u1.Versions.v4->OpenAdapterCompleteHandlerEx;
        ProtoBlock->PnPEventHandler = g_ProtocolBlock.u1.Versions.v4->u1.PnPEventHandler;
        ProtoBlock->ReceiveCompleteHandler = g_ProtocolBlock.u1.Versions.v4->ReceiveCompleteHandler;
        ProtoBlock->ReceiveHandler = g_ProtocolBlock.u1.Versions.v4->u6.ReceiveHandler;
        ProtoBlock->ReceiveNetBufferListsHandler = g_ProtocolBlock.u1.Versions.v4->ReceiveNetBufferListsHandler;
        ProtoBlock->ReceivePacketHandler = g_ProtocolBlock.u1.Versions.v4->ReceivePacketHandler;
        ProtoBlock->RequestCompleteHandler = g_ProtocolBlock.u1.Versions.v4->RequestCompleteHandler;
        ProtoBlock->ResetCompleteHandler = g_ProtocolBlock.u1.Versions.v4->ResetCompleteHandler;
        ProtoBlock->RootDeviceName = g_ProtocolBlock.u1.Versions.v4->RootDeviceName;
        ProtoBlock->SendCompleteHandler = g_ProtocolBlock.u1.Versions.v4->u4.SendCompleteHandler;
        ProtoBlock->SendNetBufferListsCompleteHandler = g_ProtocolBlock.u1.Versions.v4->SendNetBufferListsCompleteHandler;
        ProtoBlock->StatusCompleteHandler = g_ProtocolBlock.u1.Versions.v4->StatusCompleteHandler;
        ProtoBlock->StatusHandler = g_ProtocolBlock.u1.Versions.v4->u2.StatusHandler;
        ProtoBlock->TransferDataCompleteHandler = g_ProtocolBlock.u1.Versions.v4->u5.TransferDataCompleteHandler;
        ProtoBlock->UnbindAdapterHandler = g_ProtocolBlock.u1.Versions.v4->UnbindAdapterHandler;
        ProtoBlock->UnbindAdapterHandlerEx = g_ProtocolBlock.u1.Versions.v4->UnbindAdapterHandlerEx;
        ProtoBlock->UninstallHandler = g_ProtocolBlock.u1.Versions.v4->UninstallHandler;
        ProtoBlock->UnloadHandler = g_ProtocolBlock.u1.Versions.v4->UnloadHandler;
        break;

    case 5:
        RtlCopyMemory(&ProtoBlock->Name, &g_ProtocolBlock.u1.Versions.v5->Name, sizeof(UNICODE_STRING));
        RtlCopyMemory(&ProtoBlock->ImageName, &g_ProtocolBlock.u1.Versions.v5->ImageName, sizeof(UNICODE_STRING));
        ProtoBlock->OpenQueue = g_ProtocolBlock.u1.Versions.v5->OpenQueue;
        ProtoBlock->NextProtocol = g_ProtocolBlock.u1.Versions.v5->NextProtocol;

        ProtoBlock->MajorDriverVersion = g_ProtocolBlock.u1.Versions.v5->MajorDriverVersion;
        ProtoBlock->MajorNdisVersion = g_ProtocolBlock.u1.Versions.v5->MajorNdisVersion;
        ProtoBlock->MinorDriverVersion = g_ProtocolBlock.u1.Versions.v5->MinorDriverVersion;
        ProtoBlock->MinorNdisVersion = g_ProtocolBlock.u1.Versions.v5->MinorNdisVersion;

        ProtoBlock->AllocateSharedMemoryHandler = g_ProtocolBlock.u1.Versions.v5->AllocateSharedMemoryHandler;
        ProtoBlock->BindAdapterHandler = g_ProtocolBlock.u1.Versions.v5->BindAdapterHandler;
        ProtoBlock->BindAdapterHandlerEx = g_ProtocolBlock.u1.Versions.v5->BindAdapterHandlerEx;
        ProtoBlock->BindDeviceName = g_ProtocolBlock.u1.Versions.v5->BindDeviceName;
        ProtoBlock->CloseAdapterCompleteHandler = g_ProtocolBlock.u1.Versions.v5->CloseAdapterCompleteHandler;
        ProtoBlock->CloseAdapterCompleteHandlerEx = g_ProtocolBlock.u1.Versions.v5->CloseAdapterCompleteHandlerEx;
        ProtoBlock->CoAfRegisterNotifyHandler = g_ProtocolBlock.u1.Versions.v5->CoAfRegisterNotifyHandler;
        ProtoBlock->CoReceiveNetBufferListsHandler = g_ProtocolBlock.u1.Versions.v5->CoReceiveNetBufferListsHandler;
        ProtoBlock->CoReceivePacketHandler = g_ProtocolBlock.u1.Versions.v5->CoReceivePacketHandler;
        ProtoBlock->CoSendCompleteHandler = g_ProtocolBlock.u1.Versions.v5->CoSendCompleteHandler;
        ProtoBlock->CoSendNetBufferListsCompleteHandler = g_ProtocolBlock.u1.Versions.v5->CoSendNetBufferListsCompleteHandler;
        ProtoBlock->CoStatusHandler = g_ProtocolBlock.u1.Versions.v5->u3.CoStatusHandler;
        ProtoBlock->DirectOidRequestCompleteHandler = g_ProtocolBlock.u1.Versions.v5->DirectOidRequestCompleteHandler;
        ProtoBlock->FreeSharedMemoryHandler = g_ProtocolBlock.u1.Versions.v5->FreeSharedMemoryHandler;
        ProtoBlock->OidRequestCompleteHandler = g_ProtocolBlock.u1.Versions.v5->OidRequestCompleteHandler;
        ProtoBlock->OpenAdapterCompleteHandler = g_ProtocolBlock.u1.Versions.v5->OpenAdapterCompleteHandler;
        ProtoBlock->OpenAdapterCompleteHandlerEx = g_ProtocolBlock.u1.Versions.v5->OpenAdapterCompleteHandlerEx;
        ProtoBlock->PnPEventHandler = g_ProtocolBlock.u1.Versions.v5->u1.PnPEventHandler;
        ProtoBlock->ReceiveCompleteHandler = g_ProtocolBlock.u1.Versions.v5->ReceiveCompleteHandler;
        ProtoBlock->ReceiveHandler = g_ProtocolBlock.u1.Versions.v5->u6.ReceiveHandler;
        ProtoBlock->ReceiveNetBufferListsHandler = g_ProtocolBlock.u1.Versions.v5->ReceiveNetBufferListsHandler;
        ProtoBlock->ReceivePacketHandler = g_ProtocolBlock.u1.Versions.v5->ReceivePacketHandler;
        ProtoBlock->RequestCompleteHandler = g_ProtocolBlock.u1.Versions.v5->RequestCompleteHandler;
        ProtoBlock->ResetCompleteHandler = g_ProtocolBlock.u1.Versions.v5->ResetCompleteHandler;
        ProtoBlock->RootDeviceName = g_ProtocolBlock.u1.Versions.v5->RootDeviceName;
        ProtoBlock->SendCompleteHandler = g_ProtocolBlock.u1.Versions.v5->u4.SendCompleteHandler;
        ProtoBlock->SendNetBufferListsCompleteHandler = g_ProtocolBlock.u1.Versions.v5->SendNetBufferListsCompleteHandler;
        ProtoBlock->StatusCompleteHandler = g_ProtocolBlock.u1.Versions.v5->StatusCompleteHandler;
        ProtoBlock->StatusHandler = g_ProtocolBlock.u1.Versions.v5->u2.StatusHandler;
        ProtoBlock->TransferDataCompleteHandler = g_ProtocolBlock.u1.Versions.v5->u5.TransferDataCompleteHandler;
        ProtoBlock->UnbindAdapterHandler = g_ProtocolBlock.u1.Versions.v5->UnbindAdapterHandler;
        ProtoBlock->UnbindAdapterHandlerEx = g_ProtocolBlock.u1.Versions.v5->UnbindAdapterHandlerEx;
        ProtoBlock->UninstallHandler = g_ProtocolBlock.u1.Versions.v5->UninstallHandler;
        ProtoBlock->UnloadHandler = g_ProtocolBlock.u1.Versions.v5->UnloadHandler;
        break;

    default:
        return FALSE;
    }
    return TRUE;
}

/*
* CreateCompatibleOpenBlock
*
* Purpose:
*
* Build compatible open block for easy work with it.
*
*/
BOOL CreateCompatibleOpenBlock(
    _In_ ULONG ObjectVersion,
    _Out_ NDIS_OPEN_BLOCK_COMPATIBLE *OpenBlock)
{
    switch (ObjectVersion) {

    case 1: //7600
        OpenBlock->ProtocolNextOpen = g_OpenBlock.u1.Versions.v1->ProtocolNextOpen;
        OpenBlock->AllocateSharedMemoryHandler = g_OpenBlock.u1.Versions.v1->AllocateSharedMemoryContext;
        OpenBlock->BindDeviceName = g_OpenBlock.u1.Versions.v1->BindDeviceName;
        OpenBlock->CmActivateVcCompleteHandler = g_OpenBlock.u1.Versions.v1->CmActivateVcCompleteHandler;
        OpenBlock->CmDeactivateVcCompleteHandler = g_OpenBlock.u1.Versions.v1->CmDeactivateVcCompleteHandler;
        OpenBlock->CoCreateVcHandler = g_OpenBlock.u1.Versions.v1->CoCreateVcHandler;
        OpenBlock->CoDeleteVcHandler = g_OpenBlock.u1.Versions.v1->CoDeleteVcHandler;
        OpenBlock->CoOidRequestCompleteHandler = g_OpenBlock.u1.Versions.v1->CoOidRequestCompleteHandler;
        OpenBlock->CoOidRequestHandler = g_OpenBlock.u1.Versions.v1->CoOidRequestHandler;
        OpenBlock->CoRequestCompleteHandler = g_OpenBlock.u1.Versions.v1->CoRequestCompleteHandler;
        OpenBlock->CoRequestHandler = g_OpenBlock.u1.Versions.v1->CoRequestHandler;
        OpenBlock->DirectOidRequestCompleteHandler = g_OpenBlock.u1.Versions.v1->DirectOidRequestCompleteHandler;
        OpenBlock->DirectOidRequestHandler = g_OpenBlock.u1.Versions.v1->DirectOidRequestHandler;
        OpenBlock->FreeSharedMemoryHandler = g_OpenBlock.u1.Versions.v1->FreeSharedMemoryHandler;
        OpenBlock->IndicateOffloadEventHandler = g_OpenBlock.u1.Versions.v1->IndicateOffloadEventHandler;
        OpenBlock->InitiateOffloadCompleteHandler = g_OpenBlock.u1.Versions.v1->InitiateOffloadCompleteHandler;
        OpenBlock->InvalidateOffloadCompleteHandler = g_OpenBlock.u1.Versions.v1->InvalidateOffloadCompleteHandler;
        OpenBlock->MiniportCoCreateVcHandler = g_OpenBlock.u1.Versions.v1->MiniportCoCreateVcHandler;
        OpenBlock->MiniportCoOidRequestHandler = g_OpenBlock.u1.Versions.v1->MiniportCoOidRequestHandler;
        OpenBlock->MiniportCoRequestHandler = g_OpenBlock.u1.Versions.v1->MiniportCoRequestHandler;
        OpenBlock->Ndis5WanSendHandler = g_OpenBlock.u1.Versions.v1->Ndis5WanSendHandler;
        OpenBlock->NextReturnNetBufferListsHandler = g_OpenBlock.u1.Versions.v1->NextReturnNetBufferListsHandler;
        OpenBlock->NextSendHandler = g_OpenBlock.u1.Versions.v1->NextSendHandler;
        OpenBlock->OidRequestCompleteHandler = g_OpenBlock.u1.Versions.v1->OidRequestCompleteHandler;
        OpenBlock->OidRequestHandler = g_OpenBlock.u1.Versions.v1->OidRequestCompleteHandler;
        OpenBlock->ProtSendCompleteHandler = g_OpenBlock.u1.Versions.v1->ProtSendCompleteHandler;
        OpenBlock->ProtSendNetBufferListsComplete = g_OpenBlock.u1.Versions.v1->ProtSendNetBufferListsComplete;
        OpenBlock->QueryOffloadCompleteHandler = g_OpenBlock.u1.Versions.v1->QueryOffloadCompleteHandler;
        OpenBlock->ReceiveCompleteHandler = g_OpenBlock.u1.Versions.v1->ReceiveCompleteHandler;
        OpenBlock->ReceiveHandler = g_OpenBlock.u1.Versions.v1->ReceiveHandler;
        OpenBlock->ReceiveNetBufferLists = g_OpenBlock.u1.Versions.v1->ReceiveNetBufferLists;
        OpenBlock->ReceivePacketHandler = g_OpenBlock.u1.Versions.v1->ReceivePacketHandler;
        OpenBlock->RequestCompleteHandler = g_OpenBlock.u1.Versions.v1->RequestCompleteHandler;
        OpenBlock->RequestHandler = g_OpenBlock.u1.Versions.v1->RequestHandler;
        OpenBlock->ResetCompleteHandler = g_OpenBlock.u1.Versions.v1->ResetCompleteHandler;
        OpenBlock->RootDeviceName = g_OpenBlock.u1.Versions.v1->RootDeviceName;
        OpenBlock->SavedCancelSendPacketsHandler = g_OpenBlock.u1.Versions.v1->SavedCancelSendPacketsHandler;
        OpenBlock->SavedSendHandler = g_OpenBlock.u1.Versions.v1->SavedSendHandler;
        OpenBlock->SavedSendNBLHandler = g_OpenBlock.u1.Versions.v1->SavedSendNBLHandler;
        OpenBlock->SavedSendPacketsHandler = g_OpenBlock.u1.Versions.v1->SavedSendPacketsHandler;
        OpenBlock->SendCompleteHandler = g_OpenBlock.u1.Versions.v1->SendCompleteHandler;
        OpenBlock->SendHandler = g_OpenBlock.u1.Versions.v1->SendHandler;
        OpenBlock->SendPacketsHandler = g_OpenBlock.u1.Versions.v1->SendPacketsHandler;
        OpenBlock->TcpOffloadDisconnectCompleteHandler = g_OpenBlock.u1.Versions.v1->TcpOffloadDisconnectCompleteHandler;
        OpenBlock->TcpOffloadEventHandler = g_OpenBlock.u1.Versions.v1->TcpOffloadEventHandler;
        OpenBlock->TcpOffloadForwardCompleteHandler = g_OpenBlock.u1.Versions.v1->TcpOffloadForwardCompleteHandler;
        OpenBlock->TcpOffloadReceiveCompleteHandler = g_OpenBlock.u1.Versions.v1->TcpOffloadReceiveCompleteHandler;
        OpenBlock->TcpOffloadReceiveIndicateHandler = g_OpenBlock.u1.Versions.v1->TcpOffloadReceiveIndicateHandler;
        OpenBlock->TcpOffloadSendCompleteHandler = g_OpenBlock.u1.Versions.v1->TcpOffloadSendCompleteHandler;
        OpenBlock->TerminateOffloadCompleteHandler = g_OpenBlock.u1.Versions.v1->TerminateOffloadCompleteHandler;
        OpenBlock->TransferDataCompleteHandler = g_OpenBlock.u1.Versions.v1->TransferDataCompleteHandler;
        OpenBlock->TransferDataHandler = g_OpenBlock.u1.Versions.v1->TransferDataHandler;
        OpenBlock->UpdateOffloadCompleteHandler = g_OpenBlock.u1.Versions.v1->UpdateOffloadCompleteHandler;
        OpenBlock->WanReceiveHandler = g_OpenBlock.u1.Versions.v1->WanReceiveHandler;
        break;

    case 2: //9200
        OpenBlock->ProtocolNextOpen = g_OpenBlock.u1.Versions.v2->ProtocolNextOpen;
        OpenBlock->AllocateSharedMemoryHandler = g_OpenBlock.u1.Versions.v2->AllocateSharedMemoryContext;
        OpenBlock->BindDeviceName = g_OpenBlock.u1.Versions.v2->BindDeviceName;
        OpenBlock->CmActivateVcCompleteHandler = g_OpenBlock.u1.Versions.v2->CmActivateVcCompleteHandler;
        OpenBlock->CmDeactivateVcCompleteHandler = g_OpenBlock.u1.Versions.v2->CmDeactivateVcCompleteHandler;
        OpenBlock->CoCreateVcHandler = g_OpenBlock.u1.Versions.v2->CoCreateVcHandler;
        OpenBlock->CoDeleteVcHandler = g_OpenBlock.u1.Versions.v2->CoDeleteVcHandler;
        OpenBlock->CoOidRequestCompleteHandler = g_OpenBlock.u1.Versions.v2->CoOidRequestCompleteHandler;
        OpenBlock->CoOidRequestHandler = g_OpenBlock.u1.Versions.v2->CoOidRequestHandler;
        OpenBlock->CoRequestCompleteHandler = g_OpenBlock.u1.Versions.v2->CoRequestCompleteHandler;
        OpenBlock->CoRequestHandler = g_OpenBlock.u1.Versions.v2->CoRequestHandler;
        OpenBlock->DirectOidRequestHandler = g_OpenBlock.u1.Versions.v2->DirectOidRequestHandler;
        OpenBlock->FreeSharedMemoryHandler = g_OpenBlock.u1.Versions.v2->FreeSharedMemoryHandler;
        OpenBlock->IndicateOffloadEventHandler = g_OpenBlock.u1.Versions.v2->IndicateOffloadEventHandler;
        OpenBlock->InitiateOffloadCompleteHandler = g_OpenBlock.u1.Versions.v2->InitiateOffloadCompleteHandler;
        OpenBlock->InvalidateOffloadCompleteHandler = g_OpenBlock.u1.Versions.v2->InvalidateOffloadCompleteHandler;
        OpenBlock->MiniportCoCreateVcHandler = g_OpenBlock.u1.Versions.v2->MiniportCoCreateVcHandler;
        OpenBlock->MiniportCoOidRequestHandler = g_OpenBlock.u1.Versions.v2->MiniportCoOidRequestHandler;
        OpenBlock->MiniportCoRequestHandler = g_OpenBlock.u1.Versions.v2->MiniportCoRequestHandler;
        OpenBlock->Ndis5WanSendHandler = g_OpenBlock.u1.Versions.v2->Ndis5WanSendHandler;
        OpenBlock->NextReturnNetBufferListsHandler = g_OpenBlock.u1.Versions.v2->NextReturnNetBufferListsHandler;
        OpenBlock->NextSendHandler = g_OpenBlock.u1.Versions.v2->NextSendHandler;
        OpenBlock->OidRequestCompleteHandler = g_OpenBlock.u1.Versions.v2->OidRequestCompleteHandler;
        OpenBlock->OidRequestHandler = g_OpenBlock.u1.Versions.v2->OidRequestCompleteHandler;
        OpenBlock->ProtSendCompleteHandler = g_OpenBlock.u1.Versions.v2->ProtSendCompleteHandler;
        OpenBlock->ProtSendNetBufferListsComplete = g_OpenBlock.u1.Versions.v2->ProtSendNetBufferListsComplete;
        OpenBlock->QueryOffloadCompleteHandler = g_OpenBlock.u1.Versions.v2->QueryOffloadCompleteHandler;
        OpenBlock->ReceiveCompleteHandler = g_OpenBlock.u1.Versions.v2->ReceiveCompleteHandler;
        OpenBlock->ReceiveHandler = g_OpenBlock.u1.Versions.v2->ReceiveHandler;
        OpenBlock->ReceiveNetBufferLists = g_OpenBlock.u1.Versions.v2->ReceiveNetBufferLists;
        OpenBlock->ReceivePacketHandler = g_OpenBlock.u1.Versions.v2->ReceivePacketHandler;
        OpenBlock->RequestCompleteHandler = g_OpenBlock.u1.Versions.v2->RequestCompleteHandler;
        OpenBlock->RequestHandler = g_OpenBlock.u1.Versions.v2->RequestHandler;
        OpenBlock->ResetCompleteHandler = g_OpenBlock.u1.Versions.v2->ResetCompleteHandler;
        OpenBlock->RootDeviceName = g_OpenBlock.u1.Versions.v2->RootDeviceName;
        OpenBlock->SavedCancelSendPacketsHandler = g_OpenBlock.u1.Versions.v2->SavedCancelSendPacketsHandler;
        OpenBlock->SavedSendHandler = g_OpenBlock.u1.Versions.v2->SavedSendHandler;
        OpenBlock->SavedSendPacketsHandler = g_OpenBlock.u1.Versions.v2->SavedSendPacketsHandler;
        OpenBlock->SendCompleteHandler = g_OpenBlock.u1.Versions.v2->SendCompleteHandler;
        OpenBlock->SendHandler = g_OpenBlock.u1.Versions.v2->SendHandler;
        OpenBlock->SendPacketsHandler = g_OpenBlock.u1.Versions.v2->SendPacketsHandler;
        OpenBlock->TcpOffloadDisconnectCompleteHandler = g_OpenBlock.u1.Versions.v2->TcpOffloadDisconnectCompleteHandler;
        OpenBlock->TcpOffloadEventHandler = g_OpenBlock.u1.Versions.v2->TcpOffloadEventHandler;
        OpenBlock->TcpOffloadForwardCompleteHandler = g_OpenBlock.u1.Versions.v2->TcpOffloadForwardCompleteHandler;
        OpenBlock->TcpOffloadReceiveCompleteHandler = g_OpenBlock.u1.Versions.v2->TcpOffloadReceiveCompleteHandler;
        OpenBlock->TcpOffloadReceiveIndicateHandler = g_OpenBlock.u1.Versions.v2->TcpOffloadReceiveIndicateHandler;
        OpenBlock->TcpOffloadSendCompleteHandler = g_OpenBlock.u1.Versions.v2->TcpOffloadSendCompleteHandler;
        OpenBlock->TerminateOffloadCompleteHandler = g_OpenBlock.u1.Versions.v2->TerminateOffloadCompleteHandler;
        OpenBlock->TransferDataCompleteHandler = g_OpenBlock.u1.Versions.v2->TransferDataCompleteHandler;
        OpenBlock->TransferDataHandler = g_OpenBlock.u1.Versions.v2->TransferDataHandler;
        OpenBlock->UpdateOffloadCompleteHandler = g_OpenBlock.u1.Versions.v2->UpdateOffloadCompleteHandler;
        OpenBlock->WanReceiveHandler = g_OpenBlock.u1.Versions.v2->WanReceiveHandler;
        break;

    case 3: //9600 .. 10586      
        OpenBlock->ProtocolNextOpen = g_OpenBlock.u1.Versions.u_v3.v3c->ProtocolNextOpen;
        OpenBlock->AllocateSharedMemoryHandler = g_OpenBlock.u1.Versions.u_v3.v3c->AllocateSharedMemoryContext;
        OpenBlock->BindDeviceName = g_OpenBlock.u1.Versions.u_v3.v3c->BindDeviceName;
        OpenBlock->CmActivateVcCompleteHandler = g_OpenBlock.u1.Versions.u_v3.v3->CmActivateVcCompleteHandler;
        OpenBlock->CmDeactivateVcCompleteHandler = g_OpenBlock.u1.Versions.u_v3.v3->CmDeactivateVcCompleteHandler;
        OpenBlock->CoCreateVcHandler = g_OpenBlock.u1.Versions.u_v3.v3->CoCreateVcHandler;
        OpenBlock->CoDeleteVcHandler = g_OpenBlock.u1.Versions.u_v3.v3->CoDeleteVcHandler;
        OpenBlock->CoOidRequestCompleteHandler = g_OpenBlock.u1.Versions.u_v3.v3->CoOidRequestCompleteHandler;
        OpenBlock->CoOidRequestHandler = g_OpenBlock.u1.Versions.u_v3.v3->CoOidRequestHandler;
        OpenBlock->CoRequestCompleteHandler = g_OpenBlock.u1.Versions.u_v3.v3->CoRequestCompleteHandler;
        OpenBlock->CoRequestHandler = g_OpenBlock.u1.Versions.u_v3.v3->CoRequestHandler;
        OpenBlock->DirectOidRequestHandler = g_OpenBlock.u1.Versions.u_v3.v3c->DirectOidRequestHandler;
        OpenBlock->FreeSharedMemoryHandler = g_OpenBlock.u1.Versions.u_v3.v3c->FreeSharedMemoryHandler;
        OpenBlock->IndicateOffloadEventHandler = g_OpenBlock.u1.Versions.u_v3.v3c->IndicateOffloadEventHandler;
        OpenBlock->InitiateOffloadCompleteHandler = g_OpenBlock.u1.Versions.u_v3.v3c->InitiateOffloadCompleteHandler;
        OpenBlock->InvalidateOffloadCompleteHandler = g_OpenBlock.u1.Versions.u_v3.v3c->InvalidateOffloadCompleteHandler;
        OpenBlock->MiniportCoCreateVcHandler = g_OpenBlock.u1.Versions.u_v3.v3->MiniportCoCreateVcHandler;
        OpenBlock->MiniportCoOidRequestHandler = g_OpenBlock.u1.Versions.u_v3.v3->MiniportCoOidRequestHandler;
        OpenBlock->MiniportCoRequestHandler = g_OpenBlock.u1.Versions.u_v3.v3->MiniportCoRequestHandler;
        OpenBlock->Ndis5WanSendHandler = g_OpenBlock.u1.Versions.u_v3.v3c->Ndis5WanSendHandler;
        OpenBlock->NextReturnNetBufferListsHandler = g_OpenBlock.u1.Versions.u_v3.v3c->NextReturnNetBufferListsHandler;
        OpenBlock->NextSendHandler = g_OpenBlock.u1.Versions.u_v3.v3c->NextSendHandler;
        OpenBlock->OidRequestCompleteHandler = g_OpenBlock.u1.Versions.u_v3.v3c->OidRequestCompleteHandler;
        OpenBlock->OidRequestHandler = g_OpenBlock.u1.Versions.u_v3.v3c->OidRequestCompleteHandler;
        OpenBlock->ProtSendCompleteHandler = g_OpenBlock.u1.Versions.u_v3.v3c->ProtSendCompleteHandler;
        OpenBlock->ProtSendNetBufferListsComplete = g_OpenBlock.u1.Versions.u_v3.v3c->ProtSendNetBufferListsComplete;
        OpenBlock->QueryOffloadCompleteHandler = g_OpenBlock.u1.Versions.u_v3.v3c->QueryOffloadCompleteHandler;
        OpenBlock->ReceiveCompleteHandler = g_OpenBlock.u1.Versions.u_v3.v3c->ReceiveCompleteHandler;
        OpenBlock->ReceiveHandler = g_OpenBlock.u1.Versions.u_v3.v3c->ReceiveHandler;
        OpenBlock->ReceiveNetBufferLists = g_OpenBlock.u1.Versions.u_v3.v3c->ReceiveNetBufferLists;
        OpenBlock->ReceivePacketHandler = g_OpenBlock.u1.Versions.u_v3.v3c->ReceivePacketHandler;
        OpenBlock->RequestCompleteHandler = g_OpenBlock.u1.Versions.u_v3.v3c->RequestCompleteHandler;
        OpenBlock->RequestHandler = g_OpenBlock.u1.Versions.u_v3.v3c->RequestHandler;
        OpenBlock->ResetCompleteHandler = g_OpenBlock.u1.Versions.u_v3.v3c->ResetCompleteHandler;
        OpenBlock->RootDeviceName = g_OpenBlock.u1.Versions.u_v3.v3c->RootDeviceName;
        OpenBlock->SavedCancelSendPacketsHandler = g_OpenBlock.u1.Versions.u_v3.v3c->SavedCancelSendPacketsHandler;
        OpenBlock->SavedSendHandler = g_OpenBlock.u1.Versions.u_v3.v3c->SavedSendHandler;
        OpenBlock->SavedSendPacketsHandler = g_OpenBlock.u1.Versions.u_v3.v3c->SavedSendPacketsHandler;
        OpenBlock->SendCompleteHandler = g_OpenBlock.u1.Versions.u_v3.v3c->SendCompleteHandler;
        OpenBlock->SendHandler = g_OpenBlock.u1.Versions.u_v3.v3c->SendHandler;
        OpenBlock->SendPacketsHandler = g_OpenBlock.u1.Versions.u_v3.v3c->SendPacketsHandler;
        OpenBlock->TcpOffloadDisconnectCompleteHandler = g_OpenBlock.u1.Versions.u_v3.v3c->TcpOffloadDisconnectCompleteHandler;
        OpenBlock->TcpOffloadEventHandler = g_OpenBlock.u1.Versions.u_v3.v3c->TcpOffloadEventHandler;
        OpenBlock->TcpOffloadForwardCompleteHandler = g_OpenBlock.u1.Versions.u_v3.v3c->TcpOffloadForwardCompleteHandler;
        OpenBlock->TcpOffloadReceiveCompleteHandler = g_OpenBlock.u1.Versions.u_v3.v3c->TcpOffloadReceiveCompleteHandler;
        OpenBlock->TcpOffloadReceiveIndicateHandler = g_OpenBlock.u1.Versions.u_v3.v3c->TcpOffloadReceiveIndicateHandler;
        OpenBlock->TcpOffloadSendCompleteHandler = g_OpenBlock.u1.Versions.u_v3.v3c->TcpOffloadSendCompleteHandler;
        OpenBlock->TerminateOffloadCompleteHandler = g_OpenBlock.u1.Versions.u_v3.v3c->TerminateOffloadCompleteHandler;
        OpenBlock->TransferDataCompleteHandler = g_OpenBlock.u1.Versions.u_v3.v3c->TransferDataCompleteHandler;
        OpenBlock->TransferDataHandler = g_OpenBlock.u1.Versions.u_v3.v3c->TransferDataHandler;
        OpenBlock->UpdateOffloadCompleteHandler = g_OpenBlock.u1.Versions.u_v3.v3c->UpdateOffloadCompleteHandler;
        OpenBlock->WanReceiveHandler = g_OpenBlock.u1.Versions.u_v3.v3c->WanReceiveHandler;
        break;

    case 4: //14393 .. 17134
        OpenBlock->ProtocolNextOpen = g_OpenBlock.u1.Versions.u_v4.v4c->ProtocolNextOpen;
        OpenBlock->AllocateSharedMemoryHandler = g_OpenBlock.u1.Versions.u_v4.v4c->AllocateSharedMemoryContext;
        OpenBlock->BindDeviceName = g_OpenBlock.u1.Versions.u_v4.v4c->BindDeviceName;
        OpenBlock->CmActivateVcCompleteHandler = g_OpenBlock.u1.Versions.u_v4.v4->CmActivateVcCompleteHandler;
        OpenBlock->CmDeactivateVcCompleteHandler = g_OpenBlock.u1.Versions.u_v4.v4->CmDeactivateVcCompleteHandler;
        OpenBlock->CoCreateVcHandler = g_OpenBlock.u1.Versions.u_v4.v4->CoCreateVcHandler;
        OpenBlock->CoDeleteVcHandler = g_OpenBlock.u1.Versions.u_v4.v4->CoDeleteVcHandler;
        OpenBlock->CoOidRequestCompleteHandler = g_OpenBlock.u1.Versions.u_v4.v4->CoOidRequestCompleteHandler;
        OpenBlock->CoOidRequestHandler = g_OpenBlock.u1.Versions.u_v4.v4->CoOidRequestHandler;
        OpenBlock->CoRequestCompleteHandler = g_OpenBlock.u1.Versions.u_v4.v4->CoRequestCompleteHandler;
        OpenBlock->CoRequestHandler = g_OpenBlock.u1.Versions.u_v4.v4->CoRequestHandler;
        OpenBlock->DirectOidRequestHandler = g_OpenBlock.u1.Versions.u_v4.v4c->DirectOidRequestHandler;
        OpenBlock->FreeSharedMemoryHandler = g_OpenBlock.u1.Versions.u_v4.v4c->FreeSharedMemoryHandler;
        OpenBlock->IndicateOffloadEventHandler = g_OpenBlock.u1.Versions.u_v4.v4c->IndicateOffloadEventHandler;
        OpenBlock->InitiateOffloadCompleteHandler = g_OpenBlock.u1.Versions.u_v4.v4c->InitiateOffloadCompleteHandler;
        OpenBlock->InvalidateOffloadCompleteHandler = g_OpenBlock.u1.Versions.u_v4.v4c->InvalidateOffloadCompleteHandler;
        OpenBlock->MiniportCoCreateVcHandler = g_OpenBlock.u1.Versions.u_v4.v4->MiniportCoCreateVcHandler;
        OpenBlock->MiniportCoOidRequestHandler = g_OpenBlock.u1.Versions.u_v4.v4->MiniportCoOidRequestHandler;
        OpenBlock->MiniportCoRequestHandler = g_OpenBlock.u1.Versions.u_v4.v4->MiniportCoRequestHandler;
        OpenBlock->Ndis5WanSendHandler = g_OpenBlock.u1.Versions.u_v4.v4c->Ndis5WanSendHandler;
        OpenBlock->NextReturnNetBufferListsHandler = g_OpenBlock.u1.Versions.u_v4.v4c->NextReturnNetBufferListsHandler;
        OpenBlock->NextSendHandler = g_OpenBlock.u1.Versions.u_v4.v4c->NextSendHandler;
        OpenBlock->OidRequestCompleteHandler = g_OpenBlock.u1.Versions.u_v4.v4c->OidRequestCompleteHandler;
        OpenBlock->OidRequestHandler = g_OpenBlock.u1.Versions.u_v4.v4c->OidRequestCompleteHandler;
        OpenBlock->ProtSendCompleteHandler = g_OpenBlock.u1.Versions.u_v4.v4c->ProtSendCompleteHandler;
        OpenBlock->ProtSendNetBufferListsComplete = g_OpenBlock.u1.Versions.u_v4.v4c->ProtSendNetBufferListsComplete;
        OpenBlock->QueryOffloadCompleteHandler = g_OpenBlock.u1.Versions.u_v4.v4c->QueryOffloadCompleteHandler;
        OpenBlock->ReceiveCompleteHandler = g_OpenBlock.u1.Versions.u_v4.v4c->ReceiveCompleteHandler;
        OpenBlock->ReceiveHandler = g_OpenBlock.u1.Versions.u_v4.v4c->ReceiveHandler;
        OpenBlock->ReceiveNetBufferLists = g_OpenBlock.u1.Versions.u_v4.v4c->ReceiveNetBufferLists;
        OpenBlock->ReceivePacketHandler = g_OpenBlock.u1.Versions.u_v4.v4c->ReceivePacketHandler;
        OpenBlock->RequestCompleteHandler = g_OpenBlock.u1.Versions.u_v4.v4c->RequestCompleteHandler;
        OpenBlock->RequestHandler = g_OpenBlock.u1.Versions.u_v4.v4c->RequestHandler;
        OpenBlock->ResetCompleteHandler = g_OpenBlock.u1.Versions.u_v4.v4c->ResetCompleteHandler;
        OpenBlock->RootDeviceName = g_OpenBlock.u1.Versions.u_v4.v4c->RootDeviceName;
        OpenBlock->SavedCancelSendPacketsHandler = g_OpenBlock.u1.Versions.u_v4.v4c->SavedCancelSendPacketsHandler;
        OpenBlock->SavedSendHandler = g_OpenBlock.u1.Versions.u_v4.v4c->SavedSendHandler;
        OpenBlock->SavedSendPacketsHandler = g_OpenBlock.u1.Versions.u_v4.v4c->SavedSendPacketsHandler;
        OpenBlock->SendCompleteHandler = g_OpenBlock.u1.Versions.u_v4.v4c->SendCompleteHandler;
        OpenBlock->SendHandler = g_OpenBlock.u1.Versions.u_v4.v4c->SendHandler;
        OpenBlock->SendPacketsHandler = g_OpenBlock.u1.Versions.u_v4.v4c->SendPacketsHandler;
        OpenBlock->TcpOffloadDisconnectCompleteHandler = g_OpenBlock.u1.Versions.u_v4.v4c->TcpOffloadDisconnectCompleteHandler;
        OpenBlock->TcpOffloadEventHandler = g_OpenBlock.u1.Versions.u_v4.v4c->TcpOffloadEventHandler;
        OpenBlock->TcpOffloadForwardCompleteHandler = g_OpenBlock.u1.Versions.u_v4.v4c->TcpOffloadForwardCompleteHandler;
        OpenBlock->TcpOffloadReceiveCompleteHandler = g_OpenBlock.u1.Versions.u_v4.v4c->TcpOffloadReceiveCompleteHandler;
        OpenBlock->TcpOffloadReceiveIndicateHandler = g_OpenBlock.u1.Versions.u_v4.v4c->TcpOffloadReceiveIndicateHandler;
        OpenBlock->TcpOffloadSendCompleteHandler = g_OpenBlock.u1.Versions.u_v4.v4c->TcpOffloadSendCompleteHandler;
        OpenBlock->TerminateOffloadCompleteHandler = g_OpenBlock.u1.Versions.u_v4.v4c->TerminateOffloadCompleteHandler;
        OpenBlock->TransferDataCompleteHandler = g_OpenBlock.u1.Versions.u_v4.v4c->TransferDataCompleteHandler;
        OpenBlock->TransferDataHandler = g_OpenBlock.u1.Versions.u_v4.v4c->TransferDataHandler;
        OpenBlock->UpdateOffloadCompleteHandler = g_OpenBlock.u1.Versions.u_v4.v4c->UpdateOffloadCompleteHandler;
        OpenBlock->WanReceiveHandler = g_OpenBlock.u1.Versions.u_v4.v4c->WanReceiveHandler;
        break;

    case 5: //17763 .. 18362
        OpenBlock->ProtocolNextOpen = g_OpenBlock.u1.Versions.u_v5.v5c->ProtocolNextOpen;
        OpenBlock->AllocateSharedMemoryHandler = g_OpenBlock.u1.Versions.u_v5.v5c->AllocateSharedMemoryContext;
        OpenBlock->BindDeviceName = g_OpenBlock.u1.Versions.u_v5.v5c->BindDeviceName;
        OpenBlock->CmActivateVcCompleteHandler = g_OpenBlock.u1.Versions.u_v5.v5->CmActivateVcCompleteHandler;
        OpenBlock->CmDeactivateVcCompleteHandler = g_OpenBlock.u1.Versions.u_v5.v5->CmDeactivateVcCompleteHandler;
        OpenBlock->CoCreateVcHandler = g_OpenBlock.u1.Versions.u_v5.v5->CoCreateVcHandler;
        OpenBlock->CoDeleteVcHandler = g_OpenBlock.u1.Versions.u_v5.v5->CoDeleteVcHandler;
        OpenBlock->CoOidRequestCompleteHandler = g_OpenBlock.u1.Versions.u_v5.v5->CoOidRequestCompleteHandler;
        OpenBlock->CoOidRequestHandler = g_OpenBlock.u1.Versions.u_v5.v5->CoOidRequestHandler;
        OpenBlock->CoRequestCompleteHandler = g_OpenBlock.u1.Versions.u_v5.v5->CoRequestCompleteHandler;
        OpenBlock->CoRequestHandler = g_OpenBlock.u1.Versions.u_v5.v5->CoRequestHandler;
        OpenBlock->DirectOidRequestHandler = g_OpenBlock.u1.Versions.u_v5.v5c->DirectOidRequestHandler;
        OpenBlock->FreeSharedMemoryHandler = g_OpenBlock.u1.Versions.u_v5.v5c->FreeSharedMemoryHandler;
        OpenBlock->MiniportCoCreateVcHandler = g_OpenBlock.u1.Versions.u_v5.v5->MiniportCoCreateVcHandler;
        OpenBlock->MiniportCoOidRequestHandler = g_OpenBlock.u1.Versions.u_v5.v5->MiniportCoOidRequestHandler;
        OpenBlock->MiniportCoRequestHandler = g_OpenBlock.u1.Versions.u_v5.v5->MiniportCoRequestHandler;
        OpenBlock->Ndis5WanSendHandler = g_OpenBlock.u1.Versions.u_v5.v5c->Ndis5WanSendHandler;
        OpenBlock->NextReturnNetBufferListsHandler = g_OpenBlock.u1.Versions.u_v5.v5c->NextReturnNetBufferListsHandler;
        OpenBlock->NextSendHandler = g_OpenBlock.u1.Versions.u_v5.v5c->NextSendHandler;
        OpenBlock->OidRequestCompleteHandler = g_OpenBlock.u1.Versions.u_v5.v5c->OidRequestCompleteHandler;
        OpenBlock->OidRequestHandler = g_OpenBlock.u1.Versions.u_v5.v5c->OidRequestCompleteHandler;
        OpenBlock->ProtSendCompleteHandler = g_OpenBlock.u1.Versions.u_v5.v5c->ProtSendCompleteHandler;
        OpenBlock->ProtSendNetBufferListsComplete = g_OpenBlock.u1.Versions.u_v5.v5c->ProtSendNetBufferListsComplete;
        OpenBlock->ReceiveCompleteHandler = g_OpenBlock.u1.Versions.u_v5.v5c->ReceiveCompleteHandler;
        OpenBlock->ReceiveHandler = g_OpenBlock.u1.Versions.u_v5.v5c->ReceiveHandler;
        OpenBlock->ReceiveNetBufferLists = g_OpenBlock.u1.Versions.u_v5.v5c->ReceiveNetBufferLists;
        OpenBlock->ReceivePacketHandler = g_OpenBlock.u1.Versions.u_v5.v5c->ReceivePacketHandler;
        OpenBlock->RequestCompleteHandler = g_OpenBlock.u1.Versions.u_v5.v5c->RequestCompleteHandler;
        OpenBlock->RequestHandler = g_OpenBlock.u1.Versions.u_v5.v5c->RequestHandler;
        OpenBlock->ResetCompleteHandler = g_OpenBlock.u1.Versions.u_v5.v5c->ResetCompleteHandler;
        OpenBlock->RootDeviceName = g_OpenBlock.u1.Versions.u_v5.v5c->RootDeviceName;
        OpenBlock->SavedCancelSendPacketsHandler = g_OpenBlock.u1.Versions.u_v5.v5c->SavedCancelSendPacketsHandler;
        OpenBlock->SavedSendHandler = g_OpenBlock.u1.Versions.u_v5.v5c->SavedSendHandler;
        OpenBlock->SavedSendPacketsHandler = g_OpenBlock.u1.Versions.u_v5.v5c->SavedSendPacketsHandler;
        OpenBlock->SendCompleteHandler = g_OpenBlock.u1.Versions.u_v5.v5c->SendCompleteHandler;
        OpenBlock->SendHandler = g_OpenBlock.u1.Versions.u_v5.v5c->SendHandler;
        OpenBlock->SendPacketsHandler = g_OpenBlock.u1.Versions.u_v5.v5c->SendPacketsHandler;
        OpenBlock->TransferDataCompleteHandler = g_OpenBlock.u1.Versions.u_v5.v5c->TransferDataCompleteHandler;
        OpenBlock->TransferDataHandler = g_OpenBlock.u1.Versions.u_v5.v5c->TransferDataHandler;
        OpenBlock->WanReceiveHandler = g_OpenBlock.u1.Versions.u_v5.v5c->WanReceiveHandler;
        break;

    default:
        return FALSE;
    }

    return TRUE;
}

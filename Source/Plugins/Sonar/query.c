/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       QUERY.C
*
*  VERSION:     1.00
*
*  DATE:        03 July 2019
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


PVOID HeapMemoryAlloc(_In_ SIZE_T Size)
{
    return HeapAlloc(g_ctx.PluginHeap, HEAP_ZERO_MEMORY, Size);
}

BOOL HeapMemoryFree(_In_ PVOID Memory)
{
    if (Memory == NULL) return FALSE;
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

    return Result;
}

/*
* DumpObjectWithSpecifiedSize
*
* Purpose:
*
* Return dumped object version aware.
*
* Use HeapMemoryFree to free returned buffer.
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

    ObjectBuffer = HeapMemoryAlloc(BufferSize);
    if (ObjectBuffer == NULL) {
        return NULL;
    }

    if (!g_ctx.ParamBlock.ReadSystemMemoryEx(
        ObjectAddress,
        ObjectBuffer,
        (ULONG)ObjectSize,
        NULL))
    {
        HeapMemoryFree(ObjectBuffer);
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
    case 7600:
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
    case 7600:
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
* Use HeapMemoryFree to free returned buffer.
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

    DumpedString = (PVOID)HeapMemoryAlloc(tempString.Length + MAX_PATH);
    if (DumpedString) {
        if (g_ctx.ParamBlock.ReadSystemMemoryEx((ULONG_PTR)tempString.Buffer,
            DumpedString,
            tempString.Length,
            &readBytes))
        {
            if (readBytes != tempString.Length) {
                HeapMemoryFree(DumpedString);
                return NULL;
            }
        }

    }

    return DumpedString;
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

    case 7600:
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
    _In_ PROTOCOL_BLOCK_VERSIONS *ProtocolRef,
    _Out_ NDIS_PROTOCOL_BLOCK_COMPATIBLE *ProtoBlock)
{
    switch (ObjectVersion) {

    case 1:
        RtlCopyMemory(&ProtoBlock->Name, &ProtocolRef->u1.Versions.v1->Name, sizeof(UNICODE_STRING));
        RtlCopyMemory(&ProtoBlock->ImageName, &ProtocolRef->u1.Versions.v1->ImageName, sizeof(UNICODE_STRING));
        ProtoBlock->OpenQueue = ProtocolRef->u1.Versions.v1->OpenQueue;
        ProtoBlock->NextProtocol = ProtocolRef->u1.Versions.v1->NextProtocol;
        ProtoBlock->AssociatedMiniDriver = ProtocolRef->u1.Versions.v1->AssociatedMiniDriver;

        ProtoBlock->MajorDriverVersion = ProtocolRef->u1.Versions.v1->MajorDriverVersion;
        ProtoBlock->MajorNdisVersion = ProtocolRef->u1.Versions.v1->MajorNdisVersion;
        ProtoBlock->MinorDriverVersion = ProtocolRef->u1.Versions.v1->MinorDriverVersion;
        ProtoBlock->MinorNdisVersion = ProtocolRef->u1.Versions.v1->MinorNdisVersion;

        ProtoBlock->AllocateSharedMemoryHandler = ProtocolRef->u1.Versions.v1->AllocateSharedMemoryHandler;
        ProtoBlock->BindAdapterHandler = ProtocolRef->u1.Versions.v1->BindAdapterHandler;
        ProtoBlock->BindAdapterHandlerEx = ProtocolRef->u1.Versions.v1->BindAdapterHandlerEx;
        ProtoBlock->BindDeviceName = ProtocolRef->u1.Versions.v1->BindDeviceName;
        ProtoBlock->CloseAdapterCompleteHandler = ProtocolRef->u1.Versions.v1->CloseAdapterCompleteHandler;
        ProtoBlock->CloseAdapterCompleteHandlerEx = ProtocolRef->u1.Versions.v1->CloseAdapterCompleteHandlerEx;
        ProtoBlock->CoAfRegisterNotifyHandler = ProtocolRef->u1.Versions.v1->CoAfRegisterNotifyHandler;
        ProtoBlock->CoReceiveNetBufferListsHandler = ProtocolRef->u1.Versions.v1->CoReceiveNetBufferListsHandler;
        ProtoBlock->CoReceivePacketHandler = ProtocolRef->u1.Versions.v1->CoReceivePacketHandler;
        ProtoBlock->CoSendCompleteHandler = ProtocolRef->u1.Versions.v1->CoSendCompleteHandler;
        ProtoBlock->CoSendNetBufferListsCompleteHandler = ProtocolRef->u1.Versions.v1->CoSendNetBufferListsCompleteHandler;
        ProtoBlock->CoStatusHandler = ProtocolRef->u1.Versions.v1->u3.CoStatusHandler;
        ProtoBlock->DirectOidRequestCompleteHandler = ProtocolRef->u1.Versions.v1->DirectOidRequestCompleteHandler;
        ProtoBlock->FreeSharedMemoryHandler = ProtocolRef->u1.Versions.v1->FreeSharedMemoryHandler;
        ProtoBlock->IndicateOffloadEventHandler = ProtocolRef->u1.Versions.v1->IndicateOffloadEventHandler;
        ProtoBlock->InitiateOffloadCompleteHandler = ProtocolRef->u1.Versions.v1->InitiateOffloadCompleteHandler;
        ProtoBlock->InvalidateOffloadCompleteHandler = ProtocolRef->u1.Versions.v1->InvalidateOffloadCompleteHandler;
        ProtoBlock->OidRequestCompleteHandler = ProtocolRef->u1.Versions.v1->OidRequestCompleteHandler;
        ProtoBlock->OpenAdapterCompleteHandler = ProtocolRef->u1.Versions.v1->OpenAdapterCompleteHandler;
        ProtoBlock->OpenAdapterCompleteHandlerEx = ProtocolRef->u1.Versions.v1->OpenAdapterCompleteHandlerEx;
        ProtoBlock->PnPEventHandler = ProtocolRef->u1.Versions.v1->u1.PnPEventHandler;
        ProtoBlock->QueryOffloadCompleteHandler = ProtocolRef->u1.Versions.v1->QueryOffloadCompleteHandler;
        ProtoBlock->ReceiveCompleteHandler = ProtocolRef->u1.Versions.v1->ReceiveCompleteHandler;
        ProtoBlock->ReceiveHandler = ProtocolRef->u1.Versions.v1->u6.ReceiveHandler;
        ProtoBlock->ReceiveNetBufferListsHandler = ProtocolRef->u1.Versions.v1->ReceiveNetBufferListsHandler;
        ProtoBlock->ReceivePacketHandler = ProtocolRef->u1.Versions.v1->ReceivePacketHandler;
        ProtoBlock->RequestCompleteHandler = ProtocolRef->u1.Versions.v1->RequestCompleteHandler;
        ProtoBlock->ResetCompleteHandler = ProtocolRef->u1.Versions.v1->ResetCompleteHandler;
        ProtoBlock->RootDeviceName = ProtocolRef->u1.Versions.v1->RootDeviceName;
        ProtoBlock->SendCompleteHandler = ProtocolRef->u1.Versions.v1->u4.SendCompleteHandler;
        ProtoBlock->SendNetBufferListsCompleteHandler = ProtocolRef->u1.Versions.v1->SendNetBufferListsCompleteHandler;
        ProtoBlock->StatusCompleteHandler = ProtocolRef->u1.Versions.v1->StatusCompleteHandler;
        ProtoBlock->StatusHandler = ProtocolRef->u1.Versions.v1->u2.StatusHandler;
        ProtoBlock->TcpOffloadDisconnectCompleteHandler = ProtocolRef->u1.Versions.v1->TcpOffloadDisconnectCompleteHandler;
        ProtoBlock->TcpOffloadEventHandler = ProtocolRef->u1.Versions.v1->TcpOffloadEventHandler;
        ProtoBlock->TcpOffloadForwardCompleteHandler = ProtocolRef->u1.Versions.v1->TcpOffloadForwardCompleteHandler;
        ProtoBlock->TcpOffloadReceiveCompleteHandler = ProtocolRef->u1.Versions.v1->TcpOffloadReceiveCompleteHandler;
        ProtoBlock->TcpOffloadReceiveIndicateHandler = ProtocolRef->u1.Versions.v1->TcpOffloadReceiveIndicateHandler;
        ProtoBlock->TcpOffloadSendCompleteHandler = ProtocolRef->u1.Versions.v1->TcpOffloadSendCompleteHandler;
        ProtoBlock->TerminateOffloadCompleteHandler = ProtocolRef->u1.Versions.v1->TerminateOffloadCompleteHandler;
        ProtoBlock->TransferDataCompleteHandler = ProtocolRef->u1.Versions.v1->u5.TransferDataCompleteHandler;
        ProtoBlock->UnbindAdapterHandler = ProtocolRef->u1.Versions.v1->UnbindAdapterHandler;
        ProtoBlock->UnbindAdapterHandlerEx = ProtocolRef->u1.Versions.v1->UnbindAdapterHandlerEx;
        ProtoBlock->UninstallHandler = ProtocolRef->u1.Versions.v1->UninstallHandler;
        ProtoBlock->UnloadHandler = ProtocolRef->u1.Versions.v1->UnloadHandler;
        ProtoBlock->UpdateOffloadCompleteHandler = ProtocolRef->u1.Versions.v1->UpdateOffloadCompleteHandler;
        break;

    case 2:
        RtlCopyMemory(&ProtoBlock->Name, &ProtocolRef->u1.Versions.v2->Name, sizeof(UNICODE_STRING));
        RtlCopyMemory(&ProtoBlock->ImageName, &ProtocolRef->u1.Versions.v2->ImageName, sizeof(UNICODE_STRING));
        ProtoBlock->OpenQueue = ProtocolRef->u1.Versions.v2->OpenQueue;
        ProtoBlock->NextProtocol = ProtocolRef->u1.Versions.v2->NextProtocol;
        ProtoBlock->AssociatedMiniDriver = ProtocolRef->u1.Versions.v2->AssociatedMiniDriver;

        ProtoBlock->MajorDriverVersion = ProtocolRef->u1.Versions.v2->MajorDriverVersion;
        ProtoBlock->MajorNdisVersion = ProtocolRef->u1.Versions.v2->MajorNdisVersion;
        ProtoBlock->MinorDriverVersion = ProtocolRef->u1.Versions.v2->MinorDriverVersion;
        ProtoBlock->MinorNdisVersion = ProtocolRef->u1.Versions.v2->MinorNdisVersion;

        ProtoBlock->AllocateSharedMemoryHandler = ProtocolRef->u1.Versions.v2->AllocateSharedMemoryHandler;
        ProtoBlock->BindAdapterHandler = ProtocolRef->u1.Versions.v2->BindAdapterHandler;
        ProtoBlock->BindAdapterHandlerEx = ProtocolRef->u1.Versions.v2->BindAdapterHandlerEx;
        ProtoBlock->BindDeviceName = ProtocolRef->u1.Versions.v2->BindDeviceName;
        ProtoBlock->CloseAdapterCompleteHandler = ProtocolRef->u1.Versions.v2->CloseAdapterCompleteHandler;
        ProtoBlock->CloseAdapterCompleteHandlerEx = ProtocolRef->u1.Versions.v2->CloseAdapterCompleteHandlerEx;
        ProtoBlock->CoAfRegisterNotifyHandler = ProtocolRef->u1.Versions.v2->CoAfRegisterNotifyHandler;
        ProtoBlock->CoReceiveNetBufferListsHandler = ProtocolRef->u1.Versions.v2->CoReceiveNetBufferListsHandler;
        ProtoBlock->CoReceivePacketHandler = ProtocolRef->u1.Versions.v2->CoReceivePacketHandler;
        ProtoBlock->CoSendCompleteHandler = ProtocolRef->u1.Versions.v2->CoSendCompleteHandler;
        ProtoBlock->CoSendNetBufferListsCompleteHandler = ProtocolRef->u1.Versions.v2->CoSendNetBufferListsCompleteHandler;
        ProtoBlock->CoStatusHandler = ProtocolRef->u1.Versions.v2->u3.CoStatusHandler;
        ProtoBlock->DirectOidRequestCompleteHandler = ProtocolRef->u1.Versions.v2->DirectOidRequestCompleteHandler;
        ProtoBlock->FreeSharedMemoryHandler = ProtocolRef->u1.Versions.v2->FreeSharedMemoryHandler;
        ProtoBlock->IndicateOffloadEventHandler = ProtocolRef->u1.Versions.v2->IndicateOffloadEventHandler;
        ProtoBlock->InitiateOffloadCompleteHandler = ProtocolRef->u1.Versions.v2->InitiateOffloadCompleteHandler;
        ProtoBlock->InvalidateOffloadCompleteHandler = ProtocolRef->u1.Versions.v2->InvalidateOffloadCompleteHandler;
        ProtoBlock->OidRequestCompleteHandler = ProtocolRef->u1.Versions.v2->OidRequestCompleteHandler;
        ProtoBlock->OpenAdapterCompleteHandler = ProtocolRef->u1.Versions.v2->OpenAdapterCompleteHandler;
        ProtoBlock->OpenAdapterCompleteHandlerEx = ProtocolRef->u1.Versions.v2->OpenAdapterCompleteHandlerEx;
        ProtoBlock->PnPEventHandler = ProtocolRef->u1.Versions.v2->u1.PnPEventHandler;
        ProtoBlock->QueryOffloadCompleteHandler = ProtocolRef->u1.Versions.v2->QueryOffloadCompleteHandler;
        ProtoBlock->ReceiveCompleteHandler = ProtocolRef->u1.Versions.v2->ReceiveCompleteHandler;
        ProtoBlock->ReceiveHandler = ProtocolRef->u1.Versions.v2->u6.ReceiveHandler;
        ProtoBlock->ReceiveNetBufferListsHandler = ProtocolRef->u1.Versions.v2->ReceiveNetBufferListsHandler;
        ProtoBlock->ReceivePacketHandler = ProtocolRef->u1.Versions.v2->ReceivePacketHandler;
        ProtoBlock->RequestCompleteHandler = ProtocolRef->u1.Versions.v2->RequestCompleteHandler;
        ProtoBlock->ResetCompleteHandler = ProtocolRef->u1.Versions.v2->ResetCompleteHandler;
        ProtoBlock->RootDeviceName = ProtocolRef->u1.Versions.v2->RootDeviceName;
        ProtoBlock->SendCompleteHandler = ProtocolRef->u1.Versions.v2->u4.SendCompleteHandler;
        ProtoBlock->SendNetBufferListsCompleteHandler = ProtocolRef->u1.Versions.v2->SendNetBufferListsCompleteHandler;
        ProtoBlock->StatusCompleteHandler = ProtocolRef->u1.Versions.v2->StatusCompleteHandler;
        ProtoBlock->StatusHandler = ProtocolRef->u1.Versions.v2->u2.StatusHandler;
        ProtoBlock->TcpOffloadDisconnectCompleteHandler = ProtocolRef->u1.Versions.v2->TcpOffloadDisconnectCompleteHandler;
        ProtoBlock->TcpOffloadEventHandler = ProtocolRef->u1.Versions.v2->TcpOffloadEventHandler;
        ProtoBlock->TcpOffloadForwardCompleteHandler = ProtocolRef->u1.Versions.v2->TcpOffloadForwardCompleteHandler;
        ProtoBlock->TcpOffloadReceiveCompleteHandler = ProtocolRef->u1.Versions.v2->TcpOffloadReceiveCompleteHandler;
        ProtoBlock->TcpOffloadReceiveIndicateHandler = ProtocolRef->u1.Versions.v2->TcpOffloadReceiveIndicateHandler;
        ProtoBlock->TcpOffloadSendCompleteHandler = ProtocolRef->u1.Versions.v2->TcpOffloadSendCompleteHandler;
        ProtoBlock->TerminateOffloadCompleteHandler = ProtocolRef->u1.Versions.v2->TerminateOffloadCompleteHandler;
        ProtoBlock->TransferDataCompleteHandler = ProtocolRef->u1.Versions.v2->u5.TransferDataCompleteHandler;
        ProtoBlock->UnbindAdapterHandler = ProtocolRef->u1.Versions.v2->UnbindAdapterHandler;
        ProtoBlock->UnbindAdapterHandlerEx = ProtocolRef->u1.Versions.v2->UnbindAdapterHandlerEx;
        ProtoBlock->UninstallHandler = ProtocolRef->u1.Versions.v2->UninstallHandler;
        ProtoBlock->UnloadHandler = ProtocolRef->u1.Versions.v2->UnloadHandler;
        ProtoBlock->UpdateOffloadCompleteHandler = ProtocolRef->u1.Versions.v2->UpdateOffloadCompleteHandler;
        break;

    case 3:
        RtlCopyMemory(&ProtoBlock->Name, &ProtocolRef->u1.Versions.v3->Name, sizeof(UNICODE_STRING));
        RtlCopyMemory(&ProtoBlock->ImageName, &ProtocolRef->u1.Versions.v3->ImageName, sizeof(UNICODE_STRING));
        ProtoBlock->OpenQueue = ProtocolRef->u1.Versions.v3->OpenQueue;
        ProtoBlock->NextProtocol = ProtocolRef->u1.Versions.v3->NextProtocol;
        ProtoBlock->AssociatedMiniDriver = ProtocolRef->u1.Versions.v3->AssociatedMiniDriver;

        ProtoBlock->MajorDriverVersion = ProtocolRef->u1.Versions.v3->MajorDriverVersion;
        ProtoBlock->MajorNdisVersion = ProtocolRef->u1.Versions.v3->MajorNdisVersion;
        ProtoBlock->MinorDriverVersion = ProtocolRef->u1.Versions.v3->MinorDriverVersion;
        ProtoBlock->MinorNdisVersion = ProtocolRef->u1.Versions.v3->MinorNdisVersion;

        ProtoBlock->AllocateSharedMemoryHandler = ProtocolRef->u1.Versions.v3->AllocateSharedMemoryHandler;
        ProtoBlock->BindAdapterHandler = ProtocolRef->u1.Versions.v3->BindAdapterHandler;
        ProtoBlock->BindAdapterHandlerEx = ProtocolRef->u1.Versions.v3->BindAdapterHandlerEx;
        ProtoBlock->BindDeviceName = ProtocolRef->u1.Versions.v3->BindDeviceName;
        ProtoBlock->CloseAdapterCompleteHandler = ProtocolRef->u1.Versions.v3->CloseAdapterCompleteHandler;
        ProtoBlock->CloseAdapterCompleteHandlerEx = ProtocolRef->u1.Versions.v3->CloseAdapterCompleteHandlerEx;
        ProtoBlock->CoAfRegisterNotifyHandler = ProtocolRef->u1.Versions.v3->CoAfRegisterNotifyHandler;
        ProtoBlock->CoReceiveNetBufferListsHandler = ProtocolRef->u1.Versions.v3->CoReceiveNetBufferListsHandler;
        ProtoBlock->CoReceivePacketHandler = ProtocolRef->u1.Versions.v3->CoReceivePacketHandler;
        ProtoBlock->CoSendCompleteHandler = ProtocolRef->u1.Versions.v3->CoSendCompleteHandler;
        ProtoBlock->CoSendNetBufferListsCompleteHandler = ProtocolRef->u1.Versions.v3->CoSendNetBufferListsCompleteHandler;
        ProtoBlock->CoStatusHandler = ProtocolRef->u1.Versions.v3->u3.CoStatusHandler;
        ProtoBlock->DirectOidRequestCompleteHandler = ProtocolRef->u1.Versions.v3->DirectOidRequestCompleteHandler;
        ProtoBlock->FreeSharedMemoryHandler = ProtocolRef->u1.Versions.v3->FreeSharedMemoryHandler;
        ProtoBlock->IndicateOffloadEventHandler = ProtocolRef->u1.Versions.v3->IndicateOffloadEventHandler;
        ProtoBlock->InitiateOffloadCompleteHandler = ProtocolRef->u1.Versions.v3->InitiateOffloadCompleteHandler;
        ProtoBlock->InvalidateOffloadCompleteHandler = ProtocolRef->u1.Versions.v3->InvalidateOffloadCompleteHandler;
        ProtoBlock->OidRequestCompleteHandler = ProtocolRef->u1.Versions.v3->OidRequestCompleteHandler;
        ProtoBlock->OpenAdapterCompleteHandler = ProtocolRef->u1.Versions.v3->OpenAdapterCompleteHandler;
        ProtoBlock->OpenAdapterCompleteHandlerEx = ProtocolRef->u1.Versions.v3->OpenAdapterCompleteHandlerEx;
        ProtoBlock->PnPEventHandler = ProtocolRef->u1.Versions.v3->u1.PnPEventHandler;
        ProtoBlock->QueryOffloadCompleteHandler = ProtocolRef->u1.Versions.v3->QueryOffloadCompleteHandler;
        ProtoBlock->ReceiveCompleteHandler = ProtocolRef->u1.Versions.v3->ReceiveCompleteHandler;
        ProtoBlock->ReceiveHandler = ProtocolRef->u1.Versions.v3->u6.ReceiveHandler;
        ProtoBlock->ReceiveNetBufferListsHandler = ProtocolRef->u1.Versions.v3->ReceiveNetBufferListsHandler;
        ProtoBlock->ReceivePacketHandler = ProtocolRef->u1.Versions.v3->ReceivePacketHandler;
        ProtoBlock->RequestCompleteHandler = ProtocolRef->u1.Versions.v3->RequestCompleteHandler;
        ProtoBlock->ResetCompleteHandler = ProtocolRef->u1.Versions.v3->ResetCompleteHandler;
        ProtoBlock->RootDeviceName = ProtocolRef->u1.Versions.v3->RootDeviceName;
        ProtoBlock->SendCompleteHandler = ProtocolRef->u1.Versions.v3->u4.SendCompleteHandler;
        ProtoBlock->SendNetBufferListsCompleteHandler = ProtocolRef->u1.Versions.v3->SendNetBufferListsCompleteHandler;
        ProtoBlock->StatusCompleteHandler = ProtocolRef->u1.Versions.v3->StatusCompleteHandler;
        ProtoBlock->StatusHandler = ProtocolRef->u1.Versions.v3->u2.StatusHandler;
        ProtoBlock->TcpOffloadDisconnectCompleteHandler = ProtocolRef->u1.Versions.v3->TcpOffloadDisconnectCompleteHandler;
        ProtoBlock->TcpOffloadEventHandler = ProtocolRef->u1.Versions.v3->TcpOffloadEventHandler;
        ProtoBlock->TcpOffloadForwardCompleteHandler = ProtocolRef->u1.Versions.v3->TcpOffloadForwardCompleteHandler;
        ProtoBlock->TcpOffloadReceiveCompleteHandler = ProtocolRef->u1.Versions.v3->TcpOffloadReceiveCompleteHandler;
        ProtoBlock->TcpOffloadReceiveIndicateHandler = ProtocolRef->u1.Versions.v3->TcpOffloadReceiveIndicateHandler;
        ProtoBlock->TcpOffloadSendCompleteHandler = ProtocolRef->u1.Versions.v3->TcpOffloadSendCompleteHandler;
        ProtoBlock->TerminateOffloadCompleteHandler = ProtocolRef->u1.Versions.v3->TerminateOffloadCompleteHandler;
        ProtoBlock->TransferDataCompleteHandler = ProtocolRef->u1.Versions.v3->u5.TransferDataCompleteHandler;
        ProtoBlock->UnbindAdapterHandler = ProtocolRef->u1.Versions.v3->UnbindAdapterHandler;
        ProtoBlock->UnbindAdapterHandlerEx = ProtocolRef->u1.Versions.v3->UnbindAdapterHandlerEx;
        ProtoBlock->UninstallHandler = ProtocolRef->u1.Versions.v3->UninstallHandler;
        ProtoBlock->UnloadHandler = ProtocolRef->u1.Versions.v3->UnloadHandler;
        ProtoBlock->UpdateOffloadCompleteHandler = ProtocolRef->u1.Versions.v3->UpdateOffloadCompleteHandler;
        break;

    case 4:
        RtlCopyMemory(&ProtoBlock->Name, &ProtocolRef->u1.Versions.v4->Name, sizeof(UNICODE_STRING));
        RtlCopyMemory(&ProtoBlock->ImageName, &ProtocolRef->u1.Versions.v4->ImageName, sizeof(UNICODE_STRING));
        ProtoBlock->OpenQueue = ProtocolRef->u1.Versions.v4->OpenQueue;
        ProtoBlock->NextProtocol = ProtocolRef->u1.Versions.v4->NextProtocol;
        ProtoBlock->AssociatedMiniDriver = ProtocolRef->u1.Versions.v4->AssociatedMiniDriver;

        ProtoBlock->MajorDriverVersion = ProtocolRef->u1.Versions.v4->MajorDriverVersion;
        ProtoBlock->MajorNdisVersion = ProtocolRef->u1.Versions.v4->MajorNdisVersion;
        ProtoBlock->MinorDriverVersion = ProtocolRef->u1.Versions.v4->MinorDriverVersion;
        ProtoBlock->MinorNdisVersion = ProtocolRef->u1.Versions.v4->MinorNdisVersion;

        ProtoBlock->AllocateSharedMemoryHandler = ProtocolRef->u1.Versions.v4->AllocateSharedMemoryHandler;
        ProtoBlock->BindAdapterHandler = ProtocolRef->u1.Versions.v4->BindAdapterHandler;
        ProtoBlock->BindAdapterHandlerEx = ProtocolRef->u1.Versions.v4->BindAdapterHandlerEx;
        ProtoBlock->BindDeviceName = ProtocolRef->u1.Versions.v4->BindDeviceName;
        ProtoBlock->CloseAdapterCompleteHandler = ProtocolRef->u1.Versions.v4->CloseAdapterCompleteHandler;
        ProtoBlock->CloseAdapterCompleteHandlerEx = ProtocolRef->u1.Versions.v4->CloseAdapterCompleteHandlerEx;
        ProtoBlock->CoAfRegisterNotifyHandler = ProtocolRef->u1.Versions.v4->CoAfRegisterNotifyHandler;
        ProtoBlock->CoReceiveNetBufferListsHandler = ProtocolRef->u1.Versions.v4->CoReceiveNetBufferListsHandler;
        ProtoBlock->CoReceivePacketHandler = ProtocolRef->u1.Versions.v4->CoReceivePacketHandler;
        ProtoBlock->CoSendCompleteHandler = ProtocolRef->u1.Versions.v4->CoSendCompleteHandler;
        ProtoBlock->CoSendNetBufferListsCompleteHandler = ProtocolRef->u1.Versions.v4->CoSendNetBufferListsCompleteHandler;
        ProtoBlock->CoStatusHandler = ProtocolRef->u1.Versions.v4->u3.CoStatusHandler;
        ProtoBlock->DirectOidRequestCompleteHandler = ProtocolRef->u1.Versions.v4->DirectOidRequestCompleteHandler;
        ProtoBlock->FreeSharedMemoryHandler = ProtocolRef->u1.Versions.v4->FreeSharedMemoryHandler;
        ProtoBlock->OidRequestCompleteHandler = ProtocolRef->u1.Versions.v4->OidRequestCompleteHandler;
        ProtoBlock->OpenAdapterCompleteHandler = ProtocolRef->u1.Versions.v4->OpenAdapterCompleteHandler;
        ProtoBlock->OpenAdapterCompleteHandlerEx = ProtocolRef->u1.Versions.v4->OpenAdapterCompleteHandlerEx;
        ProtoBlock->PnPEventHandler = ProtocolRef->u1.Versions.v4->u1.PnPEventHandler;
        ProtoBlock->ReceiveCompleteHandler = ProtocolRef->u1.Versions.v4->ReceiveCompleteHandler;
        ProtoBlock->ReceiveHandler = ProtocolRef->u1.Versions.v4->u6.ReceiveHandler;
        ProtoBlock->ReceiveNetBufferListsHandler = ProtocolRef->u1.Versions.v4->ReceiveNetBufferListsHandler;
        ProtoBlock->ReceivePacketHandler = ProtocolRef->u1.Versions.v4->ReceivePacketHandler;
        ProtoBlock->RequestCompleteHandler = ProtocolRef->u1.Versions.v4->RequestCompleteHandler;
        ProtoBlock->ResetCompleteHandler = ProtocolRef->u1.Versions.v4->ResetCompleteHandler;
        ProtoBlock->RootDeviceName = ProtocolRef->u1.Versions.v4->RootDeviceName;
        ProtoBlock->SendCompleteHandler = ProtocolRef->u1.Versions.v4->u4.SendCompleteHandler;
        ProtoBlock->SendNetBufferListsCompleteHandler = ProtocolRef->u1.Versions.v4->SendNetBufferListsCompleteHandler;
        ProtoBlock->StatusCompleteHandler = ProtocolRef->u1.Versions.v4->StatusCompleteHandler;
        ProtoBlock->StatusHandler = ProtocolRef->u1.Versions.v4->u2.StatusHandler;
        ProtoBlock->TransferDataCompleteHandler = ProtocolRef->u1.Versions.v4->u5.TransferDataCompleteHandler;
        ProtoBlock->UnbindAdapterHandler = ProtocolRef->u1.Versions.v4->UnbindAdapterHandler;
        ProtoBlock->UnbindAdapterHandlerEx = ProtocolRef->u1.Versions.v4->UnbindAdapterHandlerEx;
        ProtoBlock->UninstallHandler = ProtocolRef->u1.Versions.v4->UninstallHandler;
        ProtoBlock->UnloadHandler = ProtocolRef->u1.Versions.v4->UnloadHandler;
        break;

    case 5:
        RtlCopyMemory(&ProtoBlock->Name, &ProtocolRef->u1.Versions.v5->Name, sizeof(UNICODE_STRING));
        RtlCopyMemory(&ProtoBlock->ImageName, &ProtocolRef->u1.Versions.v5->ImageName, sizeof(UNICODE_STRING));
        ProtoBlock->OpenQueue = ProtocolRef->u1.Versions.v5->OpenQueue;
        ProtoBlock->NextProtocol = ProtocolRef->u1.Versions.v5->NextProtocol;
        ProtoBlock->AssociatedMiniDriver = ProtocolRef->u1.Versions.v5->AssociatedMiniDriver;

        ProtoBlock->MajorDriverVersion = ProtocolRef->u1.Versions.v5->MajorDriverVersion;
        ProtoBlock->MajorNdisVersion = ProtocolRef->u1.Versions.v5->MajorNdisVersion;
        ProtoBlock->MinorDriverVersion = ProtocolRef->u1.Versions.v5->MinorDriverVersion;
        ProtoBlock->MinorNdisVersion = ProtocolRef->u1.Versions.v5->MinorNdisVersion;

        ProtoBlock->AllocateSharedMemoryHandler = ProtocolRef->u1.Versions.v5->AllocateSharedMemoryHandler;
        ProtoBlock->BindAdapterHandler = ProtocolRef->u1.Versions.v5->BindAdapterHandler;
        ProtoBlock->BindAdapterHandlerEx = ProtocolRef->u1.Versions.v5->BindAdapterHandlerEx;
        ProtoBlock->BindDeviceName = ProtocolRef->u1.Versions.v5->BindDeviceName;
        ProtoBlock->CloseAdapterCompleteHandler = ProtocolRef->u1.Versions.v5->CloseAdapterCompleteHandler;
        ProtoBlock->CloseAdapterCompleteHandlerEx = ProtocolRef->u1.Versions.v5->CloseAdapterCompleteHandlerEx;
        ProtoBlock->CoAfRegisterNotifyHandler = ProtocolRef->u1.Versions.v5->CoAfRegisterNotifyHandler;
        ProtoBlock->CoReceiveNetBufferListsHandler = ProtocolRef->u1.Versions.v5->CoReceiveNetBufferListsHandler;
        ProtoBlock->CoReceivePacketHandler = ProtocolRef->u1.Versions.v5->CoReceivePacketHandler;
        ProtoBlock->CoSendCompleteHandler = ProtocolRef->u1.Versions.v5->CoSendCompleteHandler;
        ProtoBlock->CoSendNetBufferListsCompleteHandler = ProtocolRef->u1.Versions.v5->CoSendNetBufferListsCompleteHandler;
        ProtoBlock->CoStatusHandler = ProtocolRef->u1.Versions.v5->u3.CoStatusHandler;
        ProtoBlock->DirectOidRequestCompleteHandler = ProtocolRef->u1.Versions.v5->DirectOidRequestCompleteHandler;
        ProtoBlock->FreeSharedMemoryHandler = ProtocolRef->u1.Versions.v5->FreeSharedMemoryHandler;
        ProtoBlock->OidRequestCompleteHandler = ProtocolRef->u1.Versions.v5->OidRequestCompleteHandler;
        ProtoBlock->OpenAdapterCompleteHandler = ProtocolRef->u1.Versions.v5->OpenAdapterCompleteHandler;
        ProtoBlock->OpenAdapterCompleteHandlerEx = ProtocolRef->u1.Versions.v5->OpenAdapterCompleteHandlerEx;
        ProtoBlock->PnPEventHandler = ProtocolRef->u1.Versions.v5->u1.PnPEventHandler;
        ProtoBlock->ReceiveCompleteHandler = ProtocolRef->u1.Versions.v5->ReceiveCompleteHandler;
        ProtoBlock->ReceiveHandler = ProtocolRef->u1.Versions.v5->u6.ReceiveHandler;
        ProtoBlock->ReceiveNetBufferListsHandler = ProtocolRef->u1.Versions.v5->ReceiveNetBufferListsHandler;
        ProtoBlock->ReceivePacketHandler = ProtocolRef->u1.Versions.v5->ReceivePacketHandler;
        ProtoBlock->RequestCompleteHandler = ProtocolRef->u1.Versions.v5->RequestCompleteHandler;
        ProtoBlock->ResetCompleteHandler = ProtocolRef->u1.Versions.v5->ResetCompleteHandler;
        ProtoBlock->RootDeviceName = ProtocolRef->u1.Versions.v5->RootDeviceName;
        ProtoBlock->SendCompleteHandler = ProtocolRef->u1.Versions.v5->u4.SendCompleteHandler;
        ProtoBlock->SendNetBufferListsCompleteHandler = ProtocolRef->u1.Versions.v5->SendNetBufferListsCompleteHandler;
        ProtoBlock->StatusCompleteHandler = ProtocolRef->u1.Versions.v5->StatusCompleteHandler;
        ProtoBlock->StatusHandler = ProtocolRef->u1.Versions.v5->u2.StatusHandler;
        ProtoBlock->TransferDataCompleteHandler = ProtocolRef->u1.Versions.v5->u5.TransferDataCompleteHandler;
        ProtoBlock->UnbindAdapterHandler = ProtocolRef->u1.Versions.v5->UnbindAdapterHandler;
        ProtoBlock->UnbindAdapterHandlerEx = ProtocolRef->u1.Versions.v5->UnbindAdapterHandlerEx;
        ProtoBlock->UninstallHandler = ProtocolRef->u1.Versions.v5->UninstallHandler;
        ProtoBlock->UnloadHandler = ProtocolRef->u1.Versions.v5->UnloadHandler;
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
    _In_ OPEN_BLOCK_VERSIONS *BlockRef,
    _Out_ NDIS_OPEN_BLOCK_COMPATIBLE *OpenBlock)
{
    switch (ObjectVersion) {

    case 1: //7600..7601
        OpenBlock->ProtocolNextOpen = BlockRef->u1.Versions.v1->ProtocolNextOpen;
        OpenBlock->BindDeviceName = BlockRef->u1.Versions.v1->BindDeviceName;
        OpenBlock->RootDeviceName = BlockRef->u1.Versions.v1->RootDeviceName;

        OpenBlock->AllocateSharedMemoryHandler = BlockRef->u1.Versions.v1->AllocateSharedMemoryHandler;
        OpenBlock->CancelSendPacketsHandler = BlockRef->u1.Versions.v1->CancelSendPacketsHandler;
        OpenBlock->CmActivateVcCompleteHandler = BlockRef->u1.Versions.v1->CmActivateVcCompleteHandler;
        OpenBlock->CmDeactivateVcCompleteHandler = BlockRef->u1.Versions.v1->CmDeactivateVcCompleteHandler;
        OpenBlock->CoCreateVcHandler = BlockRef->u1.Versions.v1->CoCreateVcHandler;
        OpenBlock->CoDeleteVcHandler = BlockRef->u1.Versions.v1->CoDeleteVcHandler;
        OpenBlock->CoOidRequestCompleteHandler = BlockRef->u1.Versions.v1->CoOidRequestCompleteHandler;
        OpenBlock->CoOidRequestHandler = BlockRef->u1.Versions.v1->CoOidRequestHandler;
        OpenBlock->CoRequestCompleteHandler = BlockRef->u1.Versions.v1->CoRequestCompleteHandler;
        OpenBlock->CoRequestHandler = BlockRef->u1.Versions.v1->CoRequestHandler;
        OpenBlock->DirectOidRequestCompleteHandler = BlockRef->u1.Versions.v1->DirectOidRequestCompleteHandler;
        OpenBlock->DirectOidRequestHandler = BlockRef->u1.Versions.v1->DirectOidRequestHandler;
        OpenBlock->FreeSharedMemoryHandler = BlockRef->u1.Versions.v1->FreeSharedMemoryHandler;
        OpenBlock->IndicateOffloadEventHandler = BlockRef->u1.Versions.v1->IndicateOffloadEventHandler;
        OpenBlock->InitiateOffloadCompleteHandler = BlockRef->u1.Versions.v1->InitiateOffloadCompleteHandler;
        OpenBlock->InvalidateOffloadCompleteHandler = BlockRef->u1.Versions.v1->InvalidateOffloadCompleteHandler;
        OpenBlock->MiniportCoCreateVcHandler = BlockRef->u1.Versions.v1->MiniportCoCreateVcHandler;
        OpenBlock->MiniportCoOidRequestHandler = BlockRef->u1.Versions.v1->MiniportCoOidRequestHandler;
        OpenBlock->MiniportCoRequestHandler = BlockRef->u1.Versions.v1->MiniportCoRequestHandler;
        OpenBlock->Ndis5WanSendHandler = BlockRef->u1.Versions.v1->Ndis5WanSendHandler;
        OpenBlock->NextReturnNetBufferListsHandler = BlockRef->u1.Versions.v1->NextReturnNetBufferListsHandler;
        OpenBlock->NextSendHandler = BlockRef->u1.Versions.v1->NextSendHandler;
        OpenBlock->OidRequestCompleteHandler = BlockRef->u1.Versions.v1->OidRequestCompleteHandler;
        OpenBlock->OidRequestHandler = BlockRef->u1.Versions.v1->OidRequestHandler;
        OpenBlock->ProtSendCompleteHandler = BlockRef->u1.Versions.v1->ProtSendCompleteHandler;
        OpenBlock->ProtSendNetBufferListsComplete = BlockRef->u1.Versions.v1->ProtSendNetBufferListsComplete;
        OpenBlock->QueryOffloadCompleteHandler = BlockRef->u1.Versions.v1->QueryOffloadCompleteHandler;
        OpenBlock->ReceiveCompleteHandler = BlockRef->u1.Versions.v1->ReceiveCompleteHandler;
        OpenBlock->ReceiveHandler = BlockRef->u1.Versions.v1->ReceiveHandler;
        OpenBlock->ReceiveNetBufferLists = BlockRef->u1.Versions.v1->ReceiveNetBufferLists;
        OpenBlock->ReceivePacketHandler = BlockRef->u1.Versions.v1->ReceivePacketHandler;
        OpenBlock->RequestCompleteHandler = BlockRef->u1.Versions.v1->RequestCompleteHandler;
        OpenBlock->RequestHandler = BlockRef->u1.Versions.v1->RequestHandler;
        OpenBlock->ResetCompleteHandler = BlockRef->u1.Versions.v1->ResetCompleteHandler;
        OpenBlock->ResetHandler = BlockRef->u1.Versions.v1->ResetHandler;
        OpenBlock->SavedCancelSendPacketsHandler = BlockRef->u1.Versions.v1->SavedCancelSendPacketsHandler;
        OpenBlock->SavedSendHandler = BlockRef->u1.Versions.v1->SavedSendHandler;
        OpenBlock->SavedSendNBLHandler = BlockRef->u1.Versions.v1->SavedSendNBLHandler;
        OpenBlock->SavedSendPacketsHandler = BlockRef->u1.Versions.v1->SavedSendPacketsHandler;
        OpenBlock->SendCompleteHandler = BlockRef->u1.Versions.v1->SendCompleteHandler;
        OpenBlock->SendHandler = BlockRef->u1.Versions.v1->SendHandler;
        OpenBlock->SendPacketsHandler = BlockRef->u1.Versions.v1->SendPacketsHandler;
        OpenBlock->StatusCompleteHandler = BlockRef->u1.Versions.v1->StatusCompleteHandler;
        OpenBlock->StatusHandler = BlockRef->u1.Versions.v1->StatusHandler;
        OpenBlock->TcpOffloadDisconnectCompleteHandler = BlockRef->u1.Versions.v1->TcpOffloadDisconnectCompleteHandler;
        OpenBlock->TcpOffloadEventHandler = BlockRef->u1.Versions.v1->TcpOffloadEventHandler;
        OpenBlock->TcpOffloadForwardCompleteHandler = BlockRef->u1.Versions.v1->TcpOffloadForwardCompleteHandler;
        OpenBlock->TcpOffloadReceiveCompleteHandler = BlockRef->u1.Versions.v1->TcpOffloadReceiveCompleteHandler;
        OpenBlock->TcpOffloadReceiveIndicateHandler = BlockRef->u1.Versions.v1->TcpOffloadReceiveIndicateHandler;
        OpenBlock->TcpOffloadSendCompleteHandler = BlockRef->u1.Versions.v1->TcpOffloadSendCompleteHandler;
        OpenBlock->TerminateOffloadCompleteHandler = BlockRef->u1.Versions.v1->TerminateOffloadCompleteHandler;
        OpenBlock->TransferDataCompleteHandler = BlockRef->u1.Versions.v1->TransferDataCompleteHandler;
        OpenBlock->TransferDataHandler = BlockRef->u1.Versions.v1->TransferDataHandler;
        OpenBlock->UpdateOffloadCompleteHandler = BlockRef->u1.Versions.v1->UpdateOffloadCompleteHandler;
        OpenBlock->WanReceiveHandler = BlockRef->u1.Versions.v1->WanReceiveHandler;
        OpenBlock->WSendHandler = BlockRef->u1.Versions.v1->WSendHandler;
        OpenBlock->WSendPacketsHandler = BlockRef->u1.Versions.v1->WSendPacketsHandler;
        OpenBlock->WTransferDataHandler = BlockRef->u1.Versions.v1->WTransferDataHandler;
        break;

    case 2: //9200
        OpenBlock->ProtocolNextOpen = BlockRef->u1.Versions.v2->ProtocolNextOpen;
        OpenBlock->BindDeviceName = BlockRef->u1.Versions.v2->BindDeviceName;
        OpenBlock->RootDeviceName = BlockRef->u1.Versions.v2->RootDeviceName;

        OpenBlock->AllocateSharedMemoryHandler = BlockRef->u1.Versions.v2->AllocateSharedMemoryHandler;
        OpenBlock->CancelSendPacketsHandler = BlockRef->u1.Versions.v2->CancelSendPacketsHandler;
        OpenBlock->CmActivateVcCompleteHandler = BlockRef->u1.Versions.v2->CmActivateVcCompleteHandler;
        OpenBlock->CmDeactivateVcCompleteHandler = BlockRef->u1.Versions.v2->CmDeactivateVcCompleteHandler;
        OpenBlock->CoCreateVcHandler = BlockRef->u1.Versions.v2->CoCreateVcHandler;
        OpenBlock->CoDeleteVcHandler = BlockRef->u1.Versions.v2->CoDeleteVcHandler;
        OpenBlock->CoOidRequestCompleteHandler = BlockRef->u1.Versions.v2->CoOidRequestCompleteHandler;
        OpenBlock->CoOidRequestHandler = BlockRef->u1.Versions.v2->CoOidRequestHandler;
        OpenBlock->CoRequestCompleteHandler = BlockRef->u1.Versions.v2->CoRequestCompleteHandler;
        OpenBlock->CoRequestHandler = BlockRef->u1.Versions.v2->CoRequestHandler;
        OpenBlock->DirectOidRequestHandler = BlockRef->u1.Versions.v2->DirectOidRequestHandler;
        OpenBlock->FreeSharedMemoryHandler = BlockRef->u1.Versions.v2->FreeSharedMemoryHandler;
        OpenBlock->IndicateOffloadEventHandler = BlockRef->u1.Versions.v2->IndicateOffloadEventHandler;
        OpenBlock->InitiateOffloadCompleteHandler = BlockRef->u1.Versions.v2->InitiateOffloadCompleteHandler;
        OpenBlock->InvalidateOffloadCompleteHandler = BlockRef->u1.Versions.v2->InvalidateOffloadCompleteHandler;
        OpenBlock->MiniportCoCreateVcHandler = BlockRef->u1.Versions.v2->MiniportCoCreateVcHandler;
        OpenBlock->MiniportCoOidRequestHandler = BlockRef->u1.Versions.v2->MiniportCoOidRequestHandler;
        OpenBlock->MiniportCoRequestHandler = BlockRef->u1.Versions.v2->MiniportCoRequestHandler;
        OpenBlock->Ndis5WanSendHandler = BlockRef->u1.Versions.v2->Ndis5WanSendHandler;
        OpenBlock->NextReturnNetBufferListsHandler = BlockRef->u1.Versions.v2->NextReturnNetBufferListsHandler;
        OpenBlock->NextSendHandler = BlockRef->u1.Versions.v2->NextSendHandler;
        OpenBlock->OidRequestCompleteHandler = BlockRef->u1.Versions.v2->OidRequestCompleteHandler;
        OpenBlock->OidRequestHandler = BlockRef->u1.Versions.v2->OidRequestHandler;
        OpenBlock->ProtSendCompleteHandler = BlockRef->u1.Versions.v2->ProtSendCompleteHandler;
        OpenBlock->ProtSendNetBufferListsComplete = BlockRef->u1.Versions.v2->ProtSendNetBufferListsComplete;
        OpenBlock->QueryOffloadCompleteHandler = BlockRef->u1.Versions.v2->QueryOffloadCompleteHandler;
        OpenBlock->ReceiveCompleteHandler = BlockRef->u1.Versions.v2->ReceiveCompleteHandler;
        OpenBlock->ReceiveHandler = BlockRef->u1.Versions.v2->ReceiveHandler;
        OpenBlock->ReceiveNetBufferLists = BlockRef->u1.Versions.v2->ReceiveNetBufferLists;
        OpenBlock->ReceivePacketHandler = BlockRef->u1.Versions.v2->ReceivePacketHandler;
        OpenBlock->RequestCompleteHandler = BlockRef->u1.Versions.v2->RequestCompleteHandler;
        OpenBlock->RequestHandler = BlockRef->u1.Versions.v2->RequestHandler;
        OpenBlock->ResetCompleteHandler = BlockRef->u1.Versions.v2->ResetCompleteHandler;
        OpenBlock->ResetHandler = BlockRef->u1.Versions.v2->ResetHandler;
        OpenBlock->SavedCancelSendPacketsHandler = BlockRef->u1.Versions.v2->SavedCancelSendPacketsHandler;
        OpenBlock->SavedSendHandler = BlockRef->u1.Versions.v2->SavedSendHandler;
        OpenBlock->SavedSendPacketsHandler = BlockRef->u1.Versions.v2->SavedSendPacketsHandler;
        OpenBlock->SendCompleteHandler = BlockRef->u1.Versions.v2->SendCompleteHandler;
        OpenBlock->SendHandler = BlockRef->u1.Versions.v2->SendHandler;
        OpenBlock->SendPacketsHandler = BlockRef->u1.Versions.v2->SendPacketsHandler;
        OpenBlock->StatusCompleteHandler = BlockRef->u1.Versions.v2->StatusCompleteHandler;
        OpenBlock->StatusHandler = BlockRef->u1.Versions.v2->StatusHandler;
        OpenBlock->TcpOffloadDisconnectCompleteHandler = BlockRef->u1.Versions.v2->TcpOffloadDisconnectCompleteHandler;
        OpenBlock->TcpOffloadEventHandler = BlockRef->u1.Versions.v2->TcpOffloadEventHandler;
        OpenBlock->TcpOffloadForwardCompleteHandler = BlockRef->u1.Versions.v2->TcpOffloadForwardCompleteHandler;
        OpenBlock->TcpOffloadReceiveCompleteHandler = BlockRef->u1.Versions.v2->TcpOffloadReceiveCompleteHandler;
        OpenBlock->TcpOffloadReceiveIndicateHandler = BlockRef->u1.Versions.v2->TcpOffloadReceiveIndicateHandler;
        OpenBlock->TcpOffloadSendCompleteHandler = BlockRef->u1.Versions.v2->TcpOffloadSendCompleteHandler;
        OpenBlock->TerminateOffloadCompleteHandler = BlockRef->u1.Versions.v2->TerminateOffloadCompleteHandler;
        OpenBlock->TransferDataCompleteHandler = BlockRef->u1.Versions.v2->TransferDataCompleteHandler;
        OpenBlock->TransferDataHandler = BlockRef->u1.Versions.v2->TransferDataHandler;
        OpenBlock->UpdateOffloadCompleteHandler = BlockRef->u1.Versions.v2->UpdateOffloadCompleteHandler;
        OpenBlock->WanReceiveHandler = BlockRef->u1.Versions.v2->WanReceiveHandler;
        OpenBlock->WSendHandler = BlockRef->u1.Versions.v2->WSendHandler;
        OpenBlock->WSendPacketsHandler = BlockRef->u1.Versions.v2->WSendPacketsHandler;
        OpenBlock->WTransferDataHandler = BlockRef->u1.Versions.v2->WTransferDataHandler;
        break;

    case 3: //9600..10586      
        OpenBlock->ProtocolNextOpen = BlockRef->u1.Versions.u_v3.v3c->ProtocolNextOpen;
        OpenBlock->BindDeviceName = BlockRef->u1.Versions.u_v3.v3c->BindDeviceName;
        OpenBlock->RootDeviceName = BlockRef->u1.Versions.u_v3.v3c->RootDeviceName;

        OpenBlock->AllocateSharedMemoryHandler = BlockRef->u1.Versions.u_v3.v3c->AllocateSharedMemoryHandler;
        OpenBlock->CancelSendPacketsHandler = BlockRef->u1.Versions.u_v3.v3c->CancelSendPacketsHandler;
        OpenBlock->CmActivateVcCompleteHandler = BlockRef->u1.Versions.u_v3.v3->CmActivateVcCompleteHandler;
        OpenBlock->CmDeactivateVcCompleteHandler = BlockRef->u1.Versions.u_v3.v3->CmDeactivateVcCompleteHandler;
        OpenBlock->CoCreateVcHandler = BlockRef->u1.Versions.u_v3.v3->CoCreateVcHandler;
        OpenBlock->CoDeleteVcHandler = BlockRef->u1.Versions.u_v3.v3->CoDeleteVcHandler;
        OpenBlock->CoOidRequestCompleteHandler = BlockRef->u1.Versions.u_v3.v3->CoOidRequestCompleteHandler;
        OpenBlock->CoOidRequestHandler = BlockRef->u1.Versions.u_v3.v3->CoOidRequestHandler;
        OpenBlock->CoRequestCompleteHandler = BlockRef->u1.Versions.u_v3.v3->CoRequestCompleteHandler;
        OpenBlock->CoRequestHandler = BlockRef->u1.Versions.u_v3.v3->CoRequestHandler;
        OpenBlock->DirectOidRequestHandler = BlockRef->u1.Versions.u_v3.v3c->DirectOidRequestHandler;
        OpenBlock->FreeSharedMemoryHandler = BlockRef->u1.Versions.u_v3.v3c->FreeSharedMemoryHandler;
        OpenBlock->IndicateOffloadEventHandler = BlockRef->u1.Versions.u_v3.v3c->IndicateOffloadEventHandler;
        OpenBlock->InitiateOffloadCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->InitiateOffloadCompleteHandler;
        OpenBlock->InvalidateOffloadCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->InvalidateOffloadCompleteHandler;
        OpenBlock->MiniportCoCreateVcHandler = BlockRef->u1.Versions.u_v3.v3->MiniportCoCreateVcHandler;
        OpenBlock->MiniportCoOidRequestHandler = BlockRef->u1.Versions.u_v3.v3->MiniportCoOidRequestHandler;
        OpenBlock->MiniportCoRequestHandler = BlockRef->u1.Versions.u_v3.v3->MiniportCoRequestHandler;
        OpenBlock->Ndis5WanSendHandler = BlockRef->u1.Versions.u_v3.v3c->Ndis5WanSendHandler;
        OpenBlock->NextReturnNetBufferListsHandler = BlockRef->u1.Versions.u_v3.v3c->NextReturnNetBufferListsHandler;
        OpenBlock->NextSendHandler = BlockRef->u1.Versions.u_v3.v3c->NextSendHandler;
        OpenBlock->OidRequestCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->OidRequestCompleteHandler;
        OpenBlock->OidRequestHandler = BlockRef->u1.Versions.u_v3.v3c->OidRequestHandler;
        OpenBlock->ProtSendCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->ProtSendCompleteHandler;
        OpenBlock->ProtSendNetBufferListsComplete = BlockRef->u1.Versions.u_v3.v3c->ProtSendNetBufferListsComplete;
        OpenBlock->QueryOffloadCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->QueryOffloadCompleteHandler;
        OpenBlock->ReceiveCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->ReceiveCompleteHandler;
        OpenBlock->ReceiveHandler = BlockRef->u1.Versions.u_v3.v3c->ReceiveHandler;
        OpenBlock->ReceiveNetBufferLists = BlockRef->u1.Versions.u_v3.v3c->ReceiveNetBufferLists;
        OpenBlock->ReceivePacketHandler = BlockRef->u1.Versions.u_v3.v3c->ReceivePacketHandler;
        OpenBlock->RequestCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->RequestCompleteHandler;
        OpenBlock->RequestHandler = BlockRef->u1.Versions.u_v3.v3c->RequestHandler;
        OpenBlock->ResetCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->ResetCompleteHandler;
        OpenBlock->ResetHandler = BlockRef->u1.Versions.u_v3.v3c->ResetHandler;
        OpenBlock->SavedCancelSendPacketsHandler = BlockRef->u1.Versions.u_v3.v3c->SavedCancelSendPacketsHandler;
        OpenBlock->SavedSendHandler = BlockRef->u1.Versions.u_v3.v3c->SavedSendHandler;
        OpenBlock->SavedSendPacketsHandler = BlockRef->u1.Versions.u_v3.v3c->SavedSendPacketsHandler;
        OpenBlock->SendCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->SendCompleteHandler;
        OpenBlock->SendHandler = BlockRef->u1.Versions.u_v3.v3c->SendHandler;
        OpenBlock->SendPacketsHandler = BlockRef->u1.Versions.u_v3.v3c->SendPacketsHandler;
        OpenBlock->StatusCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->StatusCompleteHandler;
        OpenBlock->StatusHandler = BlockRef->u1.Versions.u_v3.v3c->StatusHandler;
        OpenBlock->TcpOffloadDisconnectCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->TcpOffloadDisconnectCompleteHandler;
        OpenBlock->TcpOffloadEventHandler = BlockRef->u1.Versions.u_v3.v3c->TcpOffloadEventHandler;
        OpenBlock->TcpOffloadForwardCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->TcpOffloadForwardCompleteHandler;
        OpenBlock->TcpOffloadReceiveCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->TcpOffloadReceiveCompleteHandler;
        OpenBlock->TcpOffloadReceiveIndicateHandler = BlockRef->u1.Versions.u_v3.v3c->TcpOffloadReceiveIndicateHandler;
        OpenBlock->TcpOffloadSendCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->TcpOffloadSendCompleteHandler;
        OpenBlock->TerminateOffloadCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->TerminateOffloadCompleteHandler;
        OpenBlock->TransferDataCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->TransferDataCompleteHandler;
        OpenBlock->TransferDataHandler = BlockRef->u1.Versions.u_v3.v3c->TransferDataHandler;
        OpenBlock->UpdateOffloadCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->UpdateOffloadCompleteHandler;
        OpenBlock->WanReceiveHandler = BlockRef->u1.Versions.u_v3.v3c->WanReceiveHandler;
        OpenBlock->WSendHandler = BlockRef->u1.Versions.u_v3.v3c->WSendHandler;
        OpenBlock->WSendPacketsHandler = BlockRef->u1.Versions.u_v3.v3c->WSendPacketsHandler;
        OpenBlock->WTransferDataHandler = BlockRef->u1.Versions.u_v3.v3c->WTransferDataHandler;
        break;

    case 4: //14393..17134
        OpenBlock->ProtocolNextOpen = BlockRef->u1.Versions.u_v4.v4c->ProtocolNextOpen;
        OpenBlock->BindDeviceName = BlockRef->u1.Versions.u_v4.v4c->BindDeviceName;
        OpenBlock->RootDeviceName = BlockRef->u1.Versions.u_v4.v4c->RootDeviceName;

        OpenBlock->AllocateSharedMemoryHandler = BlockRef->u1.Versions.u_v4.v4c->AllocateSharedMemoryHandler;
        OpenBlock->CancelSendPacketsHandler = BlockRef->u1.Versions.u_v4.v4c->CancelSendPacketsHandler;
        OpenBlock->CmActivateVcCompleteHandler = BlockRef->u1.Versions.u_v4.v4->CmActivateVcCompleteHandler;
        OpenBlock->CmDeactivateVcCompleteHandler = BlockRef->u1.Versions.u_v4.v4->CmDeactivateVcCompleteHandler;
        OpenBlock->CoCreateVcHandler = BlockRef->u1.Versions.u_v4.v4->CoCreateVcHandler;
        OpenBlock->CoDeleteVcHandler = BlockRef->u1.Versions.u_v4.v4->CoDeleteVcHandler;
        OpenBlock->CoOidRequestCompleteHandler = BlockRef->u1.Versions.u_v4.v4->CoOidRequestCompleteHandler;
        OpenBlock->CoOidRequestHandler = BlockRef->u1.Versions.u_v4.v4->CoOidRequestHandler;
        OpenBlock->CoRequestCompleteHandler = BlockRef->u1.Versions.u_v4.v4->CoRequestCompleteHandler;
        OpenBlock->CoRequestHandler = BlockRef->u1.Versions.u_v4.v4->CoRequestHandler;
        OpenBlock->DirectOidRequestHandler = BlockRef->u1.Versions.u_v4.v4c->DirectOidRequestHandler;
        OpenBlock->FreeSharedMemoryHandler = BlockRef->u1.Versions.u_v4.v4c->FreeSharedMemoryHandler;
        OpenBlock->IndicateOffloadEventHandler = BlockRef->u1.Versions.u_v4.v4c->IndicateOffloadEventHandler;
        OpenBlock->InitiateOffloadCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->InitiateOffloadCompleteHandler;
        OpenBlock->InvalidateOffloadCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->InvalidateOffloadCompleteHandler;
        OpenBlock->MiniportCoCreateVcHandler = BlockRef->u1.Versions.u_v4.v4->MiniportCoCreateVcHandler;
        OpenBlock->MiniportCoOidRequestHandler = BlockRef->u1.Versions.u_v4.v4->MiniportCoOidRequestHandler;
        OpenBlock->MiniportCoRequestHandler = BlockRef->u1.Versions.u_v4.v4->MiniportCoRequestHandler;
        OpenBlock->Ndis5WanSendHandler = BlockRef->u1.Versions.u_v4.v4c->Ndis5WanSendHandler;
        OpenBlock->NextReturnNetBufferListsHandler = BlockRef->u1.Versions.u_v4.v4c->NextReturnNetBufferListsHandler;
        OpenBlock->NextSendHandler = BlockRef->u1.Versions.u_v4.v4c->NextSendHandler;
        OpenBlock->OidRequestCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->OidRequestCompleteHandler;
        OpenBlock->OidRequestHandler = BlockRef->u1.Versions.u_v4.v4c->OidRequestHandler;
        OpenBlock->ProtSendCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->ProtSendCompleteHandler;
        OpenBlock->ProtSendNetBufferListsComplete = BlockRef->u1.Versions.u_v4.v4c->ProtSendNetBufferListsComplete;
        OpenBlock->QueryOffloadCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->QueryOffloadCompleteHandler;
        OpenBlock->ReceiveCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->ReceiveCompleteHandler;
        OpenBlock->ReceiveHandler = BlockRef->u1.Versions.u_v4.v4c->ReceiveHandler;
        OpenBlock->ReceiveNetBufferLists = BlockRef->u1.Versions.u_v4.v4c->ReceiveNetBufferLists;
        OpenBlock->ReceivePacketHandler = BlockRef->u1.Versions.u_v4.v4c->ReceivePacketHandler;
        OpenBlock->RequestCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->RequestCompleteHandler;
        OpenBlock->RequestHandler = BlockRef->u1.Versions.u_v4.v4c->RequestHandler;
        OpenBlock->ResetCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->ResetCompleteHandler;
        OpenBlock->ResetHandler = BlockRef->u1.Versions.u_v4.v4c->ResetHandler;
        OpenBlock->SavedCancelSendPacketsHandler = BlockRef->u1.Versions.u_v4.v4c->SavedCancelSendPacketsHandler;
        OpenBlock->SavedSendHandler = BlockRef->u1.Versions.u_v4.v4c->SavedSendHandler;
        OpenBlock->SavedSendPacketsHandler = BlockRef->u1.Versions.u_v4.v4c->SavedSendPacketsHandler;
        OpenBlock->SendCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->SendCompleteHandler;
        OpenBlock->SendHandler = BlockRef->u1.Versions.u_v4.v4c->SendHandler;
        OpenBlock->SendPacketsHandler = BlockRef->u1.Versions.u_v4.v4c->SendPacketsHandler;
        OpenBlock->StatusCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->StatusCompleteHandler;
        OpenBlock->StatusHandler = BlockRef->u1.Versions.u_v4.v4c->StatusHandler;
        OpenBlock->TcpOffloadDisconnectCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->TcpOffloadDisconnectCompleteHandler;
        OpenBlock->TcpOffloadEventHandler = BlockRef->u1.Versions.u_v4.v4c->TcpOffloadEventHandler;
        OpenBlock->TcpOffloadForwardCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->TcpOffloadForwardCompleteHandler;
        OpenBlock->TcpOffloadReceiveCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->TcpOffloadReceiveCompleteHandler;
        OpenBlock->TcpOffloadReceiveIndicateHandler = BlockRef->u1.Versions.u_v4.v4c->TcpOffloadReceiveIndicateHandler;
        OpenBlock->TcpOffloadSendCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->TcpOffloadSendCompleteHandler;
        OpenBlock->TerminateOffloadCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->TerminateOffloadCompleteHandler;
        OpenBlock->TransferDataCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->TransferDataCompleteHandler;
        OpenBlock->TransferDataHandler = BlockRef->u1.Versions.u_v4.v4c->TransferDataHandler;
        OpenBlock->UpdateOffloadCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->UpdateOffloadCompleteHandler;
        OpenBlock->WanReceiveHandler = BlockRef->u1.Versions.u_v4.v4c->WanReceiveHandler;
        OpenBlock->WSendHandler = BlockRef->u1.Versions.u_v4.v4c->WSendHandler;
        OpenBlock->WSendPacketsHandler = BlockRef->u1.Versions.u_v4.v4c->WSendPacketsHandler;
        OpenBlock->WTransferDataHandler = BlockRef->u1.Versions.u_v4.v4c->WTransferDataHandler;
        break;

    case 5: //17763..18362
        OpenBlock->ProtocolNextOpen = BlockRef->u1.Versions.u_v5.v5c->ProtocolNextOpen;
        OpenBlock->BindDeviceName = BlockRef->u1.Versions.u_v5.v5c->BindDeviceName;
        OpenBlock->RootDeviceName = BlockRef->u1.Versions.u_v5.v5c->RootDeviceName;

        OpenBlock->AllocateSharedMemoryHandler = BlockRef->u1.Versions.u_v5.v5c->AllocateSharedMemoryHandler;
        OpenBlock->CancelSendPacketsHandler = BlockRef->u1.Versions.u_v5.v5c->CancelSendPacketsHandler;
        OpenBlock->CmActivateVcCompleteHandler = BlockRef->u1.Versions.u_v5.v5->CmActivateVcCompleteHandler;
        OpenBlock->CmDeactivateVcCompleteHandler = BlockRef->u1.Versions.u_v5.v5->CmDeactivateVcCompleteHandler;
        OpenBlock->CoCreateVcHandler = BlockRef->u1.Versions.u_v5.v5->CoCreateVcHandler;
        OpenBlock->CoDeleteVcHandler = BlockRef->u1.Versions.u_v5.v5->CoDeleteVcHandler;
        OpenBlock->CoOidRequestCompleteHandler = BlockRef->u1.Versions.u_v5.v5->CoOidRequestCompleteHandler;
        OpenBlock->CoOidRequestHandler = BlockRef->u1.Versions.u_v5.v5->CoOidRequestHandler;
        OpenBlock->CoRequestCompleteHandler = BlockRef->u1.Versions.u_v5.v5->CoRequestCompleteHandler;
        OpenBlock->CoRequestHandler = BlockRef->u1.Versions.u_v5.v5->CoRequestHandler;
        OpenBlock->DirectOidRequestHandler = BlockRef->u1.Versions.u_v5.v5c->DirectOidRequestHandler;
        OpenBlock->FreeSharedMemoryHandler = BlockRef->u1.Versions.u_v5.v5c->FreeSharedMemoryHandler;
        OpenBlock->MiniportCoCreateVcHandler = BlockRef->u1.Versions.u_v5.v5->MiniportCoCreateVcHandler;
        OpenBlock->MiniportCoOidRequestHandler = BlockRef->u1.Versions.u_v5.v5->MiniportCoOidRequestHandler;
        OpenBlock->MiniportCoRequestHandler = BlockRef->u1.Versions.u_v5.v5->MiniportCoRequestHandler;
        OpenBlock->Ndis5WanSendHandler = BlockRef->u1.Versions.u_v5.v5c->Ndis5WanSendHandler;
        OpenBlock->NextReturnNetBufferListsHandler = BlockRef->u1.Versions.u_v5.v5c->NextReturnNetBufferListsHandler;
        OpenBlock->NextSendHandler = BlockRef->u1.Versions.u_v5.v5c->NextSendHandler;
        OpenBlock->OidRequestCompleteHandler = BlockRef->u1.Versions.u_v5.v5c->OidRequestCompleteHandler;
        OpenBlock->OidRequestHandler = BlockRef->u1.Versions.u_v5.v5c->OidRequestHandler;
        OpenBlock->ProtSendCompleteHandler = BlockRef->u1.Versions.u_v5.v5c->ProtSendCompleteHandler;
        OpenBlock->ProtSendNetBufferListsComplete = BlockRef->u1.Versions.u_v5.v5c->ProtSendNetBufferListsComplete;
        OpenBlock->ReceiveCompleteHandler = BlockRef->u1.Versions.u_v5.v5c->ReceiveCompleteHandler;
        OpenBlock->ReceiveHandler = BlockRef->u1.Versions.u_v5.v5c->ReceiveHandler;
        OpenBlock->ReceiveNetBufferLists = BlockRef->u1.Versions.u_v5.v5c->ReceiveNetBufferLists;
        OpenBlock->ReceivePacketHandler = BlockRef->u1.Versions.u_v5.v5c->ReceivePacketHandler;
        OpenBlock->RequestCompleteHandler = BlockRef->u1.Versions.u_v5.v5c->RequestCompleteHandler;
        OpenBlock->RequestHandler = BlockRef->u1.Versions.u_v5.v5c->RequestHandler;
        OpenBlock->ResetCompleteHandler = BlockRef->u1.Versions.u_v5.v5c->ResetCompleteHandler;
        OpenBlock->ResetHandler = BlockRef->u1.Versions.u_v5.v5c->ResetHandler;
        OpenBlock->SavedCancelSendPacketsHandler = BlockRef->u1.Versions.u_v5.v5c->SavedCancelSendPacketsHandler;
        OpenBlock->SavedSendHandler = BlockRef->u1.Versions.u_v5.v5c->SavedSendHandler;
        OpenBlock->SavedSendPacketsHandler = BlockRef->u1.Versions.u_v5.v5c->SavedSendPacketsHandler;
        OpenBlock->SendCompleteHandler = BlockRef->u1.Versions.u_v5.v5c->SendCompleteHandler;
        OpenBlock->SendHandler = BlockRef->u1.Versions.u_v5.v5c->SendHandler;
        OpenBlock->SendPacketsHandler = BlockRef->u1.Versions.u_v5.v5c->SendPacketsHandler;
        OpenBlock->StatusCompleteHandler = BlockRef->u1.Versions.u_v5.v5c->StatusCompleteHandler;
        OpenBlock->StatusHandler = BlockRef->u1.Versions.u_v5.v5c->StatusHandler;
        OpenBlock->TransferDataCompleteHandler = BlockRef->u1.Versions.u_v5.v5c->TransferDataCompleteHandler;
        OpenBlock->TransferDataHandler = BlockRef->u1.Versions.u_v5.v5c->TransferDataHandler;
        OpenBlock->WanReceiveHandler = BlockRef->u1.Versions.u_v5.v5c->WanReceiveHandler;
        OpenBlock->WSendHandler = BlockRef->u1.Versions.u_v5.v5c->WSendHandler;
        OpenBlock->WSendPacketsHandler = BlockRef->u1.Versions.u_v5.v5c->WSendPacketsHandler;
        OpenBlock->WTransferDataHandler = BlockRef->u1.Versions.u_v5.v5c->WTransferDataHandler;
        break;

    default:
        return FALSE;
    }

    return TRUE;
}

/*
* ReadAndConvertProtocolBlock
*
* Purpose:
*
* Read protocol block from kernel and convert it to compatible form.
*
*/
BOOL ReadAndConvertProtocolBlock(
    _In_ ULONG_PTR ObjectAddress,
    _Inout_ NDIS_PROTOCOL_BLOCK_COMPATIBLE *ProtoBlock,
    _Out_opt_ PULONG ObjectVersion
)
{
    BOOL Result = FALSE;
    ULONG objectVersion;
    ULONG objectSize;
    PVOID objectPtr;

    PROTOCOL_BLOCK_VERSIONS ProtocolRef;

    objectPtr = DumpProtocolBlockVersionAware(ObjectAddress, &objectSize, &objectVersion);
    if (objectPtr == NULL)
        return FALSE;

    ProtocolRef.u1.Ref = objectPtr;
    Result = CreateCompatibleProtocolBlock(objectVersion, &ProtocolRef, ProtoBlock);

    if (ObjectVersion) {
        *ObjectVersion = objectVersion;
    }

    HeapMemoryFree(objectPtr);

    return Result;
}

/*
* ReadAndConvertOpenBlock
*
* Purpose:
*
* Read open block from kernel and convert it to compatible form.
*
*/
BOOL ReadAndConvertOpenBlock(
    _In_ ULONG_PTR ObjectAddress,
    _Inout_ NDIS_OPEN_BLOCK_COMPATIBLE *OpenBlock,
    _Out_opt_ PULONG ObjectVersion)
{
    BOOL Result = FALSE;
    ULONG objectVersion;
    ULONG objectSize;
    PVOID objectPtr;

    OPEN_BLOCK_VERSIONS BlockRef;

    objectPtr = DumpOpenBlockVersionAware(ObjectAddress, &objectSize, &objectVersion);
    if (objectPtr == NULL) {
        return FALSE;
    }
    BlockRef.u1.Ref = objectPtr;

    Result = CreateCompatibleOpenBlock(objectVersion, &BlockRef, OpenBlock);

    if (ObjectVersion) {
        *ObjectVersion = objectVersion;
    }

    HeapMemoryFree(objectPtr);

    return Result;
}

/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       QUERY.C
*
*  VERSION:     1.00
*
*  DATE:        23 June 2019
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
* DumpReadOpenBlockVersionAware
*
* Purpose:
*
* Return dumped NDIS_OPEN_BLOCK version aware.
*
* Use HeapFree to free returned buffer.
*
*/
PVOID DumpReadOpenBlockVersionAware(
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

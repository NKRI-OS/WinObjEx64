/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       QUERY.H
*
*  VERSION:     1.00
*
*  DATE:        29 June 2019
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

typedef struct _PROTOCOL_BLOCK_VERSIONS {
    union {
        union {
            NDIS_PROTOCOL_BLOCK_7601 *v1;
            NDIS_PROTOCOL_BLOCK_9200 *v2;
            NDIS_PROTOCOL_BLOCK_9600_17134 *v3;
            NDIS_PROTOCOL_BLOCK_17763 *v4;
            NDIS_PROTOCOL_BLOCK_18362 *v5;
        } Versions;
        PVOID Ref;
    } u1;
} PROTOCOL_BLOCK_VERSIONS, *PPROTOCOL_BLOCK_VERSIONS;

typedef struct _OPEN_BLOCK_VERSIONS {
    union {
        union {
            NDIS_OPEN_BLOCK_7601 *v1;
            NDIS_OPEN_BLOCK_9200 *v2;
            union {
                NDIS_COMMON_OPEN_BLOCK_9600_10586 *v3c;
                NDIS_OPEN_BLOCK_9600_10586 *v3;
            } u_v3;
            union {
                NDIS_COMMON_OPEN_BLOCK_14393_17134 *v4c;
                NDIS_OPEN_BLOCK_14393_17134 *v4;
            } u_v4;
            union {
                NDIS_COMMON_OPEN_BLOCK_17763_18362 *v5c;
                NDIS_OPEN_BLOCK_17763_18362 *v5;
            } u_v5;
        } Versions;
        PVOID Ref;
    } u1;
} OPEN_BLOCK_VERSIONS, *POPEN_BLOCK_VERSIONS;

enum _NDIS_OBJECT_TYPE {
    NdisOpenProtocol = 1,
    NdisOpenBlock,
    NdisMDriverBlock,
    NdisInvalidType
} NDIS_OBJECT_TYPE;

extern PROTOCOL_BLOCK_VERSIONS g_ProtocolBlock;
extern OPEN_BLOCK_VERSIONS g_OpenBlock;

//
// Structure for dump convertion, only handlers, flags, unicode strings.
//
typedef struct _NDIS_OPEN_BLOCK_COMPATIBLE{
    PVOID ProtocolNextOpen;

    UNICODE_STRING* BindDeviceName;
    UNICODE_STRING* RootDeviceName;

    PVOID NextSendHandler;
    PVOID NextReturnNetBufferListsHandler;
    PVOID SendHandler;

    PVOID TransferDataHandler;
    PVOID SendCompleteHandler;
    PVOID TransferDataCompleteHandler;
    PVOID ReceiveHandler;
    PVOID ReceiveCompleteHandler;
    PVOID WanReceiveHandler;
    PVOID RequestCompleteHandler;
    PVOID ReceivePacketHandler;
    PVOID SendPacketsHandler;
    PVOID ResetHandler;
    PVOID RequestHandler;
    PVOID OidRequestHandler;
    PVOID ResetCompleteHandler;

    PVOID ProtSendNetBufferListsComplete;
    PVOID ReceiveNetBufferLists;
    PVOID SavedSendNBLHandler;
    PVOID SavedSendPacketsHandler;
    PVOID SavedCancelSendPacketsHandler;

    PVOID SavedSendHandler;

    PVOID InitiateOffloadCompleteHandler;
    PVOID TerminateOffloadCompleteHandler;
    PVOID UpdateOffloadCompleteHandler;
    PVOID InvalidateOffloadCompleteHandler;
    PVOID QueryOffloadCompleteHandler;
    PVOID IndicateOffloadEventHandler;
    PVOID TcpOffloadSendCompleteHandler;
    PVOID TcpOffloadReceiveCompleteHandler;
    PVOID TcpOffloadDisconnectCompleteHandler;
    PVOID TcpOffloadForwardCompleteHandler;
    PVOID TcpOffloadEventHandler;
    PVOID TcpOffloadReceiveIndicateHandler;

    PVOID Ndis5WanSendHandler;
    PVOID ProtSendCompleteHandler;
    PVOID OidRequestCompleteHandler;

    PVOID DirectOidRequestCompleteHandler;
    PVOID DirectOidRequestHandler;

    PVOID AllocateSharedMemoryHandler;
    PVOID FreeSharedMemoryHandler;

    PVOID MiniportCoCreateVcHandler;
    PVOID MiniportCoRequestHandler;
    PVOID CoCreateVcHandler;
    PVOID CoDeleteVcHandler;
    PVOID CmActivateVcCompleteHandler;
    PVOID CmDeactivateVcCompleteHandler;
    PVOID CoRequestCompleteHandler;
    PVOID CoRequestHandler;

    PVOID MiniportCoOidRequestHandler;
    PVOID CoOidRequestCompleteHandler;
    PVOID CoOidRequestHandler;

} NDIS_OPEN_BLOCK_COMPATIBLE, *PNDIS_OPEN_BLOCK_COMPATIBLE;

typedef struct _NDIS_PROTOCOL_BLOCK_COMPATIBLE {
    PVOID Reserved;
} NDIS_PROTOCOL_BLOCK_COMPATIBLE, *PNDIS_PROTOCOL_BLOCK_COMPATIBLE;

ULONG_PTR QueryProtocolList();

PVOID DumpProtocolBlockVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version);

PVOID DumpOpenBlockVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version);

PVOID DumpUnicodeString(
    _In_ ULONG_PTR Address,
    _In_ WORD Length,
    _In_ WORD MaximumLength,
    _In_ BOOLEAN IsPtr);

ULONG_PTR GetNextProtocol(
    _In_ ULONG ObjectVersion);

ULONG_PTR GetProtocolOpenQueue(
    _In_ ULONG ObjectVersion);

ULONG GetNextProtocolOffset(
    _In_ ULONG WindowsVersion);

BOOL CreateCompatibleOpenBlock(
    _In_ ULONG ObjectVersion,
    _Out_ NDIS_OPEN_BLOCK_COMPATIBLE *OpenBlock);

BOOL CreateCompatibleProtocolBlock(
    _In_ ULONG ObjectVersion,
    _Out_ NDIS_PROTOCOL_BLOCK_COMPATIBLE *ProtoBlock);

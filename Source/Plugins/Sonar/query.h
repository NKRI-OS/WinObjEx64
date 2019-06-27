/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       QUERY.H
*
*  VERSION:     1.00
*
*  DATE:        23 June 2019
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

ULONG_PTR QueryProtocolList();

PVOID DumpProtocolBlockVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version);

PVOID DumpReadOpenBlockVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version);

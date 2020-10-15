#pragma once
#include "stdafx.h"
NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
//NTSTATUS ReadMem = MmReadVirtualMemory(Process, OFFSET, &RESULT, sizeof(int));
NTSTATUS MmReadVirtualMemory(PEPROCESS Process, PVOID Source, PVOID Target, SIZE_T Size) {
	SIZE_T Result;
	return MmCopyVirtualMemory(Process, Source, PsGetCurrentProcess(), Target, Size, KernelMode, &Result);
}
//NTSTATUS WriteMem = MmWriteVirtualMemory(Process, &VALUE, OFFSET, sizeof(int));
NTSTATUS MmWriteVirtualMemory(PEPROCESS Process, PVOID Source, PVOID Target, SIZE_T Size) {
	SIZE_T Result;
	return MmCopyVirtualMemory(PsGetCurrentProcess(), Source, Process, Target, Size, KernelMode, &Result);
}
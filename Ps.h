#pragma once
#include "stdafx.h"
typedef unsigned long long QWORD;
typedef unsigned short WORD;

NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);
NTKERNELAPI PPEB PsGetProcessPeb(IN PEPROCESS Process);
NTSTATUS PsSuspendProcess(IN PEPROCESS Process);
NTSTATUS PsResumeProcess(IN PEPROCESS Process);
NTSTATUS PsTerminateProcess(IN PEPROCESS Process, IN NTSTATUS Status);

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef struct _PEB {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG ImageUsesLargePages : 1;
	ULONG IsProtectedProcess : 1;
	ULONG IsLegacyProcess : 1;
	ULONG IsImageDynamicallyRelocated : 1;
	ULONG SpareBits : 4;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	VOID* ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	ULONG CrossProcessFlags;
	ULONG ProcessInJob : 1;
	ULONG ProcessInitializing : 1;
	ULONG ReservedBits0 : 30;
	union {
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved[1];
	ULONG SpareUlong;
	VOID* FreeList;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID HotpatchInformation;
	VOID** ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	LARGE_INTEGER CriticalSectionTimeout;
	ULONG HeapSegmentReserve;
	ULONG HeapSegmentCommit;
	ULONG HeapDeCommitTotalFreeThreshold;
	ULONG HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	VOID** ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;
	PRTL_CRITICAL_SECTION LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	WORD OSBuildNumber;
	WORD OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	ULONG ImageProcessAffinityMask;
	ULONG GdiHandleBuffer[34];
	PVOID PostProcessInitRoutine;
	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];
	ULONG SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo;
	UNICODE_STRING CSDVersion;
	VOID* ActivationContextData;
	VOID* ProcessAssemblyStorageMap;
	VOID* SystemDefaultActivationContextData;
	VOID* SystemAssemblyStorageMap;
	ULONG MinimumStackCommit;
	VOID* FlsCallback;
	LIST_ENTRY FlsListHead;
	PVOID FlsBitmap;
	ULONG FlsBitmapBits[4];
	ULONG FlsHighIndex;
	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;
} PEB, * PPEB;
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	VOID* EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

//NTSTATUS status = PsLookupProcessByProcessName("ac_client.exe", &Process);
NTSTATUS PsLookupProcessByProcessName(CHAR* ProcessName, PEPROCESS* Process) {
	PEPROCESS SystemProcess = PsInitialSystemProcess;
	PEPROCESS CurrentEntry = SystemProcess;
	CHAR ImageName[15];
	do {
		RtlCopyMemory((PVOID)(&ImageName), (PVOID)((ULONG64)CurrentEntry + 0x450), sizeof(ImageName));
		if (strstr(ImageName, ProcessName)) {
			ULONG ActiveThreads;
			RtlCopyMemory((PVOID)&ActiveThreads, (PVOID)((ULONG64)CurrentEntry + 0x498), sizeof(ActiveThreads));
			if (ActiveThreads) {
				*Process = CurrentEntry;
				return STATUS_SUCCESS;
			}
		}
		PLIST_ENTRY list = (PLIST_ENTRY)((ULONG64)(CurrentEntry)+0x2F0);
		CurrentEntry = (PEPROCESS)((ULONG64)list->Flink - 0x2F0);
	} while (CurrentEntry != SystemProcess);
	return STATUS_NOT_FOUND;
}
//NTSTATUS BaseAddressStatus = PsGetModuleBaseAddress(Process, L"user32.dll", &BaseAddress);
NTSTATUS PsGetModuleBaseAddress(PEPROCESS TargetProcess, LPCWSTR ModuleName, PULONG64 Result) {
	KeAttachProcess(TargetProcess);

	PPEB PEB = PsGetProcessPeb(TargetProcess);
	if (!PEB) {
		KeDetachProcess();
		ObfDereferenceObject(TargetProcess);
		return STATUS_NOT_FOUND;
	}

	if (!PEB->Ldr || !PEB->Ldr->Initialized) {
		KeDetachProcess();
		ObfDereferenceObject(TargetProcess);
		return STATUS_NOT_FOUND;
	}

	UNICODE_STRING ModuleNameU;
	RtlInitUnicodeString(&ModuleNameU, ModuleName);
	for (PLIST_ENTRY PList = PEB->Ldr->InLoadOrderModuleList.Flink; PList != &PEB->Ldr->InLoadOrderModuleList; PList = PList->Flink) {
		PLDR_DATA_TABLE_ENTRY PLDREntry = CONTAINING_RECORD(PList, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (RtlCompareUnicodeString(&PLDREntry->BaseDllName, &ModuleNameU, TRUE) == 0) {
			*Result = PLDREntry->DllBase;
			KeDetachProcess();
			ObfDereferenceObject(TargetProcess);
			return STATUS_SUCCESS;
		}
	}
}
//NTSTATUS ProcessBaseStatus = PsGetProcessBaseAddress(Process, &BaseAddress);
NTSTATUS PsGetProcessBaseAddress(PEPROCESS Process, PULONG64 Result) {
	PVOID BaseAddress = PsGetProcessSectionBaseAddress(Process);
	if (BaseAddress != 0) {
		*Result = BaseAddress;
		return STATUS_SUCCESS;
	}
	return STATUS_NOT_FOUND;
}
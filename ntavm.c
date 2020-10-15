#include "stdafx.h"
DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text(INIT, DriverEntry)

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING dosDeviceName;
	RtlUnicodeStringInit(&dosDeviceName, L"\\DosDevices\\NtaVm");
	IoDeleteSymbolicLink(&dosDeviceName);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverEntry(_In_ struct _DRIVER_OBJECT* DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	//============================================================================================ Set up service
	NTSTATUS status;
	UNICODE_STRING deviceName;
	UNICODE_STRING dosDeviceName;
	PDEVICE_OBJECT deviceObject = NULL;
	RtlUnicodeStringInit(&deviceName, L"\\Device\\NtaVm");
	RtlUnicodeStringInit(&dosDeviceName, L"\\DosDevices\\NtaVm");
	DriverObject->DriverUnload = DriverUnload;
	status = IoCreateDevice(DriverObject, 0, &deviceName, 0x00000022, 0, FALSE, &deviceObject);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	status = IoCreateSymbolicLink(&dosDeviceName, &deviceName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(deviceObject);
	}
	//============================================================================================ Declare variables
	ULONG64 BaseAddress = 0;
	ULONG64 LocalPlayer = 0;
	__int32 OldAmmoValue = 0;
	__int32 NewAmmoValue = 0;
	__int32 WriteAmmoValue = 999;
	//============================================================================================ Obtain the process
	PEPROCESS Process; 
	status = PsLookupProcessByProcessName("ac_client.exe", &Process);
	if (!NT_SUCCESS(status))
		return status;
	status = PsGetProcessBaseAddress(Process, &BaseAddress);
	if (!NT_SUCCESS(status))
		return status;
	DbgPrintElevated("BaseAddress: 0x%llx", BaseAddress);
	//============================================================================================ Manage memory region
	MmReadVirtualMemory(Process, 0x509B74, &LocalPlayer, sizeof(ULONG64));
	DbgPrintElevated("LocalPlayer: 0x%llx", LocalPlayer); //llu
	MmReadVirtualMemory(Process, LocalPlayer + 0x150, &OldAmmoValue, sizeof(__int32));
	DbgPrintElevated("Old Ammo Value: %d", OldAmmoValue);
	MmWriteVirtualMemory(Process, &WriteAmmoValue, LocalPlayer + 0x150, sizeof(__int32));
	MmReadVirtualMemory(Process, LocalPlayer + 0x150, &NewAmmoValue, sizeof(__int32));
	DbgPrintElevated("New Ammo Value: %d", NewAmmoValue);
	//============================================================================================ Return
	return STATUS_SUCCESS;
}
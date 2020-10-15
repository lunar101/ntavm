#pragma once
#include "stdafx.h"
VOID DbgkCreateThread(PETHREAD Thread, PVOID StartAddress);
VOID DbgkExitThread(NTSTATUS ExitStatus);
#define DbgPrintElevated(msg, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, msg, __VA_ARGS__);
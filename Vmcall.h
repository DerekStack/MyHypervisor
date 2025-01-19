#pragma once
#include "Vmx.h"


//////////////////////////////////////////////////
//				    Constants					//
//////////////////////////////////////////////////

#define VMCALL_TEST						0x1			// Test VMCALL
#define VMCALL_VMXOFF					0x2			// Call VMXOFF to turn off the hypervisor
#define VMCALL_EXEC_HOOK_PAGE			0x3			// VMCALL to Hook ExecuteAccess bit of the EPT Table
#define VMCALL_INVEPT_ALL_CONTEXT		0x4			// VMCALL to invalidate EPT (All Contexts)
#define VMCALL_INVEPT_SINGLE_CONTEXT	0x5			// VMCALL to invalidate EPT (A Single Context)

typedef struct _HYPER_MEMORY_CORE
{
	int Lock;
	CHAR PageData[4096];
}HYPER_MEMORY_CORE, * P_HYPER_MEMORY_CORE;

typedef struct _HYPER_MEMORY
{
	int Lock;
	CHAR Key[128];
	HYPER_MEMORY_CORE HyperMemoryCore[8];
}HYPER_MEMORY, *P_HYPER_MEMORY;

//////////////////////////////////////////////////
//				    Functions					//
//////////////////////////////////////////////////

// Main handler for VMCALLs
NTSTATUS VmxVmcallMemoryHandler(UINT64 VmcallNumber, PVOID source, PVOID dest, UINT64 size);
PVOID AllocVMMemory(UINT64 size);
NTSTATUS FreeVMMemory(PVOID source);

NTSTATUS ReadVMMemory(PVOID source,PVOID dest,UINT64 size);
NTSTATUS WriteVMMemory(PVOID source, PVOID dest, UINT64 size);



//
//// Test function which shows a message to test a successfull VMCALL
//NTSTATUS VmcallTest(UINT64 Param1, UINT64 Param2, UINT64 Param3);
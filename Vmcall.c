#include "Vmcall.h"

#include "Common.h"
#include "Invept.h"

NTSTATUS VmxVmcallMemoryHandler(UINT64 VmcallNumber, PVOID source, PVOID dest, UINT64 size)
{
	NTSTATUS status = STATUS_SUCCESS;
	switch (VmcallNumber)
	{
	case ALLOC_VM_MEMORY:
	{
		PVOID address = AllocVMMemory(size);
	}
	break;
	case FREE_VM_MEMORY:
	{
		status = FreeVMMemory(source);
	}
	break;
	case READ_VM_MEMORY:
	{
		status = ReadVMMemory(source, dest, size);
	}
	break;
	case WRITE_VM_MEMORY:
	{
		status = WriteVMMemory(source, dest, size);
	}
	break;

	default:
	{
		break;
	}
	};
	return status;
}

PVOID AllocVMMemory(UINT64 size)
{
	PVOID* newMem = (PVOID*)ExAllocatePoolWithTag(NonPagedPool, size, MYHYPERPOOLTAG);
	RtlZeroMemory(newMem, size);

	//encrypt data;

	return newMem;
}

NTSTATUS FreeVMMemory(PVOID source)
{
	if (source != NULL)
	{
		ExFreePoolWithTag(source, MYHYPERPOOLTAG);
	}

	return STATUS_SUCCESS;
}

NTSTATUS ReadVMMemory(PVOID source, PVOID dest, UINT64 size)
{
	return STATUS_SUCCESS;
}
NTSTATUS WriteVMMemory(PVOID source, PVOID dest, UINT64 size)
{
	return STATUS_SUCCESS;
}
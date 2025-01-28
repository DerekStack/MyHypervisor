#include "Memory.h"


PAGE_MEMORY_BLOCK* memoryBlock;

UINT32 AllocMemory(UINT64 Size)
{
	UINT32 offset = memoryBlock->Offset;
	PVOID PageAddress = memoryBlock->PageAddress;

	MEMORY_BLOCK_INFO* memBlockInfo = NULL;
	UINT32 memBlockSize = 0;
	//search available memory
	do
	{
		UINT32 nextOffset = offset + memBlockSize;
		memBlockInfo = (MEMORY_BLOCK_INFO*)((UINT64)PageAddress + nextOffset);
		memBlockSize = memBlockInfo->Size;

		if (memBlockInfo->Status == 1)
		{
			offset = nextOffset;
			continue;
		}

		if (memBlockSize != 0)
		{
			if (memBlockSize > Size)
			{
				break;
			}
			else
			{
				offset = nextOffset;
			}
		}
		else
		{
			break;
		}
	} while (TRUE);

	UINT32 handle = memoryBlock->CurrentHandle + 1;

	memoryBlock->CurrentHandle = handle;

	if (memBlockInfo->Size != 0)
	{
		//reuse the memory block;
		UINT32 remianSize = memBlockInfo->Size - (Size + sizeof(MEMORY_BLOCK_INFO));
		UINT32 nextOffset = offset + (Size + sizeof(MEMORY_BLOCK_INFO));
		MEMORY_BLOCK_INFO*  remainMemBlockInfo = (MEMORY_BLOCK_INFO*)((UINT64)PageAddress + nextOffset);
		remainMemBlockInfo->Size = remianSize;
		remainMemBlockInfo->Status = 0;
	}

	memBlockInfo->Size = Size + sizeof(MEMORY_BLOCK_INFO);
	memBlockInfo->Status = 1;

	//

	return handle;
}
VOID FreeMemory(UINT64 Handle)
{


	//check free block 
}

NTSTATUS WriteMemory(UINT32 Handle, PVOID Address, UINT64 Size)
{
	return STATUS_SUCCESS;
}
NTSTATUS ReadMemory(UINT32 Handle, PVOID Address, UINT64 Size)
{
	return STATUS_SUCCESS;
}

ALLOC_MEMORY_BLOCK* SearchMemory(UINT32 Handle)
{
	return NULL;
}
NTSTATUS InsertMemoryList(ALLOC_MEMORY_BLOCK* memBlock)
{
	return STATUS_SUCCESS;
}
NTSTATUS RemoveMemoryList(ALLOC_MEMORY_BLOCK* memBlock)
{
	return STATUS_SUCCESS;
}
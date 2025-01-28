#ifndef MY_HYPERVISOR_MENMORY_H
#define MY_HYPERVISOR_MENMORY_H
#include <ntddk.h>

typedef struct _MEMORY_BLOCK_INFO
{
	UINT32 Size;
	CHAR Status;
	CHAR Reversed1;
	SHORT Reversed2;

}MEMORY_BLOCK_INFO, *PMEMORY_BLOCK_INFO;

typedef struct _ALLOC_MEMORY_BLOCK
{
	UINT32 Handle;
	PVOID AllocAddress; //page physical address
	UINT32 Size;		//page size
	UINT64 Reversed;
}ALLOC_MEMORY_BLOCK, * PALLOC_MEMORY_BLOCK;

typedef struct _RT_LIST_ENTRY {
	struct _RT_LIST_ENTRY* Nextlink;
	struct _ALLOC_MEMORY_BLOCK* AllocMemoryBlock;
} RT_LIST_ENTRY, * PRT_LIST_ENTRY;

typedef struct _PAGE_MEMORY_BLOCK
{
	PVOID PageAddress;
	UINT32 Size;
	UINT32 Reversed;
	UINT32 Offset;				//last reference
	UINT32 CurrentHandle;
	RT_LIST_ENTRY* AllocMemBlock;

}PAGE_MEMORY_BLOCK, * PPAGE_MEMORY_BLOCK;


UINT32 AllocMemory(UINT64 Size);
VOID FreeMemory(UINT64 Handle);

NTSTATUS WriteMemory(UINT32 Handle,PVOID Address, UINT64 Size);
NTSTATUS ReadMemory(UINT32 Handle, PVOID Address, UINT64 Size);

ALLOC_MEMORY_BLOCK* SearchMemory(UINT32 Handle);
NTSTATUS InsertMemoryList(ALLOC_MEMORY_BLOCK* memBlock);
NTSTATUS RemoveMemoryList(ALLOC_MEMORY_BLOCK* memBlock);


#endif

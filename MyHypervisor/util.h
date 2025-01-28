#ifndef MYHYPERVISORDMA_UTIL_H
#define MYHYPERVISORDMA_UTIL_H

#include <ntddk.h>
#include "Msr.h"

typedef struct _PhysicalMemoryRun
{
	ULONG_PTR base_page;   //!< A base address / PAGE_SIZE (ie, 0x1 for 0x1000)
	ULONG_PTR page_count;  //!< A number of pages
}PhysicalMemoryRun,*PPhysicalMemoryRun;

#if defined(_AMD64_)
static_assert(sizeof(PhysicalMemoryRun) == 0x10, "Size check");
#else
static_assert(sizeof(PhysicalMemoryRun) == 0x8, "Size check");
#endif

typedef struct _PhysicalMemoryDescriptor
{
	PFN_COUNT number_of_runs;    //!< A number of PhysicalMemoryDescriptor::run
	PFN_NUMBER number_of_pages;  //!< A physical memory size in pages
	PhysicalMemoryRun run[1];    //!< ranges of addresses
}PhysicalMemoryDescriptor;


const PhysicalMemoryDescriptor* UtilGetPhysicalMemoryRanges();

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS UtilInitialization(_In_ PDRIVER_OBJECT driver_object);
_IRQL_requires_max_(PASSIVE_LEVEL) void UtilTermination();

ULONG_PTR UtilReadMsr(_In_ ULONG msr);
ULONG64 UtilReadMsr64(_In_ ULONG msr);

_IRQL_requires_max_(APC_LEVEL) NTSTATUS UtilForEachProcessor(_In_ NTSTATUS(*callback_routine)(void*),
	_In_opt_ void* context);

void* UtilAllocateContiguousMemory(SIZE_T number_of_bytes);

void UtilFreeContiguousMemory(void* base_address);

void UtilDumpGpRegisters(const AllRegisters* all_regs,ULONG_PTR stack_pointer);

#endif // !MYHYPERVISORDMA_UTIL_H

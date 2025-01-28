#include "util.h"
#include "Common.h"
#include <intrin.h>
//#include <ntddk.h>


_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS UtilpInitializePhysicalMemoryRanges();
_IRQL_requires_max_(PASSIVE_LEVEL) static PhysicalMemoryDescriptor* UtilpBuildPhysicalMemoryRanges();

#if defined(ALLOC_PRAGMA)

#pragma alloc_text(INIT, UtilpInitializePhysicalMemoryRanges)
#pragma alloc_text(INIT, UtilpBuildPhysicalMemoryRanges)

#endif

static PhysicalMemoryDescriptor* g_utilp_physical_memory_ranges;

// Initializes the physical memory ranges
NTSTATUS UtilpInitializePhysicalMemoryRanges() {
	PAGED_CODE();

	const PhysicalMemoryDescriptor* ranges = UtilpBuildPhysicalMemoryRanges();
	if (!ranges) {
		return STATUS_UNSUCCESSFUL;
	}

	g_utilp_physical_memory_ranges = ranges;

	for (ULONG i = 0ul; i < ranges->number_of_runs; ++i) {
		const ULONG64 base_addr =
			(ULONG64)(ranges->run[i].base_page) * PAGE_SIZE;
		/*HYPERPLATFORM_LOG_DEBUG("Physical Memory Range: %016llx - %016llx",
			base_addr,
			base_addr + ranges->run[i].page_count * PAGE_SIZE);*/
	}

	const ULONG64 pm_size =
		(ULONG64) (ranges->number_of_pages) * PAGE_SIZE;
	//HYPERPLATFORM_LOG_DEBUG("Physical Memory Total: %llu KB", pm_size / 1024);

	return STATUS_SUCCESS;
}

// Builds the physical memory ranges
PhysicalMemoryDescriptor* UtilpBuildPhysicalMemoryRanges() {
	PAGED_CODE();

	const PPHYSICAL_MEMORY_RANGE pm_ranges = MmGetPhysicalMemoryRanges();
	if (!pm_ranges) {
		return NULL;
	}

	PFN_COUNT number_of_runs = 0;
	PFN_NUMBER number_of_pages = 0;
	for (/**/; /**/; ++number_of_runs) {
		const PHYSICAL_MEMORY_RANGE* range = &pm_ranges[number_of_runs];
		if (!range->BaseAddress.QuadPart && !range->NumberOfBytes.QuadPart) {
			break;
		}
		number_of_pages +=
			(PFN_NUMBER) (BYTES_TO_PAGES(range->NumberOfBytes.QuadPart));
	}
	if (number_of_runs == 0) {
		ExFreePoolWithTag(pm_ranges, 'hPmM');
		return NULL;
	}

	const unsigned long long memory_block_size =
		sizeof(PhysicalMemoryDescriptor) +
		sizeof(PhysicalMemoryRun) * (number_of_runs - 1);
	PhysicalMemoryDescriptor* pm_block =
		(PhysicalMemoryDescriptor*)(ExAllocatePoolWithTag(
			NonPagedPool, memory_block_size, POOLTAG));
	if (!pm_block) {
		ExFreePoolWithTag(pm_ranges, 'hPmM');
		return NULL;
	}
	RtlZeroMemory(pm_block, memory_block_size);

	pm_block->number_of_runs = number_of_runs;
	pm_block->number_of_pages = number_of_pages;

	for (ULONG run_index = 0ul; run_index < number_of_runs; run_index++) {
		PhysicalMemoryRun* current_run = &pm_block->run[run_index];
		PHYSICAL_MEMORY_RANGE* current_block = &pm_ranges[run_index];
		current_run->base_page = (ULONG_PTR)(
			PfnFromPhysicalAddress(current_block->BaseAddress.QuadPart));
		current_run->page_count = (ULONG_PTR)(
			BYTES_TO_PAGES(current_block->NumberOfBytes.QuadPart));
	}

	ExFreePoolWithTag(pm_ranges, 'hPmM');
	return pm_block;
}

// Returns the physical memory ranges
const PhysicalMemoryDescriptor* UtilGetPhysicalMemoryRanges() 
{
	return g_utilp_physical_memory_ranges;
}


NTSTATUS UtilInitialization(PDRIVER_OBJECT driver_object) {
	PAGED_CODE();

	NTSTATUS status;
	status = UtilpInitializePhysicalMemoryRanges();
	if (!NT_SUCCESS(status)) {
		return status;
	}

	return status;
}

void UtilTermination() {
	PAGED_CODE();

	if (g_utilp_physical_memory_ranges) {
		ExFreePoolWithTag(g_utilp_physical_memory_ranges,
			"hPmM");
	}
}

ULONG_PTR UtilReadMsr(ULONG msr) 
{
	return (ULONG_PTR)(__readmsr(msr));
}

// Reads 64bit-width MSR
ULONG64 UtilReadMsr64(ULONG msr)
{
	return __readmsr(msr);
}

NTSTATUS UtilForEachProcessor(NTSTATUS(*callback_routine)(void*), void* context) 
{
	PAGED_CODE();

	const ULONG number_of_processors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	for (ULONG processor_index = 0; processor_index < number_of_processors; processor_index++) 
	{
		PROCESSOR_NUMBER processor_number = {0};
		NTSTATUS status = KeGetProcessorNumberFromIndex(processor_index, &processor_number);
		if (!NT_SUCCESS(status)) 
		{
			return status;
		}

		// Switch the current processor
		GROUP_AFFINITY affinity = {0};
		affinity.Group = processor_number.Group;
		affinity.Mask = 1ull << processor_number.Number;
		GROUP_AFFINITY previous_affinity = {0};
		KeSetSystemGroupAffinityThread(&affinity, &previous_affinity);

		// Execute callback
		status = callback_routine(context);

		KeRevertToUserGroupAffinityThread(&previous_affinity);
		if (!NT_SUCCESS(status)) 
		{
			return status;
		}
	}
	return STATUS_SUCCESS;
}

void* UtilAllocateContiguousMemory(SIZE_T number_of_bytes)
{
	PHYSICAL_ADDRESS highest_acceptable_address = {0};
	highest_acceptable_address.QuadPart = -1;

	PHYSICAL_ADDRESS lowest_acceptable_address = {0};
	PHYSICAL_ADDRESS boundary_address_multiple = {0};

	return MmAllocateContiguousNodeMemory(
		number_of_bytes, lowest_acceptable_address, highest_acceptable_address,
		boundary_address_multiple, PAGE_READWRITE, MM_ANY_NODE_OK);
}

void UtilFreeContiguousMemory(void* base_address) 
{
	MmFreeContiguousMemory(base_address);
}

void UtilDumpGpRegisters(const AllRegisters* all_regs, ULONG_PTR stack_pointer) 
{
	const auto current_irql = KeGetCurrentIrql();
	if (current_irql < DISPATCH_LEVEL) {
		KeRaiseIrqlToDpcLevel();
	}

	LogInfo(
		"Context at %p: "
		"eax= %p ebx= %p ecx= %p "
		"edx= %p esi= %p edi= %p "
		"esp= %p ebp= %p efl= %08x",
		_ReturnAddress(), all_regs->gp.rax, all_regs->gp.rbx, all_regs->gp.rcx,
		all_regs->gp.rdx, all_regs->gp.rsi, all_regs->gp.rdi, stack_pointer,
		all_regs->gp.rbp, all_regs->flags.all);

	if (current_irql < DISPATCH_LEVEL) {
		KeLowerIrql(current_irql);
	}
}
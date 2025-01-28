#include "Vmx.h"
#include "Ept.h"
#include "Common.h"
#include "InlineAsm.h"
#include "Invept.h"

#include "Vmcall.h"
#include "util.h"
/* Check whether EPT features are present or not */
BOOLEAN EptCheckFeatures()
{
	IA32_VMX_EPT_VPID_CAP_REGISTER VpidRegister;
	IA32_MTRR_DEF_TYPE_REGISTER MTRRDefType;

	VpidRegister.Flags = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
	MTRRDefType.Flags = __readmsr(MSR_IA32_MTRR_DEF_TYPE);

	if (!VpidRegister.PageWalkLength4 || !VpidRegister.MemoryTypeWriteBack || !VpidRegister.Pde2MbPages)
	{
		return FALSE;
	}

	if (!VpidRegister.AdvancedVmexitEptViolationsInformation)
	{
		LogWarning("The processor doesn't report advanced VM-exit information for EPT violations");
	}

	if (!MTRRDefType.MtrrEnable)
	{
		LogError("Mtrr Dynamic Ranges not supported");
		return FALSE;
	}

	LogInfo(" *** All EPT features are present *** ");

	return TRUE;
}


/* Get the PML1 entry for this physical address if the page is split. Return NULL if the address is invalid or the page wasn't already split. */
PEPT_PML1_ENTRY EptGetPml1Entry(PVMM_EPT_PAGE_TABLE EptPageTable, SIZE_T PhysicalAddress)
{
	SIZE_T Directory, DirectoryPointer, PML4Entry;
	PEPT_PML2_ENTRY PML2;
	PEPT_PML1_ENTRY PML1;
	PEPT_PML2_POINTER PML2Pointer;

	Directory = ADDRMASK_EPT_PML2_INDEX(PhysicalAddress);
	DirectoryPointer = ADDRMASK_EPT_PML3_INDEX(PhysicalAddress);
	PML4Entry = ADDRMASK_EPT_PML4_INDEX(PhysicalAddress);

	// Addresses above 512GB are invalid because it is > physical address bus width 
	if (PML4Entry > 0)
	{
		return NULL;
	}

	PML2 = &EptPageTable->PML2[DirectoryPointer][Directory];

	// Check to ensure the page is split 
	if (PML2->Fields.LargePage)
	{
		return NULL;
	}

	// Conversion to get the right PageFrameNumber.
	// These pointers occupy the same place in the table and are directly convertable.
	PML2Pointer = (PEPT_PML2_POINTER)PML2;

	// If it is, translate to the PML1 pointer 
	PML1 = (PEPT_PML1_ENTRY)PhysicalAddressToVirtualAddress((PVOID)(PML2Pointer->Fields.PageFrameNumber * PAGE_SIZE));

	if (!PML1)
	{
		return NULL;
	}

	// Index into PML1 for that address 
	PML1 = &PML1[ADDRMASK_EPT_PML1_INDEX(PhysicalAddress)];

	return PML1;
}


/* Get the PML2 entry for this physical address. */
PEPT_PML2_ENTRY EptGetPml2Entry(PVMM_EPT_PAGE_TABLE EptPageTable, SIZE_T PhysicalAddress)
{
	SIZE_T Directory, DirectoryPointer, PML4Entry;
	PEPT_PML2_ENTRY PML2;

	Directory = ADDRMASK_EPT_PML2_INDEX(PhysicalAddress);
	DirectoryPointer = ADDRMASK_EPT_PML3_INDEX(PhysicalAddress);
	PML4Entry = ADDRMASK_EPT_PML4_INDEX(PhysicalAddress);

	// Addresses above 512GB are invalid because it is > physical address bus width 
	if (PML4Entry > 0)
	{
		return NULL;
	}

	PML2 = &EptPageTable->PML2[DirectoryPointer][Directory];
	return PML2;
}

EPTDATA* EptInitialization()
{
	PAGED_CODE();
	static const ULONG EptPageWalkLevel = 4ul;

	EPTDATA *ept_data = (EPTDATA*)ExAllocatePoolWithTag(NonPagedPool, sizeof(EPTDATA), MYHYPERPOOLTAG);

	if (!ept_data)
	{
		return NULL;
	}

	RtlZeroMemory(ept_data, sizeof(EPTDATA));

	EPTP* ept_poiner = (EPTP*)(ExAllocatePoolWithTag(
		NonPagedPool, PAGE_SIZE, MYHYPERPOOLTAG));
	if (!ept_poiner) 
	{
		ExFreePoolWithTag(ept_data, MYHYPERPOOLTAG);
		return NULL;
	}
	RtlZeroMemory(ept_poiner, PAGE_SIZE);

	EPT_PML4* ept_pml4 = (EPT_PML4*)ExAllocatePoolWithTag(
			NonPagedPool, PAGE_SIZE, MYHYPERPOOLTAG);

	if (!ept_pml4) 
	{
		ExFreePoolWithTag(ept_poiner, MYHYPERPOOLTAG);
		ExFreePoolWithTag(ept_data, MYHYPERPOOLTAG);
		return NULL;
	}

	RtlZeroMemory(ept_pml4, PAGE_SIZE);
	ept_poiner->fields.MemoryType = (ULONG64)(EptpGetMemoryType(VirtualAddressToPhysicalAddress(ept_pml4)));
	ept_poiner->fields.PageWalkLength = EptPageWalkLevel - 1;
	ept_poiner->fields.PageFrameNumber = PfnFromVirtualAddress(VirtualAddressToPhysicalAddress(ept_pml4));

	// Initialize all EPT entries for all physical memory pages
	const PhysicalMemoryDescriptor* pm_ranges = UtilGetPhysicalMemoryRanges();

	for (ULONG run_index = 0ul; run_index < pm_ranges->number_of_runs;++run_index) 
	{
		const PhysicalMemoryRun* run = &pm_ranges->run[run_index];
		const ULONGLONG base_addr = run->base_page * PAGE_SIZE;
		for (ULONGLONG page_index = 0ull; page_index < run->page_count; ++page_index)
		{
			const ULONGLONG indexed_addr = base_addr + page_index * PAGE_SIZE;
			EPT_PML4* ept_pt_entry = InitEPTPML4ConstructTables(ept_pml4, indexed_addr);
			if (!ept_pt_entry) 
			{
				FreeEPTPML4ConstructTables(ept_pml4);
				ExFreePoolWithTag(ept_poiner, MYHYPERPOOLTAG);
				ExFreePoolWithTag(ept_data, MYHYPERPOOLTAG);
				return NULL;
			}
		}
	}

	// Initialize an EPT entry for APIC_BASE. It is required to allocated it now
	// for some reasons, or else, system hangs.
	//const IA32_APIC_BASEMSR apic_msr = { UtilReadMsr64(MSR_APIC_BASE) };


	//const auto preallocated_entries_size =
	//	sizeof(EptCommonEntry*) * kEptpNumberOfPreallocatedEntries;
	//const auto preallocated_entries = (EptCommonEntry**)(
	//	ExAllocatePoolZero(NonPagedPool, preallocated_entries_size,
	//		MYHYPERPOOLTAG));



	// Initialization completed
	ept_data->ept_pointer = ept_poiner;
	ept_data->ept_pml4 = ept_pml4;
	//ept_data->preallocated_entries = preallocated_entries;
	//ept_data->preallocated_entries_count = 0;
	return ept_data;
}

MEMORYTYPE EptpGetMemoryType(ULONG64 physical_address)
{
	UCHAR result_type = MAXUCHAR;

	int numMtrr = sizeof(g_eptp_mtrr_entries) / sizeof(g_eptp_mtrr_entries[0]);

	for (int i = 0; i< numMtrr; ++i)
	{
		MTRRDATA* mtrr_entry = &g_eptp_mtrr_entries[i];
		if (!mtrr_entry)
		{
			continue;
		}

		if (!mtrr_entry->enabled) {
			// Reached out the end of stored MTRRs
			break;
		}

		if (!(mtrr_entry->range_base <= physical_address && 
			physical_address <= mtrr_entry->range_end))
		{
			continue;
		}

		if (mtrr_entry->fixedMtrr) {
			// If a fixed MTRR describes a memory type, it is priority
			result_type = mtrr_entry->type;
			break;
		}
		enum MEMORYTYPE MemoryTypeVar = UNCACHEABLE;
		if (mtrr_entry->type == (UCHAR)(MemoryTypeVar)) {
			// If a memory type is UC, it is priority. Do not continue to search as
			// UC has the highest priority
			result_type = mtrr_entry->type;
			break;
		}

		enum MEMORYTYPE MemoryTypeWT = WRITETHROUGH;
		enum MEMORYTYPE MemoryTypeWB = WRITEBACK;

		if (result_type == (UCHAR)(MemoryTypeWT) ||
			mtrr_entry->type == (UCHAR)(MemoryTypeWT)) 
		{
			if (result_type == (UCHAR) (MemoryTypeWB)) 
			{
				// If two or more MTRRs describes an over-wrapped memory region, and
				// one is WT and the other one is WB, use WT. However, look for other
				// MTRRs, as the other MTRR specifies the memory address as UC, which is
				// priority.
				result_type = (UCHAR)(MemoryTypeWT);
				continue;
			}
		}

		result_type = mtrr_entry->type;


	}

	if (result_type == MAXUCHAR) 
	{
		result_type = g_eptp_mtrr_default_type;
	}

	return (MEMORYTYPE) (result_type);
}


ULONG64 EptpAddressToPxeIndex(_In_ ULONG64 physical_address)
{
	const ULONG64 index = ADDRMASK_EPT_PML4_INDEX(physical_address);
	return index;
}
ULONG64 EptpAddressToPpeIndex(_In_ ULONG64 physical_address)
{
	const ULONG64 index = ADDRMASK_EPT_PML3_INDEX(physical_address);
	return index;
}
ULONG64 EptpAddressToPdeIndex(_In_ ULONG64 physical_address)
{
	const ULONG64 index = ADDRMASK_EPT_PML2_INDEX(physical_address);
	return index;
}
ULONG64 EptpAddressToPteIndex(_In_ ULONG64 physical_address)
{
	const ULONG64 index = ADDRMASK_EPT_PML1_INDEX(physical_address);
	return index;
}

EPT_PML4* InitEPTPML4ConstructTables(EPT_PML4* ept_pml4, ULONG64 physical_address)
{
	const ULONG64 pxe_index = EptpAddressToPxeIndex(physical_address);
	EPT_PML4* ept_pml4_entry = &ept_pml4[pxe_index];
	if (!ept_pml4_entry->Flags)
	{
		unsigned long long allocSize = VMM_EPT_PML3E_COUNT * sizeof(EPDPTE);
		EPDPTE* ept_pdpt = (EPDPTE*)ExAllocatePoolWithTag(NonPagedPool, allocSize, MYHYPERPOOLTAG);
		if (!ept_pdpt)
		{
			return NULL;
		}
		RtlZeroMemory(ept_pdpt, allocSize);

		ept_pml4_entry->Fields.ReadAccess = 1;
		ept_pml4_entry->Fields.WriteAccess = 1;
		ept_pml4_entry->Fields.ExecuteAccess = 1;
		ept_pml4_entry->Fields.PageFrameNumber = PfnFromPhysicalAddress(VirtualAddressToPhysicalAddress(ept_pdpt));
		
		InitEPTPTEConstructTables(ept_pdpt,physical_address);
	}

	return ept_pml4_entry;
}

EPDPTE* InitEPTPTEConstructTables(EPDPTE* ept_pte, ULONG64 physical_address)
{
	const ULONG64 ppe_index = EptpAddressToPpeIndex(physical_address);
	EPDPTE* ept_pdpt_entry = &ept_pte[ppe_index];
	if (!ept_pdpt_entry->Flags)
	{
		unsigned long long allocSize = VMM_EPT_PML2E_COUNT * sizeof(EPDE_2MB);
		EPDE_2MB* ept_pdt = (EPDE_2MB*)ExAllocatePoolWithTag(NonPagedPool, allocSize, MYHYPERPOOLTAG);
		if (!ept_pdt)
		{
			return NULL;
		}
		RtlZeroMemory(ept_pdt, allocSize);

		ept_pdpt_entry->Fields.ReadAccess = 1;
		ept_pdpt_entry->Fields.WriteAccess = 1;
		ept_pdpt_entry->Fields.ExecuteAccess = 1;
		ept_pdpt_entry->Fields.PageFrameNumber = PfnFromPhysicalAddress(VirtualAddressToPhysicalAddress(ept_pdt));
	
		InitEPTPDE2MBConstructTables(ept_pdt, physical_address);
	}

	return ept_pdpt_entry;
}
EPDE_2MB* InitEPTPDE2MBConstructTables(EPDE_2MB* ept_pde, ULONG64 physical_address)
{
	const ULONG64 pde_index = EptpAddressToPdeIndex(physical_address);
	EPDE_2MB* ept_pdt_entry = &ept_pde[pde_index];
	if (!ept_pdt_entry->Flags)
	{
		unsigned long long allocSize = VMM_EPT_PML1E_COUNT * sizeof(EPTE);
		EPTE* ept_pt = (EPTE*)ExAllocatePoolWithTag(NonPagedPool, allocSize, MYHYPERPOOLTAG);
		if (!ept_pt)
		{
			return NULL;
		}
		RtlZeroMemory(ept_pt, allocSize);

		ept_pdt_entry->Fields.ReadAccess = 1;
		ept_pdt_entry->Fields.WriteAccess = 1;
		ept_pdt_entry->Fields.ExecuteAccess = 1;
		ept_pdt_entry->Fields.PageFrameNumber = PfnFromPhysicalAddress(VirtualAddressToPhysicalAddress(ept_pt));

		InitEPTPTConstructTables(ept_pt, physical_address);
	}

	return ept_pdt_entry;
}

EPTE* InitEPTPTConstructTables(EPTE* ept_pt, ULONG64 physical_address)
{
	const ULONG64 pte_index = EptpAddressToPteIndex(physical_address);
	EPTE* ept_pt_entry = &ept_pt[pte_index];
	if (!ept_pt_entry->Flags)
	{
		ept_pt_entry->Fields.ReadAccess = 1;
		ept_pt_entry->Fields.WriteAccess = 1;
		ept_pt_entry->Fields.ExecuteAccess = 1;
		ept_pt_entry->Fields.PageFrameNumber = physical_address;
	}

	return ept_pt_entry;
}

void EptTermination(EPTDATA* ept_data)
{
	FreeEPTPML4ConstructTables(ept_data->ept_pml4);
	ExFreePoolWithTag(ept_data->ept_pointer, MYHYPERPOOLTAG);
	ExFreePoolWithTag(ept_data, MYHYPERPOOLTAG);
}
void FreeEPTPML4ConstructTables(EPT_PML4* ept_pml4)
{
	if (!ept_pml4)
	{
		return;
	}
	for (unsigned long i = 0ul; i < 512; ++i) 
	{
		EPT_PML4 entry = ept_pml4[i];
		if (entry.Fields.PageFrameNumber)
		{
			EPDPTE* ept_pte = (EPDPTE*)PhysicalAddressToVirtualAddress(entry.Fields.PageFrameNumber);
			FreeEPTPTEConstructTables(ept_pte);
		}
	}

	ExFreePoolWithTag(ept_pml4, MYHYPERPOOLTAG);
}
void FreeEPTPTEConstructTables(EPDPTE* ept_pte)
{
	if (!ept_pte)
	{
		return;
	}
	for (unsigned long i = 0ul; i < 512; ++i)
	{
		EPDPTE entry = ept_pte[i];
		if (entry.Fields.PageFrameNumber)
		{
			EPDE_2MB* ept_pte = (EPDE_2MB*)PhysicalAddressToVirtualAddress(entry.Fields.PageFrameNumber);
			FreeEPTPDE2MBConstructTables(ept_pte);

		}
	}
	ExFreePoolWithTag(ept_pte, MYHYPERPOOLTAG);
}
void FreeEPTPDE2MBConstructTables(EPDE_2MB* ept_pde)
{
	if (!ept_pde)
	{
		return;
	}
	for (unsigned long i = 0ul; i < 512; ++i)
	{
		EPDE_2MB entry = ept_pde[i];
		if (entry.Fields.PageFrameNumber)
		{
			EPTE* ept_pte = (EPTE*)PhysicalAddressToVirtualAddress(entry.Fields.PageFrameNumber);
			FreeEPTPTConstructTables(ept_pte);

		}
	}
	ExFreePoolWithTag(ept_pde, MYHYPERPOOLTAG);
}
void FreeEPTPTConstructTables(EPTE* ept_pt)
{
	if (!ept_pt)
	{
		return;
	}

	if (ept_pt)
	{
		ExFreePoolWithTag(ept_pt, MYHYPERPOOLTAG);
	}
	
}

ULONG64 EptGetEptPointer(EPTDATA* ept_data) 
{
	return ept_data->ept_pointer->Flags;
}
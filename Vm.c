#include "Vm.h"
#include "util.h"
#include "InlineAsm.h"
#include "Common.h"
#include "Invept.h"
#include "Invvpid.h"

BOOLEAN VmpIsMyHyperInstalled()
{
	PAGED_CODE();
	int cpu_info[4] = { 0 };
	__cpuid(cpu_info, 1);
	const CPUFEATURESECX cpu_features = { (ULONG_PTR)(cpu_info[2]) };

	__cpuid(cpu_info, HYPERV_CPUID_INTERFACE);
	return cpu_info[0] == 'VHYM';
}

BOOLEAN IsVmxSupported()
{
	PAGED_CODE();
	int cpu_info[4] = { 0 };
	__cpuid(cpu_info, 1);
	const CPUFEATURESECX cpu_features = { (ULONG_PTR)(cpu_info[2]) };
	if (!cpu_features.fields.vmx)
	{
		LogError("VMX features are not supported.");
		return FALSE;
	}
	CPUID Data = { 0 };
	IA32_FEATURE_CONTROL_MSR FeatureControlMsr = { 0 };

	// VMX bit
	__cpuid((int*)&Data, 1);
	if ((Data.ecx & (1 << 5)) == 0)
		return FALSE;

	FeatureControlMsr.All = __readmsr(MSR_IA32_FEATURE_CONTROL);

	// BIOS lock check
	if (FeatureControlMsr.Fields.Lock == 0)
	{
		FeatureControlMsr.Fields.Lock = TRUE;
		FeatureControlMsr.Fields.EnableVmxon = TRUE;
		__writemsr(MSR_IA32_FEATURE_CONTROL, FeatureControlMsr.All);
	}

	if (FeatureControlMsr.Fields.EnableVmxon == FALSE)
	{
		LogError("Intel VMX feature is locked in BIOS");
		return FALSE;
	}

	// Check whether EPT features are present or not 
	if (!EptCheckFeatures())
	{
		LogError("Your processor doesn't support all EPT features");
		return FALSE;
	}

	return TRUE;
}

NTSTATUS VmInitialization()
{
	PAGED_CODE();
	if (VmpIsMyHyperInstalled())
	{
		LogError("The VMM has been installed.");
		return STATUS_CANCELLED;
	}

	if (IsVmxSupported())
	{
		return STATUS_HV_FEATURE_UNAVAILABLE;
	}

	const SHARED_PROCESSOR_DATA* shared_data = VmInitializeSharedData();
	if (!shared_data)
	{
		LogError("VmpInitializeSharedData Failed.");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}


	NTSTATUS status = UtilForEachProcessor(VmpStartVm, shared_data);
	if (!NT_SUCCESS(status))
	{
		UtilForEachProcessor(VmpStopVm, NULL);
		return status;
	}
	return status;

}

void VmTermination()
{
	PAGED_CODE();
	LogInfo("Uninstalling VMM.");
	NTSTATUS status = UtilForEachProcessor(VmpStopVm, NULL);
	if (NT_SUCCESS(status))
	{
		LogInfo("The VMM has been uninstalled.");
	}
	else
	{
		LogInfo("The VMM has not been uninstalled (%08x).", status);
	}
}



// Virtualize the current processor
NTSTATUS VmpStartVm(void* context)
{
	PAGED_CODE();

	LogInfo("Initializing VMX for the processor %d.",
		KeGetCurrentProcessorNumberEx(NULL));

	const BOOLEAN ok = AsmInitializeVm(VmInitializeVm, context);
	NT_ASSERT(VmpIsMyHyperInstalled() == ok);
	if (!ok) {
		return STATUS_UNSUCCESSFUL;
	}
	LogInfo("Initialized successfully.");
	return STATUS_SUCCESS;
}

NTSTATUS VmpStopVm(void* context)
{
	UNREFERENCED_PARAMETER(context);
	PAGED_CODE();

	LogInfo("Terminating VMX for the processor %d.",
		KeGetCurrentProcessorNumberEx(NULL));

	// Stop virtualization and get an address of the management structure
	PROCESSOR_DATA* processor_data = NULL;
	NTSTATUS status = AsmVmxCall(TERMINATE_VMM, &processor_data);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	// Clear CR4.VMXE, as there is no reason to leave the bit after vmxoff
	__writecr4(__readcr4() & (~X86_CR4_VMXE));

	//VmpFreeProcessorData(processor_data);
	return STATUS_SUCCESS;
}

void* VmpBuildMsrBitmap()
{
	PAGED_CODE();
	PVOID msr_bitmap = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE,
		MYHYPERPOOLTAG);

	if (!msr_bitmap)
	{
		return NULL;
	}
	RtlZeroMemory(msr_bitmap, PAGE_SIZE);

	UCHAR* bitmap_read_low = (UCHAR*)(msr_bitmap);
	UCHAR* bitmap_read_high = bitmap_read_low + 1024;
	UCHAR* bitmap_write_low = bitmap_read_low + 2048;
	UCHAR* bitmap_write_high = bitmap_read_low + 3072;

	RtlFillMemory(bitmap_read_low, 1024, 0xff);   // read        0 -     1fff
	RtlFillMemory(bitmap_read_high, 1024, 0xff);  // read c0000000 - c0001fff
	RtlFillMemory(bitmap_write_low, 1024, 0xff);   // write        0 -     1fff
	RtlFillMemory(bitmap_write_high, 1024, 0);  // write c0000000 - c0001fff

	RTL_BITMAP bitmap_read_low_header = { 0 };
	RtlInitializeBitMap(&bitmap_read_low_header,
		(PULONG)(bitmap_read_low), 1024 * 8);
	RtlClearBits(&bitmap_read_low_header, 0xe7, 2);

	for (ULONG msr = 0ul; msr < 0x1000; ++msr)
	{
		__try
		{
			UtilReadMsr(msr);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			RtlClearBits(&bitmap_read_low_header, msr, 1);
		}
	}

	RTL_BITMAP bitmap_read_high_header = { 0 };
	RtlInitializeBitMap(&bitmap_read_high_header,
		(PULONG)(bitmap_read_high),
		1024 * 8);//8bit

	RtlClearBits(&bitmap_read_high_header, 0x101, 2);

	return msr_bitmap;
}

UCHAR* VmpBuildIoBitmaps()
{
	PAGED_CODE();

	const UCHAR* io_bitmaps = (UCHAR*)(ExAllocatePoolWithTag(
		NonPagedPool, PAGE_SIZE * 2, MYHYPERPOOLTAG));
	if (!io_bitmaps)
	{
		return NULL;
	}

	const UCHAR* io_bitmap_a = io_bitmaps;              // for    0x0 - 0x7fff
	const UCHAR* io_bitmap_b = io_bitmaps + PAGE_SIZE;  // for 0x8000 - 0xffff
	RtlFillMemory(io_bitmap_a, PAGE_SIZE, 0);
	RtlFillMemory(io_bitmap_b, PAGE_SIZE, 0);


	// Activate VM-exit for IO port 0x10 - 0x2010 as an example
	RTL_BITMAP bitmap_a_header = { 0 };
	RtlInitializeBitMap(&bitmap_a_header, (PULONG)(io_bitmap_a),
		PAGE_SIZE * 8); // 8bit
	// RtlSetBits(&bitmap_a_header, 0x10, 0x2000);

	RTL_BITMAP bitmap_b_header = { 0 };
	RtlInitializeBitMap(&bitmap_b_header, (PULONG)(io_bitmap_b),
		PAGE_SIZE * 8); // 8bit
	// RtlSetBits(&bitmap_b_header, 0, 0x8000);
	return io_bitmaps;
}

SHARED_PROCESSOR_DATA* VmInitializeSharedData()
{
	PAGED_CODE();

	SHARED_PROCESSOR_DATA* shared_data = (SHARED_PROCESSOR_DATA*)(ExAllocatePoolWithTag(NonPagedPool, sizeof(SHARED_PROCESSOR_DATA),
		MYHYPERPOOLTAG));

	if (!shared_data)
	{
		return NULL;
	}

	RtlZeroMemory(shared_data, sizeof(SHARED_PROCESSOR_DATA));

	shared_data->msr_bitmap = VmpBuildMsrBitmap();
	if (!shared_data->msr_bitmap)
	{
		ExFreePoolWithTag(shared_data, MYHYPERPOOLTAG);
		return NULL;
	}

	// Setup IO bitmaps
	const UCHAR* io_bitmaps = VmpBuildIoBitmaps();
	if (!io_bitmaps)
	{
		ExFreePoolWithTag(shared_data->msr_bitmap, MYHYPERPOOLTAG);
		ExFreePoolWithTag(shared_data, MYHYPERPOOLTAG);
		return NULL;
	}
	shared_data->io_bitmap_a = io_bitmaps;
	shared_data->io_bitmap_b = io_bitmaps + PAGE_SIZE;
	return shared_data;
}

void VmLaunchVm()
{
	unsigned char status;
	size_t field_value = 0;

	status = __vmx_vmread((size_t)(VM_INSTRUCTION_ERROR), &field_value);

	if (status != 0)
	{
		LogInfo("__vmx_vmread error : %d", status);
	}

	status = __vmx_vmlaunch();

	if (status == 1)
	{
		status = __vmx_vmread((size_t)(VM_INSTRUCTION_ERROR), &field_value);

		if (status != 0)
		{
			LogInfo("__vmx_vmlaunch after __vmx_vmread error : %d", status);
		}
	}

}

void VmInitializeVm(ULONG_PTR guest_stack_pointer,
	ULONG_PTR guest_instruction_pointer,
	void* context)
{
	PAGED_CODE();

	SHARED_PROCESSOR_DATA* shared_data = (SHARED_PROCESSOR_DATA*)context;

	if (!shared_data)
	{
		return;
	}

	PROCESSOR_DATA* processor_data = (PROCESSOR_DATA*)(ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESSOR_DATA), MYHYPERPOOLTAG));

	if (!processor_data) {
		return;
	}


	RtlZeroMemory(processor_data, sizeof(PROCESSOR_DATA));
	processor_data->shared_data = shared_data;
	processor_data->vcpu_vmx = NULL;
	processor_data->CpuMode = ProtectedMode;

	InterlockedIncrement(&processor_data->shared_data->reference_count);

	processor_data->ept_data = EptInitialization();
	if (!processor_data->ept_data) {
		goto ReturnFalse;
	}

	// Check if XSAVE/XRSTOR are available and save an instruction mask for all
		// supported user state components
	processor_data->xsave_inst_mask = RtlGetEnabledExtendedFeatures((ULONG64)(-1));
	LogInfo("xsave_inst_mask       = %p", processor_data->xsave_inst_mask);

	if (processor_data->xsave_inst_mask)
	{
		int cpu_info[4] = { 0 };
		__cpuidex(cpu_info, 0xd, 0);
		const auto xsave_area_size = ROUND_TO_PAGES(cpu_info[2]);  // ecx
		processor_data->xsave_area = ExAllocatePoolWithTag(
			NonPagedPool, xsave_area_size, MYHYPERPOOLTAG);
		if (!processor_data->xsave_area) {
			goto ReturnFalse;
		}
		RtlZeroMemory(processor_data->xsave_area, xsave_area_size);
	}
	else
	{
		int cpu_info[4] = { 0 };
		__cpuid(cpu_info, 1);
		const CPUFEATURESECX cpu_features_ecx = { (ULONG32)(cpu_info[2]) };
		const CPUFEATURESEDX cpu_features_edx = { (ULONG32)(cpu_info[3]) };
		if (cpu_features_ecx.fields.avx) {
			LogInfo("A processor supports AVX but not XSAVE/XRSTOR.");
			goto ReturnFalse;
		}
		if (!cpu_features_edx.fields.fxsr) {
			LogInfo("A processor does not support FXSAVE/FXRSTOR.");
			goto ReturnFalse;
		}
	}

	processor_data->vmm_stack_limit =
		UtilAllocateContiguousMemory(KERNEL_STACK_SIZE);
	if (!processor_data->vmm_stack_limit) {
		goto ReturnFalse;
	}
	RtlZeroMemory(processor_data->vmm_stack_limit, KERNEL_STACK_SIZE);

	processor_data->vmcs_region = (VmControlStructure*)(ExAllocatePoolWithTag(
		NonPagedPool, VMCS_SIZE, MYHYPERPOOLTAG));
	if (!processor_data->vmcs_region)
	{
		goto ReturnFalse;
	}
	RtlZeroMemory(processor_data->vmcs_region, VMCS_SIZE);

	processor_data->vmxon_region = (VmControlStructure*)(ExAllocatePoolWithTag(
		NonPagedPool, VMCS_SIZE, MYHYPERPOOLTAG));
	if (!processor_data->vmxon_region) {
		goto ReturnFalse;
	}
	RtlZeroMemory(processor_data->vmxon_region, VMCS_SIZE);

	ULONG_PTR vmm_stack_region_base = (ULONG_PTR)(processor_data->vmm_stack_limit) + KERNEL_STACK_SIZE;
	ULONG_PTR vmm_stack_data = vmm_stack_region_base - sizeof(void*);
	ULONG_PTR vmm_stack_base = vmm_stack_data - sizeof(void*);

	LogInfo("vmm_stack_limit       = %p", processor_data->vmm_stack_limit);
	LogInfo("vmm_stack_region_base = %p", vmm_stack_region_base);
	LogInfo("vmm_stack_data        = %p", vmm_stack_data);
	LogInfo("vmm_stack_base        = %p", vmm_stack_base);
	LogInfo("processor_data        = %p stored at %p", processor_data, vmm_stack_data);
	LogInfo("guest_stack_pointer   = %p", guest_stack_pointer);
	LogInfo("guest_inst_pointer    = %p", guest_instruction_pointer);

	*(ULONG_PTR*)(vmm_stack_base) = MAXULONG_PTR;
	*(PROCESSOR_DATA**)(vmm_stack_data) = processor_data;

	IA32_VMXBASICMSR msr1 = { UtilReadMsr64(MSR_IA32_VMX_BASIC) };
	IA32_FEATURECONTROLMSR msr2 = { UtilReadMsr64(MSR_IA32_FEATURE_CONTROL) };
	msr2.fields.lock = 0;
	msr2.fields.enable_vmxon = 1;

	processor_data->VmxBasicMsr.QuadPart = msr1.all;
	processor_data->Ia32FeatureMsr.QuadPart = msr2.all;
	processor_data->VmxEptMsr.QuadPart = 0;

	//Start to set up VMCS
	if (!VmEnterVmxMode(processor_data))
	{
		goto ReturnFalse;
	}
	if (!VmInitializeVmcs(processor_data))
	{
		goto ReturnFalseWithVmxOff;
	}
	if (!VmSetupVmcs(processor_data, guest_stack_pointer, guest_instruction_pointer, vmm_stack_base))
	{
		goto ReturnFalseWithVmxOff;
	}

	// Do virtualize the processor
	VmLaunchVm();

ReturnFalseWithVmxOff:;
	__vmx_off();

ReturnFalse:;
	FreeProcessorData(processor_data);
}

_IRQL_requires_max_(PASSIVE_LEVEL) BOOLEAN VmEnterVmxMode(_Inout_ PROCESSOR_DATA* processor_data)
{
	PAGED_CODE();
	const CR0 cr0_fixed0 = { UtilReadMsr(MSR_IA32_VMX_CR0_FIXED0) };
	const CR0 cr0_fixed1 = { UtilReadMsr(MSR_IA32_VMX_CR0_FIXED1) };
	CR0 cr0 = { __readcr0() };
	CR0 cr0_original = cr0;
	cr0.all &= cr0_fixed1.all;
	cr0.all |= cr0_fixed0.all;
	__writecr0(cr0.all);

	LogInfo("IA32_VMX_CR0_FIXED0   = %08x", cr0_fixed0.all);
	LogInfo("IA32_VMX_CR0_FIXED1   = %08x", cr0_fixed1.all);
	LogInfo("Original CR0          = %08x", cr0_original.all);
	LogInfo("Fixed CR0             = %08x", cr0.all);

	const CR4 cr4_fixed0 = { UtilReadMsr(MSR_IA32_VMX_CR4_FIXED0) };
	const CR4 cr4_fixed1 = { UtilReadMsr(MSR_IA32_VMX_CR4_FIXED1) };
	CR4 cr4 = { __readcr4() };
	CR4 cr4_original = cr4;
	cr4.all &= cr4_fixed1.all;
	cr4.all |= cr4_fixed0.all;
	__writecr4(cr4.all);

	LogInfo("IA32_VMX_CR4_FIXED0   = %08x", cr4_fixed0.all);
	LogInfo("IA32_VMX_CR4_FIXED1   = %08x", cr4_fixed1.all);
	LogInfo("Original CR4          = %08x", cr4_original.all);
	LogInfo("Fixed CR4             = %08x", cr4.all);

	const IA32_VMX_BASIC_MSR vmx_basic_msr = { UtilReadMsr64(MSR_IA32_VMX_BASIC) };
	processor_data->vmxon_region->revision_identifier = vmx_basic_msr.Fields.RevisionIdentifier;

	ULONG64 vmxon_region_pa = VirtualAddressToPhysicalAddress(processor_data->vmxon_region);
	if (__vmx_on(&vmxon_region_pa)) {
		return FALSE;
	}

	// See: Guidelines for Use of the INVVPID Instruction, and Guidelines for Use
	// of the INVEPT Instruction
	InveptAllContexts();
	InvvpidAllContexts();


	return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL) BOOLEAN VmInitializeVmcs(_Inout_ PROCESSOR_DATA* processor_data)
{
	PAGED_CODE();

	const IA32_VMX_BASIC_MSR vmx_basic_msr = { UtilReadMsr64(MSR_IA32_VMX_BASIC) };
	processor_data->vmcs_region->revision_identifier = vmx_basic_msr.Fields.RevisionIdentifier;

	ULONG64 vmcs_region_pa = VirtualAddressToPhysicalAddress(processor_data->vmcs_region);
	if (__vmx_vmclear(&vmcs_region_pa)) {
		return FALSE;
	}
	if (__vmx_vmptrld(&vmcs_region_pa)) {
		return FALSE;
	}

	// The launch state of current VMCS is "clear"
	return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL) BOOLEAN VmSetupVmcs(
	_In_ const PROCESSOR_DATA* processor_data,
	_In_ ULONG_PTR guest_stack_pointer,
	_In_ ULONG_PTR guest_instruction_pointer, _In_ ULONG_PTR vmm_stack_pointer)
{
	PAGED_CODE();

	unsigned short gdtr_limit, idtr_limit;
	ULONG_PTR gdtr_base, idtr_base;

	gdtr_limit = AsmGetGdtLimit();
	idtr_limit = AsmGetIdtLimit();

	gdtr_base = AsmGetGdtBase();
	idtr_base = AsmGetIdtBase();

	const IA32_VMX_BASIC_MSR vmx_basic_msr = { UtilReadMsr64(MSR_IA32_VMX_BASIC) };
	unsigned int use_true_msrs = vmx_basic_msr.Fields.VmxCapabilityHint;

	/*
	* next try
	VMX_VM_ENTRYCONTROLS vm_entryctl_requested = {0};
	vm_entryctl_requested.fields.load_debug_controls = TRUE;
	vm_entryctl_requested.fields.ia32e_mode_guest = IsX64();
	*/

	VMX_VM_ENTRYCONTROLS vm_entryctl = { AdjustControls(VM_ENTRY_IA32E_MODE, (use_true_msrs) ? MSR_IA32_VMX_TRUE_ENTRY_CTLS : MSR_IA32_VMX_ENTRY_CTLS) };


	/*
	* next try
		VMX_VM_EXIT_CONTROLS vm_exitctl_requested = {0};
		vm_exitctl_requested.fields.host_address_space_size = IsX64();
		vm_exitctl_requested.fields.acknowledge_interrupt_on_exit = true;
	*/
	VMX_VM_EXIT_CONTROLS vm_exitctl = { AdjustControls(VM_EXIT_IA32E_MODE,(use_true_msrs) ? MSR_IA32_VMX_TRUE_EXIT_CTLS : MSR_IA32_VMX_EXIT_CTLS) };

	VMX_PINBASEDCONTROLS vm_pinctl = { AdjustControls(0,(use_true_msrs) ? MSR_IA32_VMX_TRUE_PINBASED_CTLS : MSR_IA32_VMX_PINBASED_CTLS) };

	/*
	VMX_PROCESSORBASEDCONTROLS vm_procctl_requested = {0};
	vm_procctl_requested.fields.invlpg_exiting = false;
	vm_procctl_requested.fields.rdtsc_exiting = false;
	vm_procctl_requested.fields.cr3_load_exiting = true;
	vm_procctl_requested.fields.cr8_load_exiting = false;  // NB: very frequent
	vm_procctl_requested.fields.mov_dr_exiting = true;
	vm_procctl_requested.fields.use_io_bitmaps = true;
	vm_procctl_requested.fields.use_msr_bitmaps = true;
	vm_procctl_requested.fields.activate_secondary_control = true;
	*/
	VMX_PROCESSORBASEDCONTROLS vm_procctl = { AdjustControls(CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS,(use_true_msrs) ? MSR_IA32_VMX_TRUE_PROCBASED_CTLS : MSR_IA32_VMX_PROCBASED_CTLS) };

	/*
		VMX_SECONDARYPROCESSORBASEDCONTROLS vm_procctl2_requested = {0};
		vm_procctl2_requested.fields.enable_ept = true;
		vm_procctl2_requested.fields.descriptor_table_exiting = true;
		vm_procctl2_requested.fields.enable_rdtscp = true;  // for Win10
		vm_procctl2_requested.fields.enable_vpid = true;
		vm_procctl2_requested.fields.enable_xsaves_xstors = true;  // for Win10
	*/

	VMX_SECONDARYPROCESSORBASEDCONTROLS vm_procctl2 = { AdjustControls(CPU_BASED_CTL2_RDTSCP |
		CPU_BASED_CTL2_ENABLE_EPT | CPU_BASED_CTL2_ENABLE_INVPCID |
		CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS | CPU_BASED_CTL2_ENABLE_VPID,MSR_IA32_VMX_PROCBASED_CTLS2) };

	unsigned int exception_bitmap = 1 << 3 | 0;
	// Set exception bitmap to hook division by zero (bit 1 of EXCEPTION_BITMAP)
	// __vmx_vmwrite(EXCEPTION_BITMAP, 0x8); // breakpoint 3nd bit

	CR0 cr0_mask = { 0 };
	CR0 cr0_shadow = { __readcr0() };

	CR4 cr4_mask = { 0 };
	CR4 cr4_shadow = { __readcr4() };

	unsigned char vmx_error = 0;

	//vmx_error |= __vmx_vmwrite(VmcsField::kVirtualProcessorId, KeGetCurrentProcessorNumberEx(nullptr) + 1);


	/* 16-Bit Guest-State Fields */
	vmx_error |= __vmx_vmwrite(GUEST_ES_SELECTOR, AsmGetEs());
	vmx_error |= __vmx_vmwrite(GUEST_CS_SELECTOR, AsmGetCs());
	vmx_error |= __vmx_vmwrite(GUEST_SS_SELECTOR, AsmGetSs());
	vmx_error |= __vmx_vmwrite(GUEST_DS_SELECTOR, AsmGetDs());
	vmx_error |= __vmx_vmwrite(GUEST_FS_SELECTOR, AsmGetFs());
	vmx_error |= __vmx_vmwrite(GUEST_GS_SELECTOR, AsmGetGs());
	vmx_error |= __vmx_vmwrite(GUEST_LDTR_SELECTOR, AsmGetLdtr());
	vmx_error |= __vmx_vmwrite(GUEST_TR_SELECTOR, AsmGetTr());

	/* 16-Bit Host-State Fields */
	// RPL and TI have to be 0
	vmx_error |= __vmx_vmwrite(HOST_ES_SELECTOR, AsmGetEs() & 0xF8);
	vmx_error |= __vmx_vmwrite(HOST_CS_SELECTOR, AsmGetCs() & 0xF8);
	vmx_error |= __vmx_vmwrite(HOST_SS_SELECTOR, AsmGetSs() & 0xF8);
	vmx_error |= __vmx_vmwrite(HOST_DS_SELECTOR, AsmGetDs() & 0xF8);
	vmx_error |= __vmx_vmwrite(HOST_FS_SELECTOR, AsmGetFs() & 0xF8);
	vmx_error |= __vmx_vmwrite(HOST_GS_SELECTOR, AsmGetGs() & 0xF8);
	vmx_error |= __vmx_vmwrite(HOST_TR_SELECTOR, AsmGetTr() & 0xF8);

	/* 64-Bit Control Fields */
	vmx_error |= __vmx_vmwrite(IO_BITMAP_A, VirtualAddressToPhysicalAddress(processor_data->shared_data->io_bitmap_a));
	vmx_error |= __vmx_vmwrite(IO_BITMAP_B, VirtualAddressToPhysicalAddress(processor_data->shared_data->io_bitmap_b));
	vmx_error |= __vmx_vmwrite(MSR_BITMAP, VirtualAddressToPhysicalAddress(processor_data->shared_data->msr_bitmap));
	vmx_error |= __vmx_vmwrite(EPT_POINTER, EptGetEptPointer(processor_data->ept_data));

	/* 64-Bit Guest-State Fields */
	vmx_error |= __vmx_vmwrite(VMCS_LINK_POINTER, MAXULONG64);
	vmx_error |= __vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL));


	/* 32-Bit Control Fields */
	vmx_error |= __vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, vm_pinctl.all);
	vmx_error |= __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, vm_procctl.all);
	vmx_error |= __vmx_vmwrite(EXCEPTION_BITMAP, exception_bitmap);
	vmx_error |= __vmx_vmwrite(VM_EXIT_CONTROLS, vm_exitctl.all);
	vmx_error |= __vmx_vmwrite(VM_ENTRY_CONTROLS, vm_entryctl.all);
	vmx_error |= __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, vm_procctl2.all);

	/* 32-Bit Guest-State Fields */
	vmx_error |= __vmx_vmwrite(GUEST_ES_LIMIT, GetSegmentLimit(AsmGetEs()));
	vmx_error |= __vmx_vmwrite(GUEST_CS_LIMIT, GetSegmentLimit(AsmGetCs()));
	vmx_error |= __vmx_vmwrite(GUEST_SS_LIMIT, GetSegmentLimit(AsmGetSs()));
	vmx_error |= __vmx_vmwrite(GUEST_DS_LIMIT, GetSegmentLimit(AsmGetDs()));
	vmx_error |= __vmx_vmwrite(GUEST_FS_LIMIT, GetSegmentLimit(AsmGetFs()));
	vmx_error |= __vmx_vmwrite(GUEST_GS_LIMIT, GetSegmentLimit(AsmGetGs()));
	vmx_error |= __vmx_vmwrite(GUEST_LDTR_LIMIT, GetSegmentLimit(AsmGetLdtr()));
	vmx_error |= __vmx_vmwrite(GUEST_TR_LIMIT, GetSegmentLimit(AsmGetTr()));
	vmx_error |= __vmx_vmwrite(GUEST_GDTR_LIMIT, gdtr_limit);
	vmx_error |= __vmx_vmwrite(GUEST_IDTR_LIMIT, idtr_limit);

	vmx_error |= __vmx_vmwrite(GUEST_ES_AR_BYTES, GetSegmentAccessRight(AsmGetEs()));
	vmx_error |= __vmx_vmwrite(GUEST_CS_AR_BYTES, GetSegmentAccessRight(AsmGetCs()));
	vmx_error |= __vmx_vmwrite(GUEST_SS_AR_BYTES, GetSegmentAccessRight(AsmGetSs()));
	vmx_error |= __vmx_vmwrite(GUEST_DS_AR_BYTES, GetSegmentAccessRight(AsmGetDs()));
	vmx_error |= __vmx_vmwrite(GUEST_FS_AR_BYTES, GetSegmentAccessRight(AsmGetFs()));
	vmx_error |= __vmx_vmwrite(GUEST_GS_AR_BYTES, GetSegmentAccessRight(AsmGetGs()));
	vmx_error |= __vmx_vmwrite(GUEST_LDTR_AR_BYTES, GetSegmentAccessRight(AsmGetLdtr()));
	vmx_error |= __vmx_vmwrite(GUEST_TR_AR_BYTES, GetSegmentAccessRight(AsmGetTr()));
	vmx_error |= __vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));

	/* 32-Bit Host-State Field */
	vmx_error |= __vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));

	/* Natural-Width Control Fields */
	vmx_error |= __vmx_vmwrite(CR0_GUEST_HOST_MASK, cr0_mask.all);
	vmx_error |= __vmx_vmwrite(CR4_GUEST_HOST_MASK, cr4_mask.all);
	vmx_error |= __vmx_vmwrite(CR0_READ_SHADOW, cr0_shadow.all);
	vmx_error |= __vmx_vmwrite(CR4_READ_SHADOW, cr4_shadow.all);

	/* Natural-Width Guest-State Fields */
	vmx_error |= __vmx_vmwrite(GUEST_CR0, __readcr0());
	vmx_error |= __vmx_vmwrite(GUEST_CR3, __readcr3());
	vmx_error |= __vmx_vmwrite(GUEST_CR4, __readcr4());

	vmx_error |= __vmx_vmwrite(GUEST_ES_BASE, GetSegmentBase(gdtr_base, AsmGetEs()));
	vmx_error |= __vmx_vmwrite(GUEST_CS_BASE, GetSegmentBase(gdtr_base, AsmGetCs()));
	vmx_error |= __vmx_vmwrite(GUEST_SS_BASE, GetSegmentBase(gdtr_base, AsmGetSs()));
	vmx_error |= __vmx_vmwrite(GUEST_DS_BASE, GetSegmentBase(gdtr_base, AsmGetDs()));
	vmx_error |= __vmx_vmwrite(GUEST_FS_BASE, GetSegmentBase(gdtr_base, AsmGetFs()));
	vmx_error |= __vmx_vmwrite(GUEST_GS_BASE, GetSegmentBase(gdtr_base, AsmGetGs()));
	vmx_error |= __vmx_vmwrite(GUEST_LDTR_BASE, GetSegmentBase(gdtr_base, AsmGetLdtr()));
	vmx_error |= __vmx_vmwrite(GUEST_TR_BASE, GetSegmentBase(gdtr_base, AsmGetTr()));
	vmx_error |= __vmx_vmwrite(GUEST_GDTR_BASE, gdtr_base);
	vmx_error |= __vmx_vmwrite(GUEST_IDTR_BASE, idtr_base);

	vmx_error |= __vmx_vmwrite(GUEST_DR7, __readdr(7));
	vmx_error |= __vmx_vmwrite(GUEST_RSP, guest_stack_pointer);
	vmx_error |= __vmx_vmwrite(GUEST_RIP, guest_instruction_pointer);//asmResumeVm //AsmVmxRestoreState
	vmx_error |= __vmx_vmwrite(GUEST_RFLAGS, __readeflags());
	vmx_error |= __vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	vmx_error |= __vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));

	vmx_error |= __vmx_vmwrite(HOST_CR0, __readcr0());
	vmx_error |= __vmx_vmwrite(HOST_CR3, __readcr3());
	vmx_error |= __vmx_vmwrite(HOST_CR4, __readcr4());

	vmx_error |= __vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
	vmx_error |= __vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));

	vmx_error |= __vmx_vmwrite(HOST_TR_BASE, GetSegmentBase(gdtr_base, AsmGetTr()));
	vmx_error |= __vmx_vmwrite(HOST_GDTR_BASE, gdtr_base);
	vmx_error |= __vmx_vmwrite(HOST_IDTR_BASE, idtr_base);
	vmx_error |= __vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	vmx_error |= __vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_EIP));
	vmx_error |= __vmx_vmwrite(HOST_RSP, vmm_stack_pointer);
	vmx_error |= __vmx_vmwrite(HOST_RIP, (ULONG_PTR)(AsmVmmEntryPoint));

	return vmx_error == 0;
}

ULONG AdjustControls(ULONG Ctl, ULONG Msr)
{
	MSR MsrValue = { 0 };

	MsrValue.Content = __readmsr(Msr);
	Ctl &= MsrValue.High;     /* bit == 0 in high word ==> must be zero */
	Ctl |= MsrValue.Low;      /* bit == 1 in low word  ==> must be one  */
	return Ctl;
}

//----------------------------Segment fucntion------------------------------------
ULONG GetSegmentAccessRight(USHORT segment_selector)
{
	PAGED_CODE();

	VMX_REGMENT_DESCRIPTOR_ACCESSRIGHT access_right = { 0 };

	SEGMENT_SELECTOR ss = { segment_selector };

	if (segment_selector)
	{
		ULONG_PTR native_access_right = AsmLoadAccessRightsByte(ss.all);
		native_access_right >>= 8;
		access_right.all = (ULONG)(native_access_right);
		access_right.fields.reserved1 = 0;
		access_right.fields.reserved2 = 0;
		access_right.fields.unusable = FALSE;
	}
	else
	{
		access_right.fields.unusable = TRUE;
	}

	return access_right.all;
}

ULONG_PTR GetSegmentBase(ULONG_PTR gdt_base, USHORT segment_selector)
{
	PAGED_CODE();
	SEGMENT_SELECTOR ss = { segment_selector };
	if (!ss.all) {
		return 0;
	}

	if (ss.fields.ti) {
		const SEGMENT_SELECTOR* local_segment_descriptor = GetSegmentDescriptor(gdt_base, AsmGetLdtr());
		const auto ldt_base = GetSegmentBaseByDescriptor(local_segment_descriptor);
		const auto segment_descriptor = GetSegmentDescriptor(ldt_base, segment_selector);
		return GetSegmentBaseByDescriptor(segment_descriptor);
	}
	else {
		const SEGMENT_SELECTOR* segment_descriptor = GetSegmentDescriptor(gdt_base, segment_selector);
		return GetSegmentBaseByDescriptor(segment_descriptor);
	}


}

SEGMENT_DESCRIPTOR* GetSegmentDescriptor(ULONG_PTR descriptor_table_base, USHORT segment_selector)
{
	PAGED_CODE();
	SEGMENT_SELECTOR ss = { segment_selector };

	return (SEGMENT_DESCRIPTOR*)(descriptor_table_base + ss.fields.index * sizeof(SEGMENT_DESCRIPTOR));
}

ULONG_PTR GetSegmentBaseByDescriptor(const SEGMENT_DESCRIPTOR* segment_descriptor)
{
	PAGED_CODE();

	ULONG64 base_high = segment_descriptor->fields.base_high << (6 * 4);
	ULONG64 base_middle = segment_descriptor->fields.base_mid << (4 * 4);
	ULONG64 base_low = segment_descriptor->fields.base_low;
	ULONG_PTR base = (base_high | base_middle | base_low) & MAXULONG;

	if (!segment_descriptor->fields.system) {
		SEGMENT_DESCRIPTOR_X64* desc64 =
			(SEGMENT_DESCRIPTOR_X64*)(segment_descriptor);
		ULONG64 base_upper32 = desc64->base_upper32;
		base |= (base_upper32 << 32);
	}
	return base;
}

void FreeProcessorData(PROCESSOR_DATA* processor_data)
{
	if (!processor_data) {
		return;
	}
	if (processor_data->vmm_stack_limit) {
		UtilFreeContiguousMemory(processor_data->vmm_stack_limit);
	}
	if (processor_data->vmcs_region) {
		ExFreePoolWithTag(processor_data->vmcs_region, MYHYPERPOOLTAG);
	}
	if (processor_data->vmxon_region) {
		ExFreePoolWithTag(processor_data->vmxon_region,
			MYHYPERPOOLTAG);
	}
	if (processor_data->ept_data) {
		EptTermination(processor_data->ept_data);
	}
	if (processor_data->xsave_area) {
		ExFreePoolWithTag(processor_data->xsave_area, MYHYPERPOOLTAG);
	}

	FreeSharedData(processor_data);

	ExFreePoolWithTag(processor_data, MYHYPERPOOLTAG);
}

void FreeSharedData(PROCESSOR_DATA* processor_data)
{
	PAGED_CODE();

	if (!processor_data->shared_data) {
		return;
	}

	if (InterlockedDecrement(&processor_data->shared_data->reference_count) !=
		0) {
		return;
	}

	LogInfo("Freeing shared data...");
	if (processor_data->shared_data->io_bitmap_a) {
		ExFreePoolWithTag(processor_data->shared_data->io_bitmap_a,
			MYHYPERPOOLTAG);
	}
	if (processor_data->shared_data->msr_bitmap) {
		ExFreePoolWithTag(processor_data->shared_data->msr_bitmap,
			MYHYPERPOOLTAG);
	}
	ExFreePoolWithTag(processor_data->shared_data, MYHYPERPOOLTAG);
}
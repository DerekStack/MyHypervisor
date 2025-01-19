#ifndef MYHYPERVISOR_VM
#define MYHYPERVISOR_VM
#include <ntddk.h>
#include "Vmm.h"


NTSTATUS VmInitialization();
void VmTermination();

BOOLEAN VmpIsMyHyperInstalled();
BOOLEAN IsVmxSupported();

NTSTATUS VmpStartVm(_In_opt_ void* context);
NTSTATUS VmpStopVm(_In_opt_ void* context);
void VmLaunchVm();

void* VmpBuildMsrBitmap();
UCHAR* VmpBuildIoBitmaps();

SHARED_PROCESSOR_DATA* VmInitializeSharedData();

void VmInitializeVm(ULONG_PTR guest_stack_pointer, ULONG_PTR guest_instruction_pointer, void* context);

_IRQL_requires_max_(PASSIVE_LEVEL) BOOLEAN VmEnterVmxMode(_Inout_ PROCESSOR_DATA* processor_data);

_IRQL_requires_max_(PASSIVE_LEVEL) BOOLEAN VmInitializeVmcs(_Inout_ PROCESSOR_DATA* processor_data);

_IRQL_requires_max_(PASSIVE_LEVEL) BOOLEAN VmSetupVmcs(
	_In_ const PROCESSOR_DATA* processor_data,
	_In_ ULONG_PTR guest_stack_pointer,
	_In_ ULONG_PTR guest_instruction_pointer, _In_ ULONG_PTR vmm_stack_pointer);


ULONG GetSegmentAccessRight(USHORT segment_selector);
ULONG_PTR GetSegmentBase(ULONG_PTR gdt_base, USHORT segment_selector);
SEGMENT_DESCRIPTOR* GetSegmentDescriptor(ULONG_PTR descriptor_table_base, USHORT segment_selector);
ULONG_PTR GetSegmentBaseByDescriptor(const SEGMENT_DESCRIPTOR* segment_descriptor);
void FreeProcessorData(PROCESSOR_DATA* processor_data);
void FreeSharedData(PROCESSOR_DATA* processor_data);

ULONG AdjustControls(ULONG Ctl, ULONG Msr);


#endif // !MYHYPERVISOR_VM

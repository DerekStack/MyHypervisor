#include "Vmm.h"
#include "Common.h"
#include "util.h"
#include "Invept.h"
#include "Invvpid.h"
#include "InlineAsm.h"
#include "Vmcall.h"

BOOLEAN IsEmulateVMExit = FALSE;

BOOLEAN VmmVmExitHandler(VMM_INITIAL_STACK* stack)
{
	KIRQL guest_irql;
	unsigned long long guest_cr8;

	guest_irql = KeGetCurrentIrql();
	guest_cr8 = __readcr8();
	ULONG Rflags, guest_rip, guest_rsp;

	if (guest_irql < DISPATCH_LEVEL)
	{
		KeRaiseIrqlToDpcLevel();
	}

	NT_ASSERT(stack->reserved == MAXULONG_PTR);

	__vmx_vmread(GUEST_RFLAGS, &Rflags);
	__vmx_vmread(GUEST_RIP, &guest_rip);

	FLAG_REGISTER flag_register = { Rflags };

	GUEST_CONTEXT guest_context = { stack,
		flag_register,
		guest_rip,
		guest_cr8,
		guest_irql,
		TRUE };

	__vmx_vmread(GUEST_RSP, &guest_rsp),

	guest_context.gp_regs->rsp = guest_rsp;

	VmmSaveExtendedProcessorState(&guest_context);

	// Dispatch the current VM-exit event
	VmmHandleVmExit(&guest_context);

	VmmRestoreExtendedProcessorState(&guest_context);

	// See: Guidelines for Use of the INVVPID Instruction, and Guidelines for Use
	// of the INVEPT Instruction
	if (!guest_context.vm_continue)
	{
		InveptAllContexts();
		InvvpidAllContexts();
	}

	// Restore guest's context
	if (guest_context.irql < DISPATCH_LEVEL && !IsEmulateVMExit)
	{
		KeLowerIrql(guest_context.irql);
	}


	__writecr8(guest_context.cr8);

	return guest_context.vm_continue;


}

void VmmSaveExtendedProcessorState(GUEST_CONTEXT* guest_context)
{
	CR0 cr0 = { __readcr0() };
	CR0 old_cr0 = cr0;

	cr0.fields.ts = FALSE;
	__writecr0(cr0.all);

	if (guest_context->stack->processor_data->xsave_inst_mask)
	{
		_xsave(guest_context->stack->processor_data->xsave_area,
			guest_context->stack->processor_data->xsave_inst_mask);
	}
	else
	{
		// Advances an address up to 15 bytes to be 16-byte aligned
		ULONG_PTR alignment = (ULONG_PTR)(guest_context->stack->processor_data->fxsave_area) % 16;
		alignment = (alignment) ? 16 - alignment : 0;
		_fxsave(guest_context->stack->processor_data->fxsave_area + alignment);
	}
	__writecr0(old_cr0.all);

}

void VmmRestoreExtendedProcessorState(GUEST_CONTEXT* guest_context)
{
	CR0 cr0 = { __readcr0() };
	CR0 old_cr0 = cr0;
	cr0.fields.ts = FALSE;
	__writecr0(cr0.all);
	if (guest_context->stack->processor_data->xsave_inst_mask)
	{
		_xrstor(guest_context->stack->processor_data->xsave_area, guest_context->stack->processor_data->xsave_inst_mask);
	}
	else
	{
		// Advances an address up to 15 bytes to be 16-byte aligned
		ULONG_PTR alignment = (ULONG_PTR)(guest_context->stack->processor_data->fxsave_area) % 16;
		alignment = (alignment) ? 16 - alignment : 0;
		_fxsave(guest_context->stack->processor_data->fxsave_area + alignment);
	}
	__writecr0(old_cr0.all);

}

void VmmHandleVmExit(GUEST_CONTEXT* guest_context)
{
	ULONG exitReason;

	exitReason = 0;
	__vmx_vmread(VM_EXIT_REASON, &exitReason);
	exitReason &= 0xffff;

	ULONG processor = KeGetCurrentProcessorNumberEx(NULL);
	//ULONG index = g_vmmp_next_history_index[processor];
	//ULONG history = g_vmmp_vm_exit_history[processor][index];

	//history.gp_regs = *guest_context->gp_regs;
	//history.ip = guest_context->ip;
	//history.exit_reason = exit_reason;
	//history.exit_qualification = UtilVmRead(VmcsField::kExitQualification);
	//history.instruction_info = UtilVmRead(VmcsField::kVmxInstructionInfo);
	//history.exception_infomation_field = { (ULONG32)UtilVmRead(VmcsField::kVmExitIntrInfo) };
	//if (++index == kVmmpNumberOfRecords)
	//{
	//	index = 0;
	//}

	IsEmulateVMExit = FALSE;

	//LogInfo(0, 0, "Mode: %x Reason: %x ", GetVmxMode(GetVcpuVmx(guest_context)), exit_reason);

	ULONG Rflags;

	NTSTATUS status = STATUS_SUCCESS;

	switch (exitReason)
	{
	case EXIT_REASON_TRIPLE_FAULT:
	{
		LogInfo("Triple fault error occured.");
		break;
	}
	case EXIT_REASON_EXCEPTION_NMI:
	{
		LogInfo("EXIT_REASON_EXCEPTION_NMI occured.");
		break;
	}
	case EXIT_REASON_EXTERNAL_INTERRUPT:
	{
		LogInfo("EXIT_REASON_EXTERNAL_INTERRUPT occured.");
		break;
	}
	case EXIT_REASON_CPUID:
	{
		LogInfo("EXIT_REASON_CPUID occured.");
		break;
	}
	case EXIT_REASON_INVD:
	{
		LogInfo("EXIT_REASON_INVD occured.");
		break;
	}
	case EXIT_REASON_INVLPG:
	{
		LogInfo("EXIT_REASON_INVLPG occured.");
		break;
	}
	case EXIT_REASON_RDTSC:
	{
		LogInfo("EXIT_REASON_RDTSC occured.");
		break;
	}
	case EXIT_REASON_CR_ACCESS:
	{
		LogInfo("EXIT_REASON_CR_ACCESS occured.");
		break;
	}
	case EXIT_REASON_DR_ACCESS:
	{
		LogInfo("EXIT_REASON_DR_ACCESS occured.");
		break;
	}
	case EXIT_REASON_IO_INSTRUCTION:
	{
		LogInfo("EXIT_REASON_IO_INSTRUCTION occured.");
		break;
	}
	case EXIT_REASON_MSR_READ:
	{
		LogInfo("EXIT_REASON_MSR_READ occured.");
		break;
	}
	case EXIT_REASON_MONITOR_TRAP_FLAG:
	{
		LogInfo("EXIT_REASON_MONITOR_TRAP_FLAG occured.");
		break;
	}
	case EXIT_REASON_ACCESS_GDTR_OR_IDTR:
	{
		LogInfo("EXIT_REASON_ACCESS_GDTR_OR_IDTR occured.");
		break;
	}
	case EXIT_REASON_APIC_ACCESS:
	{
		LogInfo("EXIT_REASON_APIC_ACCESS occured.");
		break;
	}
	case EXIT_REASON_ACCESS_LDTR_OR_TR:
	{
		LogInfo("EXIT_REASON_ACCESS_LDTR_OR_TR occured.");
		break;
	}
	case EXIT_REASON_EPT_VIOLATION:
	{
		LogInfo("EXIT_REASON_EPT_VIOLATION occured.");
		break;
	}
	case EXIT_REASON_EPT_MISCONFIG:
	{
		LogInfo("EXIT_REASON_EPT_MISCONFIG occured.");
		break;
	}
	case EXIT_REASON_VMCALL:
	{
		LogInfo("EXIT_REASON_VMCALL occured.");
		UINT64 vmcallNumber = guest_context->gp_regs->rcx;
		UINT64 OptionalParam1 = guest_context->gp_regs->rdx;
		UINT64 OptionalParam2 = guest_context->gp_regs->r8;
		UINT64 OptionalParam3 = guest_context->gp_regs->r9;

		status = VmxVmcallMemoryHandler(vmcallNumber, OptionalParam1, OptionalParam2, OptionalParam3);

		break;
	}



	// 25.1.2  Instructions That Cause VM Exits Unconditionally
	// The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC,
	// INVD, and XSETBV. This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID, 
	// VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.

	case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMPTRST:
	case EXIT_REASON_VMREAD:
	case EXIT_REASON_VMRESUME:
	case EXIT_REASON_VMWRITE:
	case EXIT_REASON_VMXOFF:
	case EXIT_REASON_VMXON:
	case EXIT_REASON_VMLAUNCH:
	{
		LogInfo("VmmpHandleVmx occured.");
		Rflags = 0;
		__vmx_vmread(GUEST_RFLAGS, &Rflags);
		__vmx_vmwrite(GUEST_RFLAGS, Rflags | 0x1); // cf=1 indicate vm instructions fail
		break;
	}

	case EXIT_REASON_RDTSCP:
	{
		//HvHandleControlRegisterAccess(GuestRegs);
		LogInfo("EXIT_REASON_RDTSCP occured.");
		break;
	}
	case EXIT_REASON_XSETBV:
	{
		LogInfo("EXIT_REASON_XSETBV occured.");
		break;
	}
	default:
	{
		LogInfo("Unkown Vmexit, reason : 0x%llx", exitReason);
		break;
	}
	}
}

void VmmVmxFailureHandler(AllRegisters* all_regs)
{
	ULONG guest_ip;
	ULONG status;
	__vmx_vmread(GUEST_RIP, &guest_ip);
	ULONG64 vmx_error = (all_regs->flags.fields.zf) ? __vmx_vmread(VM_INSTRUCTION_ERROR,&status): 0;
	LogError("vmx_error : 0x%llx", vmx_error);
}

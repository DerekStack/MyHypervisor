#pragma once


//
void AsmVmmEntryPoint();

extern __stdcall AsmInitializeVm(_In_ void (*vm_initialization_routine)(_In_ ULONG_PTR, _In_ ULONG_PTR,
    _In_opt_ void*), _In_opt_ void* context);

extern unsigned char __stdcall AsmVmxCall(_In_ ULONG_PTR hypercall_number,
    _In_opt_ void* context);


// ====================  Extended Page Tables ====================
// File : AsmEpt.asm
extern unsigned char inline AsmInvept(unsigned long Type, void* Descriptors);
extern unsigned char inline AsmInvvpid(unsigned long Type, void* Descriptors);


// ====================  Get segment registers ====================
// File : AsmSegmentRegs.asm

// Segment registers
extern unsigned short AsmGetCs();
extern unsigned short AsmGetDs();
extern unsigned short AsmGetEs();
extern unsigned short AsmGetSs();
extern unsigned short AsmGetFs();
extern unsigned short AsmGetGs();
extern unsigned short AsmGetLdtr();
extern unsigned short AsmGetTr();

// Gdt related functions
extern unsigned long long inline AsmGetGdtBase();
extern unsigned short AsmGetGdtLimit();

// Idt related functions
extern unsigned long long inline AsmGetIdtBase();
extern unsigned short AsmGetIdtLimit();

extern ULONG_PTR AsmLoadAccessRightsByte(ULONG_PTR segment_selector);




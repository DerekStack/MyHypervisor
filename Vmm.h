#ifndef MYHYPERVISOR_VMM
#define MYHYPERVISOR_VMM
#include "Msr.h"
#include "Vmx.h"
//////////////////////////////////////////////////
//					Constants					//
//////////////////////////////////////////////////

 /* Intel CPU flags in CR0 */
#define X86_CR0_PE              0x00000001      /* Enable Protected Mode    (RW) */
#define X86_CR0_MP              0x00000002      /* Monitor Coprocessor      (RW) */
#define X86_CR0_EM              0x00000004      /* Require FPU Emulation    (RO) */
#define X86_CR0_TS              0x00000008      /* Task Switched            (RW) */
#define X86_CR0_ET              0x00000010      /* Extension type           (RO) */
#define X86_CR0_NE              0x00000020      /* Numeric Error Reporting  (RW) */
#define X86_CR0_WP              0x00010000      /* Supervisor Write Protect (RW) */
#define X86_CR0_AM              0x00040000      /* Alignment Checking       (RW) */
#define X86_CR0_NW              0x20000000      /* Not Write-Through        (RW) */
#define X86_CR0_CD              0x40000000      /* Cache Disable            (RW) */
#define X86_CR0_PG              0x80000000      /* Paging     


/* Intel CPU features in CR4 */
#define X86_CR4_VME		0x0001		/* enable vm86 extensions */
#define X86_CR4_PVI		0x0002		/* virtual interrupts flag enable */
#define X86_CR4_TSD		0x0004		/* disable time stamp at ipl 3 */
#define X86_CR4_DE		0x0008		/* enable debugging extensions */
#define X86_CR4_PSE		0x0010		/* enable page size extensions */
#define X86_CR4_PAE		0x0020		/* enable physical address extensions */
#define X86_CR4_MCE		0x0040		/* Machine check enable */
#define X86_CR4_PGE		0x0080		/* enable global pages */
#define X86_CR4_PCE		0x0100		/* enable performance counters at ipl 3 */
#define X86_CR4_OSFXSR		0x0200  /* enable fast FPU save and restore */
#define X86_CR4_OSXMMEXCPT	0x0400  /* enable unmasked SSE exceptions */
#define X86_CR4_VMXE		0x2000  /* enable VMX */



/// See: Definitions of VM-Exit Controls
typedef union _VMX_VM_EXIT_CONTROLS 
{
    unsigned int all;
    struct {
        unsigned reserved1 : 2;                        //!< [0:1]
        unsigned save_debug_controls : 1;              //!< [2]
        unsigned reserved2 : 6;                        //!< [3:8]
        unsigned host_address_space_size : 1;          //!< [9]
        unsigned reserved3 : 2;                        //!< [10:11]
        unsigned load_ia32_perf_global_ctrl : 1;       //!< [12]
        unsigned reserved4 : 2;                        //!< [13:14]
        unsigned acknowledge_interrupt_on_exit : 1;    //!< [15]
        unsigned reserved5 : 2;                        //!< [16:17]
        unsigned save_ia32_pat : 1;                    //!< [18]
        unsigned load_ia32_pat : 1;                    //!< [19]
        unsigned save_ia32_efer : 1;                   //!< [20]
        unsigned load_ia32_efer : 1;                   //!< [21]
        unsigned save_vmx_preemption_timer_value : 1;  //!< [22]
    } fields;
}VMX_VM_EXIT_CONTROLS, * PVMX_VM_EXIT_CONTROLS;


/// See: Definitions of VM-Entry Controls
typedef union _VMX_VM_ENTRYCONTROLS 
{
    unsigned int all;
    struct {
        unsigned reserved1 : 2;                          //!< [0:1]
        unsigned load_debug_controls : 1;                //!< [2]
        unsigned reserved2 : 6;                          //!< [3:8]
        unsigned ia32e_mode_guest : 1;                   //!< [9]
        unsigned entry_to_smm : 1;                       //!< [10]
        unsigned deactivate_dual_monitor_treatment : 1;  //!< [11]
        unsigned reserved3 : 1;                          //!< [12]
        unsigned load_ia32_perf_global_ctrl : 1;         //!< [13]
        unsigned load_ia32_pat : 1;                      //!< [14]
        unsigned load_ia32_efer : 1;                     //!< [15]
    } fields;
}VMX_VM_ENTRYCONTROLS, * PVMX_VM_ENTRYCONTROLS;

typedef union _VMX_PINBASEDCONTROLS 
{
    unsigned int all;
    struct {
        unsigned external_interrupt_exiting : 1;    //!< [0]
        unsigned reserved1 : 2;                     //!< [1:2]
        unsigned nmi_exiting : 1;                   //!< [3]
        unsigned reserved2 : 1;                     //!< [4]
        unsigned virtual_nmis : 1;                  //!< [5]
        unsigned activate_vmx_peemption_timer : 1;  //!< [6]
        unsigned process_posted_interrupts : 1;     //!< [7]
    } fields;
}VMX_PINBASEDCONTROLS, * PVMX_PINBASEDCONTROLS;

typedef union _VMX_PROCESSORBASEDCONTROLS 
{
    unsigned int all;
    struct {
        unsigned reserved1 : 2;                   //!< [0:1]
        unsigned interrupt_window_exiting : 1;    //!< [2]
        unsigned use_tsc_offseting : 1;           //!< [3]
        unsigned reserved2 : 3;                   //!< [4:6]
        unsigned hlt_exiting : 1;                 //!< [7]
        unsigned reserved3 : 1;                   //!< [8]
        unsigned invlpg_exiting : 1;              //!< [9]
        unsigned mwait_exiting : 1;               //!< [10]
        unsigned rdpmc_exiting : 1;               //!< [11]
        unsigned rdtsc_exiting : 1;               //!< [12]
        unsigned reserved4 : 2;                   //!< [13:14]
        unsigned cr3_load_exiting : 1;            //!< [15]
        unsigned cr3_store_exiting : 1;           //!< [16]
        unsigned reserved5 : 2;                   //!< [17:18]
        unsigned cr8_load_exiting : 1;            //!< [19]
        unsigned cr8_store_exiting : 1;           //!< [20]
        unsigned use_tpr_shadow : 1;              //!< [21]
        unsigned nmi_window_exiting : 1;          //!< [22]
        unsigned mov_dr_exiting : 1;              //!< [23]
        unsigned unconditional_io_exiting : 1;    //!< [24]
        unsigned use_io_bitmaps : 1;              //!< [25]
        unsigned reserved6 : 1;                   //!< [26]
        unsigned monitor_trap_flag : 1;           //!< [27]
        unsigned use_msr_bitmaps : 1;             //!< [28]
        unsigned monitor_exiting : 1;             //!< [29]
        unsigned pause_exiting : 1;               //!< [30]
        unsigned activate_secondary_control : 1;  //!< [31]
    } fields;
}VMX_PROCESSORBASEDCONTROLS, * PVMX_PROCESSORBASEDCONTROLS;

typedef union _VMX_SECONDARYPROCESSORBASEDCONTROLS 
{
    unsigned int all;
    struct {
        unsigned virtualize_apic_accesses : 1;      //!< [0]
        unsigned enable_ept : 1;                    //!< [1]
        unsigned descriptor_table_exiting : 1;      //!< [2]
        unsigned enable_rdtscp : 1;                 //!< [3]
        unsigned virtualize_x2apic_mode : 1;        //!< [4]
        unsigned enable_vpid : 1;                   //!< [5]
        unsigned wbinvd_exiting : 1;                //!< [6]
        unsigned unrestricted_guest : 1;            //!< [7]
        unsigned apic_register_virtualization : 1;  //!< [8]
        unsigned virtual_interrupt_delivery : 1;    //!< [9]
        unsigned pause_loop_exiting : 1;            //!< [10]
        unsigned rdrand_exiting : 1;                //!< [11]
        unsigned enable_invpcid : 1;                //!< [12]
        unsigned enable_vm_functions : 1;           //!< [13]
        unsigned vmcs_shadowing : 1;                //!< [14]
        unsigned reserved1 : 1;                     //!< [15]
        unsigned rdseed_exiting : 1;                //!< [16]
        unsigned reserved2 : 1;                     //!< [17]
        unsigned ept_violation_ve : 1;              //!< [18]
        unsigned reserved3 : 1;                     //!< [19]
        unsigned enable_xsaves_xstors : 1;          //!< [20]
        unsigned reserved4 : 4;                     //!< [21:24]
        unsigned use_tsc_scaling : 1;               //!< [25]
    } fields;
}VMX_SECONDARYPROCESSORBASEDCONTROLS, * PVMX_SECONDARYPROCESSORBASEDCONTROLS;

typedef union _VMX_REGMENT_DESCRIPTOR_ACCESSRIGHT 
{
    unsigned int all;
    struct {
        unsigned type : 4;
        unsigned system : 1;
        unsigned dpl : 2;
        unsigned present : 1;
        unsigned reserved1 : 4;
        unsigned avl : 1;
        unsigned l : 1;  //!< Reserved (except for CS) 64-bit mode active (for CS)
        unsigned db : 1;
        unsigned gran : 1;
        unsigned unusable : 1;  //!< Segment unusable (0 = usable; 1 = unusable)
        unsigned reserved2 : 15;
    } fields;
}VMX_REGMENT_DESCRIPTOR_ACCESSRIGHT, * PVMX_REGMENT_DESCRIPTOR_ACCESSRIGHT;


typedef union _SEGMENT_SELECTOR 
{
    ULONG64 all;
    struct {
        ULONG64 rpl : 2;  //!< Requested Privilege Level
        ULONG64 ti : 1;   //!< Table Indicator
        ULONG64 index : 13;
        ULONG64 reserved : 48;
    } fields;
}SEGMENT_SELECTOR, * PSEGMENT_SELECTOR;

typedef union _SEGMENT_DESCRIPTOR 
{
    ULONG64 all;
    struct {
        ULONG64 limit_low : 16;
        ULONG64 base_low : 16;
        ULONG64 base_mid : 8;
        ULONG64 type : 4;
        ULONG64 system : 1;
        ULONG64 dpl : 2;
        ULONG64 present : 1;
        ULONG64 limit_high : 4;
        ULONG64 avl : 1;
        ULONG64 l : 1;  //!< 64-bit code segment (IA-32e mode only)
        ULONG64 db : 1;
        ULONG64 gran : 1;
        ULONG64 base_high : 8;
    } fields;
}SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;


typedef struct _SEGMENT_DESCRIPTOR_X64 
{
    SEGMENT_DESCRIPTOR descriptor;
    ULONG32 base_upper32;
    ULONG32 reserved;
}SEGMENT_DESCRIPTOR_X64, * PSEGMENT_DESCRIPTOR_X64;


typedef struct _VMM_INITIAL_STACK 
{
    GpRegisters gp_regs;
    ULONG_PTR reserved;
    PROCESSOR_DATA* processor_data;

}VMM_INITIAL_STACK, * PVMM_INITIAL_STACK;


#pragma pack(8)
typedef struct _GUEST_CONTEXT 
{
    union {
        VMM_INITIAL_STACK* stack;
        GpRegisters* gp_regs;
    };
    FLAG_REGISTER flag_reg;
    ULONG_PTR ip;
    ULONG_PTR cr8;
    KIRQL irql;
    BOOLEAN vm_continue;
}GUEST_CONTEXT, * PGUEST_CONTEXT;
#pragma pack()


BOOLEAN VmmVmExitHandler(VMM_INITIAL_STACK* stack);
void VmmVmxFailureHandler(AllRegisters* all_regs);

void VmmSaveExtendedProcessorState(GUEST_CONTEXT* guest_context);
void VmmHandleVmExit(GUEST_CONTEXT* guest_context);
void VmmRestoreExtendedProcessorState(GUEST_CONTEXT* guest_context);



#endif // !MYHYPERVISOR_VMM
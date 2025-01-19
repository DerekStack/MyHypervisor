; Copyright (c) 2015-2016, tandasat. All rights reserved.
; Copyright (c) 2016-2017, KelvinChan. All rights reserved.
; Use of this source code is governed by a MIT-style license that can be
; found in the LICENSE file.

;
; This module implements all assembler code
;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; References to C functions
;
EXTERN VmmVmExitHandler : PROC
EXTERN VmmVmxFailureHandler : PROC
EXTERN UtilDumpGpRegisters : PROC

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; constants
;
.CONST

VMX_OK                      EQU     0
VMX_ERROR_WITH_STATUS       EQU     1
VMX_ERROR_WITHOUT_STATUS    EQU     2

; Saves all general purpose registers to the stack
PUSHAQ MACRO
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    -1      ; dummy for rsp
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
ENDM

; Loads all general purpose registers from the stack
POPAQ MACRO
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    add     rsp, 8    ; dummy for rsp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
ENDM


; Dumps all general purpose registers and a flag register.
ASM_DUMP_REGISTERS MACRO
    pushfq
    PUSHAQ                      ; -8 * 16
    mov rcx, rsp                ; guest_context
    mov rdx, rsp
    add rdx, 8*17               ; stack_pointer

    sub rsp, 28h                ; 28h for alignment
    call UtilDumpGpRegisters    ; UtilDumpGpRegisters(guest_context, stack_pointer);
    add rsp, 28h

    POPAQ
    popfq
ENDM


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; implementations
;

.CODE

; bool __stdcall AsmInitializeVm(
;     _In_ void (*vm_initialization_routine)(_In_ ULONG_PTR, _In_ ULONG_PTR,
;                                            _In_opt_ void *),
;     _In_opt_ void *context);
AsmInitializeVm PROC
    ; RSP is not 16 bit aligned when it gets called, but the following odd
    ; number (17 times) of push makes RSP 16 bit aligned.
    pushfq
    PUSHAQ              ; -8 * 16

    mov rax, rcx
    mov r8, rdx
    mov rdx, asmResumeVm
    mov rcx, rsp

    sub rsp, 20h
    call rax            ; vm_initialization_routine(rsp, asmResumeVm, context)
    add rsp, 20h

    POPAQ
    popfq
    xor rax, rax        ; return false
    ret

    ; This is where the virtualized guest start to execute after successful
    ; vmlaunch.
asmResumeVm:
    nop                 ; keep this nop for ease of debugging
    POPAQ
    popfq

    sub rsp, 8          ; align RSP
    ASM_DUMP_REGISTERS
    add rsp, 8          ; restore RSP

    xor rax, rax
    inc rax             ; return true
    ret
AsmInitializeVm ENDP


; unsigned char __stdcall AsmVmxCall(_In_ ULONG_PTR hypercall_number,
;                                    _In_opt_ void *context);
AsmVmxCall PROC
    vmcall                  ; vmcall(hypercall_number, context)
    jz errorWithCode        ; if (ZF) jmp
    jc errorWithoutCode     ; if (CF) jmp
    xor rax, rax            ; return VMX_OK
    ret

errorWithoutCode:
    mov rax, VMX_ERROR_WITHOUT_STATUS
    ret

errorWithCode:
    mov rax, VMX_ERROR_WITH_STATUS
    ret
AsmVmxCall ENDP

; void __stdcall AsmVmmEntryPoint();
AsmVmmEntryPoint PROC
    ; No need to save the flag registers since it is restored from the VMCS at
    ; the time of vmresume.
    PUSHAQ                  ; -8 * 16
    mov rcx, rsp

    sub rsp, 20h
    call VmmVmExitHandler   ; bool vm_continue = VmmVmExitHandler(guest_context);
    add rsp, 20h

    test al, al
    jz exitVm               ; if (!vm_continue) jmp exitVm

    POPAQ
    vmresume
    jmp vmxError

exitVm:
    ; Executes vmxoff and ends virtualization
    ;   rax = Guest's rflags
    ;   rdx = Guest's rsp
    ;   rcx = Guest's rip for the next instruction
    POPAQ
    vmxoff
    jz vmxError             ; if (ZF) jmp
    jc vmxError             ; if (CF) jmp
    push rax
    popfq                   ; rflags <= GurstFlags
    mov rsp, rdx            ; rsp <= GuestRsp
    push rcx
    ret                     ; jmp AddressToReturn

vmxError:
    ; Diagnose a critical error
    pushfq
    PUSHAQ                      ; -8 * 16
    mov rcx, rsp                ; all_regs

    sub rsp, 28h                ; 28h for alignment
    call VmmVmxFailureHandler   ; VmmVmxFailureHandler(all_regs);
    add rsp, 28h
    int 3
AsmVmmEntryPoint ENDP


PURGE PUSHAQ
PURGE POPAQ
PURGE ASM_DUMP_REGISTERS
END
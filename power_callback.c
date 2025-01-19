// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Copyright (c) 2016-2017, KelvinChan. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements power callback functions.

#include "power_callback.h"
#include "common.h"
#include "log.h"
//#include "HypervisorRoutines.h"
#include "vm.h"
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

static CALLBACK_FUNCTION PowerCallbackpCallbackRoutine;

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, PowerCallbackInitialization)
#pragma alloc_text(PAGE, PowerCallbackTermination)
#pragma alloc_text(PAGE, PowerCallbackpCallbackRoutine)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

static PCALLBACK_OBJECT g_pcp_callback_object = NULL;
static PVOID g_pcp_registration = NULL;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Registers power callback
NTSTATUS PowerCallbackInitialization()
{
  PAGED_CODE();

  UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Callback\\PowerState");
  OBJECT_ATTRIBUTES oa =
      RTL_CONSTANT_OBJECT_ATTRIBUTES(&name, OBJ_CASE_INSENSITIVE);

  NTSTATUS status = ExCreateCallback(&g_pcp_callback_object, &oa, FALSE, TRUE);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  g_pcp_registration = ExRegisterCallback(
      g_pcp_callback_object, PowerCallbackpCallbackRoutine, NULL);
  if (!g_pcp_registration) {
    ObDereferenceObject(g_pcp_callback_object);
    g_pcp_callback_object = NULL;
    return STATUS_UNSUCCESSFUL;
  }
  return status;
}

// Unregister power callback
void PowerCallbackTermination() 
{
  PAGED_CODE();

  if (g_pcp_registration) {
    ExUnregisterCallback(g_pcp_registration);
  }
  if (g_pcp_callback_object) {
    ObDereferenceObject(g_pcp_callback_object);
  }
}

// Power callback routine dealing with hibernate and sleep
static void PowerCallbackpCallbackRoutine(
    PVOID callback_context, PVOID argument1, PVOID argument2) 
{
  UNREFERENCED_PARAMETER(callback_context);
  PAGED_CODE();

  if (argument1 != (void*)(PO_CB_SYSTEM_STATE_LOCK)) {
    return;
  }

  if (argument2)
  {
      // the computer has just reentered S0.
      NTSTATUS status = VmInitialization();
      if (!NT_SUCCESS(status))
      {
          LogInfo("Failed to re-virtualize processors. Please unload the driver.");
      }
  }
  else
  {
      LogInfo("Suspending the system...");
      //TerminateVmx();
      VmTermination();
  }
}


// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Copyright (c) 2016-2017, KelvinChan. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// @brief Declares interfaces to power functions.

#ifndef HYPERPLATFORM_POWER_CALLBACK_H_
#define HYPERPLATFORM_POWER_CALLBACK_H_

#include <ntddk.h>

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

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS PowerCallbackInitialization();

_IRQL_requires_max_(PASSIVE_LEVEL) void PowerCallbackTermination();

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

#endif  // HYPERPLATFORM_POWER_CALLBACK_H_

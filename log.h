// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Copyright (c) 2016-2017, KelvinChan. All rights reserved.

// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.


/// @file
/// Declares interfaces to logging functions.
#pragma once
#ifndef HYPERPLATFORM_LOG_H_
#define HYPERPLATFORM_LOG_H_

#include <ntddk.h>


////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

/// Logs a message as respective severity
/// @param format   A format string
/// @return STATUS_SUCCESS on success
///
/// Debug prints or buffers a log message with information about current
/// execution context such as time, PID and TID as respective severity.
/// Here are some guide lines to decide which level is appropriate:
///  @li DEBUG: info for only developers.
///  @li INFO: info for all users.
///  @li WARN: info may require some attention but does not prevent the program
///      working properly.
///  @li ERROR: info about issues may stop the program working properly.
///
/// A message should not exceed 512 bytes after all string construction is
/// done; otherwise this macro fails to log and returns non STATUS_SUCCESS.
#define HYPERPLATFORM_LOG_DEBUG(format, ...) \
  LogpPrint(dLogpLevelDebug, __FUNCTION__, (format), __VA_ARGS__)

/// @see HYPERPLATFORM_LOG_DEBUG
#define HYPERPLATFORM_LOG_INFO(format, ...) \
  LogpPrint(dLogpLevelInfo, __FUNCTION__, (format), __VA_ARGS__)

/// @see HYPERPLATFORM_LOG_DEBUG
#define HYPERPLATFORM_LOG_WARN(format, ...) \
  LogpPrint(dLogpLevelWarn, __FUNCTION__, (format), __VA_ARGS__)

/// @see HYPERPLATFORM_LOG_DEBUG
#define HYPERPLATFORM_LOG_ERROR(format, ...) \
  LogpPrint(dLogpLevelError, __FUNCTION__, (format), __VA_ARGS__)

/// Buffers a message as respective severity
/// @param format   A format string
/// @return STATUS_SUCCESS on success
///
/// Buffers the log to buffer and neither calls DbgPrint() nor writes to a file.
/// It is strongly recommended to use it when a status of a system is not
/// expectable in order to avoid system instability.
/// @see HYPERPLATFORM_LOG_DEBUG
#define HYPERPLATFORM_LOG_DEBUG_SAFE(format, ...)                        \
  LogpPrint(dLogpLevelDebug | dLogpLevelOptSafe, __FUNCTION__, (format), \
            __VA_ARGS__)

/// @see HYPERPLATFORM_LOG_DEBUG_SAFE
#define HYPERPLATFORM_LOG_INFO_SAFE(format, ...)                        \
  LogpPrint(dLogpLevelInfo | dLogpLevelOptSafe, __FUNCTION__, (format), \
            __VA_ARGS__)

/// @see HYPERPLATFORM_LOG_DEBUG_SAFE
#define HYPERPLATFORM_LOG_WARN_SAFE(format, ...)                        \
  LogpPrint(dLogpLevelWarn | dLogpLevelOptSafe, __FUNCTION__, (format), \
            __VA_ARGS__)

/// @see HYPERPLATFORM_LOG_DEBUG_SAFE
#define HYPERPLATFORM_LOG_ERROR_SAFE(format, ...)                        \
  LogpPrint(dLogpLevelError | dLogpLevelOptSafe, __FUNCTION__, (format), \
            __VA_ARGS__)

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

/// Save this log to buffer and not try to write to a log file.
static const unsigned long dLogpLevelOptSafe = 0x1ul;

#define dLogpLevelDebug  0x10ul  //!< Bit mask for DEBUG level logs
#define dLogpLevelInfo  0x20ul   //!< Bit mask for INFO level logs
#define dLogpLevelWarn  0x40ul   //!< Bit mask for WARN level logs
#define dLogpLevelError  0x80ul  //!< Bit mask for ERROR level logs

/// For LogInitialization(). Enables all levels of logs
static const unsigned long dLogPutLevelDebug = 0xF1ul;//dLogpLevelError | dLogpLevelWarn | dLogpLevelInfo | dLogpLevelDebug;

/// For LogInitialization(). Enables ERROR, WARN and INFO levels of logs
static const unsigned long kLogPutLevelInfo = 0xF0ul;
    //dLogpLevelError | dLogpLevelWarn | dLogpLevelInfo;

/// For LogInitialization(). Enables ERROR and WARN levels of logs
static const unsigned long dLogPutLevelWarn = 0xC0ul;//dLogpLevelError | dLogpLevelWarn;

/// For LogInitialization(). Enables an ERROR level of logs
static const unsigned long dLogPutLevelError = 0x80ul;//dLogpLevelError;

/// For LogInitialization(). Disables all levels of logs
static const unsigned long dLogPutLevelDisable = 0x00ul;

/// For LogInitialization(). Do not log a current time
static const unsigned long dLogOptDisableTime = 0x100ul;

/// For LogInitialization(). Do not log a current function name
static const unsigned long dLogOptDisableFunctionName = 0x200ul;

/// For LogInitialization(). Do not log a current processor number
static const unsigned long dLogOptDisableProcessorNumber = 0x400ul;

/// For LogInitialization(). Do not log to debug buffer
static const unsigned long dLogOptDisableDbgPrint = 0x800ul;

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

/// Initializes the log system.
/// @param flag   A OR-ed flag to control a log level and options
/// @param file_path  A log file path
/// @return STATUS_SUCCESS on success, STATUS_REINITIALIZATION_NEEDED when
/// re-initialization with LogRegisterReinitialization() is required, or else on
/// failure.
///
/// Allocates internal log buffers, initializes related resources, starts a
/// log flush thread and creates a log file if requested. This function returns
/// STATUS_REINITIALIZATION_NEEDED if a file-system is not initialized yet. In
/// that case, a driver must call LogRegisterReinitialization() for completing
/// initialization.
///
/// \a flag is a OR-ed value of kLogPutLevel* and kLogOpt*. For example,
/// kLogPutLevelDebug | dLogOptDisableFunctionName.
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    LogInitialization(_In_ ULONG flag, _In_opt_ const wchar_t *file_path);

/// Registers re-initialization.
/// @param driver_object  A driver object being loaded
///
/// A driver must call this function, or call LogTermination() and return non
/// STATUS_SUCCESS from DriverEntry() if LogInitialization() returned
/// STATUS_REINITIALIZATION_NEEDED. If this function is called, DriverEntry()
/// must return STATUS_SUCCESS.
_IRQL_requires_max_(PASSIVE_LEVEL) void LogRegisterReinitialization(
    _In_ PDRIVER_OBJECT driver_object);

/// Terminates the log system. Should be called from an IRP_MJ_SHUTDOWN handler.
_IRQL_requires_max_(PASSIVE_LEVEL) void LogIrpShutdownHandler();

/// Terminates the log system. Should be called from a DriverUnload routine.
_IRQL_requires_max_(PASSIVE_LEVEL) void LogTermination();

/// Logs a message; use HYPERPLATFORM_LOG_*() macros instead.
/// @param level   Severity of a message
/// @param function_name   A name of a function called this function
/// @param format   A format string
/// @return STATUS_SUCCESS on success
/// @see HYPERPLATFORM_LOG_DEBUG
/// @see HYPERPLATFORM_LOG_DEBUG_SAFE
NTSTATUS LogpPrint(_In_ ULONG level, _In_ const char *function_name,
                   _In_ const char *format, ...);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//


#endif  // HYPERPLATFORM_LOG_H_

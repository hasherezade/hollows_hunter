// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Thrown when the ETW trace object is already registered.
    /// </summary>
    public ref struct TraceAlreadyRegistered : public System::Exception {};

    /// <summary>
    /// Thrown when an invalid parameter is provided.
    /// </summary>
    public ref struct InvalidParameter : public System::Exception {};

    /// <summary>
    /// Thrown when the trace fails to open.
    /// </summary>
    public ref struct OpenTraceFailure : public System::Exception {};

    /// <summary>
    /// Thrown when the schema for an event could not be found.
    /// </summary>
    public ref struct CouldNotFindSchema : public System::Exception {
        /// <param name="msg">Additional context related to the error</param>
        CouldNotFindSchema(System::String^ msg) : System::Exception(msg) { }
    };

    /// <summary>
    /// Thrown when an error occurs that we did not explicitly handle.
    /// </summary>
    public ref struct UnexpectedError : public System::Exception {
        /// <param name="msg">Additional context related to the error</param>
        UnexpectedError(System::String^ msg) : System::Exception(msg) { }
    };

    /// <summary>
    /// Thrown when an error is encountered parsing an ETW property.
    /// </summary>
    public ref struct ParserException : public System::Exception {
        /// <param name="msg">the error message returned while parsing</param>
        ParserException(System::String^ msg) : System::Exception(msg) { }
    };

    /// <summary>
    /// Thrown when a requested type does not match the ETW property type.
    /// NOTE: This is only thrown in debug builds.
    /// </summary>
    public ref struct TypeMismatchAssert : public System::Exception {
        /// <param name="msg">the error message returned when types mismatched</param>
        TypeMismatchAssert(System::String^ msg) : System::Exception(msg) { }
    };

    /// <summary>
    /// Thrown on internal parsing errors when retrieving container ID's.
    /// </summary>
    public ref struct ContainerIdFormatException : public System::Exception {
        ContainerIdFormatException(System::String^ msg) : System::Exception(msg) {}
    };

    /// <summary>
    /// Thrown when no trace sessions remaining to register. An existing trace
    /// session must be deleted first.
    /// </summary>
    public ref struct NoTraceSessionsRemaining : public System::Exception {};

#define ExecuteAndConvertExceptions(e) \
        try { e; } \
        catch (const krabs::trace_already_registered &) \
        { \
            throw gcnew TraceAlreadyRegistered; \
        } \
        catch (const krabs::invalid_parameter &) \
        { \
            throw gcnew InvalidParameter; \
        } \
        catch (const krabs::open_trace_failure &) \
        { \
            throw gcnew OpenTraceFailure; \
        } \
        catch (const krabs::no_trace_sessions_remaining &) \
        { \
            throw gcnew NoTraceSessionsRemaining; \
        } \
        catch (const krabs::need_to_be_admin_failure &) \
        { \
            throw gcnew UnauthorizedAccessException("Need to be admin"); \
        } \
        catch (const krabs::function_not_supported &) \
        { \
            throw gcnew NotSupportedException(); \
        } \
        catch (const krabs::could_not_find_schema &ex) \
        { \
            throw gcnew CouldNotFindSchema(gcnew String(ex.what())); \
        } \
        catch (const krabs::unexpected_error &ex) \
        { \
            throw gcnew UnexpectedError(gcnew String(ex.what())); \
        } \

} } } }
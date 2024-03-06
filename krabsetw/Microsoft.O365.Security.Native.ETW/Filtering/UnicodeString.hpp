// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>

#include <string>

#include "../NativePtr.hpp"
#include "Predicate.hpp"
#include <msclr\marshal.h>
#include <msclr\marshal_cppstd.h>

using namespace System;
using namespace System::Runtime::InteropServices;
namespace adapt = krabs::predicates::adapters;

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Fluent filters for ANSI String properties
    /// </summary>
    public ref class UnicodeString abstract sealed {
    public:
        /// <summary>
        /// Accept event if unicode string property equals the specified string
        /// </summary>
        /// <param name="name">name of the property to match against</param>
        /// <param name="value">the value to match against</param>
        /// <returns>a predicate representing that the named property equals the specified value</returns>
        static Predicate^ Is(String^ name, String^ value)
        {
            return gcnew Predicate(krabs::predicates::property_equals(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }

        /// <summary>
        /// Accept event if unicode string property equals (case invariant) the specified string
        /// </summary>
        /// <param name="name">name of the property to match against</param>
        /// <param name="value">the value to match against</param>
        /// <returns>a predicate representing that the named property equals (case invariant) the specified value</returns>
        static Predicate^ IEquals(String^ name, String^ value)
        {
            return gcnew Predicate(krabs::predicates::property_iequals(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }

        /// <summary>
        /// Accept event if unicode string property contains the specified string
        /// </summary>
        /// <param name="name">name of the property to match against</param>
        /// <param name="value">the value to match against</param>
        /// <returns>a predicate representing that the named property contains the specified value</returns>
        static Predicate^ Contains(String^ name, String^ value)
        {
            return gcnew Predicate(krabs::predicates::property_contains(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }

        /// <summary>
        /// Accept event if unicode string property contains (case invariant) the specified string
        /// </summary>
        /// <param name="name">name of the property to match against</param>
        /// <param name="value">the value to match against</param>
        /// <returns>a predicate representing that the named property contains (case invariant) the specified value</returns>
        static Predicate^ IContains(String^ name, String^ value)
        {
            return gcnew Predicate(krabs::predicates::property_icontains(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }

        /// <summary>
        /// Accept event if unicode string property starts with the specified string
        /// </summary>
        /// <param name="name">name of the property to match against</param>
        /// <param name="value">the value to match against</param>
        /// <returns>a predicate representing that the named property starts with the specified value</returns>
        static Predicate^ StartsWith(String^ name, String^ value)
        {
            return gcnew Predicate(krabs::predicates::property_starts_with(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }

        /// <summary>
        /// Accept event if unicode string property starts with (case invariant) the specified string
        /// </summary>
        /// <param name="name">name of the property to match against</param>
        /// <param name="value">the value to match against</param>
        /// <returns>a predicate representing that the named property starts with (case invariant) the specified value</returns>
        static Predicate^ IStartsWith(String^ name, String^ value)
        {
            return gcnew Predicate(krabs::predicates::property_istarts_with(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }

        /// <summary>
        /// Accept event if unicode string property ends with the specified string
        /// </summary>
        /// <param name="name">name of the property to match against</param>
        /// <param name="value">the value to match against</param>
        /// <returns>a predicate representing that the named property ends with the specified value</returns>
        static Predicate^ EndsWith(String^ name, String^ value)
        {
            return gcnew Predicate(krabs::predicates::property_ends_with(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }

        /// <summary>
        /// Accept event if unicode string property ends with (case invariant) the specified string
        /// </summary>
        /// <param name="name">name of the property to match against</param>
        /// <param name="value">the value to match against</param>
        /// <returns>a predicate representing that the named property ends with (case invariant) the specified value</returns>
        static Predicate^ IEndsWith(String^ name, String^ value)
        {
            return gcnew Predicate(krabs::predicates::property_iends_with(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }
    };
} } } }
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
    public ref class CountedString abstract sealed {
    public:
        /// <summary>
        /// Accept event if counted string property equals the specified string
        /// </summary>
        /// <param name="name">represents the property name</param>
        /// <param name="value">represents the value to match on</param>
        /// <returns>a predicate that accepts an event if the value matches the specified string</returns>
        static Predicate^ Is(String^ name, String^ value)
        {
            return gcnew Predicate(krabs::predicates::property_equals<adapt::counted_string>(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }

        /// <summary>
        /// Accept event if counted string property equals (case invariant) the specified string
        /// </summary>
        /// <param name="name">represents the property name</param>
        /// <param name="value">represents the value to match on</param>
        /// <returns>a predicate that accepts an event if the value matches (case invariant) the specified string</returns>
        static Predicate^ IEquals(String^ name, String^ value)
        {
            return gcnew Predicate(krabs::predicates::property_iequals<adapt::counted_string>(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }

        /// <summary>
        /// Accept event if counted string property contains the specified string
        /// </summary>
        /// <param name="name">represents the property name</param>
        /// <param name="value">represents the value to match on</param>
        /// <returns>a predicate that accepts an event if the value contains the specified string</returns>
        static Predicate^ Contains(String^ name, String^ value)
        {
            return gcnew Predicate(krabs::predicates::property_contains<adapt::counted_string>(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }

        /// <summary>
        /// Accept event if counted string property contains (case invariant) the specified string
        /// </summary>
        /// <param name="name">represents the property name</param>
        /// <param name="value">represents the value to match on</param>
        /// <returns>a predicate that accepts an event if the value contains (case invariant) the specified string</returns>
        static Predicate^ IContains(String^ name, String^ value)
        {
            return gcnew Predicate(krabs::predicates::property_icontains<adapt::counted_string>(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }

        /// <summary>
        /// Accept event if counted string property starts with the specified string
        /// </summary>
        /// <param name="name">represents the property name</param>
        /// <param name="value">represents the value to match on</param>
        /// <returns>a predicate that accepts an event if the value starts with the specified string</returns>
        static Predicate^ StartsWith(String^ name, String^ value)
        {
            return gcnew Predicate(krabs::predicates::property_starts_with<adapt::counted_string>(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }

        /// <summary>
        /// Accept event if counted string property starts with (case invariant) the specified string
        /// </summary>
        /// <param name="name">represents the property name</param>
        /// <param name="value">represents the value to match on</param>
        /// <returns>a predicate that accepts an event if the value starts with (case invariant) the specified string</returns>
        static Predicate^ IStartsWith(String^ name, String^ value)
        {
            return gcnew Predicate(krabs::predicates::property_istarts_with<adapt::counted_string>(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }

        /// <summary>
        /// Accept event if counted string property ends with the specified string
        /// </summary>
        /// <param name="name">represents the property name</param>
        /// <param name="value">represents the value to match on</param>
        /// <returns>a predicate that accepts an event if the value ends with the specified string</returns>
        static Predicate^ EndsWith(String^ name, String^ value)
        {
            return gcnew Predicate(krabs::predicates::property_ends_with<adapt::counted_string>(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }

        /// <summary>
        /// Accept event if counted string property ends with (case invariant) the specified string
        /// </summary>
        /// <param name="name">represents the property name</param>
        /// <param name="value">represents the value to match on</param>
        /// <returns>a predicate that accepts an event if the value ends with (case invariant) the specified string</returns>
        static Predicate^ IEndsWith(String^ name, String^ value)
        {
            return gcnew Predicate(krabs::predicates::property_iends_with<adapt::counted_string>(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }
    };
} } } }
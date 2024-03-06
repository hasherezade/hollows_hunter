// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>

#include <string>

#include "../NativePtr.hpp"
#include "Predicate.hpp"

using namespace System;
using namespace System::Runtime::InteropServices;
namespace adpt = krabs::predicates::adapters;

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Enables a more convenient mechanism to specify filters in
    /// managed C++/C#.
    /// </summary>
    /// <remarks>
    /// The idea here is that chains of complicated filters are built
    /// iteratively, using the methods on this class. These chains are passed
    /// into the native layer a single time, where they are used to do
    /// filtering before they are bubbled up to the managed layer.
    /// </remarks>
    public ref class Filter {
    public:

        // Event Properties
        // --------------------------------------------------------------------

        /// <summary>
        /// Used to negate the result of the predicate argument.
        /// </summary>
        /// <param name="other">the predicate to negate</param>
        /// <returns>negated form of the predicate passed in</returns>
        static Predicate ^Not(Predicate ^other)
        {
            return Predicate::make_predicate<KPD::not_filter<krabs::filter_predicate>>(*other->predicate_);
        }

        /// <summary>
        /// Accepts any events.
        /// </summary>
        /// <returns>a predicate that accepts any event</returns>
        static Predicate ^AnyEvent()
        {
            return Predicate::make_predicate<krabs::predicates::details::any_event>();
        }

        /// <summary>
        /// Used to verify that an event opcode matches the expected value
        /// </summary>
        /// <param name="opcode">event opcode to verify</param>
        /// <returns>predicate that verifies an event's opcode</returns>
        static Predicate ^EventOpcodeIs(int opcode)
        {
            return Predicate::make_predicate<krabs::predicates::opcode_is>(opcode);
        }

        /// <summary>
        /// Used to verify that an event matches the given id.
        /// </summary>
        /// <param name="id">the event id to match on</param>
        /// <returns>a predicate that will match an event with the provided id</returns>
        static Predicate ^EventIdIs(int id)
        {
            return Predicate::make_predicate<krabs::predicates::id_is>(id);
        }

        /// <summary>
        /// Used to verify that an event version is the given version.
        /// </summary>
        /// <param name="version">the version to match on</param>
        /// <returns>a predicate that matches events of the specified version</returns>
        static Predicate ^EventVersionIs(int version)
        {
            return Predicate::make_predicate<krabs::predicates::version_is>(version);
        }

        /// <summary>
        /// Used to verify that an event was emitted by a specific PID.
        /// </summary>
        /// <param name="processId">the PID to match on</param>
        /// <returns>a predicate that matches events of the specified PID</returns>
        static Predicate ^ProcessIdIs(int processId)
        {
            return Predicate::make_predicate<krabs::predicates::process_id_is>(processId);
        }

        /// <summary>
        /// Used to verify that an event was emitted with a specific UInt32 property.
        /// </summary>
        /// <param name="propertyName">the name of the property to match on</param>
        /// <param name="value">the value of the property to match on</param>
        /// <returns>a predicate that matches events of the specified UInt32 property</returns>
        static Predicate ^IsUInt32(String ^propertyName, UInt32 value)
        {
            return gcnew Predicate(krabs::predicates::property_is<UInt32>(
                msclr::interop::marshal_as<std::wstring>(propertyName),
                value));
        }
    };
} } } }
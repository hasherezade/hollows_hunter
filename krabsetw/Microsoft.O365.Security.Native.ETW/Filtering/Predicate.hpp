// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>
#include "../Testing/SynthRecord.hpp"

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    namespace KP = krabs::predicates;
    namespace KPD = krabs::predicates::details;

    /// <summary>
    /// An object representing a condition to match against for use in
    /// EventFilter.
    /// </summary>
    public ref class Predicate {

    internal:
        template <typename T>
        Predicate(const T &t)
        : predicate_(t)
        { }

        krabs::filter_predicate& to_underlying()
        {
            return *predicate_;
        }

        template <typename T, typename... Args>
        static Predicate^ make_predicate(Args&&... args)
        {
            return gcnew Predicate(T(args...));
        }

    public:

        /// <summary>
        /// Creates a new <see cref="O365::Security::ETW::Predicate"/> representing
        /// the logical and of the current predicate and another predicate.
        /// </summary>
        /// <param name="other">the predicate to perform the logical and against</param>
        /// <returns>the resulting <see cref="O365::Security::ETW::Predicate"/> object</returns>
        Predicate^ operator&&(Predicate^ other)
        {
            return Predicate::make_predicate<KPD::and_filter<krabs::filter_predicate, krabs::filter_predicate>>(*predicate_, *other->predicate_);
        }

        /// <summary>
        /// Creates a new <see cref="O365::Security::ETW::Predicate"/> representing
        /// the logical or of the current predicate and another predicate.
        /// </summary>
        /// <param name="other">the predicate to perform the logical or against</param>
        /// <returns>the resulting <see cref="O365::Security::ETW::Predicate"/> object</returns>
        Predicate^ operator||(Predicate^ other)
        {
            return Predicate::make_predicate<KPD::or_filter<krabs::filter_predicate, krabs::filter_predicate>>(*predicate_, *other->predicate_);
        }

        /// <summary>
        /// Creates a new <see cref="O365::Security::ETW::Predicate"/> representing
        /// the logical not of the current predicate.
        /// </summary>
        /// <returns>the resulting negated <see cref="O365::Security::ETW::Predicate"/> object</returns>
        Predicate^ operator!()
        {
            return Predicate::make_predicate<KPD::not_filter<krabs::filter_predicate>>(*predicate_);
        }

        /// <summary>
        /// Creates a new <see cref="O365::Security::ETW::Predicate"/> representing
        /// the logical and of the current predicate and another predicate.
        /// </summary>
        /// <param name="other">the predicate to perform the logical and against</param>
        /// <returns>the resulting <see cref="O365::Security::ETW::Predicate"/> object</returns>
        Predicate^ And(Predicate^ other)
        {
            return Predicate::make_predicate<KPD::and_filter<krabs::filter_predicate, krabs::filter_predicate>>(*predicate_, *other->predicate_);
        }

        /// <summary>
        /// Creates a new <see cref="O365::Security::ETW::Predicate"/> representing
        /// the logical or of the current predicate and another predicate.
        /// </summary>
        /// <param name="other">the predicate to perform the logical or against</param>
        /// <returns>the resulting <see cref="O365::Security::ETW::Predicate"/> object</returns>
        Predicate^ Or(Predicate^ other)
        {
            return Predicate::make_predicate<KPD::or_filter<krabs::filter_predicate, krabs::filter_predicate>>(*predicate_, *other->predicate_);
        }

        /// <summary>
        /// Used to test a <see cref="O365::Security::ETW::Testing::SynthRecord"/>
        /// against a created Predicate.
        /// </summary>
        /// <param name="record">the SynthRecord to match against</param>
        /// <returns>true if the SynthRecord matches the Predicate, false otherwise</returns>
        /// <remarks>
        /// This is for testing scenarios.
        /// </remarks>
        bool Test(Testing::SynthRecord^ record)
        {
            auto& nativeRecord = *(record->record_);
            krabs::trace_context trace_context;
            return to_underlying()(nativeRecord, trace_context);
        }

    internal:
        NativePtr<krabs::filter_predicate> predicate_;
    };

} } } }
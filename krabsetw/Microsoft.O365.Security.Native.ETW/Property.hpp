// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>

#include "NativePtr.hpp"
#include <cassert>

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    using namespace System::Collections::Generic;

    /// <summary>
    /// Represents a single property in an EventRecord.
    /// </summary>
    /// <remarks>
    ///   Noticeably absent from this property is the ability to ask what its
    ///   value is.The reason for this is that this property instance is
    ///   intended to work with synth_records, which don't always have data to
    ///   correspond with properties.This class *cannot* return a value because
    ///   there isn't always a value to return.
    /// </remarks>
    public ref class Property {
    public:
        /// <summary>
        /// Represents a property on an EventRecord.
        /// </summary>
        /// <param name="name">the property's name</param>
        /// <param name="type">the property's type</param>
        /// <param name="outType">the property's out type</param>
        /// <remarks>
        /// See <see href="https://msdn.microsoft.com/en-us/library/windows/desktop/aa964763(v=vs.85).aspx"/>
        /// for more information about property types. In particular, the TDH_INTYPE_* values.
        /// </remarks>
        Property(String ^name, unsigned int type, unsigned int outType);

        /// <summary>Returns the name of this property.</summary>
        /// <returns>the name of this property</returns>
        property String ^Name {
            String ^get() {
                return gcnew String(property_->name().c_str());
            }
        }

        /// <summary>Returns the type of this property.</summary>
        /// <returns>the type of this property</returns>
        property int Type {
            int get() {
                return property_->type();
            }
        }

        /// <summary>Returns the out type of this property.</summary>
        /// <returns>the out type of this property</returns>
        property int OutType {
            int get() {
                return property_->out_type();
            }
        }

    private:
        NativePtr<krabs::property> property_;
    };

    /// <summary>
    /// Iterates the properties in an event schema.
    /// </summary>
    public ref class PropertyEnumerator : public IEnumerator<Property^> {
    internal:
        PropertyEnumerator(const krabs::schema& schema)
        : iterator_(schema)
        , vecIterator_()
        , vecIteratorEnd_()
        {
            Reset();
        }

        ~PropertyEnumerator() { }

        /// <summary>
        /// Advance the enumerator by one element.
        /// </summary>
        /// <returns>true if more elements to enumerate, false if at the end</returns>
        virtual bool MoveNext() = IEnumerator<Property^>::MoveNext {

            // C#'s enumerators expect the enumeration to point to a vacuous
            // space *before* the first element when they are Reset. Reset is
            // immediately followed by a call to MoveNext that points us to the
            // actual first element. C++ iterators don't work this way, so we
            // need to align them by lazily initializing the underlying C++
            // iterator.
            if (!vecIterator_) {
                vecIterator_.Swap(NativePtr<std::vector<krabs::property>::iterator>(iterator_->begin()));
                if (iters_match(vecIterator_, vecIteratorEnd_)) {
                    return false;
                }

                return true;
            }

            if (iters_match(vecIterator_, vecIteratorEnd_)) {
                return false;
            }

            std::advance(*vecIterator_.Get(), 1);

            if (iters_match(vecIterator_, vecIteratorEnd_)) {
                return false;
            }

            return true;
        }

        /// <summary>Return the current element in the enumeration</summary>
        /// <returns>the current element in the enumeration as a <see cref="O365::Security::ETW::Property"/></returns>
        property Property^ Current {
            virtual Property ^get() = IEnumerator<Property^>::Current::get {
                return gcnew Property(gcnew String((*vecIterator_.Get())->name().c_str()), (*vecIterator_.Get())->type(), (*vecIterator_.Get())->out_type());
            }
        };

        /// <summary>Return the current element in the enumeration</summary>
        /// <returns>the current element in the enumeration as a <see cref="System::Object"/></returns>
        property Object ^Current2 {
            virtual Object ^get() = System::Collections::IEnumerator::Current::get {
                return gcnew Property(gcnew String((*vecIterator_.Get())->name().c_str()), (*vecIterator_.Get())->type(), (*vecIterator_.Get())->out_type());
            }
        }

        /// <summary>Reset the enumeration</summary>
        virtual void Reset() = IEnumerator<Property^>::Reset {
            vecIterator_.Reset(nullptr);
            vecIteratorEnd_.Swap(NativePtr<std::vector<krabs::property>::iterator>(iterator_->end()));
        }

    private:
        template <typename T>
        bool iters_match(T %one, T %two)
        {
            return (*one.Get() == *two.Get());
        }

    internal:
        NativePtr<krabs::property_iterator> iterator_;
        NativePtr<std::vector<krabs::property>::iterator> vecIterator_;
        NativePtr<std::vector<krabs::property>::iterator> vecIteratorEnd_;
    };

    /// <summary>
    /// IEnumerable implementation for property enumeration.
    /// </summary>
    public ref class PropertyEnumerable : public IEnumerable<Property^> {
    internal:
        PropertyEnumerable(const krabs::schema& schema)
        : schema_(&schema)
        {}

    public:
        /// <summary>
        /// Implementation of generic IEnumerable::GetEnumerator
        /// </summary>
        /// <returns>an IEnumerator of <see cref="O365::Security::ETW::Property"/></returns>
        virtual IEnumerator<Property^> ^GetEnumerator() {
            return gcnew PropertyEnumerator(*schema_);
        }

        /// <summary>
        /// Implementation of non-generic IEnumerable::GetEnumerator
        /// </summary>
        /// <returns>an IEnumerator of object that can be cast to IEnumerator of
        /// <see cref="O365::Security::ETW::Property"/>
        /// </returns>
        virtual System::Collections::IEnumerator ^GetEnumerator2() = System::Collections::IEnumerable::GetEnumerator {
            return gcnew PropertyEnumerator(*schema_);
        }

    internal:
        const krabs::schema* schema_;
    };

    // Implementation
    // ------------------------------------------------------------------------

    inline Property::Property(String ^name, unsigned int type, unsigned int outType)
    : property_(msclr::interop::marshal_as<std::wstring>(name), (_TDH_IN_TYPE)type, (_TDH_OUT_TYPE)outType)
    {
    }

} /* namespace ETW */ } /* namespace Security */ } /* namespace O365 */ } /* namespace Microsoft */

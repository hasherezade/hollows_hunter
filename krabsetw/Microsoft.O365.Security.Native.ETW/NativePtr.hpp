// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// Really basic RAII wrapper for native pointers in managed classes.
// Think unique_ptr but can be a managed class member.
//
// NOTE: pointers are allocated with 'new'

#pragma once

#pragma warning(push)
#pragma warning(disable: 4634) // DocXml comment warnings in native C++

#include <msclr/lock.h>

using namespace System;

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Wraps an unmanaged ptr in a managed type. This allows unmanaged types
    /// to be members of managed types. The semantics of this work like
    /// std::unique_ptr.
    /// </summary>
    template <typename T>
    ref class NativePtr
    {
        // the wrapped native pointer
        T* ptr;

        // hide copy and assignment to prevent the pointer from
        // getting handed to another instance, which would cause double free
        NativePtr(NativePtr<T>%);
        NativePtr<T>% operator=(NativePtr<T>%);

    public:

        /// <summary>
        /// Construct an empty (null) NativePtr.
        /// </summary>
        NativePtr()
            : ptr(nullptr) { }

        /// <summary>
        /// Construct a NativePtr that assumes ownership of the specified pointer.
        /// </summary>
        NativePtr(T* p)
            : ptr(p) { }

        /// <summary>
        /// Construct a NativePtr by forwarding the specified arguments to the
        /// templated class' constructor. This DOES NOT work for ctors that
        /// take 0 parameters (the empty constructor will be called instead).
        /// In that case use NativePtr(new T()) to select the pointer ctor.
        /// </summary>
        template <typename... Args>
        NativePtr(Args&&... args)
            : ptr(new T(std::forward<Args>(args)...)) { }

        /// <summary>
        /// Destructor
        /// </summary>
        ~NativePtr()
        {
            FreeMemory();
        }

        /// <summary>
        /// Finalizer
        /// </summary>
        !NativePtr()
        {
            FreeMemory();
        }

        /// <summary>
        /// Gets the pointer to the wrapped resource.
        /// </summary>
        T* Get()
        {
            return ptr;
        }

        /// <summary>
        /// Relinquishes control of the internal pointer without doing any
        /// memory management.
        /// </summary>
        T* Release()
        {
            T* oldPtr = ptr;
            ptr = nullptr;
            return oldPtr;
        }

        /// <summary>
        /// Swaps ownership of the wrapped pointers.
        /// </summary>
        void Swap(NativePtr<T>% other)
        {
            T* p = other.ptr;
            other.ptr = ptr;
            ptr = p;
        }

        /// <summary>
        /// Release the currently held resource and takes ownership of the
        /// specified resource if the specified resource != current.
        /// </summary>
        void Reset(T* newPtr)
        {
            if (ptr != newPtr)
            {
                FreeMemory();
                ptr = newPtr;
            }
        }

        /// <summary>
        /// Access the wrapped pointer.
        /// </summary>
        T* operator->()
        {
            return Get();
        }

        /// <summary>
        /// Dereference wrapped pointer
        /// </summary>
        static T& operator*(NativePtr<T>% instance)
        {
            return *(instance.Get());
        }

        /// <summary>
        /// Cast to bool (for conditionals). Returns true if the wrapped
        /// pointer is not null.
        /// </summary>
        static operator bool(NativePtr<T>% instance)
        {
            return instance.ptr != nullptr;
        }

    private:

        /// <summary>
        /// Releases the memory held by this smart pointer, if any.
        /// </summary>
        void FreeMemory()
        {
            // call delete in a locked section to prevent possible double
            // free if Dispose is called multiple times on different threads
            msclr::lock l(this);

            if (nullptr != ptr)
            {
                delete ptr;
                ptr = nullptr;
            }
        }
    };

} } } }
#pragma warning(pop)
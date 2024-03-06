// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <krabs.hpp>

// This file exists solely to cause a double-inclusion of krabs code into the same binary.
// The reason we're doing this is that we want to make sure we've correctly inlined or
// templated every function in krabs.
//
// Because krabs is a header-only library, multiple inclusion of krabs can cause symbols to
// be defined multiple times in the compiled executable. This results in a compiler error.
// It is hard to check for this manually, so we force the issue.
//
// NOTE: Making sure the files are all #pragma once'd is a good first step, but that does
//       not prevent symbol errors. We need to make sure all functions are inlined or
//       templated in order to fix linker errors.

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <iostream>
#include <limits.h>
#include <string>

#include <sstream>
#include <WinSock2.h>
#include <windows.h>
#include <time.h>

#if (_MSC_VER >= 1900) //krabsetw is only supported with Visual Studio 2015 and above (MSVC++ 14.0)

// ETW includes
#include "krabsetw/krabs/krabs.hpp"

bool ETWstart();

#endif

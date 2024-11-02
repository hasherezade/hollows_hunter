#pragma once

#if (_MSC_VER >= 1900 )
    #define __USE_ETW__  //krabsetw is only supported with Visual Studio 2015 and above (MSVC++ 14.0)
#endif

#ifdef __USE_ETW__

#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <iostream>
#include <limits.h>
#include <string>

#include <sstream>
#include <winsock2.h>
#include <windows.h>
#include <time.h>

// ETW includes
#include "krabsetw/krabs/krabs.hpp"
#include "etw_settings.h"


bool ETWstart(ETWProfile &settings);

#endif //__USE_ETW__

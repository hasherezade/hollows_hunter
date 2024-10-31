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

struct ETWProfile {
    bool process_start;
    bool img_load;
    bool allocation;
    bool tcpip;
    bool obj_mgr;

    ETWProfile(bool _process_start = false, bool _img_load = false, bool _allocation = false, bool _tcpip = false, bool _obj_mgr = false)
        : process_start(_process_start), img_load(_img_load), allocation(_allocation), tcpip(_tcpip), obj_mgr(_obj_mgr)
    {
    }

    void setAll()
    {
        this->process_start = true;
        this->img_load = true;
        this->allocation = true;
        this->tcpip = true;
        this->obj_mgr = true;
    }
};

bool ETWstart(ETWProfile &settings);

#endif //__USE_ETW__

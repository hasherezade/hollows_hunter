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

// ETW includes
#include "krabsetw/krabs/krabs.hpp"

bool ETWstart();

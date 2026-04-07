#include "term_util.h"

#include <windows.h>

#include <iostream>
#include <string>
#include <mutex>
#include <paramkit.h>

std::mutex g_stdOutMutex;

bool hh::util::get_current_color(int descriptor, WORD &color)
{
    HANDLE hConsole = GetStdHandle(descriptor);
    if (hConsole == INVALID_HANDLE_VALUE || hConsole == NULL) {
        return false;
    }
    return paramkit::get_console_color(hConsole, color);
}

WORD hh::util::set_color(WORD color)
{
    WORD old_color = 7;
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE || hConsole == NULL) {
        return old_color;
    }
    if (paramkit::get_console_color(hConsole, old_color)) {
        SetConsoleTextAttribute(hConsole, color);
    }
    return old_color;
}

void hh::util::print_in_color(WORD color, const std::string &text)
{
    const std::lock_guard<std::mutex> stdOutLock(g_stdOutMutex);
    paramkit::print_in_color(color, text);
}

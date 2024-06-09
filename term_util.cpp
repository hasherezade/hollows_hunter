#include "term_util.h"

#include <windows.h>

#include <iostream>
#include <string>
#include <mutex>

std::mutex g_stdOutMutex;

bool get_current_color(int descriptor, WORD &color)
{
    CONSOLE_SCREEN_BUFFER_INFO info;
    if (!GetConsoleScreenBufferInfo(GetStdHandle(descriptor), &info))
        return false;
    color = info.wAttributes;
    return true;
}

WORD set_color(WORD color)
{
    WORD old_color = 7;
    get_current_color(STD_OUTPUT_HANDLE, old_color);

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    FlushConsoleInputBuffer(hConsole);
    SetConsoleTextAttribute(hConsole, color);
    FlushConsoleInputBuffer(hConsole);

    return old_color;
}

void print_in_color(WORD color, const std::string &text)
{
    const std::lock_guard<std::mutex> stdOutLock(g_stdOutMutex);
    WORD old_color = set_color(color);
    std::cout << text;
    std::cout.flush();
    set_color(old_color);
}

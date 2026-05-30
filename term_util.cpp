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

std::string hh::util::wstring_to_utf8(const std::wstring& wstr)
{
    if (wstr.empty())
        return {};

    int size = WideCharToMultiByte(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        wstr.data(),
        static_cast<int>(wstr.size()),
        nullptr,
        0,
        nullptr,
        nullptr);

    if (size == 0)
        throw std::runtime_error("WideCharToMultiByte failed");

    std::string result(size, '\0');

    int converted = WideCharToMultiByte(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        wstr.data(),
        static_cast<int>(wstr.size()),
        result.data(),
        size,
        nullptr,
        nullptr);

    if (converted == 0)
        throw std::runtime_error("WideCharToMultiByte failed");

    return result;
}


std::wstring hh::util::utf8_to_wstring(const std::string& utf8)
{
    if (utf8.empty())
        return {};

    int size = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        utf8.data(),
        static_cast<int>(utf8.size()),
        nullptr,
        0);

    if (size == 0)
        throw std::runtime_error("MultiByteToWideChar failed");

    std::wstring result(size, L'\0');

    int converted = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        utf8.data(),
        static_cast<int>(utf8.size()),
        result.data(),
        size);

    if (converted == 0)
        throw std::runtime_error("MultiByteToWideChar failed");

    return result;
}

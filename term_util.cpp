#include "term_util.h"

#include <windows.h>

#include <iostream>
#include <string>

void set_color(int color)
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    FlushConsoleInputBuffer(hConsole);
    SetConsoleTextAttribute(hConsole, color);
}

void unset_color()
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    FlushConsoleInputBuffer(hConsole);
    SetConsoleTextAttribute(hConsole, 7); // back to default color
}

void print_in_color(int color, const std::string &text)
{
    set_color(color);
    std::cout << text;
    unset_color();
}

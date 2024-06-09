#pragma once

#include <iostream>
#include <windows.h>
#include <mutex>

extern std::mutex g_stdOutMutex;

#define BLACK 0
#define DARK_BLUE 1
#define DARK_GREEN 2
#define DARK_CYAN 3
#define DARK_RED 4
#define DARK_MAGENTA 5
#define BROWN 6
#define SILVER 7
#define GRAY 8
#define BLUE 9
#define LIME 0xA
#define CYAN 0xB
#define RED 0xC
#define MAGENTA 0xD
#define YELLOW 0xE
#define WHITE 0xF

#define MAKE_COLOR(fg_color, bg_color) (fg_color | (bg_color << 4))
#define GET_BG_COLOR(color) (color >> 4)

#define YELLOW_ON_BLACK MAKE_COLOR(YELLOW, BLACK)
#define RED_ON_BLACK MAKE_COLOR(RED, BLACK)

bool get_current_color(int descriptor, WORD& color);

WORD set_color(WORD color);

// sets a color and returns the previous color:
void print_in_color(WORD color, const std::string &text);

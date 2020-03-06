#pragma once

#include <iostream>

#define BLACK 0
#define DARK_RED 0x4
#define SILVER 0x7
#define GRAY 0x8
#define BLUE 0x9
#define LIME 0xA
#define CYAN 0xB
#define RED 0xC
#define MAGENTA 0xD
#define YELLOW 0xE
#define WHITE 0xF

#define MAKE_COLOR(fg_color, bg_color) (fg_color | (bg_color << 4));

#define YELLOW_ON_BLACK MAKE_COLOR(YELLOW, BLACK)
#define RED_ON_BLACK MAKE_COLOR(RED, BLACK)

void set_color(int color);

void unset_color();

void print_in_color(int color, const std::string &text);

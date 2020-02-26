#pragma once

#include <iostream>

#define RED_ON_BLACK 0xC
#define YELLOW_ON_BLACK 0xE

void set_color(int color);

void unset_color();

void print_in_color(int color, const std::string &text);

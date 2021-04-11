#pragma once

#include <windows.h>
#include <iostream>
#include <string>
#include <set>

bool is_dec(const char *buf, size_t len);

bool is_hex(const char *buf, size_t len);

size_t strip_to_list(IN std::string s, IN std::string delim, OUT std::set<std::string> &elements_list);

std::string& trim(std::string& str, const std::string& chars = "\t\n\v\f\r ");

std::string& str_to_lower(std::string& str);

long get_number(const char *my_buf);

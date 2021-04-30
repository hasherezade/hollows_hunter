#include "util.h"

#include <algorithm>
#include <cctype>
#include <sstream>

#include "strings_util.h"

using namespace hhunter::util;

size_t strip_to_list(IN std::string s, IN std::string delim, OUT std::set<std::string> &elements_list)
{
    size_t start = 0;
    size_t end = s.find(delim);
    while (end != std::string::npos)
    {
        std::string next_str = s.substr(start, end - start);
        trim(next_str);
        if (next_str.length() > 0) {
            elements_list.insert(next_str);
        }
        start = end + delim.length();
        end = s.find(delim, start);
    }
    std::string next_str = s.substr(start, end);
    trim(next_str);
    if (next_str.length() > 0) {
        elements_list.insert(next_str);
    }
    return elements_list.size();
}

bool is_hex(const char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (buf[i] >= '0' && buf[i] <= '9') continue;
        if (buf[i] >= 'A' && buf[i] <= 'F') continue;
        if (buf[i] >= 'a' && buf[i] <= 'f') continue;
        return false;
    }
    return true;
}

bool is_dec(const char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (buf[i] >= '0' && buf[i] <= '9') continue;
        return false;
    }
    return true;
}

long get_number(const char *my_buf)
{
    const char hex_pattern[] = "0x";
    size_t hex_pattern_len = strlen(hex_pattern);

    const size_t len = strlen(my_buf);
    if (len == 0) return 0;

    long out = 0;
    const size_t min_length = 1; //tolerate number with at least 1 character is fine
    if (len > hex_pattern_len) {
        if (is_cstr_equal(my_buf, hex_pattern, hex_pattern_len)) {
            if (!is_hex(my_buf + hex_pattern_len, min_length)) return 0;

            std::stringstream ss;
            ss << std::hex << my_buf;
            ss >> out;
            return out;
        }
    }
    if (!is_dec(my_buf, min_length)) return 0;

    std::stringstream ss;
    ss << std::dec << my_buf;
    ss >> out;
    return out;
}

/*
string trimming util from: http://www.martinbroadhurst.com/how-to-trim-a-stdstring.html
*/

std::string& ltrim(std::string& str, const std::string& chars = "\t\n\v\f\r ")
{
    str.erase(0, str.find_first_not_of(chars));
    return str;
}

std::string& rtrim(std::string& str, const std::string& chars = "\t\n\v\f\r ")
{
    str.erase(str.find_last_not_of(chars) + 1);
    return str;
}

std::string& trim(std::string& str, const std::string& chars)
{
    return ltrim(rtrim(str, chars), chars);
}

//
std::string& str_to_lower(std::string& str)
{
    std::transform(str.begin(), str.end(), str.begin(), tolower);
    return str;
}


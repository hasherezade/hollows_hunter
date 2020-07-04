#pragma once
#include "../term_util.h"
#include "../color_scheme.h"

#define PARAM_SWITCH1 '/'
#define PARAM_SWITCH2 '-'

inline void print_param_in_color(int color, const std::string &text)
{
    print_in_color(color, PARAM_SWITCH1 + text);
}

inline bool is_param(const char *str)
{
    if (!str) return false;

    const size_t len = strlen(str);
    if (len < 2) return false;

    if (str[0] == PARAM_SWITCH1 || str[0] == PARAM_SWITCH2) {
        return true;
    }
    return false;
}

//from ParamKit
inline size_t copyToCStr(char *buf, size_t buf_max, const std::string &value)
{
    size_t len = value.length() + 1;
    if (len > buf_max) len = buf_max;

    memcpy(buf, value.c_str(), len);
    buf[len] = '\0';
    return len;
}

//TODO: this will be replaced when params will be refactored to use ParamKit
template<typename PARAM_T>
bool get_int_param(int argc, char *argv[], const char *param, int &param_i, 
    const char *param_id, PARAM_T &out_val, const PARAM_T default_set, 
    bool &info_req, void(*callback)(int))
{
    if (strcmp(param, param_id) != 0) {
        return false;
    }
    out_val = default_set;
    if ((param_i + 1) < argc && !is_param(argv[param_i + 1])) {
        char* mode_num = argv[param_i + 1];
        if (isdigit(mode_num[0])) {
            out_val = (PARAM_T)atoi(mode_num);
        }
        else {
            if (callback) {
                callback(ERROR_COLOR);
            }
            info_req = true;
        }
        ++param_i;
    }
    return true;
}

//TODO: this will be replaced when params will be refactored to use ParamKit
inline bool get_cstr_param(int argc, char *argv[], const char *param, int &param_i,
	const char *param_id, char* out_buf, const size_t out_buf_max,
	bool &info_req, void(*callback)(int))
{
	if (strcmp(param, param_id) != 0) {
		return false;
	}
	bool fetched = false;
	if ((param_i + 1) < argc && !is_param(argv[param_i + 1])) {
		if (argv[param_i + 1][0] != PARAM_HELP2[0]) {
			copyToCStr(out_buf, out_buf_max, argv[param_i + 1]);
			fetched = true;
		}
		++param_i;
	}
	if (!fetched) {
		callback(ERROR_COLOR);
		info_req = true;
	}
	return true;
}

//TODO: this will be replaced when params will be refactored to use ParamKit
inline bool get_string_param(int argc, char *argv[], const char *param, int &param_i,
    const char *param_id, std::string  &out_buf,
    bool &info_req, void(*callback)(int))
{
    if (strcmp(param, param_id) != 0) {
        return false;
    }
    bool fetched = false;
    if ((param_i + 1) < argc && !is_param(argv[param_i + 1])) {
        if (argv[param_i + 1][0] != PARAM_HELP2[0]) {
            out_buf = argv[param_i + 1];
            fetched = true;
        }
        ++param_i;
    }
    if (!fetched) {
        callback(ERROR_COLOR);
        info_req = true;
    }
    return true;
}


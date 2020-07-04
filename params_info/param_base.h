#pragma once
#include "../term_util.h"

#define PARAM_SWITCH1 '/'
#define PARAM_SWITCH2 '-'

//scan options:
#define PARAM_IAT "iat"
#define PARAM_HOOKS "hooks"
#define PARAM_SHELLCODE "shellc"
#define PARAM_DATA "data"
#define PARAM_MODULES_FILTER "mfilter"
#define PARAM_MODULES_IGNORE "mignore"
#define PARAM_PNAME "pname"
#define PARAM_PID "pid"
#define PARAM_LOOP "loop"
#define PARAM_REFLECTION "refl"
#define PARAM_DOTNET_POLICY "dnet"

//dump options:
#define PARAM_IMP_REC "imp"
#define PARAM_DUMP_MODE "dmode"

//output options:
#define PARAM_QUIET "quiet"
#define PARAM_OUT_FILTER "ofilter"
#define PARAM_SUSPEND "suspend"
#define PARAM_KILL "kill"
#define PARAM_UNIQUE_DIR "uniqd"
#define PARAM_DIR "dir"
#define PARAM_MINIDUMP "minidmp"
#define PARAM_LOG "log"
#define PARAM_JSON "json"

//info:
#define PARAM_HELP "help"
#define PARAM_HELP2  "?"
#define PARAM_VERSION  "version"
#define PARAM_VERSION2  "ver"
#define PARAM_DEFAULTS "default"


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

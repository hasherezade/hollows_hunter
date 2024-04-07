#pragma once
#include <sstream>
#include <codecvt>
#include <locale>

#include <pe_sieve_types.h>
#include <paramkit.h>

#include "pe_sieve_params_info.h"
#include "../term_util.h"

using namespace paramkit;
using namespace pesieve;

#define HH_URL "https://github.com/hasherezade/hollows_hunter"

//scan options:
#define PARAM_IAT "iat"
#define PARAM_HOOKS "hooks"
#define PARAM_SHELLCODE "shellc"
#define PARAM_OBFUSCATED "obfusc"
#define PARAM_THREADS "threads"
#define PARAM_DATA "data"
#define PARAM_MODULES_IGNORE "mignore"
#define PARAM_PROCESSES_IGNORE "pignore"
#define PARAM_PNAME "pname"
#define PARAM_PID "pid"
#define PARAM_LOOP "loop"
#define PARAM_ETW "etw"
#define PARAM_REFLECTION "refl"
#define PARAM_CACHE "cache"
#define PARAM_DOTNET_POLICY "dnet"
#define PARAM_PTIMES "ptimes"

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
#define PARAM_PATTERN "pattern"
#define PARAM_MINIDUMP "minidmp"
#define PARAM_LOG "log"
#define PARAM_JSON "json"
#define PARAM_JSON_LVL "jlvl"


std::string version_to_str(DWORD version)
{
    BYTE *chunks = (BYTE*)&version;
    std::stringstream stream;
    stream << std::hex <<
        (int)chunks[3] << "." <<
        (int)chunks[2] << "." <<
        (int)chunks[1] << "." <<
        (int)chunks[0];

    return stream.str();
}

void print_version(const std::string &version , WORD info_color = HILIGHTED_COLOR)
{
    WORD old_color = set_color(info_color);
    std::cout << "HollowsHunter v." << version;
    DWORD pesieve_ver = PESieve_version;
#ifdef _WIN64
    std::cout << " (x64)" << "\n";
#else
    std::cout << " (x86)" << "\n";
#endif
    std::cout << "Built on: " << __DATE__ << "\n\n";
    std::cout << "using: PE-sieve v." << version_to_str(pesieve_ver);
    set_color(old_color);
    std::cout << std::endl;
}

std::wstring to_wstring(const std::string& stringToConvert)
{
    std::wstring wideString =
        std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(stringToConvert);
    return wideString;
}

class HHParams : public Params
{
public:
    HHParams(const std::string &version)
        : Params(version)
    {
        {
            std::stringstream ss1;
            ss1 << "Scan only processes with given PIDs";
            std::stringstream ss2;
            ss2 << INFO_SPACER << "Example: 5367" << PARAM_LIST_SEPARATOR << "0xa90";
            this->addParam(new IntListParam(PARAM_PID, false, PARAM_LIST_SEPARATOR));
            this->setInfo(PARAM_PID, ss1.str(), ss2.str());
        }
        {
            std::stringstream ss1;
            ss1 << "Scan only processes with given names.";
            std::stringstream ss2;
            ss2 << INFO_SPACER << "Example: iexplore.exe" << PARAM_LIST_SEPARATOR << "firefox.exe";
            this->addParam(new StringListParam(PARAM_PNAME, false, PARAM_LIST_SEPARATOR));
            this->setInfo(PARAM_PNAME, ss1.str(), ss2.str());
        }
        {
            std::stringstream ss1;
            ss1 << "Make a unique, timestamped directory for the output of each scan.";
            std::stringstream ss2;
            ss2 << INFO_SPACER << "Prevents overwriting results from previous scans.";
            this->addParam(new BoolParam(PARAM_UNIQUE_DIR, false));
            this->setInfo(PARAM_UNIQUE_DIR, ss1.str(), ss2.str());
        }
        {
            std::stringstream ss1;
            ss1 << "Do not scan process/es with given name/s.";
            std::stringstream ss2;
            ss2 << INFO_SPACER << "Example: explorer.exe" << PARAM_LIST_SEPARATOR << "conhost.exe";
            this->addParam(new StringListParam(PARAM_PROCESSES_IGNORE, false, PARAM_LIST_SEPARATOR));
            this->setInfo(PARAM_PROCESSES_IGNORE, ss1.str(), ss2.str());
        }

        this->addParam(new IntParam(PARAM_PTIMES, false, IntParam::INT_BASE_DEC));
        this->setInfo(PARAM_PTIMES, "Scan only processes created N seconds before HH, or later.");

        this->addParam(new BoolParam(PARAM_SUSPEND, false));
        this->setInfo(PARAM_SUSPEND, "Suspend processes detected as suspicious.");

        this->addParam(new BoolParam(PARAM_LOG, false));
        this->setInfo(PARAM_LOG, "Append each scan summary to the log.");

        this->addParam(new BoolParam(PARAM_KILL, false));
        this->setInfo(PARAM_KILL, "Kill processes detected as suspicious.");

        this->addParam(new BoolParam(PARAM_HOOKS, false));
        this->setInfo(PARAM_HOOKS, "Detect inline hooks and in-memory patches.");

        this->addParam(new BoolParam(PARAM_LOOP, false));
        this->setInfo(PARAM_LOOP, "Enable continuous scanning.");
        BoolParam* etwParam = new BoolParam(PARAM_ETW, false);
        this->addParam(etwParam);
        this->setInfo(PARAM_ETW, "Use ETW (requires Administrator privilege).");
#ifndef USE_ETW
        etwParam->setActive(false);
        this->setInfo(PARAM_ETW, "Use ETW (disabled).");
#endif //USE_ETW
        EnumParam *enumParam = new EnumParam(PARAM_IMP_REC, "imprec_mode", false);
        if (enumParam) {
            this->addParam(enumParam);
            this->setInfo(PARAM_IMP_REC, "Set in which mode the ImportTable should be recovered");
            for (size_t i = 0; i < PE_IMPREC_MODES_COUNT; i++) {
                t_imprec_mode mode = (t_imprec_mode)(i);
                enumParam->addEnumValue(mode, imprec_mode_to_id(mode), translate_imprec_mode(mode));
            }
        }

        enumParam = new EnumParam(PARAM_OUT_FILTER, "ofilter_id", false);
        if (enumParam) {
            this->addParam(enumParam);
            this->setInfo(PARAM_OUT_FILTER, "Filter the dumped output.");
            for (size_t i = 0; i < OUT_FILTERS_COUNT; i++) {
                t_output_filter mode = (t_output_filter)(i);
                enumParam->addEnumValue(mode, translate_out_filter(mode));
            }
        }

        this->addParam(new StringListParam(PARAM_MODULES_IGNORE, false, PARAM_LIST_SEPARATOR));
        {
            std::stringstream ss1;
            ss1 << "Do not scan module/s with given name/s.";
            std::stringstream ss2;
            ss2 << "\t   Example: kernel32.dll" << PARAM_LIST_SEPARATOR << "user32.dll";
            this->setInfo(PARAM_MODULES_IGNORE, ss1.str(), ss2.str());
        }

        this->addParam(new BoolParam(PARAM_QUIET, false));
        this->setInfo(PARAM_QUIET, "Print only the summary. Do not log on stdout during the scan.");

        this->addParam(new BoolParam(PARAM_JSON, false));
        this->setInfo(PARAM_JSON, "Print the JSON report as the summary.");
        //
        //PARAM_JSON_LVL
        enumParam = new EnumParam(PARAM_JSON_LVL, "json_lvl", false);
        if (enumParam) {
            this->addParam(enumParam);
            this->setInfo(PARAM_JSON_LVL, "Level of details of the JSON report.");
            for (size_t i = 0; i < JSON_LVL_COUNT; i++) {
                t_json_level mode = (t_json_level)(i);
                enumParam->addEnumValue(mode, translate_json_level(mode));
            }
        }

        this->addParam(new BoolParam(PARAM_MINIDUMP, false));
        this->setInfo(PARAM_MINIDUMP, "Create a minidump of the full suspicious process.");

        //PARAM_SHELLCODE
        enumParam = new EnumParam(PARAM_SHELLCODE, "shellc_mode", false);
        if (enumParam) {
            this->addParam(enumParam);
            this->setInfo(PARAM_SHELLCODE, "Detect shellcode implants (by patterns or statistics). ");
            for (size_t i = 0; i < SHELLC_COUNT; i++) {
                t_shellc_mode mode = (t_shellc_mode)(i);
                enumParam->addEnumValue(mode, shellc_mode_mode_to_id(mode), translate_shellc_mode(mode));
            }
        }

        //PARAM_OBFUSCATED
        enumParam = new EnumParam(PARAM_OBFUSCATED, "obfusc_mode", false);
        if (enumParam) {
            this->addParam(enumParam);
            this->setInfo(PARAM_OBFUSCATED, "Detect encrypted content, and possible obfuscated shellcodes.");
            for (size_t i = 0; i < OBFUSC_COUNT; i++) {
                t_obfusc_mode mode = (t_obfusc_mode)(i);
                enumParam->addEnumValue(mode, obfusc_mode_mode_to_id(mode), translate_obfusc_mode(mode));
            }
        }

        //PARAM_THREADS
        this->addParam(new BoolParam(PARAM_THREADS, false));
        this->setInfo(PARAM_THREADS, "Scan threads' callstack. Detect shellcodes, incl. 'sleeping beacons'.");

        //PARAM_REFLECTION
        this->addParam(new BoolParam(PARAM_REFLECTION, false));
        this->setInfo(PARAM_REFLECTION, "Make a process reflection before scan.", "\t   This allows i.e. to force-read inaccessible pages.");

        //PARAM_CACHE
        this->addParam(new BoolParam(PARAM_CACHE, false));
        this->setInfo(PARAM_CACHE, "Use modules caching.", "\t   This can speed up the scan (on the cost of memory consumption).");

        //PARAM_IAT
        enumParam = new EnumParam(PARAM_IAT, "iat_scan_mode", false);
        if (enumParam) {
            this->addParam(enumParam);
            this->setInfo(PARAM_IAT, "Scan for IAT hooks.");
            for (size_t i = 0; i < PE_IATS_MODES_COUNT; i++) {
                t_iat_scan_mode mode = (t_iat_scan_mode)(i);
                enumParam->addEnumValue(mode, translate_iat_scan_mode(mode));
            }
        }

        this->addParam(new StringParam(PARAM_PATTERN, false));
        this->setInfo(PARAM_PATTERN, "Set additional shellcode patterns (file in the SIG format).");

        //PARAM_DOTNET_POLICY
        enumParam = new EnumParam(PARAM_DOTNET_POLICY, "dotnet_policy", false);
        if (enumParam) {
            this->addParam(enumParam);
            this->setInfo(PARAM_DOTNET_POLICY, "Set the policy for scanning managed processes (.NET).");
            for (size_t i = 0; i < PE_DNET_COUNT; i++) {
                t_dotnet_policy mode = (t_dotnet_policy)(i);
                enumParam->addEnumValue(mode, translate_dotnet_policy(mode));
            }
        }

        //PARAM_DATA
        enumParam = new EnumParam(PARAM_DATA, "data_scan_mode", false);
        if (enumParam) {
            this->addParam(enumParam);
            this->setInfo(PARAM_DATA, "Set if non-executable pages should be scanned.");
            for (size_t i = 0; i < PE_DATA_COUNT; i++) {
                t_data_scan_mode mode = (t_data_scan_mode)(i);
                enumParam->addEnumValue(mode, translate_data_mode(mode));
            }
        }

        //PARAM_DUMP_MODE
        enumParam = new EnumParam(PARAM_DUMP_MODE, "dump_mode", false);
        if (enumParam) {
            this->addParam(enumParam);
            this->setInfo(PARAM_DUMP_MODE, "Set in which mode the detected PE files should be dumped.");
            for (size_t i = 0; i < PE_DUMP_MODES_COUNT; i++) {
                t_dump_mode mode = (t_dump_mode)(i);
                enumParam->addEnumValue(mode, dump_mode_to_id(mode), translate_dump_mode(mode));
            }
        }
        //PARAM_DIR
        this->addParam(new StringParam(PARAM_DIR, false));
        this->setInfo(PARAM_DIR, "Set a root directory for the output (default: \""+ std::string(HH_DEFAULT_DIR) + "\").");

        //optional: group parameters
        std::string str_group = "7. output options";
        this->addGroup(new ParamGroup(str_group));
        this->addParamToGroup(PARAM_DIR, str_group);
        this->addParamToGroup(PARAM_JSON, str_group);
        this->addParamToGroup(PARAM_JSON_LVL, str_group);
        this->addParamToGroup(PARAM_OUT_FILTER, str_group);
        this->addParamToGroup(PARAM_LOG, str_group);
        this->addParamToGroup(PARAM_UNIQUE_DIR, str_group);

        str_group = "2. scanner settings";
        this->addGroup(new ParamGroup(str_group));
        this->addParamToGroup(PARAM_QUIET, str_group);
        this->addParamToGroup(PARAM_REFLECTION, str_group);
        this->addParamToGroup(PARAM_CACHE, str_group);
        this->addParamToGroup(PARAM_LOOP, str_group);

        str_group = "4. scan options";
        this->addGroup(new ParamGroup(str_group));
        this->addParamToGroup(PARAM_DATA, str_group);
        this->addParamToGroup(PARAM_IAT, str_group);
        this->addParamToGroup(PARAM_SHELLCODE, str_group);
        this->addParamToGroup(PARAM_OBFUSCATED, str_group);  
        this->addParamToGroup(PARAM_THREADS, str_group);
        this->addParamToGroup(PARAM_HOOKS, str_group);
        this->addParamToGroup(PARAM_PATTERN, str_group);
        this->addParamToGroup(PARAM_ETW, str_group);
 
        str_group = "5. dump options";
        this->addGroup(new ParamGroup(str_group));
        this->addParamToGroup(PARAM_MINIDUMP, str_group);
        this->addParamToGroup(PARAM_IMP_REC, str_group);
        this->addParamToGroup(PARAM_DUMP_MODE, str_group);

        str_group = "3. scan exclusions";
        this->addGroup(new ParamGroup(str_group));
        this->addParamToGroup(PARAM_DOTNET_POLICY, str_group);
        this->addParamToGroup(PARAM_MODULES_IGNORE, str_group);
        this->addParamToGroup(PARAM_PROCESSES_IGNORE, str_group);

        str_group = "1. scan targets";
        this->addGroup(new ParamGroup(str_group));
        this->addParamToGroup(PARAM_PID, str_group);
        this->addParamToGroup(PARAM_PNAME, str_group);
        this->addParamToGroup(PARAM_PTIMES, str_group);

        str_group = "6. post-scan actions";
        this->addGroup(new ParamGroup(str_group));
        this->addParamToGroup(PARAM_KILL, str_group);
        this->addParamToGroup(PARAM_SUSPEND, str_group);
    }

    void printBanner()
    {
        char logo2[] = ""
            "@@@  @@@  @@@@@@  @@@      @@@       @@@@@@  @@@  @@@  @@@  @@@@@@\n"
            "@@!  @@@ @@!  @@@ @@!      @@!      @@!  @@@ @@!  @@!  @@! !@@    \n"
            "@!@!@!@! @!@  !@! @!!      @!!      @!@  !@! @!!  !!@  @!@  !@@!! \n"
            "!!:  !!! !!:  !!! !!:      !!:      !!:  !!!  !:  !!:  !!      !:!\n"
            " :   : :  : :. :  : ::.: : : ::.: :  : :. :    ::.:  :::   ::.: : \n"
            "       @@@  @@@ @@@  @@@ @@@  @@@ @@@@@@@ @@@@@@@@ @@@@@@@        \n"
            "       @@!  @@@ @@!  @@@ @@!@!@@@   @!!   @@!      @@!  @@@       \n"
            "       @!@!@!@! @!@  !@! @!@@!!@!   @!!   @!!!:!   @!@!!@!        \n"
            "       !!:  !!! !!:  !!! !!:  !!!   !!:   !!:      !!: :!!        \n"
            "        :   : :  :.:: :  ::    :     :    : :: ::   :   : :       \n";
        char *logo = logo2;
        WORD logo_color = DARK_MAGENTA;

        WORD curr_color = 0;
        if (get_current_color(STD_OUTPUT_HANDLE, curr_color)) {
            WORD current_bg = GET_BG_COLOR(curr_color);
            if (current_bg == logo_color) {
                logo_color = MAKE_COLOR(CYAN, current_bg);
            }
        }
        WORD old_color = set_color(logo_color);
        std::cout << "\n" << logo << std::endl;
        set_color(old_color);
        print_version(this->versionStr);
        std::cout << std::endl;
        std::cout << "Scans running processes. Recognizes and dumps a variety of in-memory implants:\nreplaced/implanted PEs, shellcodes, hooks, patches, etc.\n";
        std::cout << "URL: " << HH_URL << std::endl;
    }

    void fillStruct(t_hh_params& ps)
    {
        fillPEsieveStruct(ps.pesieve_args);
        bool hooks = false;
        copyVal<BoolParam>(PARAM_HOOKS, hooks);
        ps.pesieve_args.no_hooks = hooks ? false : true;

        copyVal<BoolParam>(PARAM_UNIQUE_DIR, ps.unique_dir);
        copyVal<BoolParam>(PARAM_SUSPEND, ps.suspend_suspicious);
        copyVal<BoolParam>(PARAM_KILL, ps.kill_suspicious);
#ifdef USE_ETW
        copyVal<BoolParam>(PARAM_ETW, ps.etw_scan);
#endif // USE_ETW
        copyVal<BoolParam>(PARAM_LOOP, ps.loop_scanning);
        copyVal<BoolParam>(PARAM_LOG, ps.log);
        copyVal<BoolParam>(PARAM_QUIET, ps.quiet);
        copyVal<IntParam>(PARAM_PTIMES, ps.ptimes);
        copyVal<BoolParam>(PARAM_JSON, ps.json_output);
        copyVal<StringParam>(PARAM_DIR, ps.out_dir);

        StringListParam* myParam = dynamic_cast<StringListParam*>(this->getParam(PARAM_PNAME));
        if (myParam && myParam->isSet()) {
            std::set<std::string> names_list;
            myParam->stripToElements(names_list);
            for (auto itr = names_list.begin(); itr != names_list.end(); itr++) {
                ps.names_list.insert(to_wstring(*itr));
            }
        }

        myParam = dynamic_cast<StringListParam*>(this->getParam(PARAM_PROCESSES_IGNORE));
        if (myParam && myParam->isSet()) {
            std::set<std::string> ignored_names_list;
            myParam->stripToElements(ignored_names_list);
            for (auto itr = ignored_names_list.begin(); itr != ignored_names_list.end(); itr++) {
                ps.ignored_names_list.insert(to_wstring(*itr));
            }
        }
        IntListParam* myIntParam = dynamic_cast<IntListParam*>(this->getParam(PARAM_PID));
        if (myIntParam && myIntParam->isSet()) {
            myIntParam->stripToIntElements(ps.pids_list);
        }
    }

    void freeStruct(t_hh_params& ps)
    {
        free_strparam(ps.pesieve_args.modules_ignored);
        free_strparam(ps.pesieve_args.pattern_file);
    }

protected:

    // Fill PE-sieve params

    bool alloc_strparam(PARAM_STRING& strparam, size_t len)
    {
        if (strparam.buffer != nullptr) { // already allocated
            return false;
        }
        strparam.buffer = (char*)calloc(len + 1, sizeof(char));
        if (strparam.buffer) {
            strparam.length = len;
            return true;
        }
        return false;
    }

    void free_strparam(pesieve::PARAM_STRING& strparam)
    {
        if (strparam.buffer) {
            free(strparam.buffer);
        }
        strparam.buffer = nullptr;
        strparam.length = 0;
    }

    bool fillStringParam(const std::string& paramId, PARAM_STRING& strparam)
    {
        StringParam* myStr = dynamic_cast<StringParam*>(this->getParam(paramId));
        if (!myStr || !myStr->isSet()) {
            return false;
        }
        std::string val = myStr->valToString();
        const size_t len = val.length();
        if (!len) {
            return false;
        }
        alloc_strparam(strparam, len);
        bool is_copied = false;
        if (strparam.buffer) {
            is_copied = copyCStr<StringParam>(paramId, strparam.buffer, strparam.length);
        }
        return is_copied;
    }

    void fillPEsieveStruct(t_params& ps)
    {
        copyVal<EnumParam>(PARAM_IMP_REC, ps.imprec_mode);
        copyVal<EnumParam>(PARAM_OUT_FILTER, ps.out_filter);

        fillStringParam(PARAM_MODULES_IGNORE, ps.modules_ignored);

        copyVal<BoolParam>(PARAM_QUIET, ps.quiet);
        copyVal<EnumParam>(PARAM_JSON_LVL, ps.json_lvl);

        copyVal<BoolParam>(PARAM_MINIDUMP, ps.minidump);
        copyVal<EnumParam>(PARAM_SHELLCODE, ps.shellcode);
        copyVal<EnumParam>(PARAM_OBFUSCATED, ps.obfuscated);
        copyVal<BoolParam>(PARAM_THREADS, ps.threads);
        copyVal<BoolParam>(PARAM_REFLECTION, ps.make_reflection);
        copyVal<BoolParam>(PARAM_CACHE, ps.use_cache);

        copyVal<EnumParam>(PARAM_IAT, ps.iat);
        copyVal<EnumParam>(PARAM_DOTNET_POLICY, ps.dotnet_policy);
        copyVal<EnumParam>(PARAM_DATA, ps.data);
        copyVal<EnumParam>(PARAM_DUMP_MODE, ps.dump_mode);

        fillStringParam(PARAM_PATTERN, ps.pattern_file);
    }

};

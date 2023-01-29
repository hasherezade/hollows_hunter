#pragma once

#include <iostream>
#include <pe_sieve_types.h>

std::string translate_dump_mode(const DWORD dump_mode);
std::string translate_out_filter(const pesieve::t_output_filter o_filter);
std::string translate_imprec_mode(const pesieve::t_imprec_mode imprec_mode);
std::string translate_iat_scan_mode(const pesieve::t_iat_scan_mode mode);
std::string translate_dotnet_policy(const pesieve::t_dotnet_policy &mode);
std::string translate_json_level(const pesieve::t_json_level &mode);

std::string translate_data_mode(const pesieve::t_data_scan_mode &mode);

std::string dump_mode_to_id(const DWORD dump_mode);
std::string imprec_mode_to_id(const pesieve::t_imprec_mode imprec_mode);
std::string stat_rules_to_id(const pesieve::t_stat_rules stat_rules);
std::string translate_stat_rules(const pesieve::t_stat_rules stat_rule);
std::string translate_exclusion_mode(const pesieve::t_detection_filter stat_rule);

#ifndef _UTILS_H_
#define _UTILS_H_

#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <sstream>
#include <array>
#include <algorithm>

#include <pcap.h>
#include "ieee80211/ieee80211.h"

using namespace std;

pcap_t *get_wireless_adapter(unsigned char *_addr, string *_dev);
pcap_t *get_wireless_adapter(string _dev);
string get_command_string(const char *_command);
string byte_to_string(unsigned char* _byte, int _len);
bool is_equal(unsigned char* _com1, unsigned char* _com2, int _len);
bool is_zero(unsigned char* _c, int _len);

#endif
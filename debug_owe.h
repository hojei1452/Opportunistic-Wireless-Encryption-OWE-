#ifndef _DEBUG_OWE_H_
#define _DEBUG_OWE_H_

#include <iostream>
#include <sstream>
#include <string>
#include <cassert>
#include <cstdarg>
#include <iomanip>

using namespace std;

#define debug_owe(...) _debug_output(__func__, __VA_ARGS__)
#define error_owe(...) _error_output(__func__, __LINE__, __VA_ARGS__)

#define NC "\e[0m"
#define RED "\e[1;31m"
#define GRN "\e[1;32m"
#define BLU "\e[1;34m"

void _debug_output(const char *_func, const char *_str);
void _debug_output(const char *_func, const char *_str, const char *_info);
void _debug_output(const char *_func, const char *_str, const int _size, const unsigned char* _arr);
void _error_output(const char *_func, const int _line, bool _result, const char *_reason);

#endif
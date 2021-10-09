#include "debug_owe.h"

void _debug_output(
    const char *_func,
    const char *_str)
{
    string out;
    out.append(GRN).append("[INFO] ");
    out.append(NC).append("(function: ").append(_func).append(") ");
    out.append(_str);
    cout << out << endl;
}

void _debug_output(
    const char *_func,
    const char *_str,
    const char *_info)
{
    string out;
    out.append(GRN).append("[INFO] ");
    out.append(NC).append("(function: ").append(_func).append(") ");
    out.append(_str).append(": ").append(BLU).append(_info).append(NC);
    cout << out << endl;
}

void _debug_output(
    const char *_func,
    const char *_str,
    const int _size,
    const unsigned char *_arr)
{
    string out;
    out.append(GRN).append("[INFO] ");
    out.append(NC).append("(function: ").append(_func).append(") ");
    out.append(_str).append(": ").append(BLU);
    
    stringstream ss;
    for (int i = 0; i < _size; i++)
        ss << hex << uppercase << setw(2) << setfill('0') << (int)_arr[i];

    out.append(ss.str()).append(NC);
    cout << out << endl;
}

void _error_output(
    const char *_func,
    const int _line,
    bool _result,
    const char *_reason)
{
    if (!_result) return;

    string out;

    out.append(RED).append("[ERROR] ");
    out.append(NC).append("(function: ").append(_func);
    out.append(") (line: ").append(to_string(_line));
    out.append(") (reason: ").append(RED).append(_reason).append(NC).append(")");

    cout << out << endl;

    exit(-1);
}

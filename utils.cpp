#include "utils.h"
#include "debug_owe.h"

pcap_t *get_wireless_adapter(unsigned char *_addr, string *_dev)
{
    string iw = get_command_string("iwconfig");
    error_owe(iw.size() == 0, "Not Find Wireless Adapter!");

    system("clear");

    string dev = iw.substr(0, iw.find(" "));
    debug_owe("Find Wireless Apdater", dev.c_str());

    if (iw.find("Mode:Monitor") == -1)
    {
        string cmd("ifconfig ");
        cmd.append(dev).append(" down");
        get_command_string(cmd.c_str());

        cmd.clear();
        cmd.append("iwconfig ").append(dev).append(" mode monitor");
        get_command_string(cmd.c_str());

        cmd.clear();
        cmd.append("ifconfig ").append(dev).append(" up");
        get_command_string(cmd.c_str());

        debug_owe("Set Monitor Mode Wireless Apdater", dev.c_str());
    }

    error_owe(_addr == NULL, "Not Alloc Address Array!");
    string cmd("ifconfig ");
    cmd.append(dev.c_str()).append(" | grep -o -E '([[:xdigit:]]{1,2}-){5}[[:xdigit:]]{1,2}'");
    
    string addr = get_command_string(cmd.c_str());
    addr = addr.substr(0, addr.find("\n"));
    error_owe(addr[0] == '0', "Failed to get the address.");
    debug_owe("Wireless Adapter MAC Address", addr.c_str());

    replace(addr.begin(), addr.end(), '-', ' ');
    istringstream stream(addr);
    unsigned int c;
    for(int i = 0; stream >> hex >> c; i++) _addr[i] = c;

    _dev->append(dev);
    return pcap_open_live(dev.c_str(), BUFSIZ, 0, 100, NULL);
}

pcap_t *get_wireless_adapter(string _dev)
{
    return pcap_open_live(_dev.c_str(), BUFSIZ, 0, 100, NULL);
}

string get_command_string(const char *_command)
{
    unique_ptr<FILE, decltype(&pclose)> pipe(popen(_command, "r"), pclose);
    if (!pipe)
        throw runtime_error("popen() failed!");

    array<char, 128> buffer;
    string result;
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
        result += buffer.data();

    return result;
}

string byte_to_string(unsigned char* _byte, int _len)
{
    stringstream ss;
    for (int i = 0; i < _len; i++)
        ss << hex << uppercase << setw(2) << setfill('0') << (int)_byte[i];
    return ss.str();
}

bool is_equal(unsigned char* _com1, unsigned char* _com2, int _len)
{
	bool result = true;

	for (int i = 0; i < _len; i++)
	{
		if (_com1[i] == _com2[i]) continue;
		else
		{
			result = false;
			break;
		}
	}
	return result;
}

bool is_zero(unsigned char* _c, int _len)
{
    bool result = true;

    for (int i = 0; i < _len; i++)
    {
        if (_c[i] != 0)
        {
            result = false;
            break;
        }
    }
    return result;
}
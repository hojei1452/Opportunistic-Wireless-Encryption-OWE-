#ifndef _OWE_H_
#define _OWE_H_

#include "debug_owe.h"
#include "key_owe.h"
#include "utils.h"
#include "packet.h"
#include <unistd.h>
#include <thread>
#include <ctime>
#include <map>
#include <utility>

#define IS_TEST

class OWE
{
private:

    #define MAX_INTERVAL_COUNT 3

    typedef struct PACKED _ADDR
    {
        u8 ap[IEEE80211_ADDR_LEN];
        u8 bssid[IEEE80211_ADDR_LEN];
        u8 sta[IEEE80211_ADDR_LEN];
        u8 br[IEEE80211_ADDR_LEN];
    } ADDR;

    typedef enum _STATUS_CODE
    {
        NONE_AP,
        AP_ADDR_CAPTURE,
        SEND_PROBE_REQ,
        RECV_PROBE_RES,
        SEND_AUTH_REQ,
        RECV_AUTH_RES,
        SEND_ASSOC_REQ,
        RECV_ASSOC_RES,
        EAPOL,
        DONE
    } STATUS_CODE;

    typedef struct _KEY
    {
        pcap_t *handle;
        ADDR addr;
        KEY_OWE ap;
        KEY_OWE sta;
        STATUS_CODE status;
    } KEY;

    PACKET packet;
    string dev;
    string adapter;

    pcap_t *handle;
    pcap_t *beaconHandle;
    pcap_t *probeHandle;

    void init(string _dev);
    void init(KEY *_key, u8 *_sta);
    bool start_ap(KEY *_key);

    void sendp(pcap_t *_handle, const int _interval, u8 *_packet, int _len);
    bool recvp(pcap_t *_handle, u16 _fc, u8 *_src, u8 *_dst);
    bool send_recv(pcap_t *_handle, u16 _fc, const int _interval, u8 *_send_packet, int _send_len, u8 *_src, u8 *_dst);
    bool send_recv(KEY *_key, u16 _fc, const int _interval, u8 *_send_packet, int _send_len, u8 *_src, u8 *_dst);
    bool send_recv(pcap_t *_handle, u16 _fc, const int _interval, u8 *_send_packet1, int _send_len1, u8 *_send_packet2, int _send_len2, u8 *_src, u8 *_dst);
    bool send_recv(KEY *_key, u16 _fc, const int _interval, u8 *_send_packet1, int _send_len1, u8 *_send_packet2, int _send_len2, u8 *_src, u8 *_dst);
    bool send_recv_key(KEY *_key);
    void recv_send(pcap_t *_handle, u16 _recv_fc, u16 _send_fc);
    bool recv_send_key(pcap_t *_handle);

public:
    map<string, KEY> info;
    KEY key;
    ADDR addr;

    void start();

    OWE(string _dev);
    ~OWE();
};

OWE::OWE(string _dev)
{
    this->init(_dev);
    this->key.status = NONE_AP;
}

OWE::~OWE()
{
    this->handle = NULL;
}

#endif
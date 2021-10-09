#ifndef _PACKET_H_
#define _PACKET_H_

#include <cstring>
#include <sys/time.h>
#include <arpa/inet.h>

#include <openssl/bn.h>
#include <openssl/aes.h>
#include "debug_owe.h"
#include "utils.h"

#include "ieee80211/ieee80211.h"
#include "ieee80211/ieee80211_eapol.h"
#include "ieee80211/ieee80211_radiotap.h"

typedef unsigned char u8;
typedef unsigned short int u16;
typedef unsigned int u32;
typedef unsigned long int u64;

#define PACKED __attribute__((__packed__))
#define htonll(x)   ((((u64)htonl(x)) << 32UL) + htonl((u64)x >> 32UL))
#define ntohll(x)   ((((u64)ntohl(x)) << 32UL) + ntohl((u64)x >> 32UL))

class PACKET
{
private:

    #define ATH_OUI_OUI 0x12

    #define FC_BEACON (IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_BEACON)
    #define FC_PROBE_REQ (IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_PROBE_REQ)
    #define FC_PROBE_RES (IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_PROBE_RESP)
    #define FC_AUTH (IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_AUTH)
    #define FC_ASSOC_REQ (IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_ASSOC_REQ)
    #define FC_ASSOC_RES (IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_ASSOC_RESP)
    #define FC_EAPOL (IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_DATA)

    #define EAPOL_1 (EAPOL_WKEY_INFO_ACK | EAPOL_WKEY_INFO_PW | EAPOL_WKEY_INFO_AES)
    #define EAPOL_2 (EAPOL_WKEY_INFO_MIC | EAPOL_WKEY_INFO_PW | EAPOL_WKEY_INFO_AES)
    #define EAPOL_3 (EAPOL_WKEY_INFO_ENCRYPT | EAPOL_WKEY_INFO_SECURE | EAPOL_WKEY_INFO_MIC | EAPOL_WKEY_INFO_ACK | EAPOL_WKEY_INFO_INSTALL | EAPOL_WKEY_INFO_PW | EAPOL_WKEY_INFO_AES)
    #define EAPOL_4 (EAPOL_WKEY_INFO_SECURE | EAPOL_WKEY_INFO_MIC | EAPOL_WKEY_INFO_PW | EAPOL_WKEY_INFO_AES)


    #define AP_FUNC
    #define STA_FUNC
    #define AP_STA_FUNC

    struct PACKED _TLV
    {
        u8 id;
        u8 len;
        u8 data[0];
    } tlv;

    typedef struct PACKED _OUI
    {
        u32 oui:24;
        u8 type;
    } oui;

    struct PACKED _RSN
    {
        u16 version;
        oui group;
        u16 pairCount;
        oui pair;
        u16 authCount;
        oui auth;
        u16 cap;
    } rsn, eap_rsn;

    typedef struct PACKED _RSN_GTK
    {
        oui gtk_oui;
        u8 gtk_id;
        u8 reserved;
        u8 gtk[0];
    } RSN_GTK;

    struct PACKED _KEY
    {
        #define OWE_TAG_PUBKEY_ID  0x20
        #define OWE_TAG_GROUP_ID  0x1300
        #define OWE_ECKEY_LENGTH 32
        #define OWE_EAPOL_KEY_LENGTH 16
        #define OWE_EAPOL_NONCE_LENGTH 32
        u8 id;
        u16 group;
        u8 key[0];
    } key;
    
    int dataPointer;

    void memcpy_packet(u8 *_dst, const void *_src, int _len);

    void generate_radiotap(u8 *_packet);
    void generate_frame(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, u8 _ft);
    void generate_frame(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, u8 _ft, u8 _flags);
    void generate_tag_info(u8 *_packet);
    void generate_llc(u8 *_packet);

    int capture_rediotap_header(u8 *_packet);
    u8 capture_frame(u8 *_packet, u8 *_src, u8 *_dst);
    u8 capture_frame(u8 *_packet, u8 *_src, u8 *_dst, u8 _flags);
    bool capture_llc(u8 *_packet);

    AP_FUNC int generate_beacon(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid);
    AP_FUNC int generate_probe_response(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid);
    AP_FUNC int generate_association_response(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, BIGNUM *_pubKey);
    AP_FUNC int generate_eapol_1(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, u8 *_nonce);
    AP_FUNC int generate_eapol_3(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, u8 *_nonce, u8 *_mic, u8* _kek, u8 *_gtk);
    AP_FUNC bool capture_probe_request(u8 *_packet, int _len, u8 *_src, u8 *_dst);
    AP_FUNC bool capture_association_request(u8 *_packet, int _len, u8 *_src, u8 *_dst, BIGNUM *_pubKey);
    AP_FUNC bool capture_eapol_2(u8 *_packet, int _len, u8 *_src, u8 *_dst, u8 *_nonce, u8 *_mic);
    AP_FUNC bool capture_eapol_4(u8 *_packet, int _len, u8 *_src, u8 *_dst, u8 *_mic);

    STA_FUNC int generate_probe_request(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid);
    STA_FUNC int generate_association_request(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, BIGNUM *_pubKey);
    STA_FUNC int generate_eapol_2(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, u8 *_nonce, u8 *_mic);
    STA_FUNC int generate_eapol_4(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, u8 *_mic);
    STA_FUNC bool capture_beacon(u8 *_packet, int _len, u8 *_src, u8 *_dst);
    STA_FUNC bool capture_probe_response(u8 *_packet, int _len, u8 *_src, u8 *_dst);
    STA_FUNC bool capture_association_response(u8 *_packet, int _len, u8 *_src, u8 *_dst, BIGNUM *_pubKey);
    STA_FUNC bool capture_eapol_1(u8 *_packet, int _len, u8 *_src, u8 *_dst, u8 *_nonce);
    STA_FUNC bool capture_eapol_3(u8 *_packet, int _len, u8 *_src, u8 *_dst, u8 *_nonce, u8 *_mic, u8* _kek, u8 *_gtk);

    AP_STA_FUNC int generate_authentication(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, u16 _seq);
    AP_STA_FUNC bool capture_authentication(u8 *_packet, int _len, u8 *_src, u8 *_dst);

public:
    int generate_packet(u8 _fc, u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid);
    int generate_packet(u8 _fc, u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, u16 _seq);
    int generate_packet(u8 _fc, u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, BIGNUM *_pubKey);
    int generate_packet(u16 _step, u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, u8 *_data);
    int generate_packet(u16 _step, u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, u8 *_nonce, u8 *_mic);
    int generate_packet(u16 _step, u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, u8 *_nonce, u8 *_mic, u8 *_kek, u8 *_gtk);

    bool capture_packet(u8 _fc, u8 *_packet, int _len, u8 *_src, u8 *_dst);
    bool capture_packet(u8 _fc, u8 *_packet, int _len, u8 *_src, u8 *_dst, BIGNUM *_pubKey);
    bool capture_packet(u16 _step, u8 *_packet, int _len, u8 *_src, u8 *_dst, u8 *_data);
    bool capture_packet(u16 _step, u8 *_packet, int _len, u8 *_src, u8 *_dst, u8 *_nonce, u8 *_mic);
    bool capture_packet(u16 _step, u8 *_packet, int _len, u8 *_src, u8 *_dst, u8 *_nonce, u8 *_mic, u8 *_kek, u8 *_gtk);

    PACKET();
    ~PACKET();
};

#endif
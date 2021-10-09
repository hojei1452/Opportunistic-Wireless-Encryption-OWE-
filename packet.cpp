#include "packet.h"

PACKET::PACKET()
{
    // RSN
    memset(&this->rsn, 0, sizeof(this->rsn));

    this->rsn.version = htons(RSN_VERSION);
    this->rsn.group.oui = htonl(RSN_OUI);
    this->rsn.group.type = RSN_CSE_CCMP;

    this->rsn.pairCount = htons(0x0100);
    this->rsn.pair.oui = htonl(RSN_OUI);
    this->rsn.pair.type = RSN_CSE_CCMP;

    this->rsn.authCount = htons(0x0100);
    this->rsn.auth.oui = htonl(RSN_OUI);
    this->rsn.auth.type = ATH_OUI_OUI; // OWE

    // EAP_RSN
    memset(&this->eap_rsn, 0, sizeof(this->eap_rsn));

    this->eap_rsn.version = RSN_VERSION;
    this->eap_rsn.group.oui = RSN_OUI;
    this->eap_rsn.group.type = RSN_CSE_CCMP;

    this->eap_rsn.pairCount = htons(0x0100);
    this->eap_rsn.pair.oui = RSN_OUI;
    this->eap_rsn.pair.type = RSN_CSE_CCMP;

    this->eap_rsn.authCount = htons(0x0100);
    this->eap_rsn.auth.oui = RSN_OUI;
    this->eap_rsn.auth.type = ATH_OUI_OUI; // OWE

    // OWE EC Pubkey
    this->key.id = OWE_TAG_PUBKEY_ID;
    this->key.group = htons(OWE_TAG_GROUP_ID);
}

PACKET::~PACKET(){ }

#pragma region public_func

int PACKET::generate_packet(u8 _fc, u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid)
{
    if (_fc == FC_BEACON)
        return this->generate_beacon(_packet, _src, _dst, _bssid);
    else if (_fc == FC_PROBE_REQ)
        return this->generate_probe_request(_packet, _src, _dst, _bssid);
    else if (_fc == FC_PROBE_RES)
        return this->generate_probe_response(_packet, _src, _dst, _bssid);
    else error_owe(true, "Unknown Frame Control Type");
    return -1;
}

int PACKET::generate_packet(u8 _fc, u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, u16 _seq)
{
    if (_fc == FC_AUTH)
        return this->generate_authentication(_packet, _src, _dst, _bssid, _seq);
    else error_owe(true, "Unknown Frame Control Type");
    return -1;
}

int PACKET::generate_packet(u8 _fc, u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, BIGNUM *_pubKey)
{
    if (_fc == FC_ASSOC_REQ)
        return this->generate_association_request(_packet, _src, _dst, _bssid, _pubKey);
    else if (_fc == FC_ASSOC_RES)
        return this->generate_association_response(_packet, _src, _dst, _bssid, _pubKey);
    else error_owe(true, "Unknown Frame Control Type");
    return -1;
}

int PACKET::generate_packet(u16 _step, u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, u8 *_data)
{
    if (_step == EAPOL_1)
        return this->generate_eapol_1(_packet, _src, _dst, _bssid, _data);
    else if (_step == EAPOL_4)
        return this->generate_eapol_4(_packet, _src, _dst, _bssid, _data);
    else error_owe(true, "Unknown Frame Control Type");
    return -1;
}

int PACKET::generate_packet(u16 _step, u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, u8 *_nonce, u8 *_mic)
{
    if (_step == EAPOL_2)
        return this->generate_eapol_2(_packet, _src, _dst, _bssid, _nonce, _mic);
    else error_owe(true, "Unknown Frame Control Type");
    return -1;
}

int PACKET::generate_packet(u16 _step, u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, u8 *_nonce, u8 *_mic, u8 *_kek, u8 *_gtk)
{
    if (_step == EAPOL_3)
        return this->generate_eapol_3(_packet, _src, _dst, _bssid, _nonce, _mic, _kek, _gtk);
    else error_owe(true, "Unknown Frame Control Type");
    return -1;
}

bool PACKET::capture_packet(u8 _fc, u8 *_packet, int _len, u8 *_src, u8 *_dst)
{
    if (_fc == FC_BEACON)
        return this->capture_beacon(_packet, _len, _src, _dst);
    else if (_fc == FC_PROBE_REQ)
        return this->capture_probe_request(_packet, _len, _src, _dst);
    else if (_fc == FC_PROBE_RES)
        return this->capture_probe_response(_packet, _len, _src, _dst);
    else if (_fc == FC_AUTH)
        return this->capture_authentication(_packet, _len, _src, _dst);
    else error_owe(true, "Unknown Frame Control Type");
    return false;
}

bool PACKET::capture_packet(u8 _fc, u8 *_packet, int _len, u8 *_src, u8 *_dst, BIGNUM *_pubKey)
{
    if (_fc == FC_ASSOC_REQ)
        return this->capture_association_request(_packet, _len, _src, _dst, _pubKey);
    else if (_fc == FC_ASSOC_RES)
        return this->capture_association_response(_packet, _len, _src, _dst, _pubKey);
    else error_owe(true, "Unknown Frame Control Type");
    return false;
}

bool PACKET::capture_packet(u16 _step, u8 *_packet, int _len, u8 *_src, u8 *_dst, u8 *_data)
{
    if (_step == EAPOL_1)
        return this->capture_eapol_1(_packet, _len, _src, _dst, _data);
    else if (_step == EAPOL_4)
        return this->capture_eapol_4(_packet, _len, _src, _dst, _data);
    else error_owe(true, "Unknown EAPOL Type");
    return false;
}

bool PACKET::capture_packet(u16 _step, u8 *_packet, int _len, u8 *_src, u8 *_dst, u8 *_nonce, u8 *_mic)
{
    if (_step == EAPOL_2)
        return this->capture_eapol_2(_packet, _len, _src, _dst, _nonce, _mic);
    else error_owe(true, "Unknown EAPOL Type");    
    return false;
}

bool PACKET::capture_packet(u16 _step, u8 *_packet, int _len, u8 *_src, u8 *_dst, u8 *_nonce, u8 *_mic, u8 *_kek, u8 *_gtk)
{
    if (_step == EAPOL_3)
        return this->capture_eapol_3(_packet, _len, _src, _dst, _nonce, _mic, _kek, _gtk);
    else error_owe(true, "Unknown EAPOL Type");    
    return false;
}

#pragma endregion

#pragma region AP_FUNC

AP_FUNC int PACKET::generate_beacon(u8 *_packet, u8 *_src, u8 *_dst,  u8 *_bssid)
{
    error_owe((_packet == NULL) || (_src == NULL) || (_dst == NULL) || (_bssid == NULL), "Parameter Error");

    this->generate_radiotap(_packet);
    this->generate_frame(_packet, _src, _dst, _bssid, FC_BEACON);

    u64 timestamp = 0;
    this->memcpy_packet(_packet, &timestamp, sizeof(u64));
    
    u16 interval = 0;
    this->memcpy_packet(_packet, &interval, sizeof(u16));

    u16 cap = htons(0x1100);
    this->memcpy_packet(_packet, &cap, sizeof(u16));
    
    this->generate_tag_info(_packet);

    debug_owe("Generate Beacon Packet Size", to_string(this->dataPointer).c_str());
    return this->dataPointer;
}

AP_FUNC int PACKET::generate_probe_response(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid)
{
    error_owe((_packet == NULL) || (_src == NULL) || (_dst == NULL) || (_bssid == NULL), "Parameter Error");

    this->generate_radiotap(_packet);
    this->generate_frame(_packet, _src, _dst, _bssid, FC_PROBE_RES);

    u64 timestamp = 0;
    this->memcpy_packet(_packet, &timestamp, sizeof(u64));

    u16 interval = 0;
    this->memcpy_packet(_packet, &interval, sizeof(u16));

    u16 cap = htons(0x1000);
    this->memcpy_packet(_packet, &cap, sizeof(u16));

    this->generate_tag_info(_packet);

    debug_owe("Generate Probe Response Packet Size", to_string(this->dataPointer).c_str());
    return this->dataPointer;
}

AP_FUNC int PACKET::generate_association_response(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, BIGNUM *_pubKey)
{
    error_owe((_packet == NULL) || (_src == NULL) || (_dst == NULL) || (_bssid == NULL) || (_pubKey == NULL), "Parameter Error");

    this->generate_radiotap(_packet);
    this->generate_frame(_packet, _src, _dst, _bssid, FC_ASSOC_RES);

    u16 cap = htons(0x1100);
    this->memcpy_packet(_packet, &cap, sizeof(u16));

    u16 status = 0;
    this->memcpy_packet(_packet, &status, sizeof(u16));

    u16 id = htons(0x01c0);
    this->memcpy_packet(_packet, &id, sizeof(u16));

    this->generate_tag_info(_packet);

    this->tlv.id = IEEE80211_ELEMID_EXTENSION;
    this->tlv.len = OWE_ECKEY_LENGTH + sizeof(this->key);
    this->memcpy_packet(_packet, &this->tlv, sizeof(this->tlv));
    this->memcpy_packet(_packet, &this->key, sizeof(this->key));

    u8 tPub[OWE_ECKEY_LENGTH] = { 0 };
    BN_bn2bin(_pubKey, tPub);
    this->memcpy_packet(_packet, tPub, OWE_ECKEY_LENGTH);

    debug_owe("Generate Association Response Packet Size", to_string(this->dataPointer).c_str());
    return this->dataPointer;
}

AP_FUNC int PACKET::generate_eapol_1(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, u8 *_nonce)
{
    error_owe((_packet == NULL) || (_src == NULL) || (_dst == NULL) || (_bssid == NULL) || (_nonce == NULL), "Parameter Error");

    this->generate_radiotap(_packet);
    this->generate_frame(_packet, _src, _dst, _bssid, FC_EAPOL, IEEE80211_FC1_DIR_FROMDS);
    this->generate_llc(_packet);

    struct eapol_wpa_key key = { 0 };
    key.ewk_type = EAPOL_KEY_TYPE_RSN;
    key.ewk_info = htons(EAPOL_1);
    key.ewk_keylen = htons(OWE_EAPOL_KEY_LENGTH);
    key.ewk_replay = htonll(1);
    memcpy(key.ewk_nonce, _nonce, OWE_EAPOL_NONCE_LENGTH);

    struct eapol_hdr hdr = { 0 };
    hdr.eapol_type = EAPOL_TYPE_KEY;
    hdr.eapol_ver = EAPOL_VERSION_2;
    hdr.eapol_len = htons(sizeof(struct eapol_wpa_key));
    this->memcpy_packet(_packet, &hdr, sizeof(struct eapol_hdr));
    this->memcpy_packet(_packet, &key, sizeof(struct eapol_wpa_key));

    debug_owe("Generate EAPOL-1 Size", to_string(this->dataPointer).c_str());
    return this->dataPointer;
}

AP_FUNC int PACKET::generate_eapol_3(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, u8 *_nonce, u8 *_mic, u8* _kek, u8 *_gtk)
{
    error_owe((_packet == NULL) || (_src == NULL) || (_dst == NULL) || (_bssid == NULL) || (_nonce == NULL) || (_mic == NULL) || (_kek == NULL) || (_gtk == NULL), "Parameter Error");

    this->generate_radiotap(_packet);
    this->generate_frame(_packet, _src, _dst, _bssid, FC_EAPOL, IEEE80211_FC1_DIR_FROMDS);
    this->generate_llc(_packet);

    struct eapol_wpa_key key = { 0 };
    key.ewk_type = EAPOL_KEY_TYPE_RSN;
    key.ewk_info = htons(EAPOL_3);
    key.ewk_keylen = htons(OWE_EAPOL_KEY_LENGTH);
    key.ewk_replay = htonll(2);
    memcpy(key.ewk_nonce, _nonce, OWE_EAPOL_NONCE_LENGTH);
    memcpy(key.ewk_mic, _mic, OWE_EAPOL_KEY_LENGTH);

    int pPoint = 0, tSize = (sizeof(struct _TLV) * 2) + (sizeof(struct _RSN)) + sizeof(RSN_GTK) + OWE_EAPOL_KEY_LENGTH;
    if (tSize % 8 != 0) tSize += (8 - (tSize % 8));

    u8 pData[tSize] = { 0 };
    this->tlv.id = IEEE80211_ELEMID_RSN;
    this->tlv.len = sizeof(this->rsn);
    memcpy(pData, &this->tlv, sizeof(struct _TLV));
    pPoint += sizeof(struct _TLV);

    memcpy(pData + pPoint, &this->eap_rsn, sizeof(struct _RSN));
    pPoint += sizeof(struct _RSN);

    this->tlv.id = IEEE80211_ELEMID_VENDOR;
    this->tlv.len = sizeof(RSN_GTK);
    memcpy(pData + pPoint, &this->tlv, sizeof(struct _TLV));
    pPoint += sizeof(struct _TLV);

    RSN_GTK gtk = { 0 };
    gtk.gtk_oui.oui = RSN_OUI;
    gtk.gtk_oui.type = 1;
    gtk.gtk_id = 1;
    memcpy(pData + pPoint, &gtk, sizeof(RSN_GTK));
    pPoint += sizeof(RSN_GTK);

    memcpy(pData + pPoint, _gtk, OWE_EAPOL_KEY_LENGTH);
    pPoint += OWE_EAPOL_KEY_LENGTH;

    u8 eData[pPoint + 8] = { 0 };
    AES_KEY ekey;
    AES_set_encrypt_key(_kek, 128, &ekey);
    int eSize = AES_wrap_key(&ekey, NULL, eData, pData, tSize);
    error_owe(eSize == 0, "AES_wrap_key Error");

    struct eapol_hdr hdr = { 0 };
    hdr.eapol_type = EAPOL_TYPE_KEY;
    hdr.eapol_ver = EAPOL_VERSION_2;
    hdr.eapol_len = htons(sizeof(struct eapol_wpa_key) + eSize);
    key.ewk_datalen = htons(eSize);

    this->memcpy_packet(_packet, &hdr, sizeof(struct eapol_hdr));
    this->memcpy_packet(_packet, &key, sizeof(struct eapol_wpa_key));

    if (is_zero(_mic, OWE_EAPOL_KEY_LENGTH)) return this->dataPointer - sizeof(struct eapol_hdr) - sizeof(struct eapol_wpa_key);
    this->memcpy_packet(_packet, eData, eSize);

    debug_owe("Generate EAPOL-3 Size", to_string(this->dataPointer).c_str());
    return this->dataPointer;
}

AP_FUNC bool PACKET::capture_probe_request(u8 *_packet, int _len, u8 *_src, u8 *_dst)
{
    int dp = this->capture_rediotap_header(_packet);
    if (this->capture_frame(_packet + dp, _src, _dst) == FC_PROBE_REQ)
    {
        debug_owe("Capture Probe Request!", IEEE80211_ADDR_LEN, _src);
        return true;
    }
    return false;
}

AP_FUNC bool PACKET::capture_association_request(u8 *_packet, int _len, u8 *_src, u8 *_dst, BIGNUM *_pubKey)
{
    int dp = this->capture_rediotap_header(_packet);
    if (this->capture_frame(_packet + dp, _src, _dst) == FC_ASSOC_REQ)
    {
        dp += sizeof(struct ieee80211_frame) + 4; // fixed(4)

        while(dp <= _len)
        {
            struct _TLV *tlv = (struct _TLV *)(_packet + dp);
            if (tlv->id == IEEE80211_ELEMID_EXTENSION)
            {
                dp += sizeof(struct _TLV);
                struct _KEY *key = (struct _KEY *)(_packet + dp);
                if (key->id == OWE_TAG_PUBKEY_ID)
                {
                    dp += sizeof(struct _KEY);

                    BN_bin2bn(_packet + dp, OWE_ECKEY_LENGTH, _pubKey);
                    debug_owe("Capture Association Request(STA Public Key X)", BN_bn2hex(_pubKey));
                    return true;
                }
            }
            else dp += tlv->len + 2;
        }
    }
    return false;
}

AP_FUNC bool PACKET::capture_eapol_2(u8 *_packet, int _len, u8 *_src, u8 *_dst, u8 *_nonce, u8 *_mic)
{
    int dp = this->capture_rediotap_header(_packet);
    if (this->capture_frame(_packet + dp, _src, _dst, IEEE80211_FC1_DIR_TODS) == FC_EAPOL)
    {
        dp += sizeof(struct ieee80211_frame);
        if (this->capture_llc(_packet + dp))
        {
            dp += sizeof(struct ieee80211_llc);
            struct eapol_hdr *hdr = (struct eapol_hdr *)(_packet + dp);
            if (hdr->eapol_type == EAPOL_TYPE_KEY && hdr->eapol_ver == EAPOL_VERSION_1)
            {
                dp += sizeof(struct eapol_hdr);
                struct eapol_wpa_key *key = (struct eapol_wpa_key *)(_packet + dp);
                if(key->ewk_type == EAPOL_KEY_TYPE_RSN &&  key->ewk_info == ntohs(EAPOL_2))
                {
                    memcpy(_nonce, key->ewk_nonce, OWE_EAPOL_NONCE_LENGTH);
                    memcpy(_mic, key->ewk_mic, OWE_EAPOL_KEY_LENGTH);

                    debug_owe("Capture EAPOL-2, Station Nonce", OWE_EAPOL_NONCE_LENGTH, _nonce);
                    debug_owe("Capture EAPOL-2, Station MIC", OWE_EAPOL_KEY_LENGTH, _mic);
                    return true;
                }
            }
        }
    }
    return false;
}

AP_FUNC bool PACKET::capture_eapol_4(u8 *_packet, int _len, u8 *_src, u8 *_dst, u8 *_mic)
{
    int dp = this->capture_rediotap_header(_packet);
    if (this->capture_frame(_packet + dp, _src, _dst, IEEE80211_FC1_DIR_TODS) == FC_EAPOL)
    {
        dp += sizeof(struct ieee80211_frame);
        if (this->capture_llc(_packet + dp))
        {
            dp += sizeof(struct ieee80211_llc);
            struct eapol_hdr *hdr = (struct eapol_hdr *)(_packet + dp);
            if (hdr->eapol_type == EAPOL_TYPE_KEY && hdr->eapol_ver == EAPOL_VERSION_1)
            {
                dp += sizeof(struct eapol_hdr);
                struct eapol_wpa_key *key = (struct eapol_wpa_key *)(_packet + dp);
                if(key->ewk_type == EAPOL_KEY_TYPE_RSN &&  key->ewk_info == ntohs(EAPOL_4))
                {
                    memcpy(_mic, key->ewk_mic, OWE_EAPOL_KEY_LENGTH);
                    debug_owe("Capture EAPOL-4, Station MIC", OWE_EAPOL_KEY_LENGTH, _mic);
                    return true;
                }
            }
        }
    }
    return false;
}

#pragma endregion

#pragma region STA_FUNC

STA_FUNC int PACKET::generate_probe_request(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid)
{
    error_owe((_packet == NULL) || (_src == NULL) || (_dst == NULL) || (_bssid == NULL), "Parameter Error");

    this->generate_radiotap(_packet);
    this->generate_frame(_packet, _src, _dst, _bssid, FC_PROBE_REQ);
    this->generate_tag_info(_packet);

    debug_owe("Generate Probe Request Packet Size", to_string(this->dataPointer).c_str());
    return this->dataPointer;
}

STA_FUNC int PACKET::generate_association_request(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, BIGNUM *_pubKey)
{
    error_owe((_packet == NULL) || (_src == NULL) || (_dst == NULL) || (_bssid == NULL) || (_pubKey == NULL), "Parameter Error");

    this->generate_radiotap(_packet);
    this->generate_frame(_packet, _src, _dst, _bssid, FC_ASSOC_REQ);

    u16 cap = htons(0x3104);
    this->memcpy_packet(_packet, &cap, sizeof(u16));

    u16 interval = 0;
    this->memcpy_packet(_packet, &interval, sizeof(u16));

    this->generate_tag_info(_packet);

    this->tlv.id = IEEE80211_ELEMID_EXTENSION;
    this->tlv.len = OWE_ECKEY_LENGTH + sizeof(this->key);
    this->memcpy_packet(_packet, &this->tlv, sizeof(this->tlv));
    this->memcpy_packet(_packet, &this->key, sizeof(this->key));

    u8 tPub[OWE_ECKEY_LENGTH] = { 0 };
    BN_bn2bin(_pubKey, tPub);
    this->memcpy_packet(_packet, tPub, OWE_ECKEY_LENGTH);

    debug_owe("Generate Association Request Packet Size", to_string(this->dataPointer).c_str());
    return this->dataPointer;
}

STA_FUNC int PACKET::generate_eapol_2(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, u8 *_nonce, u8 *_mic)
{
    error_owe((_packet == NULL) || (_src == NULL) || (_dst == NULL) || (_bssid == NULL) || (_nonce == NULL) || (_mic == NULL), "Parameter Error");

    this->generate_radiotap(_packet);
    this->generate_frame(_packet, _src, _dst, _bssid, FC_EAPOL, IEEE80211_FC1_DIR_TODS);
    this->generate_llc(_packet);

    struct eapol_wpa_key key = { 0 };
    key.ewk_type = EAPOL_KEY_TYPE_RSN;
    key.ewk_info = htons(EAPOL_2);
    key.ewk_keylen = htons(OWE_EAPOL_KEY_LENGTH);
    key.ewk_replay = htonll(1);
    key.ewk_datalen = htons(sizeof(struct _TLV) + sizeof(struct _RSN));
    memcpy(key.ewk_nonce, _nonce, OWE_EAPOL_NONCE_LENGTH);
    memcpy(key.ewk_mic, _mic, OWE_EAPOL_KEY_LENGTH);

    struct eapol_hdr hdr = { 0 };
    hdr.eapol_type = EAPOL_TYPE_KEY;
    hdr.eapol_ver = EAPOL_VERSION_1;
    hdr.eapol_len = htons(sizeof(struct eapol_wpa_key) + sizeof(struct _TLV) + sizeof(struct _RSN));
    this->memcpy_packet(_packet, &hdr, sizeof(struct eapol_hdr));
    this->memcpy_packet(_packet, &key, sizeof(struct eapol_wpa_key));
    if (is_zero(_mic, OWE_EAPOL_KEY_LENGTH)) return this->dataPointer - sizeof(struct eapol_hdr) - sizeof(struct eapol_wpa_key);

    this->tlv.id = IEEE80211_ELEMID_RSN;
    this->tlv.len = sizeof(this->eap_rsn);
    this->memcpy_packet(_packet, &this->tlv, sizeof(struct _TLV));
    this->memcpy_packet(_packet, &this->eap_rsn, sizeof(struct _RSN));

    debug_owe("Generate EAPOL-2 Size", to_string(this->dataPointer).c_str());
    return this->dataPointer;
}

STA_FUNC int PACKET::generate_eapol_4(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, u8 *_mic)
{
    error_owe((_packet == NULL) || (_src == NULL) || (_dst == NULL) || (_bssid == NULL) || (_mic == NULL), "Parameter Error");

    this->generate_radiotap(_packet);
    this->generate_frame(_packet, _src, _dst, _bssid, FC_EAPOL, IEEE80211_FC1_DIR_TODS);
    this->generate_llc(_packet);

    struct eapol_wpa_key key = { 0 };
    key.ewk_type = EAPOL_KEY_TYPE_RSN;
    key.ewk_info = htons(EAPOL_4);
    key.ewk_keylen = htons(OWE_EAPOL_KEY_LENGTH);
    key.ewk_replay = htonll(2);
    memcpy(key.ewk_mic, _mic, OWE_EAPOL_KEY_LENGTH);

    struct eapol_hdr hdr = { 0 };
    hdr.eapol_type = EAPOL_TYPE_KEY;
    hdr.eapol_ver = EAPOL_VERSION_1;
    hdr.eapol_len = htons(sizeof(struct eapol_wpa_key));
    this->memcpy_packet(_packet, &hdr, sizeof(struct eapol_hdr));
    this->memcpy_packet(_packet, &key, sizeof(struct eapol_wpa_key));
    if (is_zero(_mic, OWE_EAPOL_KEY_LENGTH)) return this->dataPointer - sizeof(struct eapol_hdr) - sizeof(struct eapol_wpa_key);
    
    debug_owe("Generate EAPOL-4 Size", to_string(this->dataPointer).c_str());
    return this->dataPointer;
}

STA_FUNC bool PACKET::capture_beacon(u8 *_packet, int _len, u8 *_src, u8 *_dst)
{
    int dp = this->capture_rediotap_header(_packet);

    u8 tAddr[IEEE80211_ADDR_LEN] = { 0 };
    if (this->capture_frame(_packet + dp, tAddr, _dst) == FC_BEACON)
    {
        dp += sizeof(struct ieee80211_frame) + 12; // fixed(12)

        while(dp <= _len)
        {
            struct _TLV *tlv = (struct _TLV *)(_packet + dp);
            if (tlv->id == IEEE80211_ELEMID_RSN)
            {
                dp += sizeof(struct _TLV);
                struct _RSN *rsn = (struct _RSN *)(_packet + dp);
                if (rsn->auth.type == ATH_OUI_OUI)
                {
                    memcpy(_src, tAddr, IEEE80211_ADDR_LEN);
                    debug_owe("Capture Beacon Frame(AP Addreess)", IEEE80211_ADDR_LEN, _src);
                    return true;
                }
            }
            else dp += tlv->len + 2;
        }
    }
    return false;
}

STA_FUNC bool PACKET::capture_probe_response(u8 *_packet, int _len, u8 *_src, u8 *_dst)
{
    int dp = this->capture_rediotap_header(_packet);
    if (this->capture_frame(_packet + dp, _src, _dst) == FC_PROBE_RES)
    {
        debug_owe("Capture Probe Response!", IEEE80211_ADDR_LEN, _src);
        return true;
    }
    return false;
}

STA_FUNC bool PACKET::capture_association_response(u8 *_packet, int _len, u8 *_src, u8 *_dst, BIGNUM *_pubKey)
{
    int dp = this->capture_rediotap_header(_packet);
    if (this->capture_frame(_packet + dp, _src, _dst) == FC_ASSOC_RES)
    {
        dp += sizeof(struct ieee80211_frame) + 6; // fixed(6)

        while(dp <= _len)
        {
            struct _TLV *tlv = (struct _TLV *)(_packet + dp);
            if (tlv->id == IEEE80211_ELEMID_EXTENSION)
            {
                dp += sizeof(struct _TLV);
                struct _KEY *key = (struct _KEY *)(_packet + dp);
                if (key->id == OWE_TAG_PUBKEY_ID)
                {
                    dp += sizeof(struct _KEY);
                    BN_bin2bn(_packet + dp, OWE_ECKEY_LENGTH, _pubKey);
                    debug_owe("Capture Association Response(AP Public Key X)", BN_bn2hex(_pubKey));
                    return true;
                }
            }
            else dp += tlv->len + 2;
        }
    }
    return false;
}

STA_FUNC bool PACKET::capture_eapol_1(u8 *_packet, int _len, u8 *_src, u8 *_dst, u8 *_nonce)
{
    int dp = this->capture_rediotap_header(_packet);
    if (this->capture_frame(_packet + dp, _src, _dst, IEEE80211_FC1_DIR_FROMDS) == FC_EAPOL)
    {
        dp += sizeof(struct ieee80211_frame);
        if (this->capture_llc(_packet + dp))
        {
            dp += sizeof(struct ieee80211_llc);
            struct eapol_hdr *hdr = (struct eapol_hdr *)(_packet + dp);
            if (hdr->eapol_type == EAPOL_TYPE_KEY && hdr->eapol_ver == EAPOL_VERSION_2)
            {
                dp += sizeof(struct eapol_hdr);
                struct eapol_wpa_key *key = (struct eapol_wpa_key *)(_packet + dp);
                if(key->ewk_type == EAPOL_KEY_TYPE_RSN &&  key->ewk_info == ntohs(EAPOL_1))
                {
                    memcpy(_nonce, key->ewk_nonce, OWE_EAPOL_NONCE_LENGTH);

                    debug_owe("Capture EAPOL-1, AP Nonce", OWE_EAPOL_NONCE_LENGTH, _nonce);
                    return true;
                }
            }
        }
    }
    return false;
}

STA_FUNC bool PACKET::capture_eapol_3(u8 *_packet, int _len, u8 *_src, u8 *_dst, u8 *_nonce, u8 *_mic, u8* _kek, u8 *_gtk)
{
    int dp = this->capture_rediotap_header(_packet);
    if (this->capture_frame(_packet + dp, _src, _dst, IEEE80211_FC1_DIR_FROMDS) == FC_EAPOL)
    {
        dp += sizeof(struct ieee80211_frame);
        if (this->capture_llc(_packet + dp))
        {
            dp += sizeof(struct ieee80211_llc);
            struct eapol_hdr *hdr = (struct eapol_hdr *)(_packet + dp);
            if (hdr->eapol_type == EAPOL_TYPE_KEY && hdr->eapol_ver == EAPOL_VERSION_2)
            {
                dp += sizeof(struct eapol_hdr);
                struct eapol_wpa_key *key = (struct eapol_wpa_key *)(_packet + dp);
                if(key->ewk_type == EAPOL_KEY_TYPE_RSN &&  key->ewk_info == ntohs(EAPOL_3))
                {
                    memcpy(_nonce, key->ewk_nonce, OWE_EAPOL_NONCE_LENGTH);
                    memcpy(_mic, key->ewk_mic, OWE_EAPOL_KEY_LENGTH);

                    debug_owe("Capture EAPOL-3, AP Nonce", OWE_EAPOL_NONCE_LENGTH, _nonce);
                    debug_owe("Capture EAPOL-3, AP MIC", OWE_EAPOL_KEY_LENGTH, _mic);

                    int eSize = ntohs(key->ewk_datalen);
                    dp += sizeof(struct eapol_wpa_key);

                    u8 pData[eSize] = { 0 };
                    AES_KEY dkey;
                    AES_set_decrypt_key(_kek, 128, &dkey);
                    int dSize = AES_unwrap_key(&dkey, NULL, pData, (_packet + dp), eSize);
                    error_owe(dSize == 0, "AES_wrap_key Error");

                    dp = sizeof(struct _TLV) + sizeof(struct _RSN) + sizeof(RSN_GTK);
                    memcpy(_gtk, (pData + dp), OWE_EAPOL_KEY_LENGTH);
                    debug_owe("Capture EAPOL-3, GTK", OWE_EAPOL_KEY_LENGTH, _gtk);

                    return true;
                }
            }
        }
    }
    return false;
}

#pragma endregion

#pragma region AP_STA_FUNC

AP_STA_FUNC int PACKET::generate_authentication(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, u16 _seq)
{
    error_owe((_packet == NULL) || (_src == NULL) || (_dst == NULL) || (_bssid == NULL), "Parameter Error");

    this->generate_radiotap(_packet);
    this->generate_frame(_packet, _src, _dst, _bssid, FC_AUTH);

    u16 algorithm = 0;
    this->memcpy_packet(_packet, &algorithm, sizeof(u16));

    this->memcpy_packet(_packet, &_seq, sizeof(u16));
    
    u16 status = 0;
    this->memcpy_packet(_packet, &status, sizeof(u16));

    debug_owe("Generate Authentication Packet Size", to_string(this->dataPointer).c_str());
    return this->dataPointer;
}

AP_STA_FUNC bool PACKET::capture_authentication(u8 *_packet, int _len, u8 *_src, u8 *_dst)
{
    int dp = this->capture_rediotap_header(_packet);
    if (this->capture_frame(_packet + dp, _src, _dst) == FC_AUTH)
    {
        dp += sizeof(struct ieee80211_frame);
        u8 *pInfo = (u8 *)(_packet + dp);
        if(pInfo[4] == 0 && pInfo[5] == 0)
        {
            debug_owe("Capture Authtication. Status Code", 2, pInfo + 4);
            return true;
        }
    }
    return false;
}

#pragma endregion

#pragma region private_func

int PACKET::capture_rediotap_header(u8 *_packet)
{
    struct ieee80211_radiotap_header *rh = (struct ieee80211_radiotap_header *)_packet;
    return rh->it_len;
}

u8 PACKET::capture_frame(u8 *_packet, u8 *_src, u8 *_dst)
{
    error_owe((_packet == NULL) || (_dst == NULL) || (_src == NULL), "Packets that can't be processed.");

    struct ieee80211_frame *fh = (struct ieee80211_frame *)_packet;

    if(!is_equal(_dst, fh->i_addr1, IEEE80211_ADDR_LEN)) return -1;

    if (_src[0] == 0)
        memcpy(_src, fh->i_addr2, IEEE80211_ADDR_LEN);
    else if (!is_equal(_src, fh->i_addr2, IEEE80211_ADDR_LEN)) return -1;

    return (fh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) | (fh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK);
}

u8 PACKET::capture_frame(u8 *_packet, u8 *_src, u8 *_dst, u8 _flags)
{
    error_owe((_packet == NULL) || (_dst == NULL) || (_src == NULL), "Packets that can't be processed.");

    struct ieee80211_frame *fh = (struct ieee80211_frame *)_packet;

    u8 tFlags = fh->i_fc[1] & IEEE80211_FC1_DIR_MASK;
    if(tFlags != _flags) return -1;

    if (_flags == IEEE80211_FC1_DIR_TODS)
    {
        if(!is_equal(_dst, fh->i_addr3, IEEE80211_ADDR_LEN)) return -1;
        else if (!is_equal(_src, fh->i_addr2, IEEE80211_ADDR_LEN)) return -1;
    }
    else if (_flags == IEEE80211_FC1_DIR_FROMDS)
    {
        if(!is_equal(_dst, fh->i_addr1, IEEE80211_ADDR_LEN)) return -1;
        else if (!is_equal(_src, fh->i_addr3, IEEE80211_ADDR_LEN)) return -1;
    }
    
    return (fh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) | (fh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK);
}  

bool PACKET::capture_llc(u8 *_packet)
{
    struct ieee80211_llc *llc = (struct ieee80211_llc *)_packet;
    if(llc->illc_ether_type = ntohs(ETH_P_EAPOL)) return true;
    else return false;
}

void PACKET::generate_tag_info(u8 *_packet)
{
    // SSID
    string ssid("INS-OWE");
    this->tlv.id = IEEE80211_ELEMID_SSID;
    this->tlv.len = ssid.length();
    this->memcpy_packet(_packet, &this->tlv, sizeof(this->tlv));
    this->memcpy_packet(_packet, ssid.c_str(), ssid.length());

    // Rates
    u8 rates[] = {0x82, 0x84, 0x0b, 0x16};
    this->tlv.id = IEEE80211_ELEMID_RATES;
    this->tlv.len = sizeof(rates);
    this->memcpy_packet(_packet, &this->tlv, sizeof(this->tlv));
    this->memcpy_packet(_packet, rates, sizeof(rates));

    // Channel
    u8 channel = 0x01;
    this->tlv.id = IEEE80211_ELEMID_DSPARMS;
    this->tlv.len = sizeof(channel);
    this->memcpy_packet(_packet, &this->tlv, sizeof(this->tlv));
    this->memcpy_packet(_packet, &channel, sizeof(channel));

    // RSN
    this->tlv.id = IEEE80211_ELEMID_RSN;
    this->tlv.len = sizeof(this->rsn);
    this->memcpy_packet(_packet, &this->tlv, sizeof(this->tlv));
    this->memcpy_packet(_packet, &this->rsn, sizeof(this->rsn));

    // Classes
    u16 classes = 0x51;
    this->tlv.id = IEEE80211_ELEMID_CLASSES;
    this->tlv.len = sizeof(classes);
    this->memcpy_packet(_packet, &this->tlv, sizeof(this->tlv));
    this->memcpy_packet(_packet, &classes, sizeof(classes));

    // Extended Capabilities
    u8 cap[] = {0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40};
    this->tlv.id = IEEE80211_ELEMID_EX_CAP;
    this->tlv.len = sizeof(cap);
    this->memcpy_packet(_packet, &this->tlv, sizeof(this->tlv));
    this->memcpy_packet(_packet, cap, sizeof(cap));
}

void PACKET::generate_llc(u8 *_packet)
{
    struct ieee80211_llc llc = { 0 };
    llc.illc_dsap = LLC_DSAP;
    llc.illc_ssap = LLC_SSAP;
    llc.illc_control = LLC_CONTROL;
    llc.illc_ether_type = htons(ETH_P_EAPOL);

    this->memcpy_packet(_packet, &llc, sizeof(struct ieee80211_llc));
}

void PACKET::generate_radiotap(u8 *_packet)
{
    this->dataPointer = 0;

    u8 radiotap[] = {0x00, 0x00, 0x0b, 0x00, 0x00, 0x80, 0x02, 0x00, 0x00, 0x00, 0x00};
    this->memcpy_packet(_packet, radiotap, sizeof(radiotap));
}

void PACKET::generate_frame(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, u8 _ft)
{
    struct ieee80211_frame frame = {0};
    memcpy(frame.i_addr1, _dst, IEEE80211_ADDR_LEN);
    memcpy(frame.i_addr2, _src, IEEE80211_ADDR_LEN);
    memcpy(frame.i_addr3, _bssid, IEEE80211_ADDR_LEN);
    frame.i_fc[0] = _ft;

    this->memcpy_packet(_packet, &frame, sizeof(struct ieee80211_frame));
}

void PACKET::generate_frame(u8 *_packet, u8 *_src, u8 *_dst, u8 *_bssid, u8 _ft, u8 _flags)
{
    struct ieee80211_frame frame = {0};

    if(_flags == IEEE80211_FC1_DIR_TODS)
    {
        memcpy(frame.i_addr1, _bssid, IEEE80211_ADDR_LEN);
        memcpy(frame.i_addr2, _src, IEEE80211_ADDR_LEN);
        memcpy(frame.i_addr3, _dst, IEEE80211_ADDR_LEN);
    }
    else if (_flags == IEEE80211_FC1_DIR_FROMDS)
    {
        memcpy(frame.i_addr1, _dst, IEEE80211_ADDR_LEN);
        memcpy(frame.i_addr2, _bssid, IEEE80211_ADDR_LEN);
        memcpy(frame.i_addr3, _src, IEEE80211_ADDR_LEN);
    }
    else error_owe(true, "Unknown FC1");

    frame.i_fc[0] = _ft;
    frame.i_fc[1] = _flags;

    this->memcpy_packet(_packet, &frame, sizeof(struct ieee80211_frame));
}

void PACKET::memcpy_packet(u8 *_dst, const void *_src, int _len)
{
    memcpy(_dst + this->dataPointer, _src, _len);
    this->dataPointer += _len;
}

#pragma endregion
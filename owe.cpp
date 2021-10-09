#include "owe.h"

void OWE::init(string _dev)
{
    if (_dev.find("AP") != -1)
    {
        this->dev.append(_dev);
        this->handle = get_wireless_adapter(this->addr.ap, &this->adapter);
        memcpy(this->addr.bssid, this->addr.ap, IEEE80211_ADDR_LEN);
        memset(this->addr.sta, 0xFF, IEEE80211_ADDR_LEN);
    }
    else if (_dev.find("STA") != -1)
    {
        this->dev.append(_dev);
        this->handle = get_wireless_adapter(this->addr.sta, &this->adapter);
        memset(this->addr.ap, 0xFF, IEEE80211_ADDR_LEN);
        memset(this->addr.bssid, 0xFF, IEEE80211_ADDR_LEN);
    }
    else
        error_owe(true, "init device check");

    this->beaconHandle = get_wireless_adapter(this->adapter);
    this->probeHandle = get_wireless_adapter(this->adapter);
    error_owe((this->handle == NULL) || (this->beaconHandle == NULL) || (this->probeHandle == NULL), "Can't open handle");

    memset(this->addr.br, 0xFF, IEEE80211_ADDR_LEN);
}

void OWE::init(KEY *_key, u8 *_sta)
{
    memcpy(_key->addr.ap, this->addr.ap, IEEE80211_ADDR_LEN);
    memcpy(_key->addr.bssid, this->addr.bssid, IEEE80211_ADDR_LEN);
    memcpy(_key->addr.sta, _sta, IEEE80211_ADDR_LEN);
    memset(_key->addr.br, 0xFF, IEEE80211_ADDR_LEN);
    _key->handle = get_wireless_adapter(this->adapter);
    _key->status = NONE_AP;
}

void OWE::sendp(pcap_t *_handle, const int _interval, u8 *_packet, int _len)
{
    if (_interval == 0)
        pcap_sendpacket(_handle, _packet, _len);
    else
    {
        while (true)
        {
            pcap_sendpacket(_handle, _packet, _len);
            sleep(_interval);
        }
    }
}

void OWE::recv_send(pcap_t *_handle, u16 _recv_fc, u16 _send_fc)
{
    struct pcap_pkthdr *header;
    const unsigned char *pk;

    while (true)
    {
        if (!pcap_next_ex(_handle, &header, &pk))
            continue;
        else if (header->len == 0)
            continue;

        u8 tAddr[IEEE80211_ADDR_LEN] = {0};
        u8 *packet = (u8 *)pk;

        if (this->packet.capture_packet(_recv_fc, packet, header->len, tAddr, this->addr.ap))
        {
            u8 sendPacket[1500] = {0};
            int sendPacketSize = this->packet.generate_packet(_send_fc, sendPacket, this->addr.ap, tAddr, this->addr.bssid);
            this->sendp(_handle, 0, sendPacket, sendPacketSize);
        }
    }
}

bool OWE::recv_send_key(pcap_t *_handle)
{
    u8 current_recv_step = FC_AUTH;
    u8 current_send_step = FC_AUTH;

    struct pcap_pkthdr *header;
    const unsigned char *pk;

    while (true)
    {
        if (!pcap_next_ex(_handle, &header, &pk))
            continue;
        else if (header->len == 0)
            continue;

        u8 tAddr[IEEE80211_ADDR_LEN] = {0};
        u8 *packet = (u8 *)pk;

        if (current_recv_step == DONE)
            break;

        u8 sendPacket[1500] = {0};
        int sendPacketSize = 0;
        if (current_send_step == FC_AUTH)
        {
            if (this->packet.capture_packet(current_recv_step, packet, header->len, tAddr, this->addr.ap))
            {   
                string addr = byte_to_string(tAddr, IEEE80211_ADDR_LEN);
                auto item = info.find(addr);
                if (item != info.end())
                {
                    debug_owe("Re-connection STA", IEEE80211_ADDR_LEN, tAddr);
                    info.erase(addr);
                }
                KEY newKey;
                this->init(&newKey, tAddr);
                info.insert(pair<string, KEY>(addr, newKey));

                thread connectThread(&OWE::start_ap, this, &newKey);
                connectThread.join();
            }
        }
    }
    return true;
}

bool OWE::send_recv_key(KEY *_key)
{
    error_owe(_key->status != EAPOL, "Auth/Assoc Request");

    // Assoc Res
    u8 assocRes[1500] = { 0 };
    int assocResSize = this->packet.generate_packet(FC_ASSOC_RES, assocRes, _key->addr.ap, _key->addr.sta, _key->addr.bssid, _key->ap.pubX);

    // Gen EAPOL1
    u8 eapol[1500] = {0};
    _key->ap.generate_nonce(_key->addr.ap);
    int eapolSize = this->packet.generate_packet(EAPOL_1, eapol, _key->addr.ap, _key->addr.sta, _key->addr.bssid, _key->ap.nonce);

    // CAP EAPOL2
    if (!this->send_recv(_key, EAPOL_2, 2, assocRes, assocResSize, eapol, eapolSize, _key->addr.sta, _key->addr.ap))
        error_owe(true, "EAPOL packet cannot be found.");
    
    _key->ap.compute_PTK(_key->addr.ap, _key->addr.sta, _key->sta.nonce);

    // Check EAPOL2 MIC
    u8 tMIC[OWE_EAPOL_KEY_LENGTH] = { 0 };
    memcpy(tMIC, _key->sta.mic, OWE_EAPOL_KEY_LENGTH);
    memset(_key->sta.mic, 0, OWE_EAPOL_KEY_LENGTH);
    memset(eapol, 0, 1500);
    eapolSize = this->packet.generate_packet(EAPOL_2, eapol, _key->addr.sta, _key->addr.ap, _key->addr.bssid, _key->sta.nonce, _key->sta.mic);
    _key->ap.validate_MIC(eapol + eapolSize, tMIC);

    // Gen EAPOL3
    memset(eapol, 0, 1500);
    memset(_key->ap.mic, 0, OWE_EAPOL_KEY_LENGTH);
    eapolSize = this->packet.generate_packet(EAPOL_3, eapol, _key->addr.ap, _key->addr.sta, _key->addr.bssid, _key->ap.nonce, _key->ap.mic, _key->ap.kek, _key->ap.gtk);
    _key->ap.compute_MIC(eapol + eapolSize);
    _key->ap.compute_GTK(_key->addr.ap);

    // Cap EAPOL4
    eapolSize = this->packet.generate_packet(EAPOL_3, eapol, _key->addr.ap, _key->addr.sta, _key->addr.bssid, _key->ap.nonce, _key->ap.mic, _key->ap.kek, _key->ap.gtk);
    if (!this->send_recv(_key, EAPOL_4, 2, eapol, eapolSize, _key->addr.sta, _key->addr.ap))
        error_owe(true, "EAPOL packet cannot be found.");

    // Check EAPOL4 MIC
    memset(tMIC, 0, OWE_EAPOL_KEY_LENGTH);
    memcpy(tMIC, _key->sta.mic, OWE_EAPOL_KEY_LENGTH);
    memset(_key->sta.mic, 0, OWE_EAPOL_KEY_LENGTH);
    memset(eapol, 0, 1500);
    eapolSize = this->packet.generate_packet(EAPOL_4, eapol, _key->addr.sta, _key->addr.ap, _key->addr.bssid, _key->sta.mic);
    _key->ap.validate_MIC(eapol + eapolSize, tMIC);

    _key->status = DATA;
    debug_owe("Success Connecttion STA", IEEE80211_ADDR_LEN, _key->addr.sta);
    return true;
}

bool OWE::send_recv(pcap_t *_handle, u16 _fc, const int _interval, u8 *_send_packet, int _send_len, u8 *_src, u8 *_dst)
{
    for (int i = 0; i < MAX_INTERVAL_COUNT; i++)
    {
        bool is_cap = false;
        time_t startTime = time(nullptr);

        this->sendp(_handle, 0, _send_packet, _send_len);

        time_t currentTime = time(nullptr);
        while ((startTime + _interval > currentTime) && !is_cap)
        {
            struct pcap_pkthdr *header;
            const unsigned char *pk;

            if (!pcap_next_ex(_handle, &header, &pk))
                continue;
            else if (header->len == 0)
                continue;

            u8 *packet = (u8 *)pk;
            bool ret = false;
            if (_fc == FC_ASSOC_RES)
                ret = this->packet.capture_packet(_fc, packet, header->len, _src, _dst, this->key.ap.pubX);
            else if(_fc == EAPOL_1)
                ret = this->packet.capture_packet(_fc, packet, header->len, _src, _dst, this->key.ap.nonce);
            else if(_fc == EAPOL_2)
                ret = this->packet.capture_packet(_fc, packet, header->len, _src, _dst, this->key.sta.nonce, this->key.sta.mic);
            else if(_fc == EAPOL_3)
                ret = this->packet.capture_packet(_fc, packet, header->len, _src, _dst, this->key.ap.nonce, this->key.ap.mic, this->key.sta.kek, this->key.ap.gtk);
            else if(_fc == EAPOL_4)
                ret = this->packet.capture_packet(_fc, packet, header->len, _src, _dst, this->key.sta.mic);
            else
                ret = this->packet.capture_packet(_fc, packet, header->len, _src, _dst);

            if (ret)
                return true;
            currentTime = time(nullptr);
        }
    }
    return false;
}

bool OWE::send_recv(pcap_t *_handle, u16 _fc, const int _interval, u8 *_send_packet1, int _send_len1, u8 *_send_packet2, int _send_len2, u8 *_src, u8 *_dst)
{
    for (int i = 0; i < MAX_INTERVAL_COUNT; i++)
    {
        bool is_cap = false;
        time_t startTime = time(nullptr);

        this->sendp(_handle, 0, _send_packet1, _send_len1);
        this->sendp(_handle, 0, _send_packet2, _send_len2);

        time_t currentTime = time(nullptr);
        while ((startTime + _interval > currentTime) && !is_cap)
        {
            struct pcap_pkthdr *header;
            const unsigned char *pk;

            if (!pcap_next_ex(_handle, &header, &pk))
                continue;
            else if (header->len == 0)
                continue;

            u8 *packet = (u8 *)pk;
            bool ret = this->packet.capture_packet(_fc, packet, header->len, _src, _dst, this->key.sta.nonce, this->key.sta.mic);
            
            if (ret)
                return true;
            currentTime = time(nullptr);
        }
    }
    return false;
}

bool OWE::send_recv(KEY *_key, u16 _fc, const int _interval, u8 *_send_packet, int _send_len, u8 *_src, u8 *_dst)
{
    for (int i = 0; i < MAX_INTERVAL_COUNT; i++)
    {
        bool is_cap = false;
        time_t startTime = time(nullptr);

        this->sendp(_key->handle, 0, _send_packet, _send_len);

        time_t currentTime = time(nullptr);
        while ((startTime + _interval > currentTime) && !is_cap)
        {
            struct pcap_pkthdr *header;
            const unsigned char *pk;

            if (!pcap_next_ex(_key->handle, &header, &pk))
                continue;
            else if (header->len == 0)
                continue;

            u8 *packet = (u8 *)pk;
            bool ret = false;
            if (_fc == FC_ASSOC_RES)
                ret = this->packet.capture_packet(_fc, packet, header->len, _src, _dst, _key->ap.pubX);
            else if(_fc == EAPOL_1)
                ret = this->packet.capture_packet(_fc, packet, header->len, _src, _dst, _key->ap.nonce);
            else if(_fc == EAPOL_2)
                ret = this->packet.capture_packet(_fc, packet, header->len, _src, _dst, _key->sta.nonce, _key->sta.mic);
            else if(_fc == EAPOL_3)
                ret = this->packet.capture_packet(_fc, packet, header->len, _src, _dst, _key->ap.nonce, _key->ap.mic, _key->sta.kek, _key->ap.gtk);
            else if(_fc == EAPOL_4)
                ret = this->packet.capture_packet(_fc, packet, header->len, _src, _dst, _key->sta.mic);
            else
                ret = this->packet.capture_packet(_fc, packet, header->len, _src, _dst);

            if (ret)
                return true;
            currentTime = time(nullptr);
        }
    }
    return false;
}

bool OWE::send_recv(KEY *_key, u16 _fc, const int _interval, u8 *_send_packet1, int _send_len1, u8 *_send_packet2, int _send_len2, u8 *_src, u8 *_dst)
{
    for (int i = 0; i < MAX_INTERVAL_COUNT; i++)
    {
        bool is_cap = false;
        time_t startTime = time(nullptr);

        this->sendp(_key->handle, 0, _send_packet1, _send_len1);
        this->sendp(_key->handle, 0, _send_packet2, _send_len2);

        time_t currentTime = time(nullptr);
        while ((startTime + _interval > currentTime) && !is_cap)
        {
            struct pcap_pkthdr *header;
            const unsigned char *pk;

            if (!pcap_next_ex(_key->handle, &header, &pk))
                continue;
            else if (header->len == 0)
                continue;

            u8 *packet = (u8 *)pk;
            bool ret = this->packet.capture_packet(_fc, packet, header->len, _src, _dst, _key->sta.nonce, _key->sta.mic);
            
            if (ret)
                return true;
            currentTime = time(nullptr);
        }
    }
    return false;
}


bool OWE::recvp(pcap_t *_handle, u16 _fc, u8 *_src, u8 *_dst)
{
    struct pcap_pkthdr *header;
    const unsigned char *pk;

    while (true)
    {
        if (!pcap_next_ex(_handle, &header, &pk))
            continue;
        else if (header->len == 0)
            continue;

        u8 *packet = (u8 *)pk;
        if ((_fc == FC_BEACON) && this->packet.capture_packet(_fc, packet, header->len, this->addr.ap, this->addr.br))
        {
            this->key.status = AP_ADDR_CAPTURE;
            return true;
        }
        else if ((_fc == EAPOL_1) && this->packet.capture_packet(_fc, packet, header->len, _src, _dst, this->key.ap.nonce))
            return true;
    }
    return false;
}

void OWE::start()
{
    if (this->dev.find("AP") != -1)
    {
        u8 beacon[1500] = {0};
        int beaconSize = this->packet.generate_packet(FC_BEACON, beacon, this->addr.ap, this->addr.br, this->addr.bssid);

        thread beaconThread(&OWE::sendp, this, this->beaconHandle, 2, beacon, beaconSize);
        thread probeThread(&OWE::recv_send, this, this->probeHandle, FC_PROBE_REQ, FC_PROBE_RES);
        thread authThread(&OWE::recv_send_key, this, this->handle);

        beaconThread.join();
        probeThread.join();
        authThread.join();
    }

    else if (this->dev.find("STA") != -1)
    {
        this->recvp(this->handle, FC_BEACON, NULL, NULL);
        error_owe(this->key.status != AP_ADDR_CAPTURE, "No AP Address found.");

        u8 probeReq[1500] = {0};
        int probeReqSize = this->packet.generate_packet(FC_PROBE_REQ, probeReq, this->addr.sta, this->addr.ap, this->addr.bssid);
        this->key.status = SEND_PROBE_REQ;

        if (!this->send_recv(this->handle, FC_PROBE_RES, 2, probeReq, probeReqSize, this->addr.ap, this->addr.sta))
            error_owe(true, "Probe Response packet cannot be found.");
        this->key.status = RECV_PROBE_RES;

        u8 authReq[1500] = {0};
        int authReqSize = this->packet.generate_packet(FC_AUTH, authReq, this->addr.sta, this->addr.ap, this->addr.bssid, htons(0x0100));
        this->key.status = SEND_AUTH_REQ;

        if (!this->send_recv(this->handle, FC_AUTH, 2, authReq, authReqSize, this->addr.ap, this->addr.sta))
            error_owe(true, "Authentication Response packet cannot be found.");
        this->key.status = RECV_AUTH_RES;

        this->key.sta.init_key();

        u8 assocReq[1500] = {0};
        int assocReqSize = this->packet.generate_packet(FC_ASSOC_REQ, assocReq, this->addr.sta, this->addr.ap, this->addr.bssid, this->key.sta.pubX);
        this->key.status = SEND_ASSOC_REQ;

        if (!this->send_recv(this->handle, FC_ASSOC_RES, 2, assocReq, assocReqSize, this->addr.ap, this->addr.sta))
            error_owe(true, "Association Response packet cannot be found.");
        this->key.status = RECV_ASSOC_RES;
        this->key.sta.compute_oweKey(&this->key.ap);
        this->key.sta.compute_PMK(this->key.ap.pubX, this->key.sta.pubX);

        // Cap EAPOL1
        if(this->recvp(this->handle, EAPOL_1, this->addr.ap, this->addr.sta))
        {
            this->key.status = EAPOL;

            u8 eapol[1500] = {0};
            this->key.sta.generate_nonce(this->addr.sta);
            this->key.sta.compute_PTK(this->addr.sta, this->addr.ap, this->key.ap.nonce);

            // Gen EAPOL2
            memset(this->key.sta.mic, 0, OWE_EAPOL_KEY_LENGTH);
            int eapolSize = this->packet.generate_packet(EAPOL_2, eapol, this->addr.sta, this->addr.ap, this->addr.bssid, this->key.sta.nonce, this->key.sta.mic);
            this->key.sta.compute_MIC(eapol + eapolSize);

            // Cap EAPOL3
            eapolSize = this->packet.generate_packet(EAPOL_2, eapol, this->addr.sta, this->addr.ap, this->addr.bssid, this->key.sta.nonce, this->key.sta.mic);
            if (!this->send_recv(this->handle, EAPOL_3, 2, eapol, eapolSize, this->addr.ap, this->addr.sta))
                error_owe(true, "EAPOL packet cannot be found.");

            // Check EAPOL3 MIC
            u8 tMIC[OWE_EAPOL_KEY_LENGTH] = { 0 };
            memcpy(tMIC, this->key.ap.mic, OWE_EAPOL_KEY_LENGTH);
            memset(this->key.ap.mic, 0, OWE_EAPOL_KEY_LENGTH);
            memset(eapol, 0, 1500);
            eapolSize = this->packet.generate_packet(EAPOL_3, eapol, this->addr.ap, this->addr.sta, this->addr.bssid, this->key.ap.nonce, this->key.ap.mic, this->key.ap.kek, this->key.ap.gtk);
            this->key.sta.validate_MIC(eapol + eapolSize, tMIC);

            // Gen EAPOL4
            memset(eapol, 0, 1500);
            memset(this->key.sta.mic, 0, OWE_EAPOL_KEY_LENGTH);
            eapolSize = this->packet.generate_packet(EAPOL_4, eapol, this->addr.sta, this->addr.ap, this->addr.bssid, this->key.sta.mic);
            this->key.sta.compute_MIC(eapol + eapolSize);

            eapolSize = this->packet.generate_packet(EAPOL_4, eapol, this->addr.sta, this->addr.ap, this->addr.bssid, this->key.sta.mic);
            this->sendp(this->handle, 0, eapol, eapolSize);
            this->sendp(this->handle, 0, eapol, eapolSize);
            this->sendp(this->handle, 0, eapol, eapolSize);
        }
    }
}

bool OWE::start_ap(KEY *_key)
{
    int interval = 3;
    u8 sendPacket[1500] = {0};
    int sendPacketSize = this->packet.generate_packet(FC_AUTH, sendPacket, _key->addr.ap, _key->addr.sta, _key->addr.bssid, htons(0x0200));

    for (int i = 0; i < MAX_INTERVAL_COUNT; i++)
    {
        bool is_cap = false;
        time_t startTime = time(nullptr);

        this->sendp(_key->handle, 0, sendPacket, sendPacketSize);

        time_t currentTime = time(nullptr);
        while ((startTime + interval > currentTime) && !is_cap)
        {
            struct pcap_pkthdr *header;
            const unsigned char *pk;

            if (!pcap_next_ex(_key->handle, &header, &pk))
                continue;
            else if (header->len == 0)
                continue;

            u8 *packet = (u8 *)pk;
            if (this->packet.capture_packet(FC_ASSOC_REQ, packet, header->len, _key->addr.sta, _key->addr.ap, _key->sta.pubX))
            {
                _key->ap.init_key();
                _key->ap.compute_oweKey(&_key->sta);
                _key->ap.compute_PMK(_key->ap.pubX, _key->sta.pubX);
                _key->status = EAPOL;
                this->send_recv_key(_key);

                // TODO: DATA Start
                return true;
            }
            currentTime = time(nullptr);
        }
    }
    error_owe(true, "Association Request packet cannot be found.");
    return false;
}

int main(void)
{
    OWE owe(string("AP"));
    // OWE owe(string("STA"));
    owe.start();

    return 0;
}
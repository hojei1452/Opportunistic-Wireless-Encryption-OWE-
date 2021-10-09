#ifndef _KEY_OWE_H_
#define _KEY_OWE_H_

#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "debug_owe.h"
#include "packet.h"
#include "utils.h"

class KEY_OWE
{
private:
    void compute_compressed_pubKey(int _y_bit, const EC_GROUP *_group, EC_POINT *_pubKey, BIGNUM *_x, BIGNUM *_y);
    void HKDF_extract(u8 *_salt, int _slen, u8 *_key, int _klen, u8 *_prk, unsigned int _plen);
    void HKDF_expand(u8 *_prk, int _plen, u8 *_data, int _dlen, u8 *_pmk, int _klen);

    void get_ntp_timestamp(u8 *_time);
    void set_min_max(u8 *_dst, u8 *_c1, u8 *_c2, int _len);

public:
    EC_KEY *ecKey;
    const EC_GROUP *group;
    const BIGNUM *privKey;
    EC_POINT *pubKey;
    BIGNUM *pubX;
    BIGNUM *pubY;

    u8 ss[SHA256_DIGEST_LENGTH];
    u8 prk[SHA256_DIGEST_LENGTH];
    u8 pmk[SHA256_DIGEST_LENGTH];

    #define OWE_KEY_PKE_LENGTH 100
    #define OWE_KEY_GROUP_PKE_LENGTH 34
    u8 nonce[OWE_EAPOL_NONCE_LENGTH];
    u8 mic[OWE_EAPOL_KEY_LENGTH];
    u8 ptk[SHA256_DIGEST_LENGTH * 2];
    u8 tk[OWE_EAPOL_KEY_LENGTH];
    u8 kck[OWE_EAPOL_KEY_LENGTH];
    u8 kek[OWE_EAPOL_KEY_LENGTH];

    u8 gmk[SHA256_DIGEST_LENGTH];
    u8 gtk[OWE_EAPOL_KEY_LENGTH];

    void init_key();

    void compute_oweKey(KEY_OWE *_pubKey);
    void compute_PMK(BIGNUM *_apX, BIGNUM *_staX);
    void compute_PTK(u8 *_addr, u8 *_peerAddr, u8 *_peerNonce);
    void compute_MIC(u8 *_packet);
    void compute_GTK(u8 *_addr);

    void generate_nonce(u8 *_addr);

    bool validate_MIC(u8 *_packet, u8 *_mic);

    KEY_OWE();
    ~KEY_OWE();
};

#endif
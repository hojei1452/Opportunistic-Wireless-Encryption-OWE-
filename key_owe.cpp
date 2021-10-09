#include "key_owe.h"

KEY_OWE::KEY_OWE()
{
    this->ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    error_owe(this->ecKey == NULL, "eckey cannot be generated.");

    this->group = EC_KEY_get0_group(this->ecKey);
    error_owe(this->group == NULL, "eckey cannot be generated.");

    this->pubKey = EC_POINT_new(this->group);
    error_owe(this->pubKey == NULL, "ec pubkey cannot be generated.");

    this->pubX = BN_new();
    this->pubY = BN_new();
    error_owe((this->pubX == NULL) || (this->pubY == NULL), "ec pubkey cannot be generated.");
}

KEY_OWE::~KEY_OWE() {}

void KEY_OWE::init_key()
{
    int ret = EC_KEY_generate_key(this->ecKey);
    error_owe(ret == 0, "eckey cannot be generated.");

    this->pubKey = (EC_POINT *)EC_KEY_get0_public_key(this->ecKey);
    error_owe(this->pubKey == NULL, "ec pubkey cannot be generated.");

    ret = EC_POINT_get_affine_coordinates_GFp(this->group, this->pubKey, this->pubX, this->pubY, NULL);
    error_owe((ret == 0) || (this->pubX == NULL) || (this->pubY == NULL), "ec pubkey cannot be generated.");
    debug_owe("Pubkey X", BN_bn2hex(this->pubX));
    debug_owe("Pubkey Y", BN_bn2hex(this->pubY));

    this->privKey = EC_KEY_get0_private_key(this->ecKey);
    error_owe(this->privKey == NULL, "ec privkey cannot be generated.");
    debug_owe("PrivKey", BN_bn2hex(this->privKey));

    ret = RAND_bytes(this->gmk, SHA256_DIGEST_LENGTH);
    error_owe(ret == 0, "GMK cannot be generated.");
    debug_owe("Generate GMK", SHA256_DIGEST_LENGTH, this->gmk);
}

void KEY_OWE::HKDF_extract(u8 *_salt, int _slen, u8 *_key, int _klen, u8 *_prk, unsigned int _plen)
{
    const EVP_MD *md = EVP_sha256();
    HMAC_CTX *ctx = HMAC_CTX_new();
    error_owe((md == NULL) || (ctx == NULL), "Can't init EVP and CTX");

    HMAC(md, _salt, _slen, _key, _klen, _prk, &_plen);
    HMAC_CTX_free(ctx);

    debug_owe("Compute PRK", SHA256_DIGEST_LENGTH, _prk);
}

void KEY_OWE::HKDF_expand(u8 *_prk, int _plen, u8 *_data, int _dlen, u8 *_pmk, int _klen)
{
    const EVP_MD *md = EVP_sha256();
    HMAC_CTX *ctx = HMAC_CTX_new();
    error_owe((md == NULL) || (ctx == NULL), "Can't init EVP and CTX");

    u8 digest[SHA256_DIGEST_LENGTH] = {0};

    unsigned int digestlen = 0, len = 0;
    u8 ctr = 1;

    for (; len < _klen; len += digestlen, ctr++)
    {
        HMAC_Init_ex(ctx, _prk, _plen, md, NULL);
        HMAC_Update(ctx, digest, digestlen);
        HMAC_Update(ctx, _data, _dlen);
        HMAC_Update(ctx, &ctr, sizeof(unsigned char));
        HMAC_Final(ctx, digest, &digestlen);
        if ((len + digestlen) > _klen)
            memcpy(_pmk + len, digest, _klen - len);
        else
            memcpy(_pmk + len, digest, digestlen);

        HMAC_CTX_reset(ctx);
    }
    HMAC_CTX_free(ctx);

    debug_owe("Compute PMK", SHA256_DIGEST_LENGTH, _pmk);
}

void KEY_OWE::compute_compressed_pubKey(int _y_bit, const EC_GROUP *_group, EC_POINT *_pubKey, BIGNUM *_x, BIGNUM *_y)
{
    int ret = 0;

    ret = EC_POINT_set_compressed_coordinates_GFp(_group, _pubKey, _x, _y_bit, NULL);
    error_owe((ret == 0) || (_pubKey == NULL), "Can't interpretation Compressed Public Key");

    ret = EC_POINT_is_on_curve(_group, _pubKey, NULL);
    error_owe(ret == 0, "Can't interpretation Compressed Public Key");

    ret = EC_POINT_get_affine_coordinates_GFp(_group, _pubKey, _x, _y, NULL);
    error_owe(ret == 0, "Can't interpretation Compressed Public Key");

    debug_owe("Peer Public Key X Coordinate", BN_bn2hex(_x));
    debug_owe("Peer Public Key Y Coordinate", BN_bn2hex(_y));
}

void KEY_OWE::compute_PMK(BIGNUM *_apX, BIGNUM *_staX)
{
    u8 group[] = {0x00, 0x13};
    u8 salt[OWE_ECKEY_LENGTH * 2 + 2] = {0};
    u8 apX[OWE_ECKEY_LENGTH] = {0}, staX[OWE_ECKEY_LENGTH] = {0};

    BN_bn2bin(_apX, apX);
    BN_bn2bin(_staX, staX);

    memcpy(salt, staX, OWE_ECKEY_LENGTH);
    memcpy(salt + OWE_ECKEY_LENGTH, apX, OWE_ECKEY_LENGTH);
    memcpy(salt + OWE_ECKEY_LENGTH * 2, group, sizeof(group));

    string tData("OWE Key Generation");
    this->HKDF_extract(salt, sizeof(salt), this->ss, SHA256_DIGEST_LENGTH, this->prk, SHA256_DIGEST_LENGTH);
    this->HKDF_expand(this->prk, SHA256_DIGEST_LENGTH, (u8 *)tData.c_str(), tData.length(), this->pmk, SHA256_DIGEST_LENGTH);
}

void KEY_OWE::compute_oweKey(KEY_OWE *_key)
{
    this->compute_compressed_pubKey(0, _key->group, _key->pubKey, _key->pubX, _key->pubY);

    EC_POINT *tKey = EC_POINT_new(this->group);
    int ret = EC_POINT_mul(this->group, tKey, NULL, _key->pubKey, this->privKey, NULL);
    error_owe((ret == 0) || (tKey == NULL), "Can't EC_POINT mul");

    BIGNUM *tX = BN_new();
    ret = EC_POINT_get_affine_coordinates_GFp(this->group, tKey, tX, NULL, NULL);
    error_owe((ret == 0) || (tX == NULL), "Can't compute shared Secret");

    debug_owe("Shared Secret(My privKey * Peer PubKey) X", BN_bn2hex(tX));
    BN_bn2bin(tX, this->ss);
}

void KEY_OWE::get_ntp_timestamp(u8 *_time)
{
    error_owe(_time == NULL, "Time not alloc");

    struct timeval tv;
    int ret = gettimeofday(&tv, NULL);
    error_owe(ret == -1, "gettimeofday error");

    u32 sec, usec = tv.tv_usec;
    sec = tv.tv_sec + 2208988800U; /* Epoch to 1900 */
    usec = 4295 * usec - (usec >> 5) - (usec >> 9);

    u32 temp = htonl(sec);
    memcpy(_time, (u8 *)&temp, 4);
    temp = htonl(usec);
    memcpy(_time + 4, (u8 *)&temp, 4);
}

void KEY_OWE::generate_nonce(u8 *_addr)
{
    error_owe(_addr == NULL, "Parameter Error");

    u8 rb[OWE_EAPOL_NONCE_LENGTH] = {0};
    int ret = RAND_bytes(rb, OWE_EAPOL_NONCE_LENGTH);
    error_owe(ret == -1, "Dont Generate RAND_bytes");

    int np = strlen("Init Counter");
    u8 tNonce[np + 8 + IEEE80211_ADDR_LEN] = {0};

    memcpy(tNonce, "Init Counter", np);
    memcpy(tNonce + np, _addr, IEEE80211_ADDR_LEN);
    np += IEEE80211_ADDR_LEN;
    this->get_ntp_timestamp(tNonce + np);

    HMAC(EVP_sha256(), rb, OWE_EAPOL_NONCE_LENGTH, tNonce, sizeof(tNonce), this->nonce, NULL);
    debug_owe("Generate Nonce", OWE_EAPOL_NONCE_LENGTH, this->nonce);
}

void KEY_OWE::set_min_max(u8 *_dst, u8 *_c1, u8 *_c2, int _len)
{
    for (int i = 0; i < _len; i++)
    {
        if (_c1[i] < _c2[i])
        {
            memcpy(_dst, _c1, _len);
            memcpy(_dst + _len, _c2, _len);
            break;
        }
        else if (_c1[i] > _c2[i])
        {
            memcpy(_dst, _c2, _len);
            memcpy(_dst + _len, _c1, _len);
            break;
        }
    }
}

void KEY_OWE::compute_PTK(u8 *_addr, u8 *_peerAddr, u8 *_peerNonce)
{
    u8 pke[OWE_KEY_PKE_LENGTH] = {0x50, 0x61, 0x69, 0x72, 0x77, 0x69, 0x73, 0x65, 0x20, 0x6B, 0x65, 0x79, 0x20, 0x65, 0x78, 0x70, 0x61, 0x6E, 0x73, 0x69, 0x6F, 0x6E, 0x00};
    int pkePoint = strlen("Pairwise key expansion") + 1;

    this->set_min_max(pke + pkePoint, _addr, _peerAddr, IEEE80211_ADDR_LEN);
    pkePoint += IEEE80211_ADDR_LEN;

    this->set_min_max(pke + pkePoint, this->nonce, _peerNonce, OWE_EAPOL_NONCE_LENGTH);
    pkePoint += OWE_EAPOL_NONCE_LENGTH;

    for (int i = 0; i < 4; i++)
    {
        pke[99] = i;
        HMAC(EVP_sha1(), this->pmk, SHA256_DIGEST_LENGTH, pke, OWE_KEY_PKE_LENGTH, this->ptk + i * SHA_DIGEST_LENGTH, NULL);
    }

    for (int i = 0; i < OWE_EAPOL_KEY_LENGTH; i++)
    {
        this->kek[i] = this->ptk[i];
        this->kck[i] = this->ptk[i + OWE_EAPOL_KEY_LENGTH];
        this->tk[i] = this->ptk[i + OWE_EAPOL_KEY_LENGTH * 2];
    }

    debug_owe("Compute KEK", OWE_EAPOL_KEY_LENGTH, this->kek);
    debug_owe("Compute KCK", OWE_EAPOL_KEY_LENGTH, this->kck);
    debug_owe("Compute TK", OWE_EAPOL_KEY_LENGTH, this->tk);
}

void KEY_OWE::compute_MIC(u8 *_packet)
{
    int checkSize = sizeof(struct eapol_hdr) + sizeof(struct eapol_wpa_key);
    u8 data[checkSize] = { 0 };
    memcpy(data, _packet, checkSize);

    HMAC(EVP_sha1(), this->kck, OWE_EAPOL_KEY_LENGTH, data, checkSize, this->mic, NULL);
    debug_owe("Generate MIC", OWE_EAPOL_KEY_LENGTH, this->mic);
}

void KEY_OWE::compute_GTK(u8 *_addr)
{
    u8 gpke[OWE_KEY_GROUP_PKE_LENGTH] = {0x47, 0x72, 0x6F, 0x75, 0x70, 0x20, 0x6B, 0x65, 0x79, 0x20, 0x65, 0x78, 0x70, 0x61, 0x6E, 0x73, 0x69, 0x6F, 0x6E, 0x00};
    int pkePoint = strlen("Group key expansion") + 1;

    memcpy(gpke + pkePoint, _addr, IEEE80211_ADDR_LEN);
    pkePoint += IEEE80211_ADDR_LEN;

    this->get_ntp_timestamp(gpke + pkePoint);
    HMAC(EVP_sha1(), this->gmk, SHA256_DIGEST_LENGTH, gpke, OWE_KEY_GROUP_PKE_LENGTH, this->gtk, NULL);
    debug_owe("Compute GTK", OWE_EAPOL_KEY_LENGTH, this->gtk);
}

bool KEY_OWE::validate_MIC(u8 *_packet, u8 *_mic)
{
    debug_owe("Vaildate MIC", OWE_EAPOL_KEY_LENGTH, _mic);
    this->compute_MIC(_packet);
    if(is_equal(this->mic, _mic, OWE_EAPOL_KEY_LENGTH))
        return true;
    else
        error_owe(true, "Invalid MIC");
    return false;
}
#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include <openssl/param_build.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <string.h>

#include "trustm_provider_common.h"
#include "trustm_helper.h"
#include "trustm_ec_key_helper.h"


// helper function to return NID from trustm ecc curve name
int trustm_ecc_curve_to_nid(optiga_ecc_curve_t curve)
{
    switch (curve) {
    case OPTIGA_ECC_CURVE_NIST_P_256:
        return NID_X9_62_prime256v1;
    
    case OPTIGA_ECC_CURVE_NIST_P_384:
        return NID_secp384r1;

    case OPTIGA_ECC_CURVE_NIST_P_521:
        return NID_secp521r1;

    case OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1:
        return NID_brainpoolP256r1;

    case OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1:
        return NID_brainpoolP384r1;

    case OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1:
        return NID_brainpoolP512r1;

    default:
        return NID_undef;
    }
}

// helper function to return trustm ecc curve name from NID
optiga_ecc_curve_t trustm_nid_to_ecc_curve(int nid)
{
    switch (nid) {
    case NID_X9_62_prime256v1:
        return OPTIGA_ECC_CURVE_NIST_P_256;

    case NID_secp384r1:
        return OPTIGA_ECC_CURVE_NIST_P_384;

    case NID_secp521r1:
        return OPTIGA_ECC_CURVE_NIST_P_521;

    case NID_brainpoolP256r1:
        return OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1;

    case NID_brainpoolP384r1:
        return OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1;

    case NID_brainpoolP512r1:
        return OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1;

    default:
        return 0;
    }
}

// helper function to convert trustm's generated public key to ecc points
int trustm_ecc_public_key_to_point(trustm_ec_key_t *trustm_ec_key)
{
    EC_GROUP* group = NULL;
    EC_POINT* point = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;

    uint8_t uncompressed_buff[500];
    uint16_t uncompressed_buff_length;
    int res = 0;
    int tolen;

    if (trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_NIST_P_256 || trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_NIST_P_384
        || trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1 || trustm_ec_key->key_curve == OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1)
    {
        uncompressed_buff_length = trustm_ec_key->public_key[trustm_ec_key->public_key_header_length + 1] - 1;
        memcpy(uncompressed_buff, (trustm_ec_key->public_key + trustm_ec_key->public_key_header_length + 3), uncompressed_buff_length);
    }

    else 
    {
        uncompressed_buff_length = trustm_ec_key->public_key[trustm_ec_key->public_key_header_length + 2] - 1;
        memcpy(uncompressed_buff, (trustm_ec_key->public_key + trustm_ec_key->public_key_header_length + 4), uncompressed_buff_length);
    }

    if ((group = EC_GROUP_new_by_curve_name(trustm_ecc_curve_to_nid(trustm_ec_key->key_curve))) == NULL
        || (point = EC_POINT_new(group)) == NULL
        || !EC_POINT_oct2point(group, point, uncompressed_buff, uncompressed_buff_length, NULL)
        || (x = BN_new()) == NULL
        || (y = BN_new()) == NULL
        || !EC_POINT_get_affine_coordinates(group, point, x, y, NULL))
        goto final;

    tolen = (EC_GROUP_order_bits(group) + 7) / 8;

    if (BN_bn2binpad(x, trustm_ec_key->x, tolen) != tolen)
        goto final;
    trustm_ec_key->point_x_buffer_length = tolen;

    if (BN_bn2binpad(y, trustm_ec_key->y, tolen) != tolen)
        goto final;
    trustm_ec_key->point_y_buffer_length = tolen;

    res = 1;

final:
    BN_free(x);
    BN_free(y);
    EC_POINT_free(point);
    EC_GROUP_free(group);
    return res;
}

// helper function to convert compressed form buffer to ecc points
int trustm_buffer_to_ecc_point(trustm_ec_key_t *trustm_ec_key, const unsigned char *buf, size_t len)
{
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    int tolen;
    int res = 0;

    if ((group = EC_GROUP_new_by_curve_name(trustm_ecc_curve_to_nid(trustm_ec_key->key_curve))) == NULL
        || (point = EC_POINT_new(group)) == NULL
        || !EC_POINT_oct2point(group, point, buf, len, NULL)
        || (x = BN_new()) == NULL
        || (y = BN_new()) == NULL
        || !EC_POINT_get_affine_coordinates(group, point, x, y, NULL))
        goto final;

    tolen = (EC_GROUP_order_bits(group) + 7) / 8;

    if (BN_bn2binpad(x, trustm_ec_key->x, tolen) != tolen)
        goto final;
    trustm_ec_key->point_x_buffer_length = tolen;

    if (BN_bn2binpad(y, trustm_ec_key->y, tolen) != tolen)
        goto final;
    trustm_ec_key->point_y_buffer_length = tolen;

    res = 1;

final:
    BN_free(x);
    BN_free(y);
    EC_POINT_free(point);
    EC_GROUP_free(group);
    return res;
}


// helper function to set uncompressed form buffer
int trustm_ec_point_to_uncompressed_buffer(trustm_ec_key_t *trustm_ec_key, void **buffer)
{
    size_t size;
    unsigned char *out;
    
    if (trustm_ec_key->point_x_buffer_length == 0 || trustm_ec_key->point_y_buffer_length == 0)
        return 0;
    
    size = 1 + trustm_ec_key->point_x_buffer_length + trustm_ec_key->point_y_buffer_length;
    
    *buffer = OPENSSL_malloc(size);
    if (*buffer == NULL)
        return 0;
        
    out = (unsigned char *) *buffer;
    
    *(out++) = 4; // uncompressed form
    memcpy(out, trustm_ec_key->x, trustm_ec_key->point_x_buffer_length);
    out += trustm_ec_key->point_x_buffer_length;
    memcpy(out, trustm_ec_key->y, trustm_ec_key->point_y_buffer_length);
    
    return size;
}
//~ int trustm_key_write(BIO *bout, trustm_ec_key_t *trustm_ec_key) 
//~ {
   // To do
//~ }

// Using Openssl 1.1 API for testing at this moment
int trustm_key_write(BIO *bout, trustm_ec_key_t *trustm_ec_key) 
{
    int curve_nid;
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key = NULL;
    BIGNUM *priv_bn = NULL;
    BIGNUM *x = NULL, *y = NULL;
    unsigned char *privkey = NULL;
    size_t private_key_len                  = sizeof(privkey);
    int ret = 0;
    
    TRUSTM_PROVIDER_DBGFN(">");
    if (!bout || !trustm_ec_key) {
        TRUSTM_PROVIDER_DBGFN("Error: Invalid inputs");
        goto err;
    }
    curve_nid = trustm_ecc_curve_to_nid(trustm_ec_key->key_curve);
    if (curve_nid == NID_undef) {
        TRUSTM_PROVIDER_DBGFN("Error: Invalid curve NID");
        return 0;
    }
    switch (curve_nid) {
        case NID_X9_62_prime256v1: /* P-256 */
            private_key_len = 32;
            break;            
        case NID_secp384r1: /* P-384 */
            private_key_len = 48;
            break;
        case NID_secp521r1: /* P-521 */
            private_key_len = 66;
            break;
        case NID_brainpoolP256r1: /* Brainpool 256 */
            private_key_len = 32;
            break;
        case NID_brainpoolP384r1: /* Brainpool 384 */
            private_key_len = 48;
            break;
        case NID_brainpoolP512r1: /* Brainpool 512 */
            private_key_len = 64;
            break;            
        default:
            TRUSTM_PROVIDER_DBGFN("Error: Unsupported curve");
            return 0;
    }   
    ec_key = EC_KEY_new_by_curve_name(curve_nid); 
    if (!ec_key) {
        TRUSTM_PROVIDER_DBGFN("Error: Failed to create EC_KEY");
        goto err;
    }
    // Set public key using x and y coordinates
    x = BN_bin2bn(trustm_ec_key->x, trustm_ec_key->point_x_buffer_length, NULL);
    y = BN_bin2bn(trustm_ec_key->y, trustm_ec_key->point_y_buffer_length, NULL);
    if (!x || !y) {
        TRUSTM_PROVIDER_DBGFN("Error: Failed to create BIGNUMs for x, y coordinates");
        goto err;
    }
    if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
        TRUSTM_PROVIDER_DBGFN("Error: Failed to set public key coordinates");
        goto err;
    }
     privkey = OPENSSL_zalloc(private_key_len);
     uint16_t key_id = (uint16_t)trustm_ec_key->private_key_id;
     privkey[0] = (key_id >> 8) & 0xFF; // High byte
     privkey[1] = key_id & 0xFF;        // Low byte
     
    priv_bn = BN_bin2bn(privkey, private_key_len, NULL);
    if (!priv_bn) {
        TRUSTM_PROVIDER_DBGFN("Error: Failed to create BIGNUM for private key");
        goto err;
    }
    if (!EC_KEY_set_private_key(ec_key, priv_bn)) {
        TRUSTM_PROVIDER_DBGFN("Error: Failed to set private key");
        goto err;
    }

    pkey = EVP_PKEY_new();
    if (!pkey) {
        TRUSTM_PROVIDER_DBGFN("Error: Failed to create EVP_PKEY");
        goto err;
    }
    if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
        TRUSTM_PROVIDER_DBGFN("Error: Failed to assign EC_KEY to EVP_PKEY");
        EVP_PKEY_free(pkey);
        goto err;
    }
    ec_key = NULL; 
    if (!PEM_write_bio_PrivateKey(bout, pkey, NULL, NULL, 0, NULL, NULL)) {
        goto err;
    }
    TRUSTM_PROVIDER_DBGFN("<");
    ret = 1;

err:
    BN_free(priv_bn);
    OPENSSL_free(privkey);
    EVP_PKEY_free(pkey);
    return ret;
}

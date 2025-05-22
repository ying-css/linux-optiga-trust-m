#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/types.h>

int main(void) {
  OSSL_STORE_CTX *ctx = NULL;
  OSSL_LIB_CTX *trustm_libctx = NULL;
  OSSL_PROVIDER *trustm_provider = NULL;

  EVP_PKEY *private_key_handle = NULL;

  BIO *x509_req_bio = BIO_new(BIO_s_mem());
  int x509_req_len = 0;
  char *x509_req_key = NULL;

  const char prop_query[] = "?provider=trustm";
  /*
   * key_slot contain the following information:
   * - 0xe0f1: key slot to use
   * - *: no public input
   * - NEW: generate a new key
   * - 0x03: key size. 0x03 is NIST P256
   * - 0x01: key usage, a bitfield used when generating a CSR or self-signed certificate
   *
   * This is documented on https://github.com/Infineon/linux-optiga-trust-m/?tab=readme-ov-file#req
   */
  const char key_slot[] = "0xe0f1:*:NEW:0x03:0x1";

  int ret = 0;

  //~ ret = OSSL_PROVIDER_available(NULL, "trustm_provider");
  //~ if (ret == 1) {
    //~ printf("OSSL_PROVIDER_available\n");
  //~ } else {
    //~ printf("Error in OSSL_PROVIDER_available\n");
    //~ return -1;
  //~ }

  trustm_provider = OSSL_PROVIDER_load(trustm_libctx, "trustm_provider");
  if (trustm_provider == NULL) {
    printf("Error loading trustm_provider\n");
    return -1;
  }

  /* Generate store that will be used to load key */
  ctx = OSSL_STORE_open_ex(key_slot, trustm_libctx, prop_query, NULL, NULL, NULL, NULL, NULL);
  if (ctx == NULL) {
    printf("Error opening store\n");
    return -1;
  }

  /* We are looking for a private key */
  if (!OSSL_STORE_expect(ctx, OSSL_STORE_INFO_PKEY)) {
    printf("object is not of type OSSL_STORE_INFO_PKEY\n");
    return -1;
  }

  /* Load key, and verify that the key is effectively a private key */
  OSSL_STORE_INFO *info = OSSL_STORE_load(ctx);
  int type = OSSL_STORE_INFO_get_type(info);
  if (type != OSSL_STORE_INFO_PKEY) {
    printf("Expected type to be OSSL_STORE_INFO_PKEY, got %d\n", type);
    return -1;
  }

  /* Get key handle */
  private_key_handle = OSSL_STORE_INFO_get1_PKEY(info);
  if (private_key_handle  == NULL) {
    printf("Error in OSSL_STORE_INFO_get1_PKEY\n");
    return -1;
  }

  X509_REQ* x509_req = X509_REQ_new();
  if (!X509_REQ_set_pubkey(x509_req, private_key_handle)) {
    printf("Error in X509_REQ_set_pubkey\n");
    return -1;
  }

  X509_NAME* name_field = X509_REQ_get_subject_name(x509_req);
  if (!name_field) {
    printf("Error in X509_REQ_get_subject_name\n");
    return -1;
  }

  if (!X509_NAME_add_entry_by_txt(name_field, "CN", MBSTRING_UTF8, "trustm", -1, -1, 0)) {
    printf("Error in X509_NAME_add_entry_by_txt\n");
    return -1;
  }

  if (!X509_REQ_sign(x509_req, private_key_handle, EVP_sha256())) {
    printf("Error in X509_REQ_sign\n");
    return -1;
  }

  // This is the call that seems to not work properly
  //~ if (!PEM_write_bio_X509_REQ(x509_req_bio, x509_req)) {
    //~ printf("Error in PEM_write_bio_X509_REQ\n");
    //~ return -1;
  //~ }

  //~ x509_req_len = BIO_get_mem_data(x509_req_bio, &x509_req_key);
  //~ printf("%s\n", x509_req_key);
  FILE *fp = fopen("csr.pem", "w");
  if (fp == NULL) {
      fprintf(stderr, "Error opening file csr.pem: %s\n", strerror(errno));
      return -1;
  }
  if (!PEM_write_X509_REQ(fp, x509_req)) {
      fprintf(stderr, "Error in PEM_write_X509_REQ: %s\n", ERR_error_string(ERR_get_error(), NULL));
      fclose(fp);
      return -1;
  }
  fclose(fp);
  x509_req_len = BIO_get_mem_data(x509_req_bio, &x509_req_key);
  printf("%.*s\n", (int)x509_req_len, x509_req_key);

  return 0;
}

 

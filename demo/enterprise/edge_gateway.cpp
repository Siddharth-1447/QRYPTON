// Deterministic demo fixture: bounded C++ lexical/API discovery.
#include <openssl/aes.h>
#include <openssl/rsa.h>

void configure_gateway() {
    RSA_generate_key_ex(nullptr, 2048, nullptr, nullptr);
    EVP_aes_256_gcm();
    const char* suite = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
    (void)suite;
}


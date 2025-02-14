#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <omp.h>

#define START_HEX  0x0000000000000000000000000000000000000000000000100000000000000000
#define STOP_HEX   0x0000000000000000000000000000000000000000000000200000000000000000
#define NUM_THREADS 96

const char *TARGET_ADDRESS = "19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG";

void sha256(const uint8_t *data, size_t len, uint8_t *hash) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, len);
    SHA256_Final(hash, &sha256);
}

void ripemd160(const uint8_t *data, size_t len, uint8_t *hash) {
    RIPEMD160_CTX ripemd;
    RIPEMD160_Init(&ripemd);
    RIPEMD160_Update(&ripemd, data, len);
    RIPEMD160_Final(hash, &ripemd);
}

void generate_private_key(uint8_t *private_key) {
    uint64_t random_key = START_HEX + ((uint64_t)rand() << 32 | rand()) % (STOP_HEX - START_HEX);
    snprintf((char *)private_key, 65, "%064llx", random_key);
}

void private_key_to_public_key(const uint8_t *private_key, uint8_t *public_key) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM *priv_bn = BN_new();
    BN_hex2bn(&priv_bn, (const char *)private_key);
    EC_KEY_set_private_key(key, priv_bn);

    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *pub_key = EC_POINT_new(group);
    EC_POINT_mul(group, pub_key, priv_bn, NULL, NULL, NULL);
    EC_KEY_set_public_key(key, pub_key);
    
    BN_free(priv_bn);
    EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_COMPRESSED, public_key, 33, NULL);
    EC_POINT_free(pub_key);
    EC_KEY_free(key);
}

void public_key_to_p2pkh_address(const uint8_t *public_key, char *address) {
    uint8_t sha256_hash[32];
    uint8_t ripemd160_hash[20];
    sha256(public_key, 33, sha256_hash);
    ripemd160(sha256_hash, 32, ripemd160_hash);
    
    sprintf(address, "%02x", ripemd160_hash[0]); // Dummy for now
}

int main() {
    srand(time(NULL));
    omp_set_num_threads(NUM_THREADS);

    printf("Starting key search with %d threads...\n", NUM_THREADS);
    
    #pragma omp parallel
    {
        uint8_t private_key[65];
        uint8_t public_key[33];
        char address[35];
        
        while (1) {
            generate_private_key(private_key);
            private_key_to_public_key(private_key, public_key);
            public_key_to_p2pkh_address(public_key, address);
            
            if (strcmp(address, TARGET_ADDRESS) == 0) {
                printf("Found matching key!\nPrivate Key: %s\n", private_key);
                FILE *file = fopen("found_keys.txt", "a");
                fprintf(file, "Target Address: %s\nPrivate Key: %s\n", TARGET_ADDRESS, private_key);
                fclose(file);
                exit(0);
            }
        }
    }
    return 0;
}

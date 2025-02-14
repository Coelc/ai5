#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>  // Для безопасной генерации случайных чисел
#include <omp.h>

#define START_HEX  0x0000000000000000000000000000000000000000000000100000000000000000
#define STOP_HEX   0x0000000000000000000000000000000000000000000000200000000000000000
#define NUM_THREADS 96

const char *TARGET_ADDRESS = "19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG";

// Функция для хеширования SHA256
void sha256(const uint8_t *data, size_t len, uint8_t *hash) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, len);
    SHA256_Final(hash, &sha256);
}

// Функция для хеширования RIPEMD160
void ripemd160(const uint8_t *data, size_t len, uint8_t *hash) {
    RIPEMD160_CTX ripemd;
    RIPEMD160_Init(&ripemd);
    RIPEMD160_Update(&ripemd, data, len);
    RIPEMD160_Final(hash, &ripemd);
}

// Генерация случайного приватного ключа
void generate_private_key(uint8_t *private_key) {
    uint8_t random_bytes[32];
    RAND_bytes(random_bytes, 32);  // Используем OpenSSL для безопасной генерации случайных байтов
    for (int i = 0; i < 32; ++i) {
        snprintf((char *)private_key + i * 2, 3, "%02x", random_bytes[i]);
    }
}

// Преобразование приватного ключа в публичный
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

// Преобразование публичного ключа в Bitcoin адрес (P2PKH)
void public_key_to_p2pkh_address(const uint8_t *public_key, char *address) {
    uint8_t sha256_hash[32];
    uint8_t ripemd160_hash[20];
    uint8_t address_with_prefix[21];  // 1 байт префикса + 20 байт хеша

    sha256(public_key, 33, sha256_hash);  // SHA-256
    ripemd160(sha256_hash, 32, ripemd160_hash);  // RIPEMD-160

    address_with_prefix[0] = 0x00;  // Префикс для Bitcoin mainnet адреса
    memcpy(address_with_prefix + 1, ripemd160_hash, 20);
    
    // Рассчитываем контрольную сумму (первые 4 байта SHA-256(SHA-256(address)))
    uint8_t checksum[4];
    sha256(address_with_prefix, 21, sha256_hash);
    sha256(sha256_hash, 32, sha256_hash);  // Двойной SHA-256
    memcpy(checksum, sha256_hash, 4);
    
    // Добавляем контрольную сумму к адресу
    memcpy(address_with_prefix + 21, checksum, 4);
    
    // Кодируем в Base58 (нужно реализовать функцию base58_encode или использовать библиотеку)
    base58_encode(address_with_prefix, 25, address);
}

// Главная функция
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

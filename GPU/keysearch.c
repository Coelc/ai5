#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <omp.h>

// Функция для преобразования строки в шестнадцатеричное значение
void hex_to_bytes(const char *hex, unsigned char *bytes) {
    size_t len = strlen(hex);
    for (size_t i = 0; i < len / 2; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}

// Функция для хэширования с использованием SHA-256
void sha256_hash(unsigned char *data, size_t length, unsigned char *output_hash) {
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, data, length);
    SHA256_Final(output_hash, &sha256_ctx);
}

// Функция для проверки, соответствует ли хэш целевому адресу
int check_target_address(unsigned char *hash, const char *target_address) {
    char hash_string[65];
    for (int i = 0; i < 32; i++) {
        sprintf(&hash_string[i * 2], "%02x", hash[i]);
    }
    hash_string[64] = '\0';

    return strncmp(hash_string, target_address, 10) == 0;
}

int main() {
    // Стартовый и конечный ключи (в шестнадцатеричном формате)
    const char *start_hex = "0000000000000000000000000000000000000000000000100000000000000000";
    const char *stop_hex = "0000000000000000000000000000000000000000000000200000000000000000";

    // Целевой адрес
    const char *target_address = "19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG";

    unsigned char start_bytes[32], stop_bytes[32];
    hex_to_bytes(start_hex, start_bytes);
    hex_to_bytes(stop_hex, stop_bytes);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char key[32];
    
    // Используем OpenMP для параллельной обработки
    #pragma omp parallel for num_threads(96)
    for (unsigned long long int i = 0; i < 256; i++) {  // Поменяйте диапазон в зависимости от вашей задачи
        for (int j = 0; j < 32; j++) {
            key[j] = start_bytes[j] + (i % 256);
        }
        
        sha256_hash(key, 32, hash);
        
        // Проверяем, соответствует ли хэш целевому адресу
        if (check_target_address(hash, target_address)) {
            #pragma omp critical
            {
                printf("Найден ключ: ");
                for (int j = 0; j < 32; j++) {
                    printf("%02x", key[j]);
                }
                printf("\n");
            }
        }
    }

    return 0;
}

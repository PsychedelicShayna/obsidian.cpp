#ifndef CRYPTO_HXX
#define CRYPTO_HXX

#include <algorithm>
#include <iostream>
#include <iomanip>
#include <cstdint>
#include <sstream>
#include <random>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <array>

#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>


namespace ossl {
    namespace encoding {
        struct bio_free_all {
            void operator()(BIO* bio_ptr);
        };
        
        std::string base64_encode(const std::vector<uint8_t>& bytes);
        std::vector<uint8_t> base64_decode(const std::string& b64_string);

        std::string base16_encode(const std::vector<uint8_t>& bytes);
        std::vector<uint8_t> base16_decode(const std::string& hexstr);

        std::vector<uint8_t> apply_pkcs7_padding(std::vector<uint8_t> bytes, const uint8_t& multiple);
        std::vector<uint8_t> strip_pkcs7_padding(std::vector<uint8_t> bytes);
    }

    namespace hashing {
        template<typename CTX, int(*INIT)(CTX*), int(*UPDATE)(CTX*, const void*, size_t), int(*FINAL)(unsigned char*, CTX*), size_t LENGTH>
        std::vector<uint8_t> digest(const std::vector<uint8_t>& bytes) {
            std::vector<uint8_t> update_buffer(LENGTH);
            
            CTX context;
            INIT(&context);

            UPDATE(&context, bytes.data(), bytes.size());
            FINAL(update_buffer.data(), &context);
            
            return update_buffer;
        }

        extern std::vector<uint8_t> (*digest_sha1)   (const std::vector<uint8_t>&);
        extern std::vector<uint8_t> (*digest_sha224) (const std::vector<uint8_t>&);
        extern std::vector<uint8_t> (*digest_sha256) (const std::vector<uint8_t>&);
        extern std::vector<uint8_t> (*digest_sha384) (const std::vector<uint8_t>&);
        extern std::vector<uint8_t> (*digest_sha512) (const std::vector<uint8_t>&);
    }


    namespace aes {
        enum KeySize {
            KS_128_BIT = 16, KS_192_BIT = 24, KS_256_BIT = 32
        };

        template<KeySize KS>
        std::vector<uint8_t> encrypt_cbc(std::vector<uint8_t> bytes, std::array<uint8_t, KS> key, std::array<uint8_t, AES_BLOCK_SIZE> initialization_vector) {
            AES_KEY key_object;
            AES_set_encrypt_key(key.data(), key.size() * 8, &key_object);

            AES_cbc_encrypt(
                bytes.data(),
                bytes.data(),
                bytes.size(),
                &key_object,
                initialization_vector.data(),
                AES_ENCRYPT
            );

            return bytes;
        }

        template<KeySize KS>
        std::vector<uint8_t> decrypt_cbc(std::vector<uint8_t> bytes, std::array<uint8_t, KS> key, std::array<uint8_t, AES_BLOCK_SIZE> initialization_vector) {
            AES_KEY key_object;
            AES_set_decrypt_key(key.data(), key.size() * 8, &key_object);

            AES_cbc_encrypt(
                bytes.data(),
                bytes.data(),
                bytes.size(),
                &key_object,
                initialization_vector.data(),
                AES_DECRYPT
            );

            return bytes;
        }

        template<KeySize KS>
        std::vector<uint8_t> encrypt_auto_pad_iv(
            std::vector<uint8_t> bytes,
            std::vector<uint8_t> variable_length_key)
        {
            bytes = encoding::apply_pkcs7_padding(bytes, AES_BLOCK_SIZE);
            const std::vector<uint8_t>& key_sha256_digest = hashing::digest_sha256(variable_length_key);

            std::array<uint8_t, KS> encryption_key;
            std::copy_n(key_sha256_digest.begin(), KS, encryption_key.begin());

            std::array<uint8_t, AES_BLOCK_SIZE> initialization_vector;
            std::copy_n(key_sha256_digest.begin(), AES_BLOCK_SIZE, initialization_vector.begin());

            return encrypt_cbc<KS>(bytes, encryption_key, initialization_vector);
        }

        template<KeySize KS>
        std::vector<uint8_t> decrypt_auto_pad_iv(
            std::vector<uint8_t> bytes,
            std::vector<uint8_t> variable_length_key)
        {
            const std::vector<uint8_t>& key_sha256_digest = hashing::digest_sha256(variable_length_key);

            std::array<uint8_t, KS> decryption_key; // (key_sha256_digest.begin(), key_sha256_digest.begin() + KS);
            std::copy_n(key_sha256_digest.begin(), KS, decryption_key.begin());

            std::array<uint8_t, AES_BLOCK_SIZE> initialization_vector; // (key_sha256_digest.begin(), key_sha256_digest.begin() + KS);
            std::copy_n(key_sha256_digest.begin(), AES_BLOCK_SIZE, initialization_vector.begin());

            const std::vector<uint8_t>& decrypted_bytes = decrypt_cbc<KS>(bytes, decryption_key, initialization_vector);

            return encoding::strip_pkcs7_padding(decrypted_bytes);
        }

        template<KeySize KS> 
        std::vector<uint8_t> encrypt_auto_pad_iv_rand(
            std::vector<uint8_t> bytes,
            std::vector<uint8_t> variable_length_key)
        {
            std::vector<uint8_t> random_bytes = ossl::random::byte_vector(256);
            
            double epoch_timestamp = random::get_ms_since_epoch();

            for(uint8_t& byte : random_bytes) {
                uint8_t* epoch_bytes = reinterpret_cast<uint8_t*>(&epoch_timestamp);

                for(int i=0; i<sizeof(double); ++i){
                    byte ^= epoch_bytes[i];
                }
            }

            random_bytes = ossl::hashing::digest_sha256(random_bytes);

            bytes.insert(bytes.begin(), random_bytes.begin(), random_bytes.end());

            bytes = encoding::apply_pkcs7_padding(bytes, AES_BLOCK_SIZE);
            const std::vector<uint8_t>& key_sha256_digest = hashing::digest_sha256(variable_length_key);

            std::array<uint8_t, KS> encryption_key;
            std::copy_n(key_sha256_digest.begin(), KS, encryption_key.begin());

            std::array<uint8_t, AES_BLOCK_SIZE> initialization_vector;
            std::copy_n(key_sha256_digest.begin(), AES_BLOCK_SIZE, initialization_vector.begin());

            return encrypt_cbc<KS>(bytes, encryption_key, initialization_vector);
        }

        template<KeySize KS>
        std::vector<uint8_t> decrypt_auto_pad_iv_rand(
            std::vector<uint8_t> bytes,
            std::vector<uint8_t> variable_length_key)
        {
            const std::vector<uint8_t>& key_sha256_digest = hashing::digest_sha256(variable_length_key);

            std::array<uint8_t, KS> decryption_key; // (key_sha256_digest.begin(), key_sha256_digest.begin() + KS);
            std::copy_n(key_sha256_digest.begin(), KS, decryption_key.begin());

            std::array<uint8_t, AES_BLOCK_SIZE> initialization_vector; // (key_sha256_digest.begin(), key_sha256_digest.begin() + KS);
            std::copy_n(key_sha256_digest.begin(), AES_BLOCK_SIZE, initialization_vector.begin());

            std::vector<uint8_t> decrypted_bytes = decrypt_cbc<KS>(bytes, decryption_key, initialization_vector);
            decrypted_bytes = encoding::strip_pkcs7_padding(decrypted_bytes);
            decrypted_bytes.erase(decrypted_bytes.begin(), decrypted_bytes.size() > AES_BLOCK_SIZE ? decrypted_bytes.begin() + AES_BLOCK_SIZE : decrypted_bytes.end());

            return decrypted_bytes;
        }
    }

    namespace rsa {
        enum KeySize {
            KS_1024_B = 1024,
            KS_2048_B = 2048,
            KS_4096_B = 4096
        };

        RSA* generate_keypair(KeySize key_size, uint64_t public_exponent = 65537);

        std::string get_public_key_pem(RSA* public_key);
        std::string get_private_key_pem(RSA* private_key);

        RSA* load_public_key_pem(std::string public_key_pem);
        RSA* load_private_key_pem(std::string private_key_pem);

        std::pair<RSA*, RSA*> load_rsa_keypair_pem(std::string public_key_pem, std::string private_key_pem);

        std::pair<std::string, std::string> get_pem_pair(RSA* keypair);
        RSA* load_public_private_key_pem(std::string public_key_pem, std::string private_key_pem);

        std::vector<uint8_t> public_encrypt(std::vector<uint8_t> data, RSA* key, int padding = RSA_PKCS1_OAEP_PADDING);
        std::vector<uint8_t> private_decrypt(std::vector<uint8_t> data, RSA* key, int padding = RSA_PKCS1_OAEP_PADDING);
    }

    namespace random {
        int32_t number_from_range(const int32_t& from, const int32_t& to);
        std::vector<uint8_t> byte_vector(const size_t& size);
        std::vector<uint8_t> from_byteset(const std::vector<uint8_t>& byte_set, const size_t& size);
        double get_ms_since_epoch();
    }
}

#endif // CRYPTO_HXX

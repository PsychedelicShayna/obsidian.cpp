#include "../include/obsidian/asymmetric.hpp"

namespace obsidian::asymmetric::rsa {

std::shared_ptr<EVP_PKEY> generate_keypair(const KeySize&  key_size,
                                           const uint64_t& public_exponent)

{
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr),
        &EVP_PKEY_CTX_free);

    EVP_PKEY_keygen_init(context.get());
    EVP_PKEY_paramgen_init(context.get());

    EVP_PKEY* keypair = nullptr;
    EVP_PKEY_generate(context.get(), &keypair);

    return std::shared_ptr<EVP_PKEY>(keypair, EVP_PKEY_free);
}

std::vector<uint8_t> encrypt(const std::shared_ptr<EVP_PKEY>& public_key,
                             const std::vector<uint8_t>&      plaintext,
                             const int32_t&                   padding_mode)
{
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_from_pkey(nullptr, public_key.get(), nullptr),
        &EVP_PKEY_CTX_free);

    EVP_PKEY_encrypt_init(context.get());
    EVP_PKEY_CTX_set_rsa_padding(context.get(), padding_mode);

    size_t ciphertext_length = 0;

    EVP_PKEY_encrypt(context.get(),
                     nullptr,
                     &ciphertext_length,
                     plaintext.data(),
                     plaintext.size());

    std::vector<uint8_t> ciphertext(ciphertext_length, '\0');

    EVP_PKEY_encrypt(context.get(),
                     ciphertext.data(),
                     &ciphertext_length,
                     plaintext.data(),
                     plaintext.size());

    return ciphertext;
}

std::vector<uint8_t> decrypt(const std::shared_ptr<EVP_PKEY>& private_key,
                             const std::vector<uint8_t>&      ciphertext,
                             const int32_t&                   padding_mode)
{
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_from_pkey(nullptr, private_key.get(), nullptr),
        &EVP_PKEY_CTX_free);

    EVP_PKEY_decrypt_init(context.get());
    EVP_PKEY_CTX_set_rsa_padding(context.get(), padding_mode);

    size_t plaintext_length = 0;

    EVP_PKEY_decrypt(context.get(),
                     nullptr,
                     &plaintext_length,
                     ciphertext.data(),
                     ciphertext.size());

    std::vector<uint8_t> plaintext(plaintext_length, '\0');

    EVP_PKEY_decrypt(context.get(),
                     plaintext.data(),
                     &plaintext_length,
                     ciphertext.data(),
                     ciphertext.size());

    plaintext.resize(plaintext_length);
    return plaintext;
}

std::shared_ptr<EVP_PKEY> import_public(const std::string& public_key_pem)
{
    std::unique_ptr<BIO, decltype(&BIO_free)> public_key_bio(
        BIO_new_mem_buf(public_key_pem.c_str(), public_key_pem.size()),
        &BIO_free);

    EVP_PKEY* public_key_raw = nullptr;

    PEM_read_bio_PUBKEY(
        public_key_bio.get(), &public_key_raw, nullptr, nullptr);

    return std::shared_ptr<EVP_PKEY>(public_key_raw, EVP_PKEY_free);
}

std::shared_ptr<EVP_PKEY> import_private(const std::string& key_pem)
{
    std::unique_ptr<BIO, decltype(&BIO_free)> private_key_bio(
        BIO_new_mem_buf(key_pem.c_str(), key_pem.size()), &BIO_free);

    EVP_PKEY* private_key_raw = nullptr;

    PEM_read_bio_PrivateKey(
        private_key_bio.get(), &private_key_raw, nullptr, nullptr);

    return std::shared_ptr<EVP_PKEY>(private_key_raw, EVP_PKEY_free);
}

std::string export_public(const std::shared_ptr<EVP_PKEY>& key)
{
    std::unique_ptr<BIO, decltype(&BIO_free)> key_bio(BIO_new(BIO_s_mem()),
                                                      &BIO_free);

    PEM_write_bio_PUBKEY(key_bio.get(), key.get());

    BUF_MEM* key_bio_mem = nullptr;
    BIO_get_mem_ptr(key_bio.get(), &key_bio_mem);

    return std::string(key_bio_mem->data, key_bio_mem->length);
}

std::string export_private(const std::shared_ptr<EVP_PKEY>& key)
{
    std::unique_ptr<BIO, decltype(&BIO_free)> key_bio(BIO_new(BIO_s_mem()),
                                                      &BIO_free);

    PEM_write_bio_PrivateKey(
        key_bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr);

    BUF_MEM* key_bio_mem = nullptr;
    BIO_get_mem_ptr(key_bio.get(), &key_bio_mem);

    return std::string(key_bio_mem->data, key_bio_mem->length);
}

}; // namespace obsidian::asymmetric::rsa

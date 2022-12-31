#include "obsidian.hpp"

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

namespace obsidian::encoding {

std::string b64_encode(const std::vector<uint8_t>& input)
{

    std::unique_ptr<BIO, decltype(&BIO_free)> base64(BIO_new(BIO_f_base64()),
                                                     &BIO_free);

    BIO_set_flags(base64.get(), BIO_FLAGS_BASE64_NO_NL);

    std::unique_ptr<BIO, decltype(&BIO_free)> sink(BIO_new(BIO_s_mem()),
                                                   &BIO_free);

    BIO_push(base64.get(), sink.get());
    BIO_write(base64.get(), input.data(), input.size());
    BIO_flush(base64.get());

    BUF_MEM* sink_bio_mem = nullptr;
    BIO_get_mem_ptr(sink.get(), &sink_bio_mem);

    return std::string(sink_bio_mem->data, sink_bio_mem->length);
}

std::vector<uint8_t> b64_decode(const std::string& input)
{
    std::unique_ptr<BIO, decltype(&BIO_free)> b64_bio(BIO_new(BIO_f_base64()),
                                                      &BIO_free);

    BIO_set_flags(b64_bio.get(), BIO_FLAGS_BASE64_NO_NL);

    BIO* source = BIO_new_mem_buf(input.c_str(), -1);
    BIO_push(b64_bio.get(), source);

    const size_t&        maximum_length = input.size() / 4 * 3 + 1;
    std::vector<uint8_t> output(maximum_length, '\0');

    const size_t& actual_length =
        BIO_read(b64_bio.get(), output.data(), maximum_length);

    output.resize(actual_length);

    return output;
}

std::string b16_encode(const std::vector<uint8_t>& digest)
{
    std::stringstream string_stream;

    for(const uint8_t& byte : digest) {
        string_stream << std::setw(2) << std::setfill('0') << std::uppercase
                      << std::hex << static_cast<uint32_t>(byte);
    }

    return std::string(string_stream.str());
}

std::vector<uint8_t> b16_decode(const std::string& hexstring)
{
    std::vector<uint8_t> bytes;
    bytes.reserve(hexstring.size());

    if((hexstring.size() % 2) == 0) {
        char hex_buffer[4];
        hex_buffer[0] = '0';
        hex_buffer[1] = 'x';

        for(int i = 0; i < hexstring.size(); ++i) {
            if(i % 2 == 0) {
                hex_buffer[2] = hexstring.at(i);
            } else {
                hex_buffer[3] = hexstring.at(i);
                unsigned int hex_byte;

                sscanf_s(reinterpret_cast<const char*>(&hex_buffer),
                         "%x",
                         &hex_byte);

                bytes.emplace_back(hex_byte);
            }
        }
    }

    return bytes;
}

std::vector<uint8_t> apply_pkcs7_padding(std::vector<uint8_t> bytes,
                                         const uint8_t&       multiple)
{
    uint8_t difference = multiple - (bytes.size() % multiple);

    if(difference == multiple) {
        return bytes;
    }

    bytes.resize(bytes.size() + difference, difference);

    return bytes;
}

std::vector<uint8_t> strip_pkcs7_padding(std::vector<uint8_t> bytes)
{
    const uint8_t& last_byte = bytes.at(bytes.size() - 1);

    const auto& validate = [&]() {
        return std::all_of(
            bytes.cend() - last_byte, bytes.cend(), [&](const uint8_t& value) {
                return value == last_byte;
            });
    };

    if(last_byte <= bytes.size() && validate()) {
        bytes.resize(bytes.size() - last_byte);
    }

    return bytes;
}
} // namespace obsidian::encoding

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

namespace obsidian::random {

float (*rf32_from)(const float& from,
                   const float& to) = mt19937_urd_from<float>;

double (*rf64_from)(const double& from,
                    const double& to) = mt19937_urd_from<double>;

float (*rf32)()  = []() { return rf32_from(FLT_MIN, FLT_MAX); };
double (*rf64)() = []() { return rf64_from(DBL_MIN, DBL_MAX); };

uint8_t (*rui8_from)(const uint8_t&, const uint8_t&) =
    [](const uint8_t& from, const uint8_t& to) -> uint8_t {
    return static_cast<uint8_t>(mt19937_uid_from<uint16_t>(from, to));
};

uint16_t (*rui16_from)(const uint16_t&,
                       const uint16_t&) = mt19937_uid_from<uint16_t>;

uint32_t (*rui32_from)(const uint32_t&,
                       const uint32_t&) = mt19937_uid_from<uint32_t>;

uint64_t (*rui64_from)(const uint64_t&,
                       const uint64_t&) = mt19937_uid_from<uint64_t>;

int8_t (*ri8_from)(const int8_t&, const int8_t&) = [](const int8_t& from,
                                                      const int8_t& to) {
    return static_cast<int8_t>(mt19937_uid_from<int16_t>(from, to));
};

int16_t (*ri16_from)(const int16_t&,
                     const int16_t&) = mt19937_uid_from<int16_t>;

int32_t (*ri32_from)(const int32_t&,
                     const int32_t&) = mt19937_uid_from<int32_t>;

int64_t (*ri64_from)(const int64_t&,
                     const int64_t&) = mt19937_uid_from<int64_t>;

uint8_t (*rui8)() = []() -> uint8_t { return rui8_from(INT8_MIN, UINT8_MAX); };

uint16_t (*rui16)() = []() -> uint16_t {
    return ri16_from(INT16_MIN, UINT16_MAX);
};

uint32_t (*rui32)() = []() -> uint32_t {
    return ri32_from(INT32_MIN, UINT32_MAX);
};

uint64_t (*rui64)() = []() -> uint64_t {
    return rui64_from(INT64_MIN, UINT64_MAX);
};

int8_t (*ri8)()   = []() -> int8_t { return ri8_from(INT8_MIN, INT8_MAX); };
int16_t (*ri16)() = []() -> int16_t { return ri16_from(INT16_MIN, INT16_MAX); };
int32_t (*ri32)() = []() -> int32_t { return ri32_from(INT32_MIN, INT32_MAX); };
int64_t (*ri64)() = []() -> int64_t { return ri64_from(INT64_MIN, INT64_MAX); };

void write_n(uint8_t* data, const size_t& size)
{
    for(size_t i = 0; i < size; i++)
        data[i] = static_cast<uint8_t>(ri32_from(0, 0xFF));
}

std::vector<uint8_t> bytes(const size_t& size)
{
    std::vector<uint8_t> random_bytes(size);
    write_n(random_bytes.data(), size);
    return random_bytes;
}

double get_ms_since_epoch()
{
    using namespace std::chrono;

    const auto   time_since_epoch = system_clock::now().time_since_epoch();
    milliseconds ms_since_epoch = duration_cast<milliseconds>(time_since_epoch);

    return static_cast<double>(ms_since_epoch.count());
}

} // namespace obsidian::random

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

namespace obsidian::hashing {

std::vector<uint8_t> (*sha1_digest)(const std::vector<uint8_t>&) =
    generic_digest<EVP_sha1>;

std::vector<uint8_t> (*sha224_digest)(const std::vector<uint8_t>&) =
    generic_digest<EVP_sha224>;

std::vector<uint8_t> (*sha256_digest)(const std::vector<uint8_t>&) =
    generic_digest<EVP_sha256>;

std::vector<uint8_t> (*sha384_digest)(const std::vector<uint8_t>&) =
    generic_digest<EVP_sha384>;

std::vector<uint8_t> (*sha512_digest)(const std::vector<uint8_t>&) =
    generic_digest<EVP_sha512>;

} // namespace obsidian::hashing

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

namespace obsidian::key_derivation {

std::vector<uint8_t> scrypt(std::vector<uint8_t> key,
                            std::vector<uint8_t> salt,
                            uint64_t             cost_factor,
                            uint32_t             block_size_factor,
                            uint32_t             parallelization_factor,
                            const size_t&        desired_key_length)

{
    std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> key_derivation_function(
        EVP_KDF_fetch(nullptr, "SCRYPT", nullptr), &EVP_KDF_free);

    std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)>
        key_derivation_context(EVP_KDF_CTX_new(key_derivation_function.get()),
                               &EVP_KDF_CTX_free);

    const std::vector<OSSL_PARAM>& parameters {
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_PASSWORD, key.data(), key.size()),

        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, salt.data(), key.size()),

        OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &cost_factor),

        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_R,
                                    &block_size_factor),

        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_P,
                                    &parallelization_factor),

        OSSL_PARAM_construct_end()};

    std::vector<uint8_t> derived_key(desired_key_length, '\0');

    EVP_KDF_derive(key_derivation_context.get(),
                   derived_key.data(),
                   derived_key.size(),
                   parameters.data());

    return derived_key;
}

std::vector<uint8_t> scrypt_easy(const std::vector<uint8_t>& input)
{
    return scrypt(input, obsidian::random::bytes(256), 1024, 8, 4, 64);
}

}; // namespace obsidian::key_derivation

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

namespace obsidian::symmetric::aes {

std::string cbc_cipher_name(const KeySize& key_size)
{
    switch(key_size) {
        case KS_128_BIT: return "aes-128-cbc";
        case KS_192_BIT: return "aes-192-cbc";
        case KS_256_BIT: return "aes-256-cbc";
    }
}

}; // namespace obsidian::symmetric::aes

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

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

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++/

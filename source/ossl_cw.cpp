#include "ossl_cw.hpp"




/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
** Encoding Namespace Definitions
** ------------------
** TODO: Write DOCSTRING.
 */
void ossl::encoding::bio_free_all::operator()(BIO* bio_ptr) {
    BIO_free_all(bio_ptr);
}

std::string ossl::encoding::base64_encode(const std::vector<uint8_t>& binary) {
    std::unique_ptr<BIO, bio_free_all> base64(BIO_new(BIO_f_base64()));
    BIO_set_flags(base64.get(), BIO_FLAGS_BASE64_NO_NL);

    BIO* sink = BIO_new(BIO_s_mem());

    BIO_push(base64.get(), sink);
    BIO_write(base64.get(), binary.data(), binary.size());
    BIO_flush(base64.get());

    const char* encoded;
    const size_t length = BIO_get_mem_data(sink, &encoded);

    return std::string(encoded, length);
}

std::vector<uint8_t> ossl::encoding::base64_decode(const std::string& b64_string) {
    std::unique_ptr<BIO, bio_free_all> base64(BIO_new(BIO_f_base64()));
    BIO_set_flags(base64.get(), BIO_FLAGS_BASE64_NO_NL);

    BIO* source = BIO_new_mem_buf(b64_string.c_str(), -1);
    BIO_push(base64.get(), source);

    const size_t maximum_length = b64_string.size() / 4 * 3 + 1;
    std::vector<uint8_t> decoded(maximum_length);

    const size_t length = BIO_read(base64.get(), decoded.data(), maximum_length);
    decoded.resize(length);

    return decoded;
}

std::string ossl::encoding::base16_encode(const std::vector<uint8_t>& digest) {
    std::stringstream string_stream;

    for(const uint8_t& byte : digest) {
        string_stream
            << std::setw(2)
            << std::setfill('0')
            << std::uppercase
            << std::hex
            << static_cast<uint32_t>(byte);
    }

    return std::string(string_stream.str());
}

std::vector<uint8_t> ossl::encoding::base16_decode(const std::string& hexstring) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hexstring.size());

    if((hexstring.size() % 2) == 0) {
        char hex_buffer[4];
        hex_buffer[0] = '0';
        hex_buffer[1] = 'x';

        for(int i=0; i<hexstring.size(); ++i) {
            if(i % 2 == 0) {
                hex_buffer[2] = hexstring.at(i);
            } else {
                hex_buffer[3] = hexstring.at(i);
                unsigned int hex_byte;
                sscanf((const char*)&hex_buffer, "%x", &hex_byte);
                bytes.emplace_back(hex_byte);
            }
        }
    }

    return bytes;
}

std::vector<uint8_t> ossl::encoding::apply_pkcs7_padding(std::vector<uint8_t> bytes, const uint8_t& multiple) {
    uint8_t difference = multiple - (bytes.size() % multiple);

    if(difference == multiple) {
        return bytes;
    }

    bytes.resize(bytes.size() + difference, difference);

    return bytes;
}

std::vector<uint8_t> ossl::encoding::strip_pkcs7_padding(std::vector<uint8_t> bytes) {
    const uint8_t& last_byte = bytes.at(bytes.size()-1);

    const auto& validator_lambda = [&last_byte](const uint8_t& value) {
                                       return value == last_byte;
                                   };

    if(last_byte <= bytes.size() && std::all_of(bytes.cend()-last_byte, bytes.cend(), validator_lambda)) {
        bytes.resize(bytes.size() - last_byte);
    }

    return bytes;
}

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++




/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
** Hashing Namespace Definitions
** ------------------
** TODO: Write DOCSTRING.
 */

std::vector<uint8_t>(*ossl::hashing::digest_sha1)(const std::vector<uint8_t>&) =
    ossl::hashing::digest<SHA_CTX, &SHA1_Init, &SHA1_Update, &SHA1_Final, SHA_DIGEST_LENGTH>;

std::vector<uint8_t>(*ossl::hashing::digest_sha224)(const std::vector<uint8_t>&) =
    ossl::hashing::digest<SHA256_CTX, &SHA224_Init, &SHA224_Update, &SHA224_Final, SHA224_DIGEST_LENGTH>;

std::vector<uint8_t>(*ossl::hashing::digest_sha256)(const std::vector<uint8_t>&) =
    ossl::hashing::digest<SHA256_CTX, &SHA256_Init, &SHA256_Update, &SHA256_Final, SHA256_DIGEST_LENGTH>;

std::vector<uint8_t>(*ossl::hashing::digest_sha384)(const std::vector<uint8_t>&) =
    ossl::hashing::digest<SHA512_CTX, &SHA384_Init, &SHA384_Update, &SHA384_Final, SHA384_DIGEST_LENGTH>;

std::vector<uint8_t>(*ossl::hashing::digest_sha512)(const std::vector<uint8_t>&) =
    ossl::hashing::digest<SHA512_CTX, &SHA512_Init, &SHA512_Update, &SHA512_Final, SHA512_DIGEST_LENGTH>;
// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++




/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
** RSA Namespace Definitions
** ------------------
** TODO: Write DOCSTRING.
 */

RSA* ossl::rsa::generate_keypair(KeySize key_size, uint64_t public_exponent) {
    return RSA_generate_key(static_cast<size_t>(key_size), public_exponent, nullptr, nullptr);
}

std::string ossl::rsa::get_public_key_pem(RSA* key) {
    std::unique_ptr<BIO, encoding::bio_free_all> pem_bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_RSAPublicKey(pem_bio.get(), key);

    const char* raw_pem_string;
    const size_t pem_string_length = BIO_get_mem_data(pem_bio.get(), &raw_pem_string);

    return std::string(raw_pem_string, pem_string_length-1);
}

std::string ossl::rsa::get_private_key_pem(RSA* key) {
    std::unique_ptr<BIO, encoding::bio_free_all> pem_bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_RSAPrivateKey(pem_bio.get(), key, 0, 0, 0, 0, 0);

    const char* raw_pem_string;
    const size_t pem_string_length = BIO_get_mem_data(pem_bio.get(), &raw_pem_string);

    return std::string(raw_pem_string, pem_string_length-1);
}

RSA* ossl::rsa::load_public_key_pem(std::string public_key_pem) {
    BIO* public_key_bio = BIO_new_mem_buf(public_key_pem.c_str(), public_key_pem.size());
    return PEM_read_bio_RSAPublicKey(public_key_bio, nullptr, nullptr, nullptr);
}

RSA* ossl::rsa::load_private_key_pem(std::string private_key_pem) {
    BIO* private_key_bio = BIO_new_mem_buf(private_key_pem.c_str(), private_key_pem.size());
    return PEM_read_bio_RSAPrivateKey(private_key_bio, nullptr, nullptr, nullptr);
}

std::pair<RSA*, RSA*> ossl::rsa::load_rsa_keypair_pem(std::string public_key_pem, std::string private_key_pem) {
    return std::make_pair(ossl::rsa::load_public_key_pem(public_key_pem), ossl::rsa::load_private_key_pem(private_key_pem));
}

std::pair<std::string, std::string> ossl::rsa::get_pem_pair(RSA* keypair) {
    return std::make_pair(ossl::rsa::get_public_key_pem(keypair), ossl::rsa::get_private_key_pem(keypair));
}

RSA* ossl::rsa::load_public_private_key_pem(std::string public_key_pem, std::string private_key_pem) {
    BIO* private_key_bio = BIO_new_mem_buf(private_key_pem.c_str(), private_key_pem.size());
    RSA* public_key = ossl::rsa::load_public_key_pem(public_key_pem);

    RSA* keypair = PEM_read_bio_RSAPrivateKey(private_key_bio, &public_key, nullptr, nullptr);

    return keypair;
}

std::vector<uint8_t> ossl::rsa::public_encrypt(std::vector<uint8_t> data, RSA* key, int padding) {
    std::vector<uint8_t> encrypted_data(RSA_size(key));

    size_t encrypted_size = RSA_public_encrypt(data.size(), data.data(), encrypted_data.data(), key, padding);
    encrypted_data.resize(encrypted_size);

    return encrypted_data;
}

std::vector<uint8_t> ossl::rsa::private_decrypt(std::vector<uint8_t> data, RSA* key, int padding) {
    std::vector<uint8_t> decrypted_data(RSA_size(key));

    size_t decrypted_size = RSA_private_decrypt(data.size(), data.data(), decrypted_data.data(), key, padding);
    decrypted_data.resize(decrypted_size);

    return decrypted_data;
}

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++/




/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
** Random Namespace Definitions
** ------------------
** TODO: Write DOCSTRING.
 */

int32_t ossl::random::number_from_range(const int32_t& from, const int32_t& to) {
    static std::random_device device;
    static std::mt19937 generator(device());

    std::uniform_int_distribution<int32_t> uniform_distributer(from, to);

    int32_t generated = uniform_distributer(generator);
    return generated;
}

std::vector<uint8_t> ossl::random::byte_vector(const size_t& size) {
    std::vector<uint8_t> random_bytes(size);

    for(size_t i=0; i<size; ++i) {
        random_bytes[i] = static_cast<uint8_t>(ossl::random::number_from_range(0, 255));
    }

    return random_bytes;
}

std::vector<uint8_t> ossl::random::from_byteset(const std::vector<uint8_t>& byte_set, const size_t& size) {
    std::vector<uint8_t> random_bytes(size);

    for(size_t i=0; i<size; ++i) {
        const uint32_t& random_index = ossl::random::number_from_range(0, byte_set.size()-1);
        random_bytes[i] = byte_set[random_index];
    }

    return random_bytes;
}

double ossl::random::get_ms_since_epoch() {
    using namespace std::chrono;

    const auto time_since_epoch = system_clock::now().time_since_epoch();
    milliseconds ms_since_epoch = duration_cast<milliseconds>(time_since_epoch);
    
    return static_cast<double>(ms_since_epoch.count());
}
// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

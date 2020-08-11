#include "crypto-utils.hxx"

void Ossl::BIOFreeAll::operator()(BIO* bio_ptr) {
    BIO_free_all(bio_ptr);
}

std::string Ossl::Base64::Encode(const std::vector<uint8_t>& binary) {
    std::unique_ptr<BIO, BIOFreeAll> base64(BIO_new(BIO_f_base64()));
    BIO_set_flags(base64.get(), BIO_FLAGS_BASE64_NO_NL);

    BIO* sink = BIO_new(BIO_s_mem());

    BIO_push(base64.get(), sink);
    BIO_write(base64.get(), binary.data(), binary.size());
    BIO_flush(base64.get());

    const char* encoded;
    const size_t length = BIO_get_mem_data(sink, &encoded);

    return std::string(encoded, length);
}

std::vector<uint8_t> Ossl::Base64::Decode(const std::string& b64_string) {
    std::unique_ptr<BIO, BIOFreeAll> base64(BIO_new(BIO_f_base64()));
    BIO_set_flags(base64.get(), BIO_FLAGS_BASE64_NO_NL);

    BIO* source = BIO_new_mem_buf(b64_string.c_str(), -1);
    BIO_push(base64.get(), source);

    const size_t maximum_length = b64_string.size() / 4 * 3 + 1;
    std::vector<uint8_t> decoded(maximum_length);

    const size_t length = BIO_read(base64.get(), decoded.data(), maximum_length);
    decoded.resize(length);

    return decoded;
}

// (loop for i from 1 to 15 collect (> (/ 2 i) 0)

std::vector<uint8_t> Ossl::Hashing::Sha256Digest(const std::vector<uint8_t>& bytes) {
    std::vector<uint8_t> sha256_digest(SHA256_DIGEST_LENGTH);

    SHA256_CTX ossl_sha256;
    SHA256_Init(&ossl_sha256);
    SHA256_Update(&ossl_sha256, bytes.data(), bytes.size());
    SHA256_Final(sha256_digest.data(), &ossl_sha256);

    return sha256_digest;
}

std::vector<uint8_t> Ossl::Util::ApplyPkcs7Padding(std::vector<uint8_t> bytes, const uint8_t& multiple) {
    uint8_t difference = multiple - (bytes.size() % multiple);

    if(difference == multiple) {
        return bytes;
    }

    bytes.resize(bytes.size() + difference, difference);

    return bytes;
}

std::vector<uint8_t> Ossl::Util::StripPkcs7Padding(std::vector<uint8_t> bytes) {
    const uint8_t& last_byte = bytes.at(bytes.size()-1);

    const auto& validator_lambda = [&last_byte](const uint8_t& value) {
                                       return value == last_byte;
                                   };

    if(last_byte <= bytes.size() && std::all_of(bytes.cend()-last_byte, bytes.cend(), validator_lambda)) {
        bytes.resize(bytes.size() - last_byte);
    }

    return bytes;
}

std::string Ossl::Util::Hexlify(const std::vector<uint8_t>& digest) {
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

RSA* Ossl::Rsa::GenerateKeypair(KeySize key_size, uint64_t public_exponent) {
    return RSA_generate_key(static_cast<size_t>(key_size), public_exponent, nullptr, nullptr);
}

std::string Ossl::Rsa::GetPublicKeyPem(RSA* key) {
    std::unique_ptr<BIO, BIOFreeAll> pem_bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_RSAPublicKey(pem_bio.get(), key);

    const char* raw_pem_string;
    const size_t pem_string_length = BIO_get_mem_data(pem_bio.get(), &raw_pem_string);

    return std::string(raw_pem_string, pem_string_length-1);
}

std::string Ossl::Rsa::GetPrivateKeyPem(RSA* key) {
    std::unique_ptr<BIO, BIOFreeAll> pem_bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_RSAPrivateKey(pem_bio.get(), key, 0, 0, 0, 0, 0);

    const char* raw_pem_string;
    const size_t pem_string_length = BIO_get_mem_data(pem_bio.get(), &raw_pem_string);

    return std::string(raw_pem_string, pem_string_length-1);
}

RSA* Ossl::Rsa::LoadPublicKeyPem(std::string public_key_pem) {
    BIO* public_key_bio = BIO_new_mem_buf(public_key_pem.c_str(), public_key_pem.size());
    return PEM_read_bio_RSAPublicKey(public_key_bio, nullptr, nullptr, nullptr);
}

RSA* Ossl::Rsa::LoadPrivateKeyPem(std::string private_key_pem) {
    BIO* private_key_bio = BIO_new_mem_buf(private_key_pem.c_str(), private_key_pem.size());
    return PEM_read_bio_RSAPrivateKey(private_key_bio, nullptr, nullptr, nullptr);
}

std::pair<RSA*, RSA*> Ossl::Rsa::LoadRSAKeypairPem(std::string public_key_pem, std::string private_key_pem) {
    return std::make_pair(Ossl::Rsa::LoadPublicKeyPem(public_key_pem), Ossl::Rsa::LoadPrivateKeyPem(private_key_pem));
}

std::pair<std::string, std::string> Ossl::Rsa::GetPemPair(RSA* keypair) {
    return std::make_pair(Ossl::Rsa::GetPublicKeyPem(keypair), Ossl::Rsa::GetPrivateKeyPem(keypair));
}

RSA* Ossl::Rsa::LoadPublicPrivateKeyPem(std::string public_key_pem, std::string private_key_pem) {
    BIO* private_key_bio = BIO_new_mem_buf(private_key_pem.c_str(), private_key_pem.size());
    RSA* public_key = Ossl::Rsa::LoadPublicKeyPem(public_key_pem);

    RSA* keypair = PEM_read_bio_RSAPrivateKey(private_key_bio, &public_key, nullptr, nullptr);

    return keypair;
}

std::vector<uint8_t> Ossl::Rsa::PublicEncrypt(std::vector<uint8_t> data, RSA* key, int padding) {
    std::vector<uint8_t> encrypted_data(RSA_size(key));

    size_t encrypted_size = RSA_public_encrypt(data.size(), data.data(), encrypted_data.data(), key, padding);
    encrypted_data.resize(encrypted_size);

    return encrypted_data;
}

std::vector<uint8_t> Ossl::Rsa::PrivateDecrypt(std::vector<uint8_t> data, RSA* key, int padding) {
    std::vector<uint8_t> decrypted_data(RSA_size(key));

    size_t decrypted_size = RSA_private_decrypt(data.size(), data.data(), decrypted_data.data(), key, padding);
    decrypted_data.resize(decrypted_size);

    return decrypted_data;
}

int32_t Ossl::Random::NumberFromRange(const int32_t& from, const int32_t& to) {
    static std::random_device device;
    static std::mt19937 generator(device());

    std::uniform_int_distribution<int32_t> uniform_distributer(from, to);

    int32_t generated = uniform_distributer(generator);
    return generated;
}

std::vector<uint8_t> Ossl::Random::ByteVector(const size_t& size) {
    std::vector<uint8_t> random_bytes(size);

    for(size_t i=0; i<size; ++i) {
        random_bytes[i] = static_cast<uint8_t>(Ossl::Random::NumberFromRange(0, 255));
    }

    return random_bytes;
}

std::vector<uint8_t> Ossl::Random::FromByteSet(const std::vector<uint8_t>& byte_set, const size_t& size) {
    std::vector<uint8_t> random_bytes(size);

    for(size_t i=0; i<size; ++i) {
        const uint32_t& random_index = Ossl::Random::NumberFromRange(0, byte_set.size()-1);
        random_bytes[i] = byte_set[random_index];
    }

    return random_bytes;
}

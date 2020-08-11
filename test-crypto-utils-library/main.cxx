#include <iostream>
#include <iomanip>

#include "crypto-utils.hxx"

void PrintHexdump(const uint8_t* bytes, size_t size) {
    for(int i = 0; i < size; ++i) {
        if(i != 0 && i % 8 == 0) std::cout << std::endl << "|";
        if(i == 0) std::cout << "|";

        std::cout
            << std::setw(2)
            << std::setfill('0')
            << std::uppercase
            << std::hex
            << static_cast<uint32_t>(bytes[i])
            << "|";
    }

    std::cout << std::dec << std::endl;
}

/*
Lisp expression that gives N amount of random bytes. 

(loop for i from 0 to 16 collect
 (intern (concat "0x" (format "%x" (random-from-range 0 254)))))
*/

bool Test_AesCbc() {
    std::vector<uint8_t> sample_bytes = {
        0x46, 0x91, 0x94, 0x26, 0x6C, 0xE1, 0xB5, 0xAA,
        0x19, 0x8E, 0x45, 0xC7, 0x17, 0x23, 0x9A, 0x7D,
        0xFA, 0x76, 0x85, 0x3A, 0xD7, 0xD9, 0xA7, 0x6D,
        0x6B, 0x5D, 0x56, 0x6C, 0x98, 0xED, 0x77, 0xFF
    };

    std::array<uint8_t, AES_BLOCK_SIZE> sample_iv {
        0xE8, 0xE1, 0xA8, 0xE8, 0x99, 0xAE, 0xE8, 0x4A,
        0xDF, 0x1C, 0xCB, 0x9C, 0x9A, 0x06, 0x04, 0x60
    };

    std::array<uint8_t, Ossl::Aes::KS_128_BIT> sample_128b_key {
        0xD9, 0x42, 0x23, 0x25, 0xAC, 0xEB, 0x00, 0x79,
        0xE5, 0xFE, 0xF7, 0xF7, 0x90, 0x99, 0x12, 0x0D
    };

    std::array<uint8_t, Ossl::Aes::KS_192_BIT> sample_192b_key {
        0xAE, 0xA5, 0xDC, 0x90, 0xEE, 0x24, 0x5A, 0x02,
        0x16, 0x51, 0x76, 0xBA, 0xC0, 0x80, 0xFF, 0xE0,
        0xE0, 0x79, 0x7E, 0x6C, 0x1A, 0xE3, 0x87, 0x92
    };

    std::array<uint8_t, Ossl::Aes::KS_256_BIT> sample_256b_key {
        0xA6, 0x87, 0xD9, 0x52, 0x27, 0x14, 0xBD, 0xD8,
        0xD0, 0x88, 0x32, 0xA0, 0xB8, 0x47, 0xEA, 0x2D,
        0xE1, 0x24, 0x7D, 0x3D, 0xBB, 0x52, 0x9D, 0xE5,
        0x5C, 0xC9, 0x6A, 0x90, 0x3D, 0x47, 0x22, 0x17
    };

    std::cout << "AES-CBC Sample Data SHA-256: " << Ossl::Util::Hexlify(Ossl::Hashing::Sha256Digest(sample_bytes))  << std::endl;
    std::cout << "AES-CBC Sample IV SHA-256:   " << Ossl::Util::Hexlify(Ossl::Hashing::Sha256Digest(std::vector<uint8_t>(sample_iv.begin(), sample_iv.end()))) << std::endl << std::endl;

    // AES-CBC Encryption, various key lengths.
    const std::vector<uint8_t>& encrypt_output_128 =
        Ossl::Aes::CbcEncrypt<Ossl::Aes::KS_128_BIT>(sample_bytes, sample_128b_key, sample_iv);

    const std::vector<uint8_t>& encrypt_output_192 =
        Ossl::Aes::CbcEncrypt<Ossl::Aes::KS_192_BIT>(sample_bytes, sample_192b_key, sample_iv);

    const std::vector<uint8_t>& encrypt_output_256 =
        Ossl::Aes::CbcEncrypt<Ossl::Aes::KS_256_BIT>(sample_bytes, sample_256b_key, sample_iv);

    std::cout << "AES-CBC-128 Encrypt SHA-256: " << Ossl::Util::Hexlify(Ossl::Hashing::Sha256Digest(encrypt_output_128)) << std::endl;
    std::cout << "AES-CBC-192 Encrypt SHA-256: " << Ossl::Util::Hexlify(Ossl::Hashing::Sha256Digest(encrypt_output_192)) << std::endl;
    std::cout << "AES-CBC-256 Encrypt SHA-256: " << Ossl::Util::Hexlify(Ossl::Hashing::Sha256Digest(encrypt_output_256)) << std::endl;

    // AES-CBC Decryption, various key lengths.
    const std::vector<uint8_t>& decrypt_output_128 =
        Ossl::Aes::CbcDecrypt<Ossl::Aes::KS_128_BIT>(encrypt_output_128, sample_128b_key, sample_iv);

    const std::vector<uint8_t>& decrypt_output_192 =
        Ossl::Aes::CbcDecrypt<Ossl::Aes::KS_192_BIT>(encrypt_output_192, sample_192b_key, sample_iv);

    const std::vector<uint8_t>& decrypt_output_256 =
        Ossl::Aes::CbcDecrypt<Ossl::Aes::KS_256_BIT>(encrypt_output_256, sample_256b_key, sample_iv);

    std::cout << std::endl;

    std::cout << "AES-CBC-128 Decrypt SHA-256: " << Ossl::Util::Hexlify(Ossl::Hashing::Sha256Digest(decrypt_output_128)) << std::endl;
    std::cout << "AES-CBC-192 Decrypt SHA-256: " << Ossl::Util::Hexlify(Ossl::Hashing::Sha256Digest(decrypt_output_192)) << std::endl;
    std::cout << "AES-CBC-256 Decrypt SHA-256: " << Ossl::Util::Hexlify(Ossl::Hashing::Sha256Digest(decrypt_output_256)) << std::endl;

    std::cout << std::endl;

    return true;
}

bool Test_Rsa() {
    std::vector<uint8_t> sample_bytes = {
        0x46, 0x91, 0x94, 0x26, 0x6C, 0xE1, 0xB5, 0xAA,
        0x19, 0x8E, 0x45, 0xC7, 0x17, 0x23, 0x9A, 0x7D,
        0xFA, 0x76, 0x85, 0x3A, 0xD7, 0xD9, 0xA7, 0x6D,
        0x6B, 0x5D, 0x56, 0x6C, 0x98, 0xED, 0x77, 0xFF
    };

    std::cout << sample_bytes.size() << std::endl;

    std::cout << "Reference hash: " << Ossl::Util::Hexlify(Ossl::Hashing::Sha256Digest(sample_bytes)) << std::endl;

    std::cout << sample_bytes.size() << std::endl;

    RSA* rsa_keypair = Ossl::Rsa::GenerateKeypair(Ossl::Rsa::KS_4096_B);
    std::vector<uint8_t> encrypted = Ossl::Rsa::PublicEncrypt(sample_bytes, rsa_keypair);
    std::vector<uint8_t> encrypted2 = Ossl::Rsa::PublicEncrypt(sample_bytes, rsa_keypair);
    std::cout << "Equal: " << (encrypted == encrypted2) << std::endl;

    std::cout << sample_bytes.size() << std::endl;

    std::cout << "Encrypted hash: " << Ossl::Util::Hexlify(Ossl::Hashing::Sha256Digest(encrypted)) << std::endl;

    

    std::cout << sample_bytes.size() << std::endl;

    PrintHexdump(encrypted.data(), encrypted.size());
    std::cout << std::endl;

    std::cout << sample_bytes.size() << std::endl;

    std::vector<uint8_t> decrypted = Ossl::Rsa::PrivateDecrypt(encrypted, rsa_keypair);
    std::cout << sample_bytes.size() << std::endl;


    std::cout << "Decrypted hash: " << Ossl::Util::Hexlify(Ossl::Hashing::Sha256Digest(decrypted)) << std::endl;

    std::cout << sample_bytes.size() << std::endl;

    std::string public_key_pem = Ossl::Rsa::GetPublicKeyPem(rsa_keypair);
    std::cout << public_key_pem << std::endl;
    std::cout << sample_bytes.size() << std::endl;


    std::string private_key_pem = Ossl::Rsa::GetPrivateKeyPem(rsa_keypair);
    std::cout << private_key_pem << std::endl;
        std::cout << sample_bytes.size() << std::endl;


    RSA* public_key = Ossl::Rsa::LoadPublicKeyPem(public_key_pem);
    RSA* private_key = Ossl::Rsa::LoadPrivateKeyPem(private_key_pem);

    std::cout << sample_bytes.size() << std::endl;

    std::cout << encrypted.size() << std::endl;
    std::cout << (Ossl::Rsa::PrivateDecrypt(encrypted, private_key).size()) << std::endl;

    return true;
}

bool Test_Rsa_File() {
    return true;
}

int main(int argc, char* argv[]) {
    // Test_AesCbc();
    Test_Rsa();



    return 0;
}

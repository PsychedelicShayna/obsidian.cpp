#ifndef OBSIDIAN_ENCODING_HPP
#define OBSIDIAN_ENCODING_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <sstream>
#include <iomanip>
#include <algorithm>

#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

namespace obsidian::encoding {

std::string          b64_encode(const std::vector<uint8_t>& bytes);
std::vector<uint8_t> b64_decode(const std::string& b64_string);

std::string          b16_encode(const std::vector<uint8_t>& bytes);
std::vector<uint8_t> b16_decode(const std::string& hexstr);

std::vector<uint8_t> apply_pkcs7_padding(std::vector<uint8_t> bytes,
                                         const uint8_t&       multiple);

std::vector<uint8_t> strip_pkcs7_padding(std::vector<uint8_t> bytes);

} // namespace obsidian::encoding

#endif

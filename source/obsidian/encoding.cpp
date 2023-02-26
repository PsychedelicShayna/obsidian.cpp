#include "../include/obsidian/encoding.hpp"

namespace obsidian::encoding {

std::string b64_encode(const std::vector<uint8_t>& input)
{

    std::unique_ptr<BIO, decltype(&BIO_free)> base64(BIO_new(BIO_f_base64()),
                                                     &BIO_free);

    BIO_set_flags(base64.get(), BIO_FLAGS_BASE64_NO_NL);

    std::unique_ptr<BIO, decltype(&BIO_free)> sink(BIO_new(BIO_s_mem()),
                                                   &BIO_free);

    BIO_push(base64.get(), sink.get());
    BIO_write(base64.get(), input.data(), static_cast<int32_t>(input.size()));
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

    const size_t& actual_length = BIO_read(
        b64_bio.get(), output.data(), static_cast<int32_t>(maximum_length));

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

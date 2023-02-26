#include "../include/obsidian/random.hpp"

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

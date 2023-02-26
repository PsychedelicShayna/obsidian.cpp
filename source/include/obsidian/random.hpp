#ifndef OBSIDIAN_RANDOM_HPP
#define OBSIDIAN_RANDOM_HPP

#include <cstdint>
#include <random>
#include <vector>
#include <chrono>

namespace obsidian::random {

template<typename T>
T mt19937_urd_from(const T& min, const T& max)
{
    static std::random_device device;
    static std::mt19937       generator(device());

    std::uniform_real_distribution<T> uniform_distributer(min, max);

    T generated = uniform_distributer(generator);
    return generated;
}

extern float (*rf32_from)(const float& from, const float& to);
extern double (*rf64_from)(const double& from, const double& to);

extern float (*rf32)();
extern double (*rf64)();

template<typename T>
T mt19937_uid_from(const T& min, const T& max)
{
    static std::random_device device;
    static std::mt19937       generator(device());

    std::uniform_int_distribution<T> uniform_distributer(min, max);

    T generated = uniform_distributer(generator);
    return generated;
}

extern uint8_t (*rui8_from)(const uint8_t& from, const uint8_t& to);
extern uint16_t (*rui16_from)(const uint16_t& from, const uint16_t& to);
extern uint32_t (*rui32_from)(const uint32_t& from, const uint32_t& to);
extern uint64_t (*rui64_from)(const uint64_t& from, const uint64_t& to);

extern int8_t (*ri8_from)(const int8_t& from, const int8_t& to);
extern int16_t (*ri16_from)(const int16_t& from, const int16_t& to);
extern int32_t (*ri32_from)(const int32_t& from, const int32_t& to);
extern int64_t (*ri64_from)(const int64_t& from, const int64_t& to);

extern uint8_t (*rui8)();
extern uint16_t (*rui16)();
extern uint32_t (*rui32)();
extern uint64_t (*rui64)();

extern int8_t (*ri8)();
extern int16_t (*ri16)();
extern int32_t (*ri32)();
extern int64_t (*ri64)();

void write_n(uint8_t* data, const size_t& size);

std::vector<uint8_t> bytes(const size_t& size);

template<typename T>
std::vector<T> pick_from(const std::vector<T>& set, const size_t& amount)
{
    std::vector<T> random_selections(amount);

    for(size_t i = 0; i < amount; ++i) {
        const uint64_t& index = rui64_from(0, set.size() - 1);
        random_selections[i]  = set[index];
    }

    return random_selections;
}

double get_ms_since_epoch();

} // namespace obsidian::random

#endif

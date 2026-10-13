#pragma once

#include <duckdb/common/types.hpp>

namespace duckdb {

inline constexpr char INET_TYPE_NAME[] = "INET";
inline constexpr char CIDR_TYPE_NAME[] = "CIDR";

inline constexpr idx_t INET_SORT_KEY_V4_SIZE = sizeof(uint8_t) + 2 * sizeof(uint32_t) + sizeof(uint16_t);
inline constexpr idx_t INET_SORT_KEY_V6_SIZE = sizeof(uint8_t) + 2 * sizeof(uhugeint_t) + sizeof(uint16_t);

LogicalType make_inet_type();
LogicalType make_cidr_type();

} // namespace duckdb

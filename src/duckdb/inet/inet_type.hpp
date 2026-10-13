#pragma once

#include <duckdb/common/types.hpp>

namespace duckdb {

inline constexpr char INET_TYPE_NAME[] = "INET";
inline constexpr char CIDR_TYPE_NAME[] = "CIDR";

LogicalType make_inet_type();
LogicalType make_cidr_type();

} // namespace duckdb

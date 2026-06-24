#pragma once

#include <duckdb/common/types.hpp>

namespace duckdb {

inline constexpr char INET_TYPE_NAME[] = "INET";

LogicalType make_inet_type();

} // namespace duckdb

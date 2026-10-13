#pragma once

#include "duckdb.h"

#include <stdint.h>

// Constants
static constexpr uint16_t IPV4_DEFAULT_MASK = 32;
static constexpr uint16_t IPV6_DEFAULT_MASK = 128;
static constexpr uint16_t IPV6_HALF_MASK = IPV6_DEFAULT_MASK / 2;

// Enum for IP address type
typedef enum { INET_IP_ADDRESS_INVALID = 0, INET_IP_ADDRESS_V4 = 1, INET_IP_ADDRESS_V6 = 2 } INET_IPAddressType;

// IPAddress struct
typedef struct {
	INET_IPAddressType type;
	duckdb_uhugeint address;
	uint16_t mask;
} INET_IPAddress;

// Try to parse an IP address from a string.
// If error_message is not NULL, it will be set to an error message on failure.
// The error_message does not need to be freed, it is a static string.
INET_IPAddress ipaddress_from_string(const char *buffer, size_t buffer_size);

// Returns length of string written to buffer. Returns 0 if buffer is too small.
size_t ipaddress_to_string(const INET_IPAddress *ip, char *buffer, size_t buffer_size);
size_t cidr_to_string(const INET_IPAddress *ip, char *buffer, size_t buffer_size);
bool ipaddress_has_host_bits(const INET_IPAddress *ip);

inline duckdb_uhugeint ipaddress_host_mask(const INET_IPAddress *ip) {
	const uint64_t all = ~uint64_t(0);
	duckdb_uhugeint host;
	if (ip->type == INET_IP_ADDRESS_V4) {
		host.upper = 0;
		host.lower = ip->mask >= IPV4_DEFAULT_MASK ? 0 : UINT32_MAX >> ip->mask;
		return host;
	}
	host.upper = ip->mask >= IPV6_HALF_MASK ? 0 : all >> ip->mask;
	host.lower = ip->mask >= IPV6_DEFAULT_MASK ? 0
	             : ip->mask <= IPV6_HALF_MASK  ? all
	                                           : all >> (ip->mask - IPV6_HALF_MASK);
	return host;
}

INET_IPAddress ipaddress_netmask(const INET_IPAddress *ip);
INET_IPAddress ipaddress_network(const INET_IPAddress *ip);
INET_IPAddress ipaddress_broadcast(const INET_IPAddress *ip);

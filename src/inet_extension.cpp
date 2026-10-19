#include "duckdb/inet/inet_extension.hpp"

#include "duckdb/inet/inet_ipaddress.hpp"
#include "duckdb/inet/inet_html.hpp"
#include "duckdb/inet/inet_type.hpp"

#include "duckdb/catalog/catalog.hpp"
#include "duckdb/common/bswap.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/operator/cast_operators.hpp"
#include "duckdb/common/types/hugeint.hpp"
#include "duckdb/common/types/uhugeint.hpp"
#include "duckdb/common/vector_operations/generic_executor.hpp"
#include "duckdb/common/vector_operations/unary_executor.hpp"
#include "duckdb/common/vector_operations/binary_executor.hpp"
#include "duckdb/function/cast/default_casts.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/main/database_manager.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/planner/collation_binding.hpp"

#include <memory>
#include <string.h>

namespace duckdb {

//----------------------------------------------------------------------------------------------------------------------
// INET TYPE DEFINITION
//----------------------------------------------------------------------------------------------------------------------
using INET_T = StructTypeTernary<uint8_t, hugeint_t, uint16_t>;

static constexpr idx_t INET_IP_TYPE_IDX = 0;
static constexpr idx_t INET_ADDRESS_IDX = 1;
static constexpr idx_t INET_MASK_IDX = 2;

static LogicalType make_inet_struct_type() {
	child_list_t<LogicalType> children;
	children.push_back(make_pair("ip_type", LogicalType::UTINYINT));
	children.push_back(make_pair("address", LogicalType::HUGEINT));
	children.push_back(make_pair("mask", LogicalType::USMALLINT));
	return LogicalType::STRUCT(std::move(children));
}

LogicalType make_inet_type() {
	return make_inet_struct_type().WithAlias(INET_TYPE_NAME);
}

LogicalType make_cidr_type() {
	return make_inet_struct_type().WithAlias(CIDR_TYPE_NAME);
}

//----------------------------------------------------------------------------------------------------------------------
// CAST FUNCTIONS
//----------------------------------------------------------------------------------------------------------------------
static duckdb_uhugeint from_compatible_address(hugeint_t compat_addr, INET_IPAddressType addr_type) {
	duckdb_uhugeint retval;
	memcpy(&retval, &compat_addr, sizeof(duckdb_uhugeint));
	// Only flip the bit for order on IPv6 addresses. It can never be set in IPv4
	if (addr_type == INET_IP_ADDRESS_V6) {
		// The top bit is flipped when storing as the signed hugeint so that sorting
		// works correctly. Flip it back here to have a proper unsigned value.
		retval.upper ^= (((uint64_t)(1)) << 63);
	}
	return retval;
}

static hugeint_t to_compatible_address(duckdb_uhugeint new_addr, INET_IPAddressType addr_type) {
	if (addr_type == INET_IP_ADDRESS_V6) {
		// Flip the top bit when storing as a signed hugeint_t so that sorting
		// works correctly.
		new_addr.upper ^= (((uint64_t)(1)) << 63);
	}
	// Don't need to flip the bit for IPv4, and the original IPv4 only
	// implementation didn't do the flipping, so maintain compatibility.
	hugeint_t retval;
	memcpy(&retval, &new_addr, sizeof(hugeint_t));
	return retval;
}

//----------------------------------------------------------------------------------------------------------------------
// HTML ESCAPE
//----------------------------------------------------------------------------------------------------------------------
struct HTMLEscapeBuffer {
	std::unique_ptr<char[]> buffer;
	idx_t size = 0;

	char *GetData() {
		return buffer.get();
	}
	void Allocate(idx_t new_size) {
		if (new_size <= size) {
			// already have enough space
			return;
		}
		buffer = std::unique_ptr<char[]>(new char[new_size]);
		size = new_size;
	}
};

static string_t escape_html(string_t input, bool input_quote, HTMLEscapeBuffer &buffer) {
	auto input_data = input.GetData();
	auto input_size = input.GetSize();

	const idx_t QUOTE_SZ = 1;
	const idx_t AMPERSAND_SZ = 5;
	const idx_t ANGLE_BRACKET_SZ = 4;
	const idx_t TRANSLATED_QUOTE_SZ = 6; // e.g. \" is translated to &quot;, \' is translated to &#x27;

	size_t result_size = 0;
	for (idx_t j = 0; j < input_size; j++) {
		switch (input_data[j]) {
		case '&':
			result_size += AMPERSAND_SZ;
			break;
		case '<':
		case '>':
			result_size += ANGLE_BRACKET_SZ;
			break;
		case '\"':
		case '\'':
			result_size += input_quote ? TRANSLATED_QUOTE_SZ : QUOTE_SZ;
			break;
		default:
			result_size++;
		}
	}

	buffer.Allocate(result_size);
	auto result_data = buffer.GetData();

	size_t pos = 0;
	for (idx_t j = 0; j < input_size; j++) {
		switch (input_data[j]) {
		case '&':
			memcpy(result_data + pos, "&amp;", AMPERSAND_SZ);
			pos += AMPERSAND_SZ;
			break;
		case '<':
			memcpy(result_data + pos, "&lt;", ANGLE_BRACKET_SZ);
			pos += ANGLE_BRACKET_SZ;
			break;
		case '>':
			memcpy(result_data + pos, "&gt;", ANGLE_BRACKET_SZ);
			pos += ANGLE_BRACKET_SZ;
			break;
		case '"':
			if (input_quote) {
				memcpy(result_data + pos, "&quot;", TRANSLATED_QUOTE_SZ);
				pos += TRANSLATED_QUOTE_SZ;
			} else {
				result_data[pos++] = input_data[j];
			}
			break;
		case '\'':
			if (input_quote) {
				memcpy(result_data + pos, "&#x27;", TRANSLATED_QUOTE_SZ);
				pos += TRANSLATED_QUOTE_SZ;
			} else {
				result_data[pos++] = input_data[j];
			}
			break;
		default:
			result_data[pos++] = input_data[j];
		}
	}

	return string_t(result_data, result_size);
}

template <bool WITH_MASK>
static bool InetToVarcharCast(Vector &source, Vector &result, idx_t count, CastParameters &parameters) {
	StructTypeState<3> state;
	state.PrepareVector(source);
	auto result_data = FlatVector::GetDataMutable<string_t>(result);
	for (idx_t i = 0; i < count; i++) {
		auto idx = state.main_data.sel->get_index(i);
		if (!state.main_data.validity.RowIsValid(idx)) {
			FlatVector::SetNull(result, i, true);
			continue;
		}
		INET_T input;
		if (!INET_T::ConstructType(state, i, input)) {
			FlatVector::SetNull(result, i, true);
			continue;
		}
		INET_IPAddress inet;
		inet.type = (INET_IPAddressType)input.a_val;
		inet.address = from_compatible_address(input.b_val, inet.type);
		inet.mask = input.c_val;

		char buffer[256];
		size_t written = WITH_MASK ? cidr_to_string(&inet, buffer, sizeof(buffer))
		                           : ipaddress_to_string(&inet, buffer, sizeof(buffer));
		result_data[i] = StringVector::AddString(result, buffer, written);
	}
	return true;
}

static BoundCastInfo BindInetToVarchar(BindCastInput &input, const LogicalType &source, const LogicalType &target) {
	if (input.context) {
		auto &context = *input.context;
		auto db = DatabaseManager::Get(context).GetDatabase(DatabaseManager::TryGetDefaultDatabase(context));
		if (db && db->GetCatalog().Compatibility() == SqlCompatibility::POSTGRES) {
			return BoundCastInfo(InetToVarcharCast<true>);
		}
	}
	return BoundCastInfo(InetToVarcharCast<false>);
}

template <bool CIDR>
static bool VarcharToInetCast(Vector &source, Vector &result, idx_t count, CastParameters &parameters) {
	UnifiedVectorFormat sdata;
	source.ToUnifiedFormat(sdata);
	auto strs = UnifiedVectorFormat::GetData<string_t>(sdata);
	auto &entries = StructVector::GetEntries(result);
	auto a = FlatVector::GetDataMutable<uint8_t>(entries[0]);
	auto b = FlatVector::GetDataMutable<hugeint_t>(entries[1]);
	auto c = FlatVector::GetDataMutable<uint16_t>(entries[2]);
	bool success = true;
	for (idx_t i = 0; i < count; i++) {
		auto idx = sdata.sel->get_index(i);
		if (!sdata.validity.RowIsValid(idx)) {
			FlatVector::SetNull(result, i, true);
			continue;
		}
		const auto &input = strs[idx];
		INET_IPAddress inet;
		try {
			inet = ipaddress_from_string(input.GetData(), input.GetSize());
		} catch (const std::exception &) {
			HandleCastError::AssignError(StringUtil::Format("invalid input syntax for type %s: \"%s\"",
			                                                CIDR ? "cidr" : "inet", input.GetString()),
			                             parameters);
			FlatVector::SetNull(result, i, true);
			success = false;
			continue;
		}
		if (CIDR && ipaddress_has_host_bits(&inet)) {
			HandleCastError::AssignError(StringUtil::Format("invalid cidr value: \"%s\"", input.GetString()),
			                             parameters);
			FlatVector::SetNull(result, i, true);
			success = false;
			continue;
		}
		a[i] = (uint8_t)inet.type;
		b[i] = to_compatible_address(inet.address, inet.type);
		c[i] = inet.mask;
	}
	return success;
}

struct StructToInetCastData : public BoundCastData {
	explicit StructToInetCastData(BoundCastInfo struct_cast_p)
	    : fields_type(make_inet_struct_type()), struct_cast(std::move(struct_cast_p)) {
	}

	LogicalType fields_type;
	BoundCastInfo struct_cast;

	unique_ptr<BoundCastData> Copy() const override {
		return make_uniq<StructToInetCastData>(struct_cast.Copy());
	}
};

static unique_ptr<FunctionLocalState> InitStructToInetLocalState(CastLocalStateParameters &parameters) {
	auto &cast_data = parameters.cast_data->Cast<StructToInetCastData>();
	if (!cast_data.struct_cast.HasInitLocalState()) {
		return nullptr;
	}
	CastLocalStateParameters struct_parameters(parameters, cast_data.struct_cast.GetCastData());
	return cast_data.struct_cast.InitLocalState(struct_parameters);
}

static const char *InvalidInetReason(uint8_t ip_type, hugeint_t address, uint16_t mask) {
	switch (ip_type) {
	case INET_IP_ADDRESS_V4:
		if (address.upper != 0 || address.lower > NumericLimits<uint32_t>::Maximum()) {
			return "the IPv4 address is out of range";
		}
		return mask > IPV4_DEFAULT_MASK ? "the IPv4 mask exceeds 32" : nullptr;
	case INET_IP_ADDRESS_V6:
		return mask > IPV6_DEFAULT_MASK ? "the IPv6 mask exceeds 128" : nullptr;
	default:
		return "ip_type must be 1 (IPv4) or 2 (IPv6)";
	}
}

static bool HasHostBits(uint8_t ip_type, hugeint_t address, uint16_t mask) {
	INET_IPAddress inet;
	inet.type = static_cast<INET_IPAddressType>(ip_type);
	inet.address = from_compatible_address(address, inet.type);
	inet.mask = mask;
	return ipaddress_has_host_bits(&inet);
}

template <bool CIDR>
static bool StructToInetCast(Vector &source, Vector &result, idx_t count, CastParameters &parameters) {
	auto &cast_data = parameters.cast_data->Cast<StructToInetCastData>();
	CastParameters struct_parameters(parameters, cast_data.struct_cast.GetCastData(), parameters.local_state);
	Vector fields(cast_data.fields_type, count);
	bool success = cast_data.struct_cast.Cast(source, fields, count, struct_parameters);
	auto &entries = StructVector::GetEntries(result);
	auto ip_types = FlatVector::GetDataMutable<uint8_t>(entries[INET_IP_TYPE_IDX]);
	auto addresses = FlatVector::GetDataMutable<hugeint_t>(entries[INET_ADDRESS_IDX]);
	auto masks = FlatVector::GetDataMutable<uint16_t>(entries[INET_MASK_IDX]);
	auto values = fields.Values<VectorStructType<uint8_t, hugeint_t, uint16_t>>();
	for (idx_t i = 0; i < count; i++) {
		const auto entry = values[i];
		if (!entry.IsValid()) {
			FlatVector::SetNull(result, i, true);
			continue;
		}
		const auto ip_type = entry.template GetChildValue<INET_IP_TYPE_IDX>();
		const auto address = entry.template GetChildValue<INET_ADDRESS_IDX>();
		const auto mask = entry.template GetChildValue<INET_MASK_IDX>();
		if (!ip_type.IsValid() || !address.IsValid() || !mask.IsValid()) {
			FlatVector::SetNull(result, i, true);
			continue;
		}
		auto reason = InvalidInetReason(ip_type.GetValueUnsafe(), address.GetValueUnsafe(), mask.GetValueUnsafe());
		if (!reason && CIDR && HasHostBits(ip_type.GetValueUnsafe(), address.GetValueUnsafe(), mask.GetValueUnsafe())) {
			reason = "bits are set to the right of the mask";
		}
		if (reason) {
			HandleCastError::AssignError(StringUtil::Format("Invalid %s value: %s", CIDR ? "CIDR" : "INET", reason),
			                             parameters);
			FlatVector::SetNull(result, i, true);
			success = false;
			continue;
		}
		ip_types[i] = ip_type.GetValueUnsafe();
		addresses[i] = address.GetValueUnsafe();
		masks[i] = mask.GetValueUnsafe();
	}
	return success;
}

template <bool CIDR>
static BoundCastInfo BindStructToInetCast(BindCastInput &input, const LogicalType &source, const LogicalType &target) {
	auto struct_cast = input.GetCastFunction(source, make_inet_struct_type());
	return BoundCastInfo(StructToInetCast<CIDR>, make_uniq<StructToInetCastData>(std::move(struct_cast)),
	                     InitStructToInetLocalState);
}

static void HostFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	StructTypeState<3> st;
	st.PrepareVector(args.data[0]);
	auto result_data = FlatVector::GetDataMutable<string_t>(result);
	char buffer[256];
	for (idx_t i = 0; i < args.size(); i++) {
		auto idx = st.main_data.sel->get_index(i);
		if (!st.main_data.validity.RowIsValid(idx)) {
			FlatVector::SetNull(result, i, true);
			continue;
		}
		INET_T input;
		if (!INET_T::ConstructType(st, i, input)) {
			FlatVector::SetNull(result, i, true);
			continue;
		}
		INET_IPAddress inet;
		inet.type = (INET_IPAddressType)input.a_val;
		inet.address = from_compatible_address(input.b_val, inet.type);
		inet.mask = inet.type == INET_IP_ADDRESS_V4 ? 32 : 128;

		size_t len = ipaddress_to_string(&inet, buffer, sizeof(buffer));
		if (len == 0) {
			throw std::runtime_error("Could not write inet string");
		}
		if (len >= sizeof(buffer)) {
			throw std::runtime_error("Could not write string");
		}
		result_data[i] = StringVector::AddString(result, buffer, len);
	}
}

static void FamilyFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	GenericExecutor::ExecuteUnary<INET_T, PrimitiveType<uint8_t>>(
	    args.data[0], result, args.size(), [](INET_T input) -> PrimitiveType<uint8_t> {
		    switch ((INET_IPAddressType)input.a_val) {
		    case INET_IP_ADDRESS_V4:
			    return 4;
		    case INET_IP_ADDRESS_V6:
			    return 6;
		    default:
			    throw std::runtime_error("Invalid IP address type");
		    }
	    });
}

static void NetmaskFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	GenericExecutor::ExecuteUnary<INET_T, INET_T>(args.data[0], result, args.size(), [](INET_T input) -> INET_T {
		INET_IPAddress old_inet = {};
		old_inet.type = (INET_IPAddressType)input.a_val;
		old_inet.address = from_compatible_address(input.b_val, old_inet.type);
		old_inet.mask = input.c_val;

		// Apply the function
		INET_IPAddress new_inet = ipaddress_netmask(&old_inet);

		INET_T result;
		result.a_val = (uint8_t)new_inet.type;
		result.b_val = to_compatible_address(new_inet.address, new_inet.type);
		result.c_val = new_inet.type == INET_IP_ADDRESS_V4 ? IPV4_DEFAULT_MASK : IPV6_DEFAULT_MASK;
		return result;
	});
}

static INET_T NetworkOf(INET_T input) {
	INET_IPAddress old_inet = {};
	old_inet.type = (INET_IPAddressType)input.a_val;
	old_inet.address = from_compatible_address(input.b_val, old_inet.type);
	old_inet.mask = input.c_val;

	INET_IPAddress new_inet = ipaddress_network(&old_inet);

	INET_T result;
	result.a_val = (uint8_t)new_inet.type;
	result.b_val = to_compatible_address(new_inet.address, new_inet.type);
	result.c_val = new_inet.mask;
	return result;
}

static void NetworkFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	GenericExecutor::ExecuteUnary<INET_T, INET_T>(args.data[0], result, args.size(), NetworkOf);
}

static bool InetToCidrCast(Vector &source, Vector &result, idx_t count, CastParameters &parameters) {
	GenericExecutor::ExecuteUnary<INET_T, INET_T>(source, result, count, NetworkOf);
	return true;
}

static void BroadcastFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	GenericExecutor::ExecuteUnary<INET_T, INET_T>(args.data[0], result, args.size(), [](INET_T input) -> INET_T {
		INET_IPAddress old_inet = {};
		old_inet.type = (INET_IPAddressType)input.a_val;
		old_inet.address = from_compatible_address(input.b_val, old_inet.type);
		old_inet.mask = input.c_val;

		// Apply the function
		INET_IPAddress new_inet = ipaddress_broadcast(&old_inet);

		INET_T result;
		result.a_val = (uint8_t)new_inet.type;
		result.b_val = to_compatible_address(new_inet.address, new_inet.type);
		result.c_val = new_inet.mask;
		return result;
	});
}

static INET_T AddImplementation(const INET_T &lhs, const hugeint_t &rhs) {
	if (rhs == 0) {
		return lhs;
	}

	INET_T result;
	auto addr_type = (INET_IPAddressType)lhs.a_val;
	duckdb_uhugeint compat_in = from_compatible_address(lhs.b_val, addr_type);
	uhugeint_t address_in;
	address_in.lower = compat_in.lower;
	address_in.upper = compat_in.upper;
	uhugeint_t address_out;

	if (rhs > 0) {
		address_out = Uhugeint::Add(address_in, uhugeint_t((uint64_t)rhs.upper, (uint64_t)rhs.lower));
	} else {
		hugeint_t mag = Hugeint::Abs(rhs);
		address_out = Uhugeint::Subtract(address_in, uhugeint_t((uint64_t)mag.upper, (uint64_t)mag.lower));
	}
	if (lhs.a_val == INET_IP_ADDRESS_V4) {
		// Check if overflow ipv4
		if (address_out.lower > 0xffffffff) {
			throw OutOfRangeException("Cannot add to IPv4 Address: result out of range");
		}
	}

	duckdb_uhugeint compat_out;
	compat_out.lower = address_out.lower;
	compat_out.upper = address_out.upper;
	result.a_val = lhs.a_val;
	result.b_val = to_compatible_address(compat_out, addr_type);
	result.c_val = lhs.c_val;
	return result;
}

static void AddFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	GenericExecutor::ExecuteBinary<INET_T, PrimitiveType<hugeint_t>, INET_T>(
	    args.data[0], args.data[1], result, args.size(),
	    [](INET_T lhs, PrimitiveType<hugeint_t> rhs) -> INET_T { return AddImplementation(lhs, rhs.val); });
}

static void SubtractFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	GenericExecutor::ExecuteBinary<INET_T, PrimitiveType<hugeint_t>, INET_T>(
	    args.data[0], args.data[1], result, args.size(), [](INET_T lhs, PrimitiveType<hugeint_t> rhs) -> INET_T {
		    return AddImplementation(lhs, Hugeint::Negate(rhs.val));
	    });
}

static bool ContainsImplementation(const INET_T &lhs, const INET_T &rhs) {
	if (lhs.a_val != rhs.a_val) {
		return false;
	}
	INET_IPAddress lhs_inet;
	lhs_inet.type = (INET_IPAddressType)lhs.a_val;
	lhs_inet.address = from_compatible_address(lhs.b_val, lhs_inet.type);
	lhs_inet.mask = lhs.c_val;

	INET_IPAddress rhs_inet;
	rhs_inet.type = (INET_IPAddressType)rhs.a_val;
	rhs_inet.address = from_compatible_address(rhs.b_val, rhs_inet.type);
	rhs_inet.mask = rhs.c_val;

	INET_IPAddress lhs_network = ipaddress_network(&lhs_inet);
	INET_IPAddress lhs_broadcast = ipaddress_broadcast(&lhs_inet);

	INET_IPAddress rhs_network = ipaddress_network(&rhs_inet);
	INET_IPAddress rhs_broadcast = ipaddress_broadcast(&rhs_inet);

	// Set the output
	const bool network_in_lower = lhs_network.address.lower >= rhs_network.address.lower;
	const bool network_in_upper = lhs_network.address.upper >= rhs_network.address.upper;
	const bool broadcast_in_lower = lhs_broadcast.address.lower <= rhs_broadcast.address.lower;
	const bool broadcast_in_upper = lhs_broadcast.address.upper <= rhs_broadcast.address.upper;

	return network_in_lower && network_in_upper && broadcast_in_lower && broadcast_in_upper;
}

static void ContainsLeftFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	GenericExecutor::ExecuteBinary<INET_T, INET_T, PrimitiveType<bool>>(
	    args.data[0], args.data[1], result, args.size(),
	    [](INET_T lhs, INET_T rhs) -> PrimitiveType<bool> { return ContainsImplementation(lhs, rhs); });
}

static void ContainsRightFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	GenericExecutor::ExecuteBinary<INET_T, INET_T, PrimitiveType<bool>>(
	    args.data[0], args.data[1], result, args.size(),
	    [](INET_T lhs, INET_T rhs) -> PrimitiveType<bool> { return ContainsImplementation(rhs, lhs); });
}

static void StrictlyContainedByFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	GenericExecutor::ExecuteBinary<INET_T, INET_T, PrimitiveType<bool>>(
	    args.data[0], args.data[1], result, args.size(), [](INET_T lhs, INET_T rhs) -> PrimitiveType<bool> {
		    return lhs.c_val > rhs.c_val && ContainsImplementation(lhs, rhs);
	    });
}

static void StrictlyContainsFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	GenericExecutor::ExecuteBinary<INET_T, INET_T, PrimitiveType<bool>>(
	    args.data[0], args.data[1], result, args.size(), [](INET_T lhs, INET_T rhs) -> PrimitiveType<bool> {
		    return rhs.c_val > lhs.c_val && ContainsImplementation(rhs, lhs);
	    });
}

static void OverlapsFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	GenericExecutor::ExecuteBinary<INET_T, INET_T, PrimitiveType<bool>>(
	    args.data[0], args.data[1], result, args.size(), [](INET_T lhs, INET_T rhs) -> PrimitiveType<bool> {
		    return ContainsImplementation(lhs, rhs) || ContainsImplementation(rhs, lhs);
	    });
}

static INET_T WithAddress(const INET_T &input, duckdb_uhugeint address, uint16_t mask) {
	INET_T result;
	result.a_val = input.a_val;
	result.b_val = to_compatible_address(address, static_cast<INET_IPAddressType>(input.a_val));
	result.c_val = mask;
	return result;
}

static void BitwiseNotFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	GenericExecutor::ExecuteUnary<INET_T, INET_T>(args.data[0], result, args.size(), [](INET_T input) -> INET_T {
		const auto type = static_cast<INET_IPAddressType>(input.a_val);
		auto address = from_compatible_address(input.b_val, type);
		if (type == INET_IP_ADDRESS_V4) {
			address.upper = 0;
			address.lower = ~address.lower & NumericLimits<uint32_t>::Maximum();
		} else {
			address.upper = ~address.upper;
			address.lower = ~address.lower;
		}
		return WithAddress(input, address, input.c_val);
	});
}

template <bool IS_AND>
static void BitwiseBinaryFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	GenericExecutor::ExecuteBinary<INET_T, INET_T, INET_T>(
	    args.data[0], args.data[1], result, args.size(), [](INET_T lhs, INET_T rhs) -> INET_T {
		    if (lhs.a_val != rhs.a_val) {
			    throw InvalidInputException("cannot %s inet values of different sizes", IS_AND ? "AND" : "OR");
		    }
		    const auto type = static_cast<INET_IPAddressType>(lhs.a_val);
		    const auto left = from_compatible_address(lhs.b_val, type);
		    const auto right = from_compatible_address(rhs.b_val, type);
		    duckdb_uhugeint address;
		    address.upper = IS_AND ? left.upper & right.upper : left.upper | right.upper;
		    address.lower = IS_AND ? left.lower & right.lower : left.lower | right.lower;
		    return WithAddress(lhs, address, MaxValue(lhs.c_val, rhs.c_val));
	    });
}

static constexpr idx_t INET_SORT_KEY_MALFORMED_SIZE = 5 * sizeof(uint8_t) + sizeof(uhugeint_t) + sizeof(uint16_t);
static constexpr data_t INET_SORT_KEY_MALFORMED = 0xFF;

static bool IsInetSortKeyV4(uint8_t ip_type, hugeint_t compat_address) {
	return ip_type == INET_IP_ADDRESS_V4 && compat_address.upper == 0 &&
	       compat_address.lower <= NumericLimits<uint32_t>::Maximum();
}

static idx_t InetSortKeySize(uint8_t ip_type, hugeint_t compat_address) {
	if (ip_type == INET_IP_ADDRESS_V6) {
		return INET_SORT_KEY_V6_SIZE;
	}
	return IsInetSortKeyV4(ip_type, compat_address) ? INET_SORT_KEY_V4_SIZE : INET_SORT_KEY_MALFORMED_SIZE;
}

template <class T>
static data_ptr_t AppendBigEndian(data_ptr_t out, T value) {
	Store<T>(BSwap(value), out);
	return out + sizeof(T);
}

static idx_t WriteMalformedInetSortKey(data_ptr_t out, optional_ptr<const uint8_t> ip_type,
                                       optional_ptr<const hugeint_t> address, optional_ptr<const uint16_t> mask) {
	auto pos = out;
	*pos++ = INET_SORT_KEY_MALFORMED;
	*pos++ = ip_type ? 1 : 0;
	*pos++ = ip_type ? *ip_type : 0;
	*pos++ = address ? 1 : 0;
	pos = AppendBigEndian(pos, address ? static_cast<uint64_t>(address->upper) : uint64_t(0));
	pos = AppendBigEndian(pos, address ? address->lower : uint64_t(0));
	*pos++ = mask ? 1 : 0;
	pos = AppendBigEndian(pos, mask ? *mask : uint16_t(0));
	return NumericCast<idx_t>(pos - out);
}

static idx_t WriteInetSortKey(data_ptr_t out, uint8_t ip_type, hugeint_t compat_address, uint16_t mask) {
	INET_IPAddress inet;
	inet.type = static_cast<INET_IPAddressType>(ip_type);
	inet.address = from_compatible_address(compat_address, inet.type);
	inet.mask = mask;
	const bool is_v4 = IsInetSortKeyV4(ip_type, compat_address);
	if (!is_v4 && inet.type != INET_IP_ADDRESS_V6) {
		return WriteMalformedInetSortKey(out, &ip_type, &compat_address, &mask);
	}
	const auto host = ipaddress_host_mask(&inet);
	auto pos = out;
	*pos++ = ip_type;
	if (is_v4) {
		const auto address = static_cast<uint32_t>(inet.address.lower);
		pos = AppendBigEndian(pos, static_cast<uint32_t>(address & ~host.lower));
		pos = AppendBigEndian(pos, mask);
		pos = AppendBigEndian(pos, address);
	} else {
		pos = AppendBigEndian(pos, inet.address.upper & ~host.upper);
		pos = AppendBigEndian(pos, inet.address.lower & ~host.lower);
		pos = AppendBigEndian(pos, mask);
		pos = AppendBigEndian(pos, inet.address.upper);
		pos = AppendBigEndian(pos, inet.address.lower);
	}
	return NumericCast<idx_t>(pos - out);
}

static bool IsFlatWithoutNulls(const Vector &vector, idx_t count) {
	return vector.GetVectorType() == VectorType::FLAT_VECTOR && FlatVector::Validity(vector).CheckAllValid(count);
}

static void WriteInetSortKey(VectorWriter<string_t> &writer, uint8_t ip_type, hugeint_t compat_address, uint16_t mask) {
	auto &key = writer.WriteEmptyString(InetSortKeySize(ip_type, compat_address));
	const auto size = WriteInetSortKey(data_ptr_cast(key.GetDataWriteable()), ip_type, compat_address, mask);
	D_ASSERT(size == key.GetSize());
	(void)size;
	key.Finalize();
}

static void InetSortKeyFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	const auto count = args.size();
	auto &input = args.data[0];
	auto writer = FlatVector::Writer<string_t>(result, count);
	if (IsFlatWithoutNulls(input, count)) {
		const auto &children = StructVector::GetEntries(input);
		if (IsFlatWithoutNulls(children[INET_IP_TYPE_IDX], count) &&
		    IsFlatWithoutNulls(children[INET_ADDRESS_IDX], count) &&
		    IsFlatWithoutNulls(children[INET_MASK_IDX], count)) {
			const auto ip_type_in = FlatVector::GetData<uint8_t>(children[INET_IP_TYPE_IDX]);
			const auto address_in = FlatVector::GetData<hugeint_t>(children[INET_ADDRESS_IDX]);
			const auto mask_in = FlatVector::GetData<uint16_t>(children[INET_MASK_IDX]);
			for (idx_t i = 0; i < count; i++) {
				WriteInetSortKey(writer, ip_type_in[i], address_in[i], mask_in[i]);
			}
			return;
		}
	}
	auto entries = input.Values<VectorStructType<uint8_t, hugeint_t, uint16_t>>();
	for (const auto entry : entries) {
		if (!entry.IsValid()) {
			writer.WriteNull();
			continue;
		}
		const auto ip_type = entry.GetChildValue<INET_IP_TYPE_IDX>();
		const auto address = entry.GetChildValue<INET_ADDRESS_IDX>();
		const auto mask = entry.GetChildValue<INET_MASK_IDX>();
		if (ip_type.IsValid() && address.IsValid() && mask.IsValid()) {
			WriteInetSortKey(writer, ip_type.GetValueUnsafe(), address.GetValueUnsafe(), mask.GetValueUnsafe());
			continue;
		}
		const auto ip_type_value = ip_type.IsValid() ? ip_type.GetValueUnsafe() : uint8_t(0);
		const auto address_value = address.IsValid() ? address.GetValueUnsafe() : hugeint_t(0);
		const auto mask_value = mask.IsValid() ? mask.GetValueUnsafe() : uint16_t(0);
		auto &key = writer.WriteEmptyString(INET_SORT_KEY_MALFORMED_SIZE);
		WriteMalformedInetSortKey(data_ptr_cast(key.GetDataWriteable()), ip_type.IsValid() ? &ip_type_value : nullptr,
		                          address.IsValid() ? &address_value : nullptr, mask.IsValid() ? &mask_value : nullptr);
		key.Finalize();
	}
}

static bool HasInetAlias(const LogicalType &type, const char *alias) {
	return type.id() == LogicalTypeId::STRUCT && type.GetAlias() == alias;
}

static bool MatchesInetAndCidr(const LogicalType &left, const LogicalType &right) {
	return (HasInetAlias(left, INET_TYPE_NAME) && HasInetAlias(right, CIDR_TYPE_NAME)) ||
	       (HasInetAlias(left, CIDR_TYPE_NAME) && HasInetAlias(right, INET_TYPE_NAME));
}

static bool CombineInetAndCidr(LogicalTypeResolver &, const LogicalType &, const LogicalType &, LogicalType &result) {
	result = make_inet_type();
	return true;
}

static vector<string> GetInetCollationFunctions(ClientContext &, const LogicalType &sql_type, CollationType type) {
	if (type == CollationType::EQUALITY_COLLATIONS || sql_type.id() != LogicalTypeId::STRUCT ||
	    (sql_type.GetAlias() != INET_TYPE_NAME && sql_type.GetAlias() != CIDR_TYPE_NAME)) {
		return {};
	}
	return {"inet_sort_key"};
}

static void HtmlEscapeFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	HTMLEscapeBuffer buffer;
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t input) {
		return StringVector::AddString(result, escape_html(input, true, buffer));
	});
}

static void HtmlEscapeQuoteFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	HTMLEscapeBuffer buffer;
	BinaryExecutor::Execute<string_t, bool, string_t>(
	    args.data[0], args.data[1], result, args.size(), [&](string_t input, bool input_quote) {
		    return StringVector::AddString(result, escape_html(input, input_quote, buffer));
	    });
}

static void HtmlUnescapeFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	HTMLEscapeBuffer buffer;
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t input) {
		auto input_data = input.GetData();
		auto input_size = input.GetSize();

		// Compute the result size
		auto result_size = inet_html_unescaped_get_required_size(input_data, input_size);
		buffer.Allocate(result_size);
		auto result_data = buffer.GetData();
		inet_html_unescape(input_data, input_size, result_data, result_size);

		return StringVector::AddString(result, string_t(result_data, result_size));
	});
}

//----------------------------------------------------------------------------------------------------------------------
// EXTENSION ENTRY
//----------------------------------------------------------------------------------------------------------------------
static void LoadInternal(ExtensionLoader &loader) {
	auto inet_type = make_inet_type();
	loader.RegisterType("INET", inet_type);
	auto cidr_type = make_cidr_type();
	loader.RegisterType("CIDR", cidr_type);

	// Register cast functions
	loader.RegisterCastFunction(inet_type, LogicalType::VARCHAR, BindInetToVarchar);
	loader.RegisterCastFunction(LogicalType::VARCHAR, inet_type, BoundCastInfo(VarcharToInetCast<false>));
	loader.RegisterCastFunction(cidr_type, LogicalType::VARCHAR, BoundCastInfo(InetToVarcharCast<true>));
	loader.RegisterCastFunction(LogicalType::VARCHAR, cidr_type, BoundCastInfo(VarcharToInetCast<true>));
	loader.RegisterCastFunction(cidr_type, inet_type, DefaultCasts::ReinterpretCast, 1);
	loader.RegisterCastFunction(inet_type, cidr_type, BoundCastInfo(InetToCidrCast));
	loader.RegisterCombineTypesRule(CombineTypesRule {MatchesInetAndCidr, CombineInetAndCidr});
	for (const auto &source : {LogicalType::STRUCT({{"any", LogicalType::ANY}}), LogicalType::TUPLE({LogicalType::ANY}),
	                           LogicalType::JSON(), LogicalType::VARIANT()}) {
		loader.RegisterCastFunction(source, inet_type, BindStructToInetCast<false>);
		loader.RegisterCastFunction(source, cidr_type, BindStructToInetCast<true>);
	}

	// scalar functions
	loader.RegisterFunction(ScalarFunction("host", {inet_type}, LogicalType::VARCHAR, HostFunction));
	loader.RegisterFunction(ScalarFunction("family", {inet_type}, LogicalType::UTINYINT, FamilyFunction));
	loader.RegisterFunction(ScalarFunction("netmask", {inet_type}, inet_type, NetmaskFunction));
	loader.RegisterFunction(ScalarFunction("network", {inet_type}, cidr_type, NetworkFunction));
	loader.RegisterFunction(ScalarFunction("broadcast", {inet_type}, inet_type, BroadcastFunction));
	ScalarFunction add_fun("+", {inet_type, LogicalType::HUGEINT}, inet_type, AddFunction);
	add_fun.SetFallible();
	loader.RegisterFunction(add_fun);
	ScalarFunction subtract_fun("-", {inet_type, LogicalType::HUGEINT}, inet_type, SubtractFunction);
	subtract_fun.SetFallible();
	loader.RegisterFunction(subtract_fun);
	loader.RegisterFunction(ScalarFunction("<<=", {inet_type, inet_type}, LogicalType::BOOLEAN, ContainsLeftFunction));
	loader.RegisterFunction(ScalarFunction("subnet_contained_by_or_equals", {inet_type, inet_type},
	                                       LogicalType::BOOLEAN, ContainsLeftFunction));
	loader.RegisterFunction(ScalarFunction(">>=", {inet_type, inet_type}, LogicalType::BOOLEAN, ContainsRightFunction));
	loader.RegisterFunction(ScalarFunction("subnet_contains_or_equals", {inet_type, inet_type}, LogicalType::BOOLEAN,
	                                       ContainsRightFunction));
	loader.RegisterFunction(
	    ScalarFunction("<<", {inet_type, inet_type}, LogicalType::BOOLEAN, StrictlyContainedByFunction));
	loader.RegisterFunction(
	    ScalarFunction(">>", {inet_type, inet_type}, LogicalType::BOOLEAN, StrictlyContainsFunction));
	loader.RegisterFunction(ScalarFunction("&&", {inet_type, inet_type}, LogicalType::BOOLEAN, OverlapsFunction));
	loader.RegisterFunction(ScalarFunction("~", {inet_type}, inet_type, BitwiseNotFunction));
	ScalarFunction and_fun("&", {inet_type, inet_type}, inet_type, BitwiseBinaryFunction<true>);
	and_fun.SetFallible();
	loader.RegisterFunction(and_fun);
	ScalarFunction or_fun("|", {inet_type, inet_type}, inet_type, BitwiseBinaryFunction<false>);
	or_fun.SetFallible();
	loader.RegisterFunction(or_fun);
	loader.RegisterFunction(ScalarFunction("inet_sort_key", {inet_type}, LogicalType::BLOB, InetSortKeyFunction));
	CollationBinding::Get(loader.GetDatabaseInstance()).RegisterCollation(CollationCallback(GetInetCollationFunctions));

	ScalarFunctionSet html_escape("html_escape");
	html_escape.AddFunction(ScalarFunction({LogicalType::VARCHAR}, LogicalType::VARCHAR, HtmlEscapeFunction));
	html_escape.AddFunction(
	    ScalarFunction({LogicalType::VARCHAR, LogicalType::BOOLEAN}, LogicalType::VARCHAR, HtmlEscapeQuoteFunction));
	loader.RegisterFunction(html_escape);
	loader.RegisterFunction(
	    ScalarFunction("html_unescape", {LogicalType::VARCHAR}, LogicalType::VARCHAR, HtmlUnescapeFunction));
}

void InetExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}

std::string InetExtension::Name() {
	return "inet";
}

std::string InetExtension::Version() const {
	return "v1.0.0";
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(inet, loader) { // NOLINT
	duckdb::LoadInternal(loader);
}
}

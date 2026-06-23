#include "duckdb/inet/inet_extension.hpp"

#include "duckdb/inet/inet_ipaddress.hpp"
#include "duckdb/inet/inet_html.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/types/hugeint.hpp"
#include "duckdb/common/types/uhugeint.hpp"
#include "duckdb/common/vector_operations/generic_executor.hpp"
#include "duckdb/common/vector_operations/unary_executor.hpp"
#include "duckdb/common/vector_operations/binary_executor.hpp"
#include "duckdb/function/cast/default_casts.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include <memory>
#include <string.h>

namespace duckdb {

//----------------------------------------------------------------------------------------------------------------------
// INET TYPE DEFINITION
//----------------------------------------------------------------------------------------------------------------------
using INET_T = StructTypeTernary<uint8_t, hugeint_t, uint16_t>;

static LogicalType make_inet_type() {
	child_list_t<LogicalType> children;
	children.push_back(make_pair("ip_type", LogicalType::UTINYINT));
	children.push_back(make_pair("address", LogicalType::HUGEINT));
	children.push_back(make_pair("mask", LogicalType::USMALLINT));
	auto inet_type = LogicalType::STRUCT(std::move(children));
	inet_type.SetAlias("INET");
	return inet_type;
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
		size_t written = ipaddress_to_string(&inet, buffer, sizeof(buffer));
		result_data[i] = StringVector::AddString(result, buffer, written);
	}
	return true;
}

static bool VarcharToInetCast(Vector &source, Vector &result, idx_t count, CastParameters &parameters) {
	UnifiedVectorFormat sdata;
	source.ToUnifiedFormat(count, sdata);
	auto strs = UnifiedVectorFormat::GetData<string_t>(sdata);
	auto &entries = StructVector::GetEntries(result);
	auto a = FlatVector::GetDataMutable<uint8_t>(entries[0]);
	auto b = FlatVector::GetDataMutable<hugeint_t>(entries[1]);
	auto c = FlatVector::GetDataMutable<uint16_t>(entries[2]);
	for (idx_t i = 0; i < count; i++) {
		auto idx = sdata.sel->get_index(i);
		if (!sdata.validity.RowIsValid(idx)) {
			FlatVector::SetNull(result, i, true);
			continue;
		}
		const auto &input = strs[idx];
		INET_IPAddress inet = ipaddress_from_string(input.GetData(), input.GetSize());
		a[i] = (uint8_t)inet.type;
		b[i] = to_compatible_address(inet.address, inet.type);
		c[i] = inet.mask;
	}
	return true;
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
		result.c_val = new_inet.mask;
		return result;
	});
}

static void NetworkFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	GenericExecutor::ExecuteUnary<INET_T, INET_T>(args.data[0], result, args.size(), [](INET_T input) -> INET_T {
		INET_IPAddress old_inet = {};
		old_inet.type = (INET_IPAddressType)input.a_val;
		old_inet.address = from_compatible_address(input.b_val, old_inet.type);
		old_inet.mask = input.c_val;

		// Apply the function
		INET_IPAddress new_inet = ipaddress_network(&old_inet);

		INET_T result;
		result.a_val = (uint8_t)new_inet.type;
		result.b_val = to_compatible_address(new_inet.address, new_inet.type);
		result.c_val = new_inet.mask;
		return result;
	});
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
		if (address_out.lower >= 0xffffffff) {
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
	    args.data[0], args.data[1], result, args.size(),
	    [](INET_T lhs, PrimitiveType<hugeint_t> rhs) -> INET_T { return AddImplementation(lhs, Hugeint::Negate(rhs.val)); });
}

static bool ContainsImplementation(const INET_T &lhs, const INET_T &rhs) {
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

	// Register cast functions
	loader.RegisterCastFunction(inet_type, LogicalType::VARCHAR, BoundCastInfo(InetToVarcharCast));
	loader.RegisterCastFunction(LogicalType::VARCHAR, inet_type, BoundCastInfo(VarcharToInetCast));

	// scalar functions
	loader.RegisterFunction(ScalarFunction("host", {inet_type}, LogicalType::VARCHAR, HostFunction));
	loader.RegisterFunction(ScalarFunction("family", {inet_type}, LogicalType::UTINYINT, FamilyFunction));
	loader.RegisterFunction(ScalarFunction("netmask", {inet_type}, inet_type, NetmaskFunction));
	loader.RegisterFunction(ScalarFunction("network", {inet_type}, inet_type, NetworkFunction));
	loader.RegisterFunction(ScalarFunction("broadcast", {inet_type}, inet_type, BroadcastFunction));
	loader.RegisterFunction(ScalarFunction("+", {inet_type, LogicalType::HUGEINT}, inet_type, AddFunction));
	loader.RegisterFunction(ScalarFunction("-", {inet_type, LogicalType::HUGEINT}, inet_type, SubtractFunction));
	loader.RegisterFunction(
	    ScalarFunction("<<=", {inet_type, inet_type}, LogicalType::BOOLEAN, ContainsLeftFunction));
	loader.RegisterFunction(ScalarFunction("subnet_contained_by_or_equals", {inet_type, inet_type},
	                                       LogicalType::BOOLEAN, ContainsLeftFunction));
	loader.RegisterFunction(
	    ScalarFunction(">>=", {inet_type, inet_type}, LogicalType::BOOLEAN, ContainsRightFunction));
	loader.RegisterFunction(ScalarFunction("subnet_contains_or_equals", {inet_type, inet_type}, LogicalType::BOOLEAN,
	                                       ContainsRightFunction));

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

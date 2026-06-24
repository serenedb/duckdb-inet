# duckdb_inet

Vendored fork of [duckdb/duckdb-inet](https://github.com/duckdb/duckdb-inet),
ported to DuckDB's in-tree C++ extension API and statically linked into serened.

Provides the `INET` type and functions (`host`, `family`, `netmask`, `network`,
`broadcast`, containment operators, `html_escape`/`html_unescape`). Headers live
under `src/duckdb/inet/` and are consumed as `<duckdb/inet/...>`.

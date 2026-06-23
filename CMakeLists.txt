cmake_minimum_required(VERSION 2.8.12...3.29)

project(INETExtension)

# Headers live under src/duckdb/inet/ and are included as <duckdb/inet/...>,
# so src is the include root.
include_directories(src)

set(INET_EXTENSION_FILES
    src/inet_extension.cpp
    src/inet_ipaddress.cpp
    src/inet_html.cpp
    src/inet_html_table.cpp)

build_static_extension(inet ${INET_EXTENSION_FILES})
set(PARAMETERS "-warnings")
build_loadable_extension(inet ${PARAMETERS} ${INET_EXTENSION_FILES})

install(
  TARGETS inet_extension
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")

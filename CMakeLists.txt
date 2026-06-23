cmake_minimum_required(VERSION 2.8.12...3.29)

project(INETExtension)

include_directories(src/include src)

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

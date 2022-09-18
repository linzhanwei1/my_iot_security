cmake_minimum_required(VERSION 3.8.2)
project("Ciphersuite_list")

include_directories(./ $ENV{MBEDTLS_BASE}/include)
aux_source_directory($ENV{MBEDTLS_BASE}/library MBEDTLS_SOURCES)

set(SOURCES ${CMAKE_CURRENT_LIST_DIR}/ciphersuite_list.c ${MBEDTLS_SOURCES})

# coustom Mbedtls config file
add_compile_definitions(MBEDTLS_CONFIG_FILE=<$ENV{MBEDTLS_BASE}/configs/config-mini-tls1_1.h>)

add_executable(ciphersuite_list ${SOURCES})

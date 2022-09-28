cmake_minimum_required(VERSION 3.15)
project("hello")

include_directories(./ $ENV{MBEDTLS_BASE}/include)
aux_source_directory($ENV{MBEDTLS_BASE}/library MBEDTLS_SOURCES)

set(SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/hello.c
    ${MBEDTLS_SOURCES})
set(SOURCES1 ${CMAKE_CURRENT_LIST_DIR}/generic_sum.c ${MBEDTLS_SOURCES})

add_executable(hello ${SOURCES})
add_executable(generic_sum ${SOURCES1})

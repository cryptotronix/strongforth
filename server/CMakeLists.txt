cmake_minimum_required(VERSION 3.1.0)
project(stf_server C)

include(GNUInstallDirs)

set(DEFAULT_LIB_PATH "${CMAKE_INSTALL_FULL_LIBDIR}" CACHE STRING "default absolute lib path")
set(DEFAULT_INC_PATH )

add_library(${PROJECT_NAME} SHARED)

target_include_directories(${PROJECT_NAME} PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/core
    /usr/include/cryptoauthlib
)

target_sources(${PROJECT_NAME} PRIVATE
    ../lib/core/common.c
    ../lib/core/strongforth.c
    ../lib/core/base32.c
    ../lib/core/hydrogen.c
    ../lib/core/zforth.c
    server.c
    uECC.c
)

target_compile_definitions(${PROJECT_NAME} PRIVATE -DSTF_SERVER=1)

target_link_libraries(${PROJECT_NAME} cryptoauth m)

set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER ../lib/core/strongforth.h)

install(TARGETS ${PROJECT_NAME} 
    LIBRARY DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

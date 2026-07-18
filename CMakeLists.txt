cmake_minimum_required(VERSION 3.16)

# NOTE: CMake rejects pre-release semver suffixes, so the project version is the
# plain 1.0.0 triple. The alpha spelling ("1.0.0-alpha10") lives in vcpkg.json,
# conanfile.py, README and the AXIAM_VERSION macro.
project(axiam_c_sdk
    VERSION 1.0.0
    DESCRIPTION "AXIAM C SDK — REST client conforming to CONTRACT.md §1–§7, §9–§11 (incl. §6.1 mTLS)"
    HOMEPAGE_URL "https://github.com/ilpanich/axiam-c-sdk"
    LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
endif()

option(AXIAM_BUILD_TESTS "Build the AXIAM C SDK test suite" OFF)
option(AXIAM_ENABLE_COVERAGE "Instrument for gcov/lcov coverage" OFF)
option(AXIAM_BUILD_SHARED "Build the shared library variant" ON)
option(AXIAM_BUILD_STATIC "Build the static library variant" ON)

# Expose POSIX + GNU symbols (strdup, strncasecmp, pthread_barrier, usleep,
# strcasestr) while keeping the language standard at C11.
add_compile_definitions(_GNU_SOURCE)

include(GNUInstallDirs)

find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# ---- vendored cJSON (offline-friendly JSON) ----
add_library(axiam_cjson OBJECT third_party/cjson/cJSON.c)
target_include_directories(axiam_cjson PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/third_party/cjson>)
set_target_properties(axiam_cjson PROPERTIES POSITION_INDEPENDENT_CODE ON)

set(AXIAM_SOURCES
    src/error.c
    src/util.c
    src/sensitive.c
    src/config.c
    src/json_build.c
    src/transport_curl.c
    src/client.c
    src/jwks.c
    src/guard.c
    src/version.c)

# Compile the SDK sources once into an object library shared by both variants.
add_library(axiam_obj OBJECT ${AXIAM_SOURCES})
set_target_properties(axiam_obj PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(axiam_obj PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cjson)
target_link_libraries(axiam_obj PUBLIC CURL::libcurl OpenSSL::Crypto OpenSSL::SSL Threads::Threads)

if(AXIAM_ENABLE_COVERAGE)
    target_compile_options(axiam_obj PRIVATE --coverage -O0 -g)
    target_link_options(axiam_obj PUBLIC --coverage)
endif()

set(AXIAM_INSTALL_TARGETS "")

# Shared library — the canonical `axiam` target.
if(AXIAM_BUILD_SHARED)
    add_library(axiam SHARED
        $<TARGET_OBJECTS:axiam_obj> $<TARGET_OBJECTS:axiam_cjson>)
    set_target_properties(axiam PROPERTIES
        VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR}
        OUTPUT_NAME axiam)
    target_include_directories(axiam PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    target_link_libraries(axiam PUBLIC CURL::libcurl OpenSSL::Crypto OpenSSL::SSL Threads::Threads)
    if(AXIAM_ENABLE_COVERAGE)
        target_link_options(axiam PUBLIC --coverage)
    endif()
    add_library(axiam::axiam ALIAS axiam)
    list(APPEND AXIAM_INSTALL_TARGETS axiam)
endif()

# Static library variant (OUTPUT_NAME axiam so it produces libaxiam.a).
if(AXIAM_BUILD_STATIC)
    add_library(axiam_static STATIC
        $<TARGET_OBJECTS:axiam_obj> $<TARGET_OBJECTS:axiam_cjson>)
    set_target_properties(axiam_static PROPERTIES OUTPUT_NAME axiam)
    target_include_directories(axiam_static PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    target_link_libraries(axiam_static PUBLIC CURL::libcurl OpenSSL::Crypto OpenSSL::SSL Threads::Threads)
    if(NOT AXIAM_BUILD_SHARED)
        add_library(axiam::axiam ALIAS axiam_static)
    endif()
    list(APPEND AXIAM_INSTALL_TARGETS axiam_static)
endif()

# ---- install rules + package config ----
install(TARGETS ${AXIAM_INSTALL_TARGETS}
    EXPORT axiam-c-sdkTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/axiam DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT axiam-c-sdkTargets
    FILE axiam-c-sdkTargets.cmake
    NAMESPACE axiam::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/axiam-c-sdk)

include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/axiam-c-sdkConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/axiam-c-sdkConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/axiam-c-sdk)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/axiam-c-sdkConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/axiam-c-sdkConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/axiam-c-sdkConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/axiam-c-sdk)

# ---- tests ----
if(AXIAM_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ---- CPack (.tar.gz) ----
set(CPACK_PACKAGE_NAME "axiam-c-sdk")
set(CPACK_PACKAGE_VENDOR "AXIAM")
set(CPACK_PACKAGE_VERSION "1.0.0-alpha10")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_GENERATOR "TGZ")
set(CPACK_SOURCE_GENERATOR "TGZ")
include(CPack)

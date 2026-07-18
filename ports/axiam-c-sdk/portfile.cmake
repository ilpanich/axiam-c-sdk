# Overlay port for the AXIAM C SDK.
#
# By default this builds from the local source tree (overlay usage from within
# this repository). For registry usage, replace the SOURCE_PATH block with
# vcpkg_from_github(... REF v1.0.0-alpha8 SHA512 <hash> ...).

if(DEFINED AXIAM_C_SDK_SOURCE_DIR)
    set(SOURCE_PATH "${AXIAM_C_SDK_SOURCE_DIR}")
else()
    # Local overlay: the port lives at <repo>/ports/axiam-c-sdk, sources two up.
    get_filename_component(SOURCE_PATH "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
endif()

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DAXIAM_BUILD_TESTS=OFF
)

vcpkg_cmake_install()

vcpkg_cmake_config_fixup(PACKAGE_NAME axiam-c-sdk
    CONFIG_PATH lib/cmake/axiam-c-sdk)

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")

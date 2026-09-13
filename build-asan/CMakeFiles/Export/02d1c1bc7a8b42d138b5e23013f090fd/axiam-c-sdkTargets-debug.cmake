#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "axiam::axiam" for configuration "Debug"
set_property(TARGET axiam::axiam APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(axiam::axiam PROPERTIES
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/lib/libaxiam.so.1.0.0"
  IMPORTED_SONAME_DEBUG "libaxiam.so.1"
  )

list(APPEND _cmake_import_check_targets axiam::axiam )
list(APPEND _cmake_import_check_files_for_axiam::axiam "${_IMPORT_PREFIX}/lib/libaxiam.so.1.0.0" )

# Import target "axiam::axiam_static" for configuration "Debug"
set_property(TARGET axiam::axiam_static APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(axiam::axiam_static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_DEBUG "C"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/lib/libaxiam.a"
  )

list(APPEND _cmake_import_check_targets axiam::axiam_static )
list(APPEND _cmake_import_check_files_for_axiam::axiam_static "${_IMPORT_PREFIX}/lib/libaxiam.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)

# Fails unless the shared library's SONAME is EXPECTED (readelf -d on the built file).
find_program(READELF readelf)
if(NOT READELF)
    message(FATAL_ERROR "readelf not found")
endif()
execute_process(COMMAND ${READELF} -d ${LIB}
    OUTPUT_VARIABLE dyn RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "readelf -d ${LIB} failed (${rc})")
endif()
if(NOT dyn MATCHES "\\(SONAME\\)[ \t]+Library soname: \\[${EXPECTED}\\]")
    message(FATAL_ERROR "SONAME is not ${EXPECTED}:\n${dyn}")
endif()

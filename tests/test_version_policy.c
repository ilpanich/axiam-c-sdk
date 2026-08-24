/*
 * Language-version support policy.
 *
 * The SDK states which C standard it supports in three places that nothing compares:
 *
 *   1. CMAKE_C_STANDARD in CMakeLists.txt — what the build actually passes to the
 *      compiler, and the default every consumer inherits;
 *   2. AXIAM_MIN_C_STANDARD in include/axiam/axiam.h — the value the compile-time
 *      #error guard enforces, and the only one a consumer can read;
 *   3. the CI matrix in .github/workflows/sdk-ci-c.yml — the only one ever compiled.
 *
 * Before this test existed, CI built gcc and clang at one standard: C11. Two
 * compilers, one standard, so the compiler axis was covered twice and the language
 * axis not at all. That matters more in C than in most languages, because newer C
 * standards REMOVE things: K&R declarations are gone in C23, bool/true/false became
 * keywords, and an implicit function declaration is an error rather than a warning.
 * A consumer whose own project sets -std=c23 — entirely their prerogative — would
 * have been the first to compile this SDK that way.
 *
 * The paths below are handed in by CMake as AXIAM_REPO_ROOT so the test does not
 * guess at its working directory.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"

void setUp(void) {}
void tearDown(void) {}

#ifndef AXIAM_REPO_ROOT
#error "AXIAM_REPO_ROOT must be defined by the build (see tests/CMakeLists.txt)."
#endif

/* Reads a repository file into a heap buffer, or NULL. Caller frees. */
static char *read_repo_file(const char *relative) {
    char path[4096];
    int written = snprintf(path, sizeof(path), "%s/%s", AXIAM_REPO_ROOT, relative);
    if (written < 0 || (size_t)written >= sizeof(path)) {
        return NULL;
    }

    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return NULL;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long size = ftell(f);
    if (size < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }

    char *buf = malloc((size_t)size + 1U);
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }
    size_t got = fread(buf, 1U, (size_t)size, f);
    buf[got] = '\0';
    fclose(f);
    return buf;
}

/*
 * The compiling standard is at least the declared floor.
 *
 * The #error guard in axiam.h already refuses to compile below it, so reaching this
 * assertion at all proves half of it. Asserting anyway keeps the two in the same
 * place: if the guard were ever removed, this is what would notice.
 */
static void test_compiling_standard_meets_the_declared_floor(void) {
#ifdef __STDC_VERSION__
    TEST_ASSERT_TRUE_MESSAGE(__STDC_VERSION__ >= AXIAM_MIN_C_STANDARD,
                             "compiled below AXIAM_MIN_C_STANDARD");
#else
    TEST_FAIL_MESSAGE("__STDC_VERSION__ is undefined — this is a pre-C94 compiler");
#endif
}

/*
 * The compiling standard is one the policy actually names.
 *
 * The C23 case is a range rather than an equality, and the reason is worth writing
 * down because it is invisible and compiler-specific. `CMAKE_C_STANDARD 23` does not
 * produce the same __STDC_VERSION__ everywhere: gcc 13 has no `-std=c23` at all, so
 * CMake selects `-std=c2x` and the compiler reports the PRE-RATIFICATION 202000L,
 * while clang 18 accepts `-std=c23` and reports the ratified 202311L. Both are doing
 * exactly what they were asked to do. An equality against 202311L would therefore
 * pass on clang and fail on gcc for identical, correct builds — which is precisely
 * what happened when this test was first written.
 *
 * Anything past C17 is C23-or-later, whichever spelling the compiler landed on.
 */
static void test_compiling_standard_is_a_declared_leg(void) {
#ifdef __STDC_VERSION__
    const long v = __STDC_VERSION__;
    const int is_floor = (v == AXIAM_MIN_C_STANDARD);
    /* C17 (201710L) is a bug-fix revision of C11 and is the default on several
       toolchains; it sits between two green legs. */
    const int is_c17 = (v == 201710L);
    const int is_c23_or_later = (v > 201710L);

    TEST_ASSERT_TRUE_MESSAGE(
        is_floor || is_c17 || is_c23_or_later,
        "compiling under a C standard older than the declared floor and not one the "
        "policy names — add a CI leg or update the macros");

    if (is_c23_or_later) {
        /* Sanity-check the macro against reality rather than trusting it: whatever
           the compiler reports for C23, the declared "newest tested" value must be
           in the same era, not left behind at C11. */
        TEST_ASSERT_TRUE_MESSAGE(
            AXIAM_NEWEST_TESTED_C_STANDARD > 201710L,
            "building C23 but AXIAM_NEWEST_TESTED_C_STANDARD still names an older "
            "standard");
    }
#endif
}

/* AXIAM_MIN_C_STANDARD and the CMake default describe the same standard. */
static void test_header_floor_matches_cmake_default(void) {
    char *cmake = read_repo_file("CMakeLists.txt");
    TEST_ASSERT_NOT_NULL_MESSAGE(cmake, "could not read CMakeLists.txt");

    /* The floor is the literal in `set(CMAKE_C_STANDARD 11)`. Mapping it to the
       __STDC_VERSION__ form the header uses is the whole point of the check. */
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(cmake, "set(CMAKE_C_STANDARD 11)"),
                                 "CMakeLists.txt no longer defaults to C11, but "
                                 "AXIAM_MIN_C_STANDARD still says C11");
    TEST_ASSERT_EQUAL_INT64(201112L, (long long)AXIAM_MIN_C_STANDARD);
    free(cmake);
}

/*
 * The CMake default is overridable, which is what lets CI compile a second standard
 * at all. A plain `set()` would silently ignore -DCMAKE_C_STANDARD=23 and the newest
 * leg would build C11 while reporting green.
 */
static void test_cmake_standard_is_overridable(void) {
    char *cmake = read_repo_file("CMakeLists.txt");
    TEST_ASSERT_NOT_NULL_MESSAGE(cmake, "could not read CMakeLists.txt");
    TEST_ASSERT_NOT_NULL_MESSAGE(
        strstr(cmake, "if(NOT DEFINED CMAKE_C_STANDARD)"),
        "CMAKE_C_STANDARD is set unconditionally, so -DCMAKE_C_STANDARD=23 is "
        "ignored and the newest CI leg silently builds C11");
    free(cmake);
}

/* CI compiles both ends of the declared range. */
static void test_ci_builds_the_floor_and_the_newest(void) {
    char *workflow = read_repo_file(".github/workflows/sdk-ci-c.yml");
    TEST_ASSERT_NOT_NULL_MESSAGE(workflow, "could not read sdk-ci-c.yml");

    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(workflow, "std: 11"),
                                 "no CI leg builds the C11 floor");
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(workflow, "std: 23"),
                                 "no CI leg builds C23, so nothing proves the SDK "
                                 "compiles under the newest standard");
    free(workflow);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_compiling_standard_meets_the_declared_floor);
    RUN_TEST(test_compiling_standard_is_a_declared_leg);
    RUN_TEST(test_header_floor_matches_cmake_default);
    RUN_TEST(test_cmake_standard_is_overridable);
    RUN_TEST(test_ci_builds_the_floor_and_the_newest);
    return UNITY_END();
}

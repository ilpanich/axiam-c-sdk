/*
 * version_compatibility.c — reports the C standard this translation unit was
 * compiled under, against the range the SDK is built and tested against.
 *
 * The floor enforces itself: <axiam/axiam.h> carries an #error guard, so a
 * toolchain below C11 fails at the #include with a message that names the problem
 * rather than at some later unexplained syntax error. Nothing enforces the upper
 * end, and in C that gap is worth taking seriously, because newer standards REMOVE
 * things rather than only adding them — K&R declarations are gone in C23,
 * bool/true/false became keywords, and an implicit function declaration is an error
 * rather than a warning.
 *
 * A consumer whose own project sets -std=c23 is entirely within their rights, and
 * this is how they check whether that combination is one the SDK has a green build
 * for.
 *
 * This example is illustrative and self-contained: no server, no network, no
 * configuration.
 *
 * Build:  cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=ON && cmake --build build
 * Run:    ./build/examples/version_compatibility
 */
#include <axiam/axiam.h>
#include <stdio.h>

/* Renders a __STDC_VERSION__ value as the standard people actually say. */
static const char *standard_name(long version) {
    if (version >= 202311L) return "C23";
    /* gcc implements C23 as -std=c2x and reports this pre-ratification value. */
    if (version >= 202000L) return "C23 (pre-ratification -std=c2x)";
    if (version >= 201710L) return "C17";
    if (version >= 201112L) return "C11";
    if (version >= 199901L) return "C99";
    return "older than C99";
}

int main(void) {
#ifndef __STDC_VERSION__
    /* Unreachable in practice — axiam.h's #error guard rejects this first. */
    fprintf(stderr, "UNSUPPORTED: __STDC_VERSION__ is undefined (pre-C94 compiler).\n");
    return 1;
#else
    const long compiled = __STDC_VERSION__;

    printf("axiam-c-sdk version:  %s\n", axiam_version());
    printf("compiled under:       %s (__STDC_VERSION__ = %ldL)\n",
           standard_name(compiled), compiled);
    printf("SDK floor:            %s (%ldL)\n",
           standard_name((long)AXIAM_MIN_C_STANDARD), (long)AXIAM_MIN_C_STANDARD);
    printf("newest tested:        %s (%ldL)\n",
           standard_name((long)AXIAM_NEWEST_TESTED_C_STANDARD),
           (long)AXIAM_NEWEST_TESTED_C_STANDARD);

    if (compiled < AXIAM_MIN_C_STANDARD) {
        printf("UNSUPPORTED: below the SDK's floor.\n");
        return 1;
    }

    /* Compared as a lower bound, never for equality: see the note on
       AXIAM_NEWEST_TESTED_C_STANDARD — gcc and clang report different values for
       the same C23 build. */
    if (compiled > 201710L) {
        printf("SUPPORTED: C23 or later, which CI builds on both gcc and clang.\n");
    } else if (compiled == AXIAM_MIN_C_STANDARD) {
        printf("SUPPORTED: the declared floor, which CI builds on both gcc and clang.\n");
    } else {
        printf("SUPPORTED: between the floor and the newest tested standard.\n");
    }
    return 0;
#endif
}

# Local patches to the vendored cJSON (1.7.19)

Keep this list short; re-apply it when cJSON is re-vendored.

1. `cJSON.c`, `global_error`: declared thread-local (`AXIAM_CJSON_TLS`: C23 `thread_local`,
   else `__thread` on GCC/Clang, `_Thread_local` on other C11 compilers, `__declspec(thread)` on
   MSVC; a compiler with none of these fails to build rather than silently racing). Upstream
   keeps one process-global record that every parse resets and every failed parse overwrites, a
   data race under concurrent parsing (ilpanich/axiam-c-sdk#91). `cJSON_GetErrorPtr()` now
   reports the calling thread's last parse; the SDK never calls it. Covered by
   `tests/test_cjson_threads.c` (needs a `-fsanitize=thread` build to observe the race).

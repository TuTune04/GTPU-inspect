# Build: CC=clang CXX=clang++ cmake -B build-fuzz -DGTPU_BUILD_FUZZ=ON
# Chạy:  ./build-fuzz/fuzz/fuzz_parser fuzz/corpus -max_total_time=600
add_executable(fuzz_parser fuzz_parser.c)
target_compile_options(fuzz_parser PRIVATE ${GTPU_C_WARNINGS})
target_link_libraries(fuzz_parser PRIVATE gtpu_core)
target_link_options(fuzz_parser PRIVATE -fsanitize=fuzzer)

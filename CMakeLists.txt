cmake_minimum_required(VERSION 3.16)
project(gtpu_inspect VERSION 0.1.0 LANGUAGES C CXX)

option(GTPU_BUILD_TESTS "Build unit tests (GoogleTest)"            ON)
option(GTPU_SANITIZE    "Build with AddressSanitizer + UBSan"       OFF)
option(GTPU_BUILD_FUZZ  "Build libFuzzer targets (requires Clang)"  OFF)
option(GTPU_BUILD_BENCH "Build benchmark programs in bench/"        OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)          # -std=c11, không phải gnu11
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# -std=c11 tắt các khai báo POSIX trong header hệ thống; bật lại một cách
# tường minh (cần cho pthread, ntohl/htonl qua <arpa/inet.h>, clock_gettime).
add_compile_definitions(_POSIX_C_SOURCE=200809L)

set(GTPU_C_WARNINGS
  -Wall -Wextra -Werror
  -Wshadow -Wconversion -Wsign-conversion -Wcast-align
  -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith
  -Wvla -Wformat=2 -Wundef)
set(GTPU_CXX_WARNINGS -Wall -Wextra -Werror)

if(GTPU_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=all
                      -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address,undefined)
endif()

if(GTPU_BUILD_FUZZ)
  if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "GTPU_BUILD_FUZZ cần Clang (CC=clang CXX=clang++)")
  endif()
  # Instrument toàn bộ code core để libFuzzer đo được coverage.
  add_compile_options(-fsanitize=fuzzer-no-link,address,undefined
                      -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address,undefined)
endif()

find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# Core library
#
# Các file core do bạn tự viết. CMake chỉ đưa vào build những file đã tồn
# tại, nên repo build được ngay từ ngày đầu và mỗi module tự "bật" khi bạn
# tạo file .c của nó. Thêm module mới thì thêm tên vào danh sách này.
# ---------------------------------------------------------------------------
set(GTPU_CORE_CANDIDATES
  src/pcap.c
  src/parser.c
  src/gtpu.c
  src/session_table.c
  src/stats.c
  src/ring.c
  src/mempool.c)

set(GTPU_CORE_SOURCES "")
foreach(f IN LISTS GTPU_CORE_CANDIDATES)
  if(EXISTS ${CMAKE_SOURCE_DIR}/${f})
    list(APPEND GTPU_CORE_SOURCES ${f})
    message(STATUS "core: ${f}")
  else()
    message(STATUS "core: ${f} (chưa có, bỏ qua)")
  endif()
endforeach()

if(GTPU_CORE_SOURCES)
  add_library(gtpu_core STATIC ${GTPU_CORE_SOURCES})
  target_include_directories(gtpu_core PUBLIC ${CMAKE_SOURCE_DIR}/include)
  target_compile_options(gtpu_core PRIVATE ${GTPU_C_WARNINGS})
  target_link_libraries(gtpu_core PUBLIC Threads::Threads)
else()
  add_library(gtpu_core INTERFACE)
  target_include_directories(gtpu_core INTERFACE ${CMAKE_SOURCE_DIR}/include)
  target_link_libraries(gtpu_core INTERFACE Threads::Threads)
endif()

if(EXISTS ${CMAKE_SOURCE_DIR}/src/main.c)
  add_executable(gtpu-inspect src/main.c)
  target_compile_options(gtpu-inspect PRIVATE ${GTPU_C_WARNINGS})
  target_link_libraries(gtpu-inspect PRIVATE gtpu_core)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(GTPU_BUILD_TESTS AND NOT GTPU_BUILD_FUZZ)
  enable_testing()
  add_subdirectory(tests)
endif()

if(GTPU_BUILD_FUZZ)
  add_subdirectory(fuzz)
endif()

if(GTPU_BUILD_BENCH)
  add_subdirectory(bench)
endif()

# ---------------------------------------------------------------------------
# Tiện ích
# ---------------------------------------------------------------------------
find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
  add_custom_target(fixtures
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tools/gen_pcaps.py
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Sinh lại pcap test vào tests/data/")
endif()

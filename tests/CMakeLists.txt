include(FetchContent)

find_package(GTest QUIET)
if(NOT GTest_FOUND)
  FetchContent_Declare(googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
endif()

include(GoogleTest)

add_executable(gtpu_tests
  test_fixtures.cpp
  test_bytes.cpp
  test_pcap.cpp
  test_parser.cpp
  test_gtpu.cpp
  test_session_table.cpp
  test_stats.cpp
  test_ring.cpp
  test_mempool.cpp)
target_compile_options(gtpu_tests PRIVATE ${GTPU_CXX_WARNINGS})
target_compile_definitions(gtpu_tests PRIVATE
  GTPU_TEST_DATA_DIR="${CMAKE_SOURCE_DIR}/tests/data")
target_link_libraries(gtpu_tests PRIVATE gtpu_core GTest::gtest_main)

gtest_discover_tests(gtpu_tests DISCOVERY_TIMEOUT 30)

# Chạy chương trình chính trên mọi fixture: không được crash, kể cả với
# file hỏng. Chỉ đăng ký khi đã có src/main.c.
if(TARGET gtpu-inspect)
  file(GLOB GTPU_FIXTURE_PCAPS ${CMAKE_SOURCE_DIR}/tests/data/*.pcap)
  foreach(pcap IN LISTS GTPU_FIXTURE_PCAPS)
    get_filename_component(name ${pcap} NAME_WE)
    # Exit code khác 0 với file hỏng là hợp lệ; chỉ crash (signal) hoặc lỗi
    # sanitizer mới fail. Khi đã chốt quy ước exit code, hãy siết lại.
    add_test(NAME cli.${name}
      COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/run_no_crash.sh
              $<TARGET_FILE:gtpu-inspect> ${pcap})
    set_tests_properties(cli.${name} PROPERTIES
      FAIL_REGULAR_EXPRESSION "AddressSanitizer|runtime error|LeakSanitizer")
  endforeach()
endif()

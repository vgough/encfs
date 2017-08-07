file(GLOB_RECURSE TEST_SOURCES "*_test.cpp")
add_executable (unittests ${TEST_SOURCES})
target_link_libraries(unittests gtest gtest_main encfs)
add_test(unit unittests)

file(GLOB_RECURSE BENCH_SOURCES "*_bench.cpp")
add_executable (benchmarks ${BENCH_SOURCES})
target_link_libraries(benchmarks benchmark encfs)

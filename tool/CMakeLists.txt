# 抗量子威胁判定引擎 pqc-judge — CMake 构建（备选方案）
# 用法：cmake -B build && cmake --build build
cmake_minimum_required(VERSION 3.10)
project(pqc_judge C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra)

set(LIB_SRC
    src/threat_judge.c
    src/oid_db.c
    src/cert_parser.c)

add_executable(pqc-judge src/main.c ${LIB_SRC})
add_executable(test_judge test/test_judge.c ${LIB_SRC})

target_include_directories(pqc-judge PRIVATE src)
target_include_directories(test_judge PRIVATE src)

enable_testing()
add_test(NAME judge COMMAND test_judge)
set_tests_properties(judge PROPERTIES WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

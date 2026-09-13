# CMakeLists.txt
cmake_minimum_required(VERSION 3.20)
project(secure_file_transfer CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POLICY_DEFAULT_CMP0135 NEW)
include(FetchContent)
FetchContent_Declare(googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.14.0
)
FetchContent_Declare(asio
  GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
  GIT_TAG asio-1-30-2
)
FetchContent_MakeAvailable(googletest)
add_executable(sft_server server/main.cpp)
add_executable(sft_client client/main.cpp)
target_include_directories(sft_server PRIVATE include)
target_include_directories(sft_client PRIVATE include)
enable_testing()
add_executable(sft_tests tests/smoke/test_build.cpp)
target_include_directories(sft_tests PRIVATE include)
target_link_libraries(sft_tests PRIVATE gtest_main)
include(GoogleTest)
gtest_discover_tests(sft_tests)
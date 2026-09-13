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
FetchContent_MakeAvailable(googletest asio)
add_executable(sft_server server/main.cpp)
add_executable(sft_client client/main.cpp)
target_include_directories(sft_server PRIVATE include)
target_include_directories(sft_client PRIVATE include)
target_link_libraries(sft_server PRIVATE sft_app)
target_link_libraries(sft_client PRIVATE sft_app)
enable_testing()
file(GLOB APP_SRCS src/*/*.cpp src/*/*/*.cpp)
file(GLOB TEST_SRCS tests/*/*.cpp)
add_library(sft_app STATIC ${APP_SRCS})
target_include_directories(sft_app PRIVATE include ${CMAKE_BINARY_DIR}/_deps/asio-src/asio/include)
add_executable(sft_tests ${TEST_SRCS})
target_include_directories(sft_tests PRIVATE include)
target_link_libraries(sft_tests PRIVATE gtest_main sft_app)
include(GoogleTest)
gtest_discover_tests(sft_tests)
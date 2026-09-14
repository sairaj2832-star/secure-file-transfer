# CMakeLists.txt
cmake_minimum_required(VERSION 3.20)
project(secure_file_transfer C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POLICY_DEFAULT_CMP0135 NEW)
set(CMAKE_TLS_VERIFY ON)
# CA bundle must be provided by developer environment. Configure via -DCMAKE_TLS_CAINFO=/path/to/ca-bundle.crt
# Do not hardcode a specific Git installation path; document in certs/README.md that valid CA verification is required.
# Attempt to locate common CA bundles if not explicitly set (not a hardcoded Git path, but a search).
if(NOT DEFINED CMAKE_TLS_CAINFO)
  find_file(AUTO_CA_BUNDLE ca-bundle.crt PATHS "C:/Program Files/Git/mingw64/etc/ssl/certs" "C:/mingw64/etc/ssl/certs" "/etc/ssl/certs" "/usr/local/etc/openssl/certs")
  if(AUTO_CA_BUNDLE)
    set(CMAKE_TLS_CAINFO "${AUTO_CA_BUNDLE}")
  endif()
endif()
find_package(OpenSSL REQUIRED)
include(FetchContent)
FetchContent_Declare(googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.14.0
)
FetchContent_Declare(asio
  GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
  GIT_TAG asio-1-34-2
)
FetchContent_Declare(argon2
  GIT_REPOSITORY https://github.com/P-H-C/phc-winner-argon2.git
  GIT_TAG 20190702
)
FetchContent_Declare(sqlite3
  URL https://www.sqlite.org/2024/sqlite-amalgamation-3460000.zip
)
# libsodium 1.0.18 is documented stretch for crypto_box_seal (Task 4 alternative).
# Current ClientCryptoProvider uses OpenSSL EVP_aes_256_gcm + X25519 ECDH (real seal via RAND_bytes+SHA256 KDF)
# which provides real AES-GCM + X25519 security and passes 10k nonce uniq / tag / wrong-key checks.
# To switch to libsodium: uncomment below and add target_link_libraries(sft_app PRIVATE sodium)
# FetchContent_Declare(libsodium URL https://download.libsodium.org/libsodium/releases/libsodium-1.0.18.tar.gz)
# FetchContent_MakeAvailable(googletest asio argon2 sqlite3 libsodium)
FetchContent_MakeAvailable(googletest asio argon2 sqlite3)
# Build argon2 static lib
add_library(argon2 STATIC
  ${argon2_SOURCE_DIR}/src/argon2.c
  ${argon2_SOURCE_DIR}/src/core.c
  ${argon2_SOURCE_DIR}/src/blake2/blake2b.c
  ${argon2_SOURCE_DIR}/src/thread.c
  ${argon2_SOURCE_DIR}/src/encoding.c
  ${argon2_SOURCE_DIR}/src/ref.c)
target_include_directories(argon2 PUBLIC ${argon2_SOURCE_DIR}/include)
# Build sqlite3
add_library(sqlite3 STATIC ${sqlite3_SOURCE_DIR}/sqlite3.c)
target_include_directories(sqlite3 PUBLIC ${sqlite3_SOURCE_DIR})
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
target_include_directories(sft_app PRIVATE include ${CMAKE_BINARY_DIR}/_deps/asio-src/asio/include ${argon2_SOURCE_DIR}/include ${sqlite3_SOURCE_DIR})
if(OPENSSL_FOUND)
  target_include_directories(sft_app PRIVATE ${OPENSSL_INCLUDE_DIR})
  target_link_libraries(sft_app PRIVATE argon2 sqlite3 ws2_32 wsock32 OpenSSL::SSL OpenSSL::Crypto)
else()
  target_link_libraries(sft_app PRIVATE argon2 sqlite3 ws2_32 wsock32)
endif()
add_executable(sft_tests ${TEST_SRCS})
target_include_directories(sft_tests PRIVATE include ${argon2_SOURCE_DIR}/include ${sqlite3_SOURCE_DIR} ${CMAKE_BINARY_DIR}/_deps/asio-src/asio/include)
if(OPENSSL_FOUND)
  target_include_directories(sft_tests PRIVATE ${OPENSSL_INCLUDE_DIR})
  target_link_libraries(sft_tests PRIVATE gtest_main sft_app argon2 sqlite3 ws2_32 wsock32 OpenSSL::SSL OpenSSL::Crypto)
else()
  target_link_libraries(sft_tests PRIVATE gtest_main sft_app argon2 sqlite3 ws2_32 wsock32)
endif()
include(GoogleTest)
gtest_discover_tests(sft_tests)

# Auto-copy OpenSSL DLLs next to exe so MinGW exe loads vcpkg's MinGW DLLs, not ShiningLight's MSVC DLLs (fixes OPENSSL_Uplink)
if(WIN32 AND OPENSSL_FOUND)
  # vcpkg's MinGW OpenSSL DLLs are in <root>/bin, ShiningLight's are in C:/Program Files/OpenSSL-Win64/bin
  # Use OPENSSL_ROOT_DIR if set, otherwise derive from INCLUDE_DIR
  if(DEFINED OPENSSL_ROOT_DIR AND EXISTS "${OPENSSL_ROOT_DIR}/bin/libcrypto-3-x64.dll")
    set(OPENSSL_BIN_DIR "${OPENSSL_ROOT_DIR}/bin")
  elseif(EXISTS "${OPENSSL_INCLUDE_DIR}/../bin/libcrypto-3-x64.dll")
    get_filename_component(OPENSSL_BIN_DIR "${OPENSSL_INCLUDE_DIR}/../bin" ABSOLUTE)
  else()
    set(OPENSSL_BIN_DIR "")
  endif()
  if(OPENSSL_BIN_DIR)
    foreach(tgt sft_server sft_client sft_tests)
      add_custom_command(TARGET ${tgt} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${OPENSSL_BIN_DIR}/libcrypto-3-x64.dll" "$<TARGET_FILE_DIR:${tgt}>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${OPENSSL_BIN_DIR}/libssl-3-x64.dll" "$<TARGET_FILE_DIR:${tgt}>"
        COMMENT "Copying OpenSSL DLLs for ${tgt} (fixes OPENSSL_Uplink)"
      )
    endforeach()
  endif()
endif()
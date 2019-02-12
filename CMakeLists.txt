# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

set(CMAKE_C_COMPILER /usr/local/bin/gcc-8 CACHE PATH "" FORCE)
set(CMAKE_CXX_COMPILER /usr/local/bin/g++-8 CACHE PATH "" FORCE)

project(SEALExamples VERSION 3.1.0 LANGUAGES CXX)

# Executable will be in the same folder
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})

add_executable(encrypted_controller encrypted_controller_main.cpp)

# Import SEAL
find_package(SEAL 3.1.0 EXACT REQUIRED)

# Link SEAL
target_link_libraries(encrypted_controller SEAL::seal)

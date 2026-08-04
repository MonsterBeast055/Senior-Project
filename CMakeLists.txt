# Top-level CMake project file.

cmake_minimum_required(VERSION 3.20)

# Needed so CMAKE_MSVC_RUNTIME_LIBRARY works correctly.
if(POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW)
endif()

# Enable Hot Reload / debug info for MSVC where supported.
if(POLICY CMP0141)
    cmake_policy(SET CMP0141 NEW)
    set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT
        "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>"
    )
endif()

project("Senior-Project" LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Must match the prebuilt LIEF runtime:
#   Release / RelWithDebInfo = /MT
#   Debug                    = /MTd  (requires a Debug LIEF build)
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
# LIEF_ROOT is a cache variable rather than a hardcoded path so every team
# member can point at their own install without editing this file:
#   cmake -DLIEF_ROOT=D:/libs/LIEF-0.17.6-win64 ...
# or set the LIEF_ROOT environment variable. Using vcpkg for both dependencies
# removes the need for it entirely.
set(LIEF_ROOT "C:/libs/LIEF-0.17.6-win64" CACHE PATH "Root of the LIEF install")

if(DEFINED ENV{LIEF_ROOT})
    set(LIEF_ROOT "$ENV{LIEF_ROOT}" CACHE PATH "Root of the LIEF install" FORCE)
endif()

if(NOT DEFINED LIEF_DIR AND EXISTS "${LIEF_ROOT}/lib/cmake/LIEF")
    set(LIEF_DIR "${LIEF_ROOT}/lib/cmake/LIEF")
endif()

find_package(LIEF REQUIRED)
find_package(capstone CONFIG REQUIRED)

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------
add_subdirectory("Senior-Project")

option(SP_BUILD_TESTS "Build the test suite" ON)

if(SP_BUILD_TESTS)
    enable_testing()
    add_subdirectory("tests")
endif()

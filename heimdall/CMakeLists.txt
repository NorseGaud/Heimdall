cmake_minimum_required(VERSION 3.10)

project(heimdall)

if((NOT ${CMAKE_SYSTEM_NAME} MATCHES "Linux") AND (NOT DEFINED libusb_USE_STATIC_LIBS))
    set(libusb_USE_STATIC_LIBS YES)
endif((NOT ${CMAKE_SYSTEM_NAME} MATCHES "Linux") AND (NOT DEFINED libusb_USE_STATIC_LIBS))

find_package(libusb REQUIRED)

set(LIBPIT_INCLUDE_DIRS
    ../libpit/source)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")

if(MINGW)
    set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++ -static")
endif(MINGW)

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    add_definitions(-DOS_LINUX)
endif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

include_directories(SYSTEM ${LIBUSB_INCLUDE_DIRS})

include_directories(${LIBPIT_INCLUDE_DIRS})

set(HEIMDALL_SOURCE_FILES
    source/Arguments.cpp
    source/BridgeManager.cpp
    source/ClosePcScreenAction.cpp
    source/DetectAction.cpp
    source/DownloadPitAction.cpp
    source/FlashAction.cpp
    source/HelpAction.cpp
    source/InfoAction.cpp
    source/Interface.cpp
    source/main.cpp
    source/PrintPitAction.cpp
    source/Utility.cpp
    source/VersionAction.cpp)

include(LargeFiles)
use_large_files(heimdall YES)
add_executable(heimdall ${HEIMDALL_SOURCE_FILES})

target_link_libraries(heimdall PRIVATE pit)
target_link_libraries(heimdall PRIVATE ${LIBUSB_LIBRARIES})

if(APPLE)
    # Static libusb on macOS requires these frameworks for darwin_usb symbols.
    target_link_libraries(heimdall PRIVATE
        "-framework CoreFoundation"
        "-framework IOKit"
        "-framework Security")
endif()
install (TARGETS heimdall
		RUNTIME	DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
		LIBRARY	DESTINATION ${CMAKE_INSTALL_LIBDIR})


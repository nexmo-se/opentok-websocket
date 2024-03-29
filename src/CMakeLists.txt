PROJECT(vonage-rti-connector)

SET(CMAKE_VERBOSE_MAKEFILE ON)

CMAKE_MINIMUM_REQUIRED(VERSION 3.5)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=c++11 -stdlib=libc++  -D_GNU_SOURCE")
SET(LIBUWSC_INCLUDE_DIR "/home/admin/libuwsc/libuwsc/install/usr/local/include/uwsc")
SET(LIBUWSC_LIB_DIR "/home/admin/libuwsc/libuwsc/build/src")
# Remove the commented out line below to enable OpenTok debug traces.
# SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DCONSOLE_LOGGING")

INCLUDE(FindPkgConfig)
PKG_SEARCH_MODULE(LIBSDL2 REQUIRED sdl2)
PKG_SEARCH_MODULE(LIBOPENTOK REQUIRED libopentok)

FIND_PACKAGE(Threads)
find_package(Libev REQUIRED)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/../common/src ${LIBSDL2_INCLUDE_DIRS} ${LIBOPENTOK_INCLUDE_DIRS} ${LIBUWSC_INCLUDE_DIR} ${LIBEV_INCLUDE_DIR})
LINK_DIRECTORIES(${LIBSDL2_LIBRARY_DIRS} ${LIBOPENTOK_LIBRARY_DIRS} ${$LIBUWSC_LIB_DIR})

ADD_EXECUTABLE(${PROJECT_NAME} main.cpp ${CMAKE_CURRENT_SOURCE_DIR}/../common/src/otk_thread.c ${CMAKE_CURRENT_SOURCE_DIR}/../common/src/circular_buffer.c)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} pthread uwsc ${LIBSDL2_LIBRARIES} ${LIBOPENTOK_LIBRARIES} ${LIBEV_LIBRARY} -L"${LIBUWSC_LIB_DIR}")

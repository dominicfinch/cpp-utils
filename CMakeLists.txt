
cmake_minimum_required(VERSION 3.5)

set(PROJECT_NAME "rsa-utils")
project(${PROJECT_NAME})

set(PROJECT_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
file(GLOB PROJECT_SRC_FILESET
    ${PROJECT_SRC_DIR}/utils/*.cc
    ${PROJECT_SRC_DIR}/*.cc)

include_directories(${PROJECT_SRC_DIR})
set(LIBS_LINK
    -lssl
    -lcrypto
    -lstdc++fs)

add_executable(${PROJECT_NAME} ${PROJECT_SRC_FILESET})
target_link_libraries(${PROJECT_NAME} ${LIBS_LINK})

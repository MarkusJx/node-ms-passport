# CMakeLists.txt for use with cmake-js
# It would be used to build this project, if it was not designed to delete the whole project, because this seems like a great idea
cmake_minimum_required(VERSION 3.12)
project(passport)

set(CMAKE_CXX_STANDARD 17)

include_directories(${CMAKE_JS_INC})
add_compile_definitions(NAPI_CPP_EXCEPTIONS)

file(GLOB src
        *.hpp
        *.cpp
        )

include_directories(${CMAKE_JS_INC} "../NodeMsPassport/NodeMsPassport")

if ("${CMAKE_SIZEOF_VOID_P}" STREQUAL "4")
    link_directories("../NodeMsPassport/Release")
else ()
    link_directories("../NodeMsPassport/x64/Release")
endif ()


add_library(${PROJECT_NAME} SHARED ${src})

set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")
target_link_libraries(${PROJECT_NAME} ${CMAKE_JS_LIB} "NodeMsPassport")

# Include N-API wrappers
execute_process(COMMAND node -p "require('node-addon-api').include"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE NODE_ADDON_API_DIR
        )
string(REPLACE "\n" "" NODE_ADDON_API_DIR ${NODE_ADDON_API_DIR})
string(REPLACE "\"" "" NODE_ADDON_API_DIR ${NODE_ADDON_API_DIR})
target_include_directories(${PROJECT_NAME} PRIVATE ${NODE_ADDON_API_DIR})

# define NPI_VERSION
add_definitions(-DNAPI_VERSION=3)

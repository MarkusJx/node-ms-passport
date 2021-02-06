cmake_minimum_required(VERSION 3.15)
project(passport LANGUAGES CXX CSharp)

set(DOTNET_FRAMEWORK_VERSION "v4.7.2")

# Include CMake utilities for CSharp, for WinForm and WPF application support.
include(CSharpUtilities)

set(CSHARP_SRC ${CMAKE_SOURCE_DIR}/cs_src/Passport.cs ${CMAKE_SOURCE_DIR}/cs_src/SubjectPublicKeyinfo.cs)
add_library(CSNodeMsPassport SHARED ${CSHARP_SRC})

find_file(WINDOWS_WINMD "Windows.winmd" HINTS 
        "C:\\Program Files (x86)\\Windows Kits\\10\\UnionMetadata\\${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}"
        REQUIRED)

message(STATUS "Found Windows.winmd file: ${WINDOWS_WINMD}")

set_property(TARGET CSNodeMsPassport PROPERTY DOTNET_TARGET_FRAMEWORK_VERSION ${DOTNET_FRAMEWORK_VERSION})
set_property(TARGET CSNodeMsPassport PROPERTY VS_CONFIGURATION_TYPE ClassLibrary)
set_property(TARGET CSNodeMsPassport PROPERTY VS_DOTNET_REFERENCES
        "Microsoft.CSharp"
        "System"
        "System.Core"
        "System.Data"
        "System.Data.DataSetExtensions"
        "System.Net.Http"
        "System.Runtime.WindowsRuntime"
        "System.Security"
        "System.Xml"
        "System.Xml.Linq"
        ${WINDOWS_WINMD})

set(SIGN_KEY "${CMAKE_SOURCE_DIR}/cs_src/passport.snk")
set_target_properties(CSNodeMsPassport PROPERTIES
        VS_GLOBAL_SignAssembly "true"
        VS_GLOBAL_AssemblyOriginatorKeyFile "${SIGN_KEY}")
    

# C++ part
set(CPP_SRC ${CMAKE_SOURCE_DIR}/cpp_src/NodeMsPassport.cpp ${CMAKE_SOURCE_DIR}/cpp_src/NodeMsPassport.hpp)

add_library(NodeMsPassport STATIC ${CPP_SRC})

set_target_properties(NodeMsPassport PROPERTIES COMMON_LANGUAGE_RUNTIME "")
set_property(TARGET NodeMsPassport PROPERTY VS_GLOBAL_CLRSupport "true")
set_property(TARGET NodeMsPassport PROPERTY VS_DOTNET_TARGET_FRAMEWORK_VERSION ${DOTNET_FRAMEWORK_VERSION})
set_property(TARGET NodeMsPassport PROPERTY VS_DOTNET_REFERENCES
            "System"
            "System.Data"
            "System.Xml"
            "mscorlib")

# Build the actual node.js addon
set(CMAKE_CXX_STANDARD 17)

set(ADDON_SRC ${CMAKE_SOURCE_DIR}/cpp_src/msPassport.cpp)
add_library(${PROJECT_NAME} SHARED ${ADDON_SRC} ${CMAKE_JS_SRC})

target_compile_definitions(${PROJECT_NAME} PRIVATE NAPI_CPP_EXCEPTIONS)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_JS_INC})

set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")
target_link_libraries(${PROJECT_NAME} ${CMAKE_JS_LIB} NodeMsPassport)

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
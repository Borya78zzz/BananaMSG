cmake_minimum_required(VERSION 3.10)
project(SecureMessenger)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(messenger V1.cpp)

if (WIN32)
    # Пути к MSYS2
    target_include_directories(messenger PRIVATE "D:/Msydk/ucrt64/include")
    target_link_directories(messenger PRIVATE "D:/Msydk/ucrt64/lib")
    # Добавили ws2_32 и wsock32 для работы с сетью на Windows
    target_link_libraries(messenger pthread sodium miniupnpc ws2_32)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED libsodium)
    target_include_directories(messenger PRIVATE ${SODIUM_INCLUDE_DIRS})
    target_link_libraries(messenger PRIVATE ${SODIUM_LIBRARIES})
endif()

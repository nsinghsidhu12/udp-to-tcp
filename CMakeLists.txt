cmake_minimum_required(VERSION 3.27)
project(code C)

set(CMAKE_C_STANDARD 17)

add_executable(client client.c)
add_executable(server server.c)
add_executable(proxy proxy.c)

cmake_minimum_required(VERSION 3.5.0)

# 设置项目名称和版本
project(k3sNWPU VERSION 0.1.0 LANGUAGES C CXX)

# 设置 C++17 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找 Boost 和 program_options 库
find_package(Boost REQUIRED COMPONENTS program_options)
find_package(Threads REQUIRED)

# 创建可执行文件
add_executable(k3sNWPU main.cpp server/server.cpp agent/agent.cpp) 

# 将 struct 目录添加到包含路径
target_include_directories(k3sNWPU PRIVATE ${CMAKE_SOURCE_DIR}/struct)

# 如果使用 GCC 或 Clang 编译器，链接 stdc++fs 库
if (CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_link_libraries(k3sNWPU PRIVATE stdc++fs)
endif()

# 链接 Boost program_options 库
target_link_libraries(k3sNWPU PRIVATE Boost::program_options pthread systemd)
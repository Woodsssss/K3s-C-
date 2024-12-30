# K3s-C-
k3s-C++ code
# 环境搭建
使用cmake构建项目，vcpkg管理项目的相关库

## 1.工具准备
- Visual Studio Code
- Ubuntu 20.04.6 
- vscode必要插件 C++ 扩展、CMake Tools

## 2.配置教程
[vscode上利用cmake配置项目](https://blog.csdn.net/qq_41246375/article/details/119546955)

[vcpkg配置教程](https://learn.microsoft.com/zh-cn/vcpkg/get_started/get-started-vscode?pivots=shell-bash)

## 3.注意事项
__使用 export 命令设置环境变量只会影响当前 shell 会话。 要使此更改在整个会话中永久存在，需要将 export 命令添加到 shell 的配置文件脚本。__

    1.sudo nano ~/.bashrc
    2.在末尾添加 export PATH=$PATH:/path/to/vcpkg
    3.source ~/.bashrc
    4.验证：vcpkg --version
__添加用vcpkg管理的库时，在项目的vcpkg.json中向后追加，追加完成后使用如下命令安装相关的库：__

    vcpkg install
__在不同主机编译项目时，记得更改*CMakeUserPresets.json*以及*CMakeLists.txt*中相关的路径为目标主机中的vcpkg安装路径__

```
CMakeUserPresets.json
"VCPKG_ROOT": "/path/to/vcpkg"
```

```
CMakeLists.txt
# 设置 CMAKE_PREFIX_PATH，告诉 CMake 去指定路径下寻找包
set(CMAKE_PREFIX_PATH "/path/to/code/vcpkg_installed/x64-linux/include")
```
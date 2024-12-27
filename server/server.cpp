// server.cpp
#include "server.h"
#include <cstdlib>  // 包含 C++ 标准库的 std::getenv
#include "/usr/include/stdlib.h"
#include <iostream>
#include <filesystem>
#include <spdlog/spdlog.h>
#include <sys/prctl.h>
#include "server_Struct.h"
#include "agent_Struct.h"
#include <netinet/in.h>  // For inet_pton()
#include <arpa/inet.h>   // For inet_ntoa
#include <netinet/ip.h>  // For netmask and IP calculation
#include <fstream>
#include <string>
#include <stdexcept>
#include <boost/asio.hpp>  // For context and IO services
#include <boost/bind.hpp>
#include <chrono>
#include <condition_variable>
#include <atomic>
#include <systemd/sd-daemon.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <cstring>
#include <unistd.h>  // for getuid
#include <pwd.h>     // for getpwuid
#include <sys/types.h>  // for getuid
// oatpp 相关库
#include "oatpp/web/server/HttpConnectionHandler.hpp"
#include "oatpp/network/tcp/server/ConnectionProvider.hpp"
#include "oatpp/network/Server.hpp"
#include "handler.h"
namespace fs = std::filesystem;

std::string BindAddress;
std::string Loopback(bool urlSafe) {
    return urlSafe ? "[127.0.0.1]" : "127.0.0.1"; // 返回回环地址
}

// 用于映射TLS版本名称到版本ID
std::map<std::string, uint16_t> tls_versions = {
    {"SSLv3", 0x0300},
    {"TLSv1.0", 0x0301},
    {"TLSv1.1", 0x0302},
    {"TLSv1.2", 0x0303},
    {"TLSv1.3", 0x0304}
};

// 返回默认TLS版本（这里假设为TLSv1.2的版本ID）
uint16_t DefaultTLSVersion() {
    return 0x0303; // 默认TLS版本：TLSv1.2
}

// 用于选择主机接口的 IP 地址
std::string ChooseHostInterface() {
    struct ifaddrs *ifAddrStruct = nullptr;
    struct ifaddrs *ifa = nullptr;
    void *tmpAddrPtr = nullptr;
    getifaddrs(&ifAddrStruct);
    std::string hostIP;

    // 遍历所有网络接口
    for (ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family == AF_INET) {  // IPv4
                tmpAddrPtr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
                char addressBuffer[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
                hostIP = addressBuffer;
                break;
        }
        // 可根据需要添加对 IPv6 的处理
    }
    if (ifAddrStruct != nullptr) {
        freeifaddrs(ifAddrStruct);
    }

    return hostIP;
}

// 判断 IP 是否是 IPv6 地址
bool IsIPv6String(const std::string &ip) {
    struct sockaddr_in6 sa;
    return inet_pton(AF_INET6, ip.c_str(), &(sa.sin6_addr)) != 0;
}

// BindAddressOrLoopback 方法的实现
std::string BindAddressOrLoopback(bool chooseHostInterface, bool urlSafe) {
    std::string ip = BindAddress;
    if (ip.empty() && chooseHostInterface) {
        ip = ChooseHostInterface();
    }

    if (urlSafe && IsIPv6String(ip)) {
        std::ostringstream oss;
        oss << "[" << ip << "]";
        return oss.str();  // 如果是 IPv6 地址，返回加上方括号的地址
    } else if (!ip.empty()) {
        return ip;  // 返回选中的地址
    }
    return Loopback(urlSafe);  // 否则返回回环地址
}


// A utility function to parse CIDR (like net.ParseCIDR in Go)
// Convert string CIDR to IP and Network (IPNet)
// CIDR解析函数
// 辅助函数：解析CIDR字符串，并将其转换为IPNet结构
bool parseCIDR(const std::string& cidr, IPNet& parsedIP) {
    try {
        // 使用boost::asio解析CIDR
        boost::asio::ip::network_v4 network = boost::asio::ip::make_network_v4(cidr);

        // 获取IP和掩码
        boost::asio::ip::address_v4 ipAddr = network.network();
        std::vector<unsigned char> ipVec(ipAddr.to_bytes().begin(), ipAddr.to_bytes().end());

        boost::asio::ip::address_v4::bytes_type maskBytes = network.netmask().to_bytes();

        // 将 maskBytes 转换为 std::vector<unsigned char>
        std::vector<unsigned char> maskVec(maskBytes.begin(), maskBytes.end());

        // 创建 IPNet 对象并将其传递给 parsedIP
        parsedIP = IPNet(IP(cidr.substr(0, cidr.find('/'))), maskVec);  // 提取CIDR中的IP部分

        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error parsing CIDR: " << e.what() << std::endl;
        return false;
    }
}

// A utility function to parse an IP address (like net.ParseIP in Go)
bool parseIP(const std::string& ipStr, struct in_addr& ip) {
    return inet_pton(AF_INET, ipStr.c_str(), &ip) == 1;
}

// A utility function to split a string by a delimiter (similar to SplitStringSlice in Go)
std::vector<std::string> splitString(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(str);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

// A utility function to calculate the indexed IP (for ClusterDNS)
std::string getIndexedIP(std::string cidr, int index) {
    struct in_addr addr;
    if (inet_pton(AF_INET, cidr.c_str(), &addr) != 1) {
        // Handle invalid IP address format
        return "";
    }
    uint32_t ip = ntohl(addr.s_addr);  // Convert the IP to host byte order
    ip += index;  // Add the index to the IP
    addr.s_addr = htonl(ip);  // Convert the IP back to network byte order
    // Convert the IP back to a string
    char ip_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN) == nullptr) {
        // Handle conversion error
        return "";
    }
    return std::string(ip_str);
}

std::vector<std::string> SplitStringSlice(const std::string& str, const std::string& delimiter) {
    std::vector<std::string> tokens;
    size_t start = 0;
    size_t end = str.find(delimiter);
    while (end != std::string::npos) {
        tokens.push_back(str.substr(start, end - start));
        start = end + delimiter.length();
        end = str.find(delimiter, start);
    }
    tokens.push_back(str.substr(start));
    return tokens;
}

void TrimString(std::string& str) {
    size_t first = str.find_first_not_of(" \t");
    if (first == std::string::npos) {
        str = ""; // If string is only whitespace
    } else {
        size_t last = str.find_last_not_of(" \t");
        str = str.substr(first, last - first + 1);
    }
}

// Helper function to split a string by a delimiter and return the first two parts
std::pair<std::string, std::string> splitArg(const std::string& arg, const std::string& delimiter) {
    size_t pos = arg.find(delimiter);
    if (pos != std::string::npos) {
        return {arg.substr(0, pos), arg.substr(pos + delimiter.length())};
    }
    return {arg, ""};  // If no delimiter is found, return the whole string as the first part
}

// 模拟从 ExtraAPIArgs 中获取参数值的函数
// Function to simulate getting an argument value from the list of ExtraAPIArgs
std::string getArgValueFromList(const std::string& searchArg, const std::vector<std::string>& argList) {
    std::string value;
    for (const auto& arg : argList) {
        auto [key, val] = splitArg(arg, "=");
        if (key == searchArg) {
            value = val;
            break;
        }
    }
    return value;
}

std::vector<std::string> GetArgs(const std::map<std::string, std::string>& initialArgs, const std::vector<std::string>& extraArgs) {
    const std::string hyphens = "--";

    std::map<std::string, std::vector<std::string>> multiArgs;

    for (const auto& unsplitArg : extraArgs) {
        std::string arg;
        std::string value = "true";
        size_t eqPos = unsplitArg.find('=');
        if (eqPos != std::string::npos) {
            arg = unsplitArg.substr(0, eqPos);
            value = unsplitArg.substr(eqPos + 1);
        } else {
            arg = unsplitArg;
        }

        // Remove hyphens and '+' or '-' suffixes
        std::string cleanedArg = arg;
        if (cleanedArg.size() > 2 && cleanedArg.substr(0, 2) == hyphens) {
            cleanedArg = cleanedArg.substr(2);
        }
        if (!cleanedArg.empty() && (cleanedArg.back() == '+' || cleanedArg.back() == '-')) {
            cleanedArg.pop_back();
        }

        auto it = initialArgs.find(cleanedArg);
        bool initialValueExists = it != initialArgs.end();
        std::vector<std::string>& existingValues = multiArgs[cleanedArg];

        std::vector<std::string> newValues;
        if (arg.back() == '+') { // Append value to initial args
            if (initialValueExists) {
                newValues.push_back(it->second);
            }
            newValues.insert(newValues.end(), existingValues.begin(), existingValues.end());
            newValues.push_back(value);
        } else if (arg.back() == '-') { // Prepend value to initial args
            newValues.push_back(value);
            if (initialValueExists) {
                newValues.push_back(it->second);
            }
            newValues.insert(newValues.end(), existingValues.begin(), existingValues.end());
        } else { // Append value ignoring initial args
            newValues.insert(newValues.end(), existingValues.begin(), existingValues.end());
            newValues.push_back(value);
        }

        multiArgs[cleanedArg] = newValues;
    }

    // Add any remaining initial args to the map
    for (const auto& pair : initialArgs) {
        if (multiArgs.find(pair.first) == multiArgs.end()) {
            multiArgs[pair.first] = {pair.second};
        }
    }

    // Get args so we can output them sorted while preserving the order of repeated keys
    std::vector<std::string> keys;
    for (const auto& pair : multiArgs) {
        keys.push_back(pair.first);
    }
    std::sort(keys.begin(), keys.end());

    std::vector<std::string> args;
    for (const auto& arg : keys) {
        for (const auto& value : multiArgs[arg]) {
            std::ostringstream cmd;
            cmd << hyphens << arg << "=" << value;
            args.push_back(cmd.str());
        }
    }

    return args;
}


std::error_code MkdirAll(const fs::path& path, fs::perms perm) {
    // Fast path: if we can tell whether path is a directory or file, stop with success or error.
    std::error_code ec;
    fs::file_status status = fs::status(path, ec);
    if (!ec) {
        if (fs::is_directory(status)) {
            return ec;
        }
        return std::make_error_code(std::errc::not_a_directory);
    }

    // Slow path: make sure parent exists and then call Mkdir for path.
    if (path.has_parent_path()) {
        if (!fs::exists(path.parent_path())) {
            MkdirAll(path.parent_path(), perm);
        }
    }

    // Parent now exists; invoke Mkdir and use its result.
    if (!fs::create_directory(path, ec)) {
        // Handle arguments like "foo/." by double-checking that directory doesn't exist.
        if (ec == std::errc::file_exists) {
            status = fs::status(path, ec);
            if (!ec && fs::is_directory(status)) {
                return ec;
            }
        }
        return ec;
    }
    return ec;
}

// 获取TLS版本ID的函数
uint16_t TLSVersion(const std::string& versionName) {
    if (versionName.empty()) {
        return DefaultTLSVersion(); // 如果传入空字符串，则返回默认版本
    }
    
    auto it = tls_versions.find(versionName);
    if (it != tls_versions.end()) {
        return it->second; // 如果找到对应的版本，返回版本ID
    }

    // 如果未找到对应版本，抛出异常
    throw std::invalid_argument("unknown tls version " + versionName);
}

// ResetLoadBalancer deletes the local state file for the load balancer on disk
// Returns true if the file was successfully deleted, false otherwise.
bool ResetLoadBalancer(const std::string& dataDir, const std::string& serviceName) {
    try {
        // Construct the file path
        fs::path stateFile = fs::path(dataDir) / "etc" / (serviceName + ".json");

        // Check if file exists before trying to remove it
        if (fs::exists(stateFile)) {
            // Try to remove the file
            fs::remove(stateFile);
            std::cout << "Successfully removed load balancer state file: " << stateFile << std::endl;
            return true;
        } else {
            std::cerr << "Warning: File does not exist: " << stateFile << std::endl;
            return false;
        }
    } catch (const std::exception& e) {
        // Log the exception with details
        std::cerr << "Error removing file: " << e.what() << std::endl;
        return false;
    }
}


// 模拟启动API Server和ETCD的过程
void simulateServerState(Config& server) {
    std::this_thread::sleep_for(std::chrono::seconds(2));
    server.ControlConfig.APIServerReady = true;
    std::this_thread::sleep_for(std::chrono::seconds(2));
    server.ControlConfig.ETCDReady = true;
}

//健康检查
void healthCheck(Config& server, const std::string& notifySocket) {
    std::thread healthThread([&]() {
        if (!server.ControlConfig.DisableAPIServer) {
            while (!server.ControlConfig.APIServerReady) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            std::cout << "Kube API server is now running" << std::endl;
        }

        if (!server.ControlConfig.DisableETCD) {
            while (!server.ControlConfig.ETCDReady) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            std::cout << "ETCD server is now running" << std::endl;
        }

        std::cout << "K3s is up and running" << std::endl;

        // Set environment variable
        setenv("NOTIFY_SOCKET", notifySocket.c_str(), 1);

        // Notify systemd that the service is ready
        sd_notify(0, "READY=1\n");
    });

    healthThread.join();  // 等待线程完成
}

// FormatTokenBytes 函数
std::string FormatTokenBytes(const std::string& creds, const std::string& certData) {
    // 这里的逻辑是简化版，实际可能涉及加密等处理
    std::stringstream tokenStream;
    tokenStream << creds << ":" << certData;  // 将凭证与证书数据格式化成一个简单的 token
    return tokenStream.str();
}

// FormatToken 函数
std::string FormatToken(const std::string& creds, const std::string& certFile) {
    if (creds.empty()) {
        return "";  // 如果凭证为空，返回空字符串
    }

    std::ifstream certStream(certFile);
    if (!certStream.is_open()) {
        throw std::runtime_error("Failed to open cert file");
    }

    std::stringstream certBuffer;
    certBuffer << certStream.rdbuf();  // 读取证书文件内容

    return FormatTokenBytes(creds, certBuffer.str());
}

//ReadFile
std::string ReadFile(const std::string& path) {
    if (path.empty()) {
        return "";
    }

    auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start < std::chrono::minutes(4)) {
        std::ifstream file(path);
        if (file.is_open()) {
            std::string content((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
            return content;
        } else if (file.fail() && !file.bad()) {
            std::cerr << "Waiting for " << path << " to be available" << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(2));
        } else {
            throw std::runtime_error("Failed to read the file");
        }
    }

    throw std::runtime_error("Timeout while trying to read the file");
}

//SplitStringSlice overwrite
std::vector<std::string> SplitStringSlice(const std::vector<std::string>& ss) {
    std::vector<std::string> result;
    
    for (const auto& s : ss) {
        std::string token;
        std::stringstream ss_stream(s);
        
        // Split the string by commas
        while (std::getline(ss_stream, token, ',')) {
            result.push_back(token);
        }
    }

    return result;
}

// 函数：获取指定网络接口的IP地址
std::string GetIPFromInterface(const std::string& ifaceName) {
    struct ifaddrs *ifAddrStruct = nullptr;
    struct ifaddrs *ifa = nullptr;
    void *tmpAddrPtr = nullptr;
    
    // 获取所有网络接口的信息
    if (getifaddrs(&ifAddrStruct) == -1) {
        throw std::runtime_error("Failed to get network interfaces");
    }

    // 遍历接口
    for (ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }
        
        // 检查是否是我们要找的接口，并且是一个IPv4地址
        if (ifa->ifa_name == ifaceName && ifa->ifa_addr->sa_family == AF_INET) {
            tmpAddrPtr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
            
            // 将IP地址转为字符串形式
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            
            // 返回找到的IP地址
            freeifaddrs(ifAddrStruct);
            return std::string(addressBuffer);
        }
    }

    // 如果没有找到有效的IP地址
    freeifaddrs(ifAddrStruct);
    throw std::runtime_error("interface " + ifaceName + " does not have a correct global unicast IP");
}

// 函数：检查是否是有效的 IP 地址
bool isValidIP(const std::string& ip) {
    struct sockaddr_in sa;
    // 检查 IPv4 地址
    if (inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) == 1) {
        return true;
    }
    // 检查 IPv6 地址
    struct sockaddr_in6 sa6;
    if (inet_pton(AF_INET6, ip.c_str(), &(sa6.sin6_addr)) == 1) {
        return true;
    }
    return false;
}

// // 函数：返回列表中第一个有效的 IP 地址
// std::string GetFirstValidIPString(const std::vector<std::string>& ipList) {
//     for (const auto& unparsedIP : ipList) {
//         // 将逗号分隔的字符串拆分
//         std::stringstream ss(unparsedIP);
//         std::string token;
//         while (std::getline(ss, token, ',')) {
//             // 检查 IP 是否有效
//             if (isValidIP(token)) {
//                 return token;
//             }
//         }
//     }
//     return ""; // 如果没有找到有效 IP，返回空字符串
// }

// 获取主机名，支持传递 nodeName 参数
std::string GetHostname(const std::string& nodeName) {
    if (!nodeName.empty()) {
        return nodeName; // 如果传入了 nodeName，直接返回它
    }

    // 如果没有传入 nodeName，获取系统默认的主机名
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        throw std::runtime_error("Failed to get hostname");
    }
    return std::string(hostname);
}

// 获取系统接口的 IP 地址
std::vector<std::string> GetHostIPs(const std::vector<std::string>& nodeIPs) {
    std::vector<std::string> ips;

    // 如果传入的 IP 地址列表为空，则尝试获取系统默认的 IP 地址
    if (nodeIPs.empty()) {
        struct ifaddrs *ifAddrStruct = nullptr;
        struct ifaddrs *ifa = nullptr;
        void *tmpAddrPtr = nullptr;

        // 获取所有接口的地址信息
        if (getifaddrs(&ifAddrStruct) == -1) {
            throw std::runtime_error("Failed to get network interfaces");
        }

        // 遍历每个网络接口，获取 IPv4 地址
        for (ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr) {
                continue;
            }

            // 检查接口是否是有效的 IPv4 地址
            if (ifa->ifa_addr->sa_family == AF_INET) {
                tmpAddrPtr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
                char addressBuffer[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
                ips.push_back(addressBuffer);
            }
        }

        freeifaddrs(ifAddrStruct);
    } else {
        // 如果提供了 IP 地址列表，直接返回
        for (const auto& ip : nodeIPs) {
            if (isValidIP(ip)) {
                ips.push_back(ip);
            } else {
                throw std::invalid_argument("Invalid IP address: " + ip);
            }
        }
    }

    return ips;
}

// 返回第一个有效的 IP 地址
std::string GetFirstValidIPString(const std::vector<std::string>& s) {
    for (const auto& unparsedIP : s) {
        // 使用 ',' 分割字符串
        std::stringstream ss(unparsedIP);
        std::string token;
        while (std::getline(ss, token, ',')) {
            // 检查每个 IP 是否有效
            if (isValidIP(token)) {
                return token;  // 返回第一个有效的 IP
            }
        }
    }
    return "";  // 如果没有找到有效 IP，返回空字符串
}

// 判断是否为有效的 IPv4 地址
bool IsIPv4(const std::string& ip) {
    struct sockaddr_in sa;
    // inet_pton 返回 1 表示有效的 IPv4 地址
    return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) == 1;
}

// 判断是否为有效的 IPv6 地址
bool IsIPv6(const std::string& ip) {
    struct sockaddr_in6 sa;
    // inet_pton 返回 1 表示有效的 IPv6 地址
    return inet_pton(AF_INET6, ip.c_str(), &(sa.sin6_addr)) == 1;
}

// Helper function to trim leading and trailing spaces
std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n\r");
    if (first == std::string::npos) {
        return "";  // No non-whitespace characters
    }
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, (last - first + 1));
}

// Function to parse and set the port range
bool setPortRange(PortRange& pr, const std::string& value) {
    const int SinglePortNotation = 1 << 0;
    const int HyphenNotation = 1 << 1;
    const int PlusNotation = 1 << 2;

    std::string trimmedValue = trim(value);  // Trim the string to remove any leading/trailing spaces
    size_t hyphenIndex = trimmedValue.find("-");
    size_t plusIndex = trimmedValue.find("+");

    if (trimmedValue.empty()) {
        pr.base = 0;
        pr.size = 0;
        return true;
    }

    int low = 0, high = 0;
    int notation = 0;
    bool errorOccurred = false;

    // Determine which notation is used
    if (hyphenIndex == std::string::npos && plusIndex == std::string::npos) {
        notation |= SinglePortNotation;
    }
    if (hyphenIndex != std::string::npos) {
        notation |= HyphenNotation;
    }
    if (plusIndex != std::string::npos) {
        notation |= PlusNotation;
    }

    switch (notation) {
        case SinglePortNotation:
            try {
                low = std::stoi(trimmedValue);
                high = low;
            } catch (const std::invalid_argument&) {
                errorOccurred = true;
            }
            break;

        case HyphenNotation:
            try {
                low = std::stoi(trimmedValue.substr(0, hyphenIndex));
                high = std::stoi(trimmedValue.substr(hyphenIndex + 1));
            } catch (const std::invalid_argument&) {
                errorOccurred = true;
            }
            break;

        case PlusNotation:
            try {
                low = std::stoi(trimmedValue.substr(0, plusIndex));
                int offset = std::stoi(trimmedValue.substr(plusIndex + 1));
                high = low + offset;
            } catch (const std::invalid_argument&) {
                errorOccurred = true;
            }
            break;

        default:
            errorOccurred = true;
            break;
    }

    if (errorOccurred) {
        std::cerr << "Error: Invalid port range format: " << value << std::endl;
        return false;
    }

    if (low > 65535 || high > 65535) {
        std::cerr << "Error: The port range cannot be greater than 65535: " << value << std::endl;
        return false;
    }

    if (high < low) {
        std::cerr << "Error: End port cannot be less than start port: " << value << std::endl;
        return false;
    }

    pr.base = low;
    pr.size = high - low + 1;  // Size of the range

    return true;
}

// Function to parse a port range string and return a PortRange object
std::unique_ptr<PortRange> parsePortRange(const std::string& value) {
    auto pr = std::make_unique<PortRange>();  // Dynamically allocate a new PortRange
    if (setPortRange(*pr, value)) {
        return pr;  // Return the pointer to the valid PortRange
    } else {
        return nullptr;  // Return null if there was an error
    }
}

// Function to get the minimum value between two integers
int min(int a, int b) {
    return a < b ? a : b;
}

// 计算子网范围的大小
long long RangeSize(const IPNet& subnet) {
    int ones = subnet.countOnes();
    int bits = subnet.getBits();

    if ((bits == 32 && (bits - ones) >= 31) || (bits == 128 && (bits - ones) >= 127)) {
        return 0;
    }

    // 检查是否溢出 int64
    if (bits - ones >= 63) {
        return LLONG_MAX; // C++ 的最大值
    }

    return static_cast<long long>(1) << (bits - ones); // 使用位移操作
}

// ServiceIPRange function equivalent in C++
// This version returns only the API server service IP (struct in_addr).
IP ServiceIPRange(const IPNet& passedServiceClusterIPRange) {
    IPNet serviceClusterIPRange = passedServiceClusterIPRange;

    // Default CIDR (simulating kubeoptions.DefaultServiceIPCIDR)
    IP defaultIp("10.0.0.0");
    std::vector<uint8_t> mask = {255, 255, 255, 0}; // 子网掩码 255.255.255.0
    const IPNet DefaultServiceIPCIDR = IPNet(defaultIp,mask);  // This is just an example

    if (RangeSize(serviceClusterIPRange) == 0) {
        std::cerr << "No CIDR for service cluster IPs specified. Default value which was " << DefaultServiceIPCIDR.toString()
                  << " is deprecated and will be removed in future releases. Please specify it using --service-cluster-ip-range on kube-apiserver." << std::endl;

        // Use default CIDR if not passed
        serviceClusterIPRange = IPNet(DefaultServiceIPCIDR);
    }

    int size = min(RangeSize(serviceClusterIPRange), 1 << 16);
    if (size < 8) {
        std::cerr << "The service cluster IP range must be at least 8 IP addresses" << std::endl;
        return IP("");  // Return an empty in_addr on error
    }

    // Get the first valid IP from the range to use as the GenericAPIServer service IP
    IP apiServerServiceIP = serviceClusterIPRange.ip;

    std::cout << "Setting service IP to " << apiServerServiceIP.toString() << " (read-write)." << std::endl;

    // Return the API Server Service IP
    return apiServerServiceIP;
}

// Validate Network Configuration Function
bool validateNetworkConfiguration(const Config& serverConfig) {
    if(serverConfig.ControlConfig.EgressSelectorMode=="cluster"||serverConfig.ControlConfig.EgressSelectorMode=="pod"){
        // No action needed for valid modes
        return true;
    }else if(serverConfig.ControlConfig.EgressSelectorMode=="agent"||serverConfig.ControlConfig.EgressSelectorMode=="disabled"){
        if (serverConfig.ControlConfig.DisableAgent) {
            spdlog::warn("Webhooks and apiserver aggregation may not function properly without an agent; please set egress-selector-mode to 'cluster' or 'pod'");
        }
        return true;
    }else{
        throw std::invalid_argument("Invalid egress-selector-mode");
        return false;
    }
}

// 获取当前用户的主目录
std::string getUserHomeDir() {
    const char* homeDir = std::getenv("HOME");
    if (homeDir) {
        return std::string(homeDir);
    } else {
        // 如果没有通过环境变量获取 HOME，则使用 getpwuid 获取
        struct passwd* pw = getpwuid(getuid());
        if (pw) {
            return std::string(pw->pw_dir);
        } else {
            throw std::runtime_error("Unable to determine the current user's home directory");
        }
    }
}

// homes 列表
std::vector<std::string> homes = {"$HOME", "${HOME}", "~"};

// 解析路径中的 home 替换
std::string Resolve(std::string s) {
    try {
        std::string homeDir = getUserHomeDir();

        // 遍历 homes 列表并替换路径
        for (const auto& home : homes) {
            size_t pos = 0;
            while ((pos = s.find(home, pos)) != std::string::npos) {
                s.replace(pos, home.length(), homeDir);
                pos += homeDir.length(); // 移动到替换后的位置
            }
        }
    } catch (const std::exception& e) {
        throw std::runtime_error("Error resolving home directory: " + std::string(e.what()));
    }

    return s;
}

// LocalHome 函数：返回解析后的路径，如果 dataDir 为空则使用默认值
std::string LocalHome(const std::string& dataDir, bool forceLocal) {
    std::string finalDataDir = dataDir;
    
    // 如果传入的 dataDir 为空，根据用户身份选择默认路径
    if (finalDataDir.empty()) {
        if (getuid() == 0 && !forceLocal) {  // root 用户
            finalDataDir = "/var/lib/rancher/k3s";  // 默认的路径
        } else {
            finalDataDir = "${HOME}/.rancher/k3s";  // 默认的用户路径
        }
    }

    // 解析路径
    try {
        finalDataDir = Resolve(finalDataDir);
    } catch (const std::exception& e) {
        throw std::runtime_error("Error resolving data directory: " + std::string(e.what()));
    }

    // 获取绝对路径
    try {
        fs::path absPath = fs::absolute(finalDataDir);
        return absPath.string();
    } catch (const std::exception& e) {
        throw std::runtime_error("Error getting absolute path: " + std::string(e.what()));
    }
}

// 模拟的 ciphers 和 insecureCiphers 集合 (示例数据)
std::map<std::string, uint16_t> ciphers() {
    return {
        {"TLS_AES_128_GCM_SHA256", 0x1301},
        {"TLS_AES_256_GCM_SHA384", 0x1302},
        {"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 0xc02c},
        {"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 0xc030},
        {"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",0xc02b},
        {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",0xc02f},
        {"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",0xcca9},
        {"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",0xcca8}
        // 添加更多的密码套件
    };
}

std::map<std::string, uint16_t> insecureCiphers() {
    return {
        {"TLS_RSA_WITH_RC4_128_SHA", 0x0005},
        {"TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x000a},
        {"TLS_RSA_WITH_AES_128_CBC_SHA256",0x003c},
        {"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",0xc007},
        {"TLS_ECDHE_RSA_WITH_RC4_128_SHA",0xc011},
        {"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",0xc012},
        {"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",0xc023},
        {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",0xc027}
        // 添加更多的密码套件
    };
}

// allCiphers 函数：合并 ciphers 和 insecureCiphers，并返回所有可用的密码套件映射
std::map<std::string, uint16_t> allCiphers() {
    std::map<std::string, uint16_t> acceptedCiphers;

    // 合并 ciphers
    for (const auto& cipher : ciphers()) {
        acceptedCiphers[cipher.first] = cipher.second;
    }

    // 合并 insecureCiphers
    for (const auto& cipher : insecureCiphers()) {
        acceptedCiphers[cipher.first] = cipher.second;
    }

    return acceptedCiphers;
}

// TLSCipherSuites 函数：返回从密码套件名称列表转换得到的密码套件 ID 列表
std::vector<uint16_t> TLSCipherSuites(const std::vector<std::string>& cipherNames) {
    // 如果输入为空，直接返回空的结果
    if (cipherNames.empty()) {
        return {};
    }

    // 获取所有可能的密码套件
    std::map<std::string, uint16_t> possibleCiphers = allCiphers();
    std::vector<uint16_t> ciphersIntSlice;

    // 遍历输入的密码套件名称列表
    for (const auto& cipher : cipherNames) {
        // 查找密码套件名称对应的整数值
        auto it = possibleCiphers.find(cipher);
        if (it == possibleCiphers.end()) {
            throw std::runtime_error("Cipher suite " + cipher + " not supported or doesn't exist");
        }
        // 将对应的整数值添加到结果列表中
        ciphersIntSlice.push_back(it->second);
    }

    return ciphersIntSlice;
}

std::string GetFirstValidInterface() {
    struct ifaddrs *ifAddrStruct = nullptr;
    struct ifaddrs *ifa = nullptr;

    // 获取所有网络接口的信息
    if (getifaddrs(&ifAddrStruct) == -1) {
        std::cerr << "Failed to get network interfaces" << std::endl;
        return "";  // 如果获取失败，返回空字符串
    }

    // 遍历接口列表，寻找第一个有效接口
    for (ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) {
            continue;  // 跳过没有地址信息的接口
        }

        // 检查接口类型是否为IPv4
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)ifa->ifa_addr;
            char ipAddress[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ipv4->sin_addr), ipAddress, INET_ADDRSTRLEN);

            if (strcmp(ipAddress, "127.0.0.1") != 0) {
                // 这里 ipAddress 不是 "127.0.0.1"，执行相应的操作
                // 找到第一个有效的IPv4接口，返回接口名称
                std::string interfaceName = ifa->ifa_name;
                freeifaddrs(ifAddrStruct);  // 释放内存
                return interfaceName;
            }
        }
    }

    // 如果没有找到有效的IPv4接口，返回空字符串
    freeifaddrs(ifAddrStruct);
    return "";
}

// 函数：计算根据CIDR前缀长度计算掩码
std::vector<uint8_t> calculateMask(int prefixLength) {
    std::vector<uint8_t> mask(4, 0);  // 初始化为0，表示四个字节
    int remainingBits = prefixLength;
    for (int i = 0; i < 4 && remainingBits > 0; ++i) {
        if (remainingBits >= 8) {
            mask[i] = 255;  // 设置8个1
            remainingBits -= 8;
        } else {
            mask[i] = (255 << (8 - remainingBits));  // 设置剩余的位
            remainingBits = 0;  // 完成掩码设置
        }
    }
    return mask;
}
void StartServer(Context ctx, Config* config, cmds::Server* server) {
    // 初始化数据目录并切换目录
    // setupDataDirAndChdir(&config->ControlConfig);

    // 设置无代理环境变量
    // setNoProxyEnv(&config->ControlConfig);

    // 启动 Kubernetes 控制平面
    Server(ctx, &config->ControlConfig);

    // 启动在 API 服务器就绪时的操作
    // startOnAPIServerReady(ctx, config);

    // 打印令牌
    // printTokens(&config->ControlConfig);

    // 写入 Kubernetes 配置
    // writeKubeConfig(config->ControlConfig.Runtime.ServerCA, config);
}

// 处理服务器命令的函数
int server_run(boost::program_options::variables_map& vm,Server_user& config, CustomControllers& leaderControllers, CustomControllers& controllers) {
    // spdlog::info("Starting server with config file: {}", config.config_file);
    // spdlog::info("Port: {}", config.port);
    // spdlog::info("Logging enabled: {}", config.enable_logging);

    // 服务器启动逻辑
    spdlog::info("Server is running...");
    // 将进程的标题设置为k3s server，隐藏敏感参数
    prctl(PR_SET_NAME, "k3s server", 0, 0, 0);
    // 初始化 oatpp 环境
    oatpp::base::Environment::init();
    // 初始化日志系统
    spdlog::info("Initializing logging system...");

    Config server;
    Agent agentConfig;
    server.DisableAgent = config.DisableAgent;
    //server.ControlConfig.Runtime = config.NewRuntime(containerRuntimeReady)
	server.ControlConfig.Token = config.Token;
	server.ControlConfig.AgentToken = config.AgentToken;
	server.ControlConfig.JoinURL = config.ServerURL;
	if (config.AgentTokenFile != "" ){
		server.ControlConfig.AgentToken = ReadFile(config.AgentTokenFile);
	}
	if (config.TokenFile != "" ){
		server.ControlConfig.Token = ReadFile(config.TokenFile);
	}
	server.ControlConfig.DataDir = config.DataDir;
	server.ControlConfig.KubeConfigOutput = config.KubeConfigOutput;
	server.ControlConfig.KubeConfigMode = config.KubeConfigMode;
	server.ControlConfig.KubeConfigGroup = config.KubeConfigGroup;
	server.ControlConfig.HelmJobImage = config.HelmJobImage;
	server.ControlConfig.Rootless = config.Rootless;
	server.ControlConfig.ServiceLBNamespace = config.ServiceLBNamespace;
	server.ControlConfig.SANs = SplitStringSlice(config.TLSSan);
	server.ControlConfig.SANSecurity = config.TLSSanSecurity;
	server.ControlConfig.BindAddress = agentConfig.BindAddress;
	server.ControlConfig.SupervisorPort = config.SupervisorPort;
	server.ControlConfig.HTTPSPort = config.HTTPSPort;
	server.ControlConfig.APIServerPort = config.APIServerPort;
	server.ControlConfig.APIServerBindAddress = config.APIServerBindAddress;
	server.ControlConfig.ExtraAPIArgs = config.ExtraAPIArgs;
	server.ControlConfig.ExtraControllerArgs = config.ExtraControllerArgs;
	server.ControlConfig.ExtraEtcdArgs = config.ExtraEtcdArgs;
	server.ControlConfig.ExtraSchedulerAPIArgs = config.ExtraSchedulerArgs;
	server.ControlConfig.ClusterDomain = config.ClusterDomain;
    std::chrono::seconds interval(5);  // 5 seconds
	server.ControlConfig.Datastore.NotifyInterval = interval;
	server.ControlConfig.Datastore.Endpoint = config.DatastoreEndpoint;
	server.ControlConfig.Datastore.BackendTLSConfig.CAFile = config.DatastoreCAFile;
	server.ControlConfig.Datastore.BackendTLSConfig.CertFile = config.DatastoreCertFile;
	server.ControlConfig.Datastore.BackendTLSConfig.KeyFile = config.DatastoreKeyFile;
	server.ControlConfig.KineTLS = config.KineTLS;
	server.ControlConfig.AdvertiseIP = config.AdvertiseIP;
	server.ControlConfig.AdvertisePort = config.AdvertisePort;
	server.ControlConfig.FlannelBackend = config.FlannelBackend;
	server.ControlConfig.FlannelIPv6Masq = config.FlannelIPv6Masq;
	server.ControlConfig.FlannelExternalIP = config.FlannelExternalIP;
	server.ControlConfig.EgressSelectorMode = config.EgressSelectorMode;
	server.ControlConfig.ExtraCloudControllerArgs = config.ExtraCloudControllerArgs;
	server.ControlConfig.DisableCCM = config.DisableCCM;
	server.ControlConfig.DisableNPC = config.DisableNPC;
	server.ControlConfig.DisableHelmController = config.DisableHelmController;
	server.ControlConfig.DisableKubeProxy = config.DisableKubeProxy;
	server.ControlConfig.DisableETCD = config.DisableETCD;
	server.ControlConfig.DisableAPIServer = config.DisableAPIServer;
	server.ControlConfig.DisableScheduler = config.DisableScheduler;
	server.ControlConfig.DisableControllerManager = config.DisableControllerManager;
	server.ControlConfig.DisableAgent = config.DisableAgent;
	server.ControlConfig.EmbeddedRegistry = config.EmbeddedRegistry;
	server.ControlConfig.ClusterInit = config.ClusterInit;
	server.ControlConfig.EncryptSecrets = config.EncryptSecrets;
	server.ControlConfig.EtcdExposeMetrics = config.EtcdExposeMetrics;
	server.ControlConfig.EtcdDisableSnapshots = config.EtcdDisableSnapshots;
	server.ControlConfig.SupervisorMetrics = config.SupervisorMetrics;
    Log LogConfig;
	server.ControlConfig.VLevel = LogConfig.VLevel;
	server.ControlConfig.VModule = LogConfig.VModule;

    if(!config.EtcdDisableSnapshots || config.ClusterReset){
        server.ControlConfig.EtcdSnapshotCompress = config.EtcdSnapshotCompress;
		server.ControlConfig.EtcdSnapshotName = config.EtcdSnapshotName;
		server.ControlConfig.EtcdSnapshotCron = config.EtcdSnapshotCron;
		server.ControlConfig.EtcdSnapshotDir = config.EtcdSnapshotDir;
		server.ControlConfig.EtcdSnapshotRetention = config.EtcdSnapshotRetention;
		if(config.EtcdS3){
            config.EtcdS3->AccessKey = config.EtcdS3AccessKey;
            config.EtcdS3->Bucket = config.EtcdS3BucketName;
            config.EtcdS3->ConfigSecret = config.EtcdS3ConfigSecret;
            config.EtcdS3->Endpoint = config.EtcdS3Endpoint;
            config.EtcdS3->EndpointCA = config.EtcdS3EndpointCA;
            config.EtcdS3->Folder = config.EtcdS3Folder;
            config.EtcdS3->Insecure = config.EtcdS3Insecure;
            config.EtcdS3->Proxy = config.EtcdS3Proxy;
            config.EtcdS3->Region = config.EtcdS3Region;
            config.EtcdS3->SecretKey = config.EtcdS3SecretKey;
            config.EtcdS3->SkipSSLVerify = config.EtcdS3SkipSSLVerify;
            config.EtcdS3->Timeout = config.EtcdS3Timeout;
			server.ControlConfig.EtcdS3 = config.EtcdS3;
		}
    }else{
        spdlog::info("ETCD snapshots are disabled");       
    }

    if (config.ClusterResetRestorePath != "" && !config.ClusterReset ){
		spdlog::info("invalid flag use; --cluster-reset required with --cluster-reset-restore-path");
        return 1;
	}

	server.ControlConfig.ClusterReset = config.ClusterReset;
	server.ControlConfig.ClusterResetRestorePath = config.ClusterResetRestorePath;
	server.ControlConfig.SystemDefaultRegistry = config.SystemDefaultRegistry;

    if (server.ControlConfig.SupervisorPort == 0 ){
		server.ControlConfig.SupervisorPort = server.ControlConfig.HTTPSPort;
	}

	if (server.ControlConfig.DisableETCD && server.ControlConfig.JoinURL == "") {
		spdlog::info("invalid flag use; --server is required with --disable-etcd");
        return 1;
	}

	if (server.ControlConfig.Datastore.Endpoint != "" && server.ControlConfig.DisableAPIServer) {
		spdlog::info("invalid flag use; cannot use --disable-apiserver with --datastore-endpoint");
        return 1;		
	}

	if (server.ControlConfig.Datastore.Endpoint != "" && server.ControlConfig.DisableETCD) {
		spdlog::info("invalid flag use; cannot use --disable-etcd with --datastore-endpoint");
        return 1;			
	}

	if (server.ControlConfig.DisableAPIServer){
		// Servers without a local apiserver need to connect to the apiserver via the proxy load-balancer.
		server.ControlConfig.APIServerPort = agentConfig.LBServerPort;
		// If the supervisor and externally-facing apiserver are not on the same port, the proxy will
		// have a separate load-balancer for the apiserver that we need to use instead.
		if(server.ControlConfig.SupervisorPort != server.ControlConfig.HTTPSPort){
			server.ControlConfig.APIServerPort = agentConfig.LBServerPort - 1;
		}
	}

    agentConfig.FlannelIface = GetFirstValidInterface();
    agentConfig.NodeIP.push_back("");
	if (agentConfig.FlannelIface != "" && strlen(agentConfig.NodeIP[0].c_str())== 0){
		std::string ip = GetIPFromInterface(agentConfig.FlannelIface);
		agentConfig.NodeIP[0] = ip;
	}else{
        std::cerr << "Error: FlannelIface is empty." << std::endl;
        return 1;
    }

	if (server.ControlConfig.PrivateIP == "" && strlen(agentConfig.NodeIP[0].c_str()) != 0 ){
		server.ControlConfig.PrivateIP = GetFirstValidIPString(agentConfig.NodeIP);
	}

	// Ensure that we add the localhost name/ip and node name/ip to the SAN list. This list is shared by the
	// certs for the supervisor, kube-apiserver cert, and etcd. DNS entries for the in-cluster kubernetes
	// service endpoint are added later when the certificates are created.
	// 确保将本地节点的名称（hostname）和IP地址（包括本机的127.0.0.1和::1地址）添加到Subject Alternative Name (SAN) 列表中，用于生成和管理与Kubernetes集群相关的TLS证书。
	//nodeName, nodeIPs, err := util.GetHostnameAndIPs(cmds.AgentConfig.NodeName, cmds.AgentConfig.NodeIP);
	std::string nodeName = GetHostname(agentConfig.NodeName);
	std::vector<std::string> nodeIPs = GetHostIPs(agentConfig.NodeIP);


	server.ControlConfig.ServerNodeName = nodeName;
	server.ControlConfig.SANs.push_back("127.0.0.1");
	server.ControlConfig.SANs.push_back("::1");	
	server.ControlConfig.SANs.push_back("localhost");	
	server.ControlConfig.SANs.push_back(nodeName);			
	
	// 处理返回的 IP 列表
    for (const auto& ip : nodeIPs) {
        server.ControlConfig.SANs.push_back(ip);
    }

	// 设置advertiseIP
	// // 通过外部 IP 和节点 IP 设置 AdvertiseIP
	// // if not set, try setting advertise-ip from agent node-external-ip
	// if (server.ControlConfig.AdvertiseIP == "" && strlen(agentConfig.NodeExternalIP[0].c_str()) != 0 ){
	// 	server.ControlConfig.AdvertiseIP = GetFirstValidIPString(agentConfig.NodeExternalIP);
	// }

	// if not set, try setting advertise-ip from agent node-ip
	if (server.ControlConfig.AdvertiseIP == "" && strlen(agentConfig.NodeIP[0].c_str()) != 0) {
		server.ControlConfig.AdvertiseIP = GetFirstValidIPString(agentConfig.NodeIP);
	}

	// if we ended up with any advertise-ips, ensure they're added to the SAN list;
	// note that kube-apiserver does not support dual-stack advertise-ip as of 1.21.0:
	/// https://github.com/kubernetes/kubeadm/issues/1612#issuecomment-772583989
	if (server.ControlConfig.AdvertiseIP != "" ){
		server.ControlConfig.SANs.push_back(server.ControlConfig.AdvertiseIP);
	}

	// 配置 Kubernetes 集群的 ClusterIPRanges，即集群内部用于通信的 IP 地址范围。
	std::string	ListenAddress = "";
	std::string	clusterCIDR = "";
	std::string	serviceCIDR = "";	
	if(IsIPv4(nodeIPs[0])){
		ListenAddress = "0.0.0.0";
		clusterCIDR = "10.42.0.0/16";
		serviceCIDR = "10.43.0.0/16";
	}
	else if(IsIPv6(nodeIPs[0])) {
		ListenAddress = "::";
		clusterCIDR = "fd00:42::/56";
		serviceCIDR = "fd00:43::/112";
	}else{
		ListenAddress = "";
		clusterCIDR = "";
		serviceCIDR = "";
		spdlog::info("ip: %v is not ipv4 or ipv6", nodeIPs[0]);	
	}

    // 检查 ClusterCIDR 是否为空，如果为空，则设置为默认值
    if (clusterCIDR.empty()) {
        std::cerr << "Error: ClusterCIDR is empty." << std::endl;
        return 1;
    }

    // 假设 config.ClusterCIDR 是一个包含 CIDR 字符串的 vector
    std::vector<std::string> configClusterCIDR = { clusterCIDR };

    // 循环处理每个 CIDR
    for (const auto& cidr : configClusterCIDR) {
        std::vector<std::string> cidrList = splitString(cidr, ',');       
        for (const auto& singleCIDR : cidrList) {
            size_t slashPos = singleCIDR .find('/');
            std::string ipAddress;
            std::vector<uint8_t> mask = {255, 255, 255, 0};  // subnet mask
            if (slashPos != std::string::npos) {
                ipAddress = singleCIDR .substr(0, slashPos);   // Get IP address part
                int prefixLength = std::stoi(singleCIDR.substr(slashPos + 1));  // 获取CIDR前缀长度
                mask = calculateMask(prefixLength);  // 根据前缀长度计算掩码
            } else {
                throw std::invalid_argument("Invalid singleCIDR format");
            }       
            IPNet parsed = IPNet(IP(ipAddress),mask);
            // if (!parseCIDR(ipAddress, parsed)) {
            //     std::cerr << "Invalid service-cidr " << singleCIDR << std::endl;
            //     return 1;  // 错误处理，返回非零状态
            // }
            // 使用 std::make_shared 包装 parsed 对象
            std::shared_ptr<IPNet> parsedPtr1 = std::make_shared<IPNet>(parsed);
            // 将有效的 CIDR 解析结果添加到 ServiceIPRanges
            server.ControlConfig.ClusterIPRanges.push_back(parsedPtr1);
        }
    }


	// set ClusterIPRange to the first address (first defined IPFamily is preferred)
	server.ControlConfig.ClusterIPRange = server.ControlConfig.ClusterIPRanges[0];

	// configure ServiceIPRanges. Use default 10.43.0.0/16 or fd00:43::/112 if user did not set it
	config.ServiceCIDR.push_back("");
    if (strlen(config.ServiceCIDR[0].c_str()) == 0){
		config.ServiceCIDR[0] = serviceCIDR;
	}
	// Loop through each CIDR
    for (const auto& cidr : config.ServiceCIDR) {
        // Split the CIDR string by ',' (if multiple CIDRs are provided as a comma-separated list)
        std::vector<std::string> cidrList = splitString(cidr, ',');
        for (const auto& singleCIDR : cidrList) {
            size_t slashPos = singleCIDR .find('/');
            std::string ipAddress;
            std::vector<uint8_t> mask = {255, 255, 255, 0};  // subnet mask
            if (slashPos != std::string::npos) {
                ipAddress = singleCIDR .substr(0, slashPos);   // Get IP address part
                int prefixLength = std::stoi(singleCIDR.substr(slashPos + 1));  // 获取CIDR前缀长度
                mask = calculateMask(prefixLength);  // 根据前缀长度计算掩码
            } else {
                throw std::invalid_argument("Invalid singleCIDR format");
            }       
            IPNet parsedIP = IPNet(IP(ipAddress),mask);
            // if (!parseCIDR(ipAddress, parsed)) {
            //     std::cerr << "Invalid service-cidr " << singleCIDR << std::endl;
            //     return 1;  // 错误处理，返回非零状态
            // }
            // 使用 std::make_shared 包装 parsed 对象
            std::shared_ptr<IPNet> parsedPtr = std::make_shared<IPNet>(parsedIP);
            // Add valid parsed CIDR to ClusterIPRanges
            server.ControlConfig.ServiceIPRanges.push_back(parsedPtr);
        }
    }
	
	// set ServiceIPRange to the first address (first defined IPFamily is preferred)
	server.ControlConfig.ServiceIPRange = server.ControlConfig.ServiceIPRanges[0];

	server.ControlConfig.ServiceNodePortRange = parsePortRange(config.ServiceNodePortRange);

	// the apiserver service does not yet support dual-stack operation
	std::string apiServerServiceIP = ServiceIPRange(*server.ControlConfig.ServiceIPRanges[0]).toString();

	server.ControlConfig.SANs.push_back(apiServerServiceIP);

    // If ClusterDNS is not set, try to compute it based on ServiceCIDR
    if (server.ControlConfig.ClusterDNS.empty()) {
        bool foundIPv4 = false;
        for (const auto& svcCIDR : server.ControlConfig.ServiceIPRanges) {
            // Here we assume the svcCIDR is in the format "IP/Netmask"
            //size_t slashPos = svcCIDR->toString().find('/');
            // if (slashPos == std::string::npos) {
            //     std::cerr << "Error: Invalid service-cidr " << svcCIDR << std::endl;
            //     return 1;
            // }

            std::string ipStr = svcCIDR->toString();
            struct in_addr ipParsed;
            if (!parseIP(ipStr, ipParsed)) {
                spdlog::info("Error: Invalid service-cidr IP {}", ipStr);
                return 1;
            }

            // Get the "indexed" IP (add 10 to the last byte)
			std::string clusterDNS = getIndexedIP(svcCIDR->toString(), 10);
            server.ControlConfig.ClusterDNSs.push_back(clusterDNS);
            foundIPv4 = true;
        }
        if (!foundIPv4) {
            std::cerr << "Error: No valid IPv4 service CIDR found" << std::endl;
			spdlog::info("Error: No valid IPv4 service CIDR found" );
            return 1;
        }
    } 
	else{
        // If ClusterDNS is set, parse and validate the addresses
		std::vector<std::string> cdnsList = splitString(server.ControlConfig.ClusterDNS, ',');
        for (const auto& ip : cdnsList) {
            struct in_addr parsedIP;
            if (!parseIP(ip, parsedIP)) {
                std::cerr << "Error: invalid cluster-dns address " << ip << std::endl;
				spdlog::info("Error: invalid cluster-dns address " );
                return 1;
            }
            server.ControlConfig.ClusterDNSs.push_back(ip);
        }
    }

	server.ControlConfig.ClusterDNS = server.ControlConfig.ClusterDNSs[0];

	if(!validateNetworkConfiguration(server)){
        std::cerr << "Error: validateNetworkConfiguration" << std::endl;
		spdlog::info("Error: validateNetworkConfiguration");		
	}

	if (config.DefaultLocalStoragePath == "") {
		std::string dataDir = LocalHome(config.DataDir, false);
		std::string filepath = "";
		filepath.append(dataDir);
		filepath.append("/storage");
		server.ControlConfig.DefaultLocalStoragePath = filepath;
	} else {
		server.ControlConfig.DefaultLocalStoragePath = config.DefaultLocalStoragePath;
	}
    
	server.ControlConfig.Skips = std::map<std::string, bool>();
    server.ControlConfig.Disables = std::map<std::string, bool>();


    // 提取disable_str
    std::vector<std::string> disable_str;

    // 如果存在disable选项
    if (vm.count("disable")) {
        disable_str = vm["disable"].as<std::vector<std::string>>();
    }
    
    // 处理每个 disable 值
    for (auto& disable : disable_str) {
        TrimString(disable);  // 去掉前后空白字符
        server.ControlConfig.Skips[disable] = true;
        server.ControlConfig.Disables[disable] = true;
    }

    // 如果 skips 中包含 "servicelb"，则禁用 ServiceLB
    if (server.ControlConfig.Skips["servicelb"]) {
        server.ControlConfig.DisableServiceLB = true;
    }

    // 如果同时禁用了 CCM 和 ServiceLB，禁用 "ccm"
    if (server.ControlConfig.DisableCCM && server.ControlConfig.DisableServiceLB) {
        server.ControlConfig.Skips["ccm"] = true;
        server.ControlConfig.Disables["ccm"] = true;
    }

	 // 获取 tls-min-version 参数值
    std::string tlsMinVersionArg = getArgValueFromList("tls-min-version", server.ControlConfig.ExtraAPIArgs);
    server.ControlConfig.MinTLSVersion = tlsMinVersionArg;
	
	try {
        // 转换为整数表示的 TLS 版本
        server.ControlConfig.TLSMinVersion = TLSVersion(tlsMinVersionArg);
        std::cout << "TLS Min Version: " << server.ControlConfig.MinTLSVersion << std::endl;
    } catch (const std::invalid_argument& e) {
        // 处理错误，类似 Go 中的 errors.Wrap
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;  // 返回非零值表示错误
    }

	// 将 cfg.StartupHooks, leaderControllers 和 controllers 添加到 serverConfig 中
    server.StartupHooks.insert(server.StartupHooks.end(), config.StartupHooks.begin(), config.StartupHooks.end());
    
    // 将 leaderControllers 中的所有控制器添加到 server.LeaderControllers
    for (auto& controller : leaderControllers.controllers) {
        server.LeaderControllers.addController(controller);  // 添加控制器
    }

    // 将 Controllers 中的所有控制器添加到 server.Controllers
    for (auto& controller : controllers.controllers) {
        server.Controllers.addController(controller);  // 添加控制器
    }
    
	// Get the "tls-cipher-suites" value from ExtraAPIArgs
    std::string tlsCipherSuitesArg = getArgValueFromList("tls-cipher-suites", server.ControlConfig.ExtraAPIArgs);

    // 将 tls-cipher-suites 字符串按照逗号分割
    std::vector<std::string> tlsCipherSuites;
    if (!tlsCipherSuitesArg.empty()) {
        std::stringstream ss(tlsCipherSuitesArg);
        std::string cipher;
        while (std::getline(ss, cipher, ',')) {
            // 去除每个密码套件中的空格
            cipher.erase(std::remove_if(cipher.begin(), cipher.end(), ::isspace), cipher.end());
            tlsCipherSuites.push_back(cipher);
        }
    }
    
    // 如果没有密码套件，使用默认密码套件
    if (tlsCipherSuites.empty() || tlsCipherSuites[0].empty()) {
        tlsCipherSuites = {
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
        };
    }

    // 拼接密码套件为一个字符串
    std::string joinedCipherSuites;
    for (size_t i = 0; i < tlsCipherSuites.size(); ++i) {
        joinedCipherSuites += tlsCipherSuites[i];
        if (i != tlsCipherSuites.size() - 1) {
            joinedCipherSuites += ",";
        }
    }
    
    // 将密码套件更新回 ExtraAPIArgs
    server.ControlConfig.ExtraAPIArgs.push_back("tls-cipher-suites=" + joinedCipherSuites);
	
	server.ControlConfig.CipherSuites = tlsCipherSuites;

	server.ControlConfig.TLSCipherSuites = TLSCipherSuites(tlsCipherSuites);

	// If performing a cluster reset, make sure control-plane components are
	// disabled so we only perform a reset or restore and bail out.
	Version version;
	if(config.ClusterReset){
		server.ControlConfig.ClusterInit = true;
		server.ControlConfig.DisableAPIServer = true;
		server.ControlConfig.DisableControllerManager = true;
		server.ControlConfig.DisableScheduler = true;
		server.ControlConfig.DisableCCM = true;
		server.ControlConfig.DisableServiceLB = true;

		// If the supervisor and apiserver are on the same port, everything is running embedded
		// and we don't need the kubelet or containerd up to perform a cluster reset.
		if (server.ControlConfig.SupervisorPort == server.ControlConfig.HTTPSPort){
			config.DisableAgent = true;
		}

		// If the user uses the cluster-reset argument in a cluster that has a ServerURL, we must return an error
		// to remove the server flag on the configuration or in the cli
		if (server.ControlConfig.JoinURL != "" ){
			std::cout<<"cannot perform cluster-reset while server URL is set - remove server from configuration before resetting"<<std::endl;
		}

		std::string dataDir = LocalHome(config.DataDir, false);

		// delete local loadbalancers state for apiserver and supervisor servers
		// 删除本地负载均衡器的状态文件

    	std::string SupervisorServiceName = version.Program + "-agent-load-balancer";
		std::string APIServerServiceName  = version.Program + "-api-server-agent-load-balancer";
		
		ResetLoadBalancer(dataDir + "/agent", SupervisorServiceName);
    	ResetLoadBalancer(dataDir + "/agent", APIServerServiceName);

		if(config.ClusterResetRestorePath!=""){
			// at this point we're doing a restore. Check to see if we've
			// passed in a token and if not, check if the token file exists.
			// If it doesn't, return an error indicating the token is necessary.
			if(config.Token == ""){
				// Construct the file path
       		    fs::path tokenFile = fs::path(dataDir) / "server" / "token";
        	    // Check if the file exists
        	    if (!fs::exists(tokenFile)) {
            		// If file does not exist, throw an error
            		std::cout<<(tokenFile.string() + " does not exist, please pass --token to complete the restoration")<<std::endl;
        		}
			}
		}
	}
	spdlog::info("Starting " + version.Program + " " + "app... App.Version "+"v1.0");
    // 获取环境变量 NOTIFY_SOCKET 的值
    const char* notifySocket = std::getenv("NOTIFY_SOCKET");
    // 检查是否获取到环境变量
    if (notifySocket != nullptr) {
        std::cout << "NOTIFY_SOCKET = " << notifySocket << std::endl;
    } else {
        std::cout << "NOTIFY_SOCKET is not set." << std::endl;
    }
    // 删除环境变量 NOTIFY_SOCKET
    unsetenv("NOTIFY_SOCKET");
    std::cout << "NOTIFY_SOCKET has been unset." << std::endl;
   // 为 HTTP 请求创建路由器
    auto router = oatpp::web::server::HttpRouter::createShared();
    // 路由 GET - "/index" 请求到处理程序
    router->route("GET", "/index", std::make_shared<Handler>());
    // 创建 HTTP 连接处理程序
    auto connectionHandler = oatpp::web::server::HttpConnectionHandler::createShared(router);
    // 创建 TCP 连接提供者
    auto connectionProvider = oatpp::network::tcp::server::ConnectionProvider::createShared({server.ControlConfig.PrivateIP, 8080, oatpp::network::Address::IP_4});
    // 创建服务器，它接受提供的 TCP 连接并将其传递给 HTTP 连接处理程序
    oatpp::network::Server oatpp_server(connectionProvider, connectionHandler);
    // 打印服务器端口
    OATPP_LOGI("MyApp", "Server running on %s:%s", connectionProvider->getProperty("host").getData(),connectionProvider->getProperty("port").getData());
    // 运行服务器
    oatpp_server.run();
    // // 启动信号处理：ctx := signals.SetupSignalContext()用于捕获和处理系统信号，确保程序在收到信号时能安全退出。
	// ctx = SetupSignalContext();

    // // 启动服务器：调用server.StartServer(ctx, &serverConfig, cfg)启动控制平面各组件（如API服务器、etcd、控制器等）。
	StartServer(ctx, &server, config);
    
    // // 健康检查和系统通知：监听API服务器和etcd的状态，确保其已启动并且处于运行状态。
    // // 模拟启动服务器状态
    // std::thread serverStateThread(simulateServerState, std::ref(server));
    // // 假设系统通知的socket路径
    // std::string notifySocket = "/run/systemd/notify";
    // // 健康检查与系统通知
    // healthCheck(server, notifySocket);
    // serverStateThread.join();  // 等待服务器状态模拟线程完成

    // // URL 格式化
    // BindAddress = server.ControlConfig.BindAddress;  // 设置为空表示需要选择主机接口
    // std::ostringstream urlStream;
    // urlStream << "https://" << BindAddressOrLoopback(false, true)
    //           << ":" << server.ControlConfig.SupervisorPort;
    // std::string url = urlStream.str();
    // std::cout << "Generated URL: " << url << std::endl;
    // std::string token;
    // // FormatToken 格式化 token
    // try {
    //     token = FormatToken(server.ControlConfig.AgentToken, server.ControlConfig.Runtime->ServerCA);
    //     std::cout << "Generated Token: " << token << std::endl;
    // } catch (const std::exception& e) {
    //     std::cerr << "Error generating token: " << e.what() << std::endl;
    // }
    // // 为节点代理（agent）配置各种参数，如调试模式、数据目录、服务负载均衡、集群重置等。

	// agentConfig.ContainerRuntimeReady = containerRuntimeReady;
	// agentConfig.Debug = app.GlobalBool("debug");
	// agentConfig.DataDir = fs::path(server.ControlConfig.DataDir).parent_path().string();
	// agentConfig.ServerURL = url;
	// agentConfig.Token = token;
	// agentConfig.DisableLoadBalancer = !server.ControlConfig.DisableAPIServer;
	// agentConfig.DisableServiceLB = server.ControlConfig.DisableServiceLB;
	// agentConfig.ETCDAgent = server.ControlConfig.DisableAPIServer;
	// agentConfig.ClusterReset = server.ControlConfig.ClusterReset;
	// agentConfig.Rootless = config.Rootless;

	// //处理代理的Rootless模式：若代理配置了Rootless模式，防止重复进入无根环境。
	// if(agentConfig.Rootless){
	// 	// let agent specify Rootless kubelet flags, but not unshare twice
	// 	agentConfig.RootlessAlreadyUnshared = true;
	// }

    // // Simulating a check for ServerURL and handling it accordingly
    // if (server.ControlConfig.DisableAPIServer) {
    //     if (config.ServerURL.empty()) {
    //         // If this node is the initial member of the cluster and is not hosting an apiserver,
    //         // always bootstrap the agent off local supervisor
    //         std::cout << "Bootstrap agent off local supervisor as no ServerURL is provided." << std::endl;
    //         ResetLoadBalancer(fs::path(agentConfig.DataDir) / "agent", "SupervisorServiceName");
    //     } else {
    //         // If this is a secondary member of the cluster and is not hosting an apiserver,
    //         // bootstrap the agent off the existing supervisor
    //         agentConfig.ServerURL = config.ServerURL;
    //         std::cout << "Bootstrap agent with existing supervisor at " << config.ServerURL << std::endl;
    //     }

    //     // Initialize the API address channel (std::vector in this case)
    //     std::cout << "Initializing API Address channel." << std::endl;
    //     agentConfig.APIAddressCh.clear();  // Clear any existing addresses

    //     // Simulate async operation (equivalent to Go's go routine)
    //     std::thread apiThread(getAPIAddressFromEtcd, server, agentConfig);
    //     apiThread.detach();  // Detach the thread for asynchronous operation

    //     // Simulate waiting for the API address
    //     std::this_thread::sleep_for(std::chrono::seconds(3));  // Simulate time for API address to arrive
    //     if (!agentConfig.APIAddressCh.empty()) {
    //         std::cout << "API Address: " << agentConfig.APIAddressCh.front() << std::endl;
    //     }
    // }

	// // Until the agent is run and retrieves config from the server, we won't know
	// // if the embedded registry is enabled. If it is not enabled, these are not
	// // used as the registry is never started.
	// registry = spegel.DefaultRegistry;
	
    // registry.Bootstrapper = spegel.NewChainingBootstrapper(
	// 	spegel.NewServerBootstrapper(&server.ControlConfig),
	// 	spegel.NewAgentBootstrapper(config.ServerURL, token, agentConfig.DataDir),
	// 	spegel.NewSelfBootstrapper(),
	// );

	// registry.Router = https.Start(ctx, nodeConfig, server.ControlConfig.Runtime);

    // // same deal for metrics - these are not used if the extra metrics listener is not enabled.
	// metrics = k3smetrics.DefaultMetrics;
	// metrics.Router = https.Start(ctx, nodeConfig, server.ControlConfig.Runtime);

    // // and for pprof as well
	// pprof = profile.DefaultProfiler;
	// pprof.Router = https.Start(ctx, nodeConfig, serverConfig.ControlConfig.Runtime);

    // //启动代理：如果代理未禁用，则调用agent.Run(ctx, agentConfig)启动代理。若代理被禁用，则通过agent.RunStandalone(ctx, agentConfig)仅启动独立代理
	// if(config.DisableAgent){
	// 	agentConfig.ContainerRuntimeEndpoint = "/dev/null";
	// 	RunStandalone(ctx, agentConfig);
    //     return 0;
	// }
    
    // RunStandalone(ctx, agentConfig);
	return 0;
}



void new_server_command(boost::program_options::variables_map& vm) {
    // 解析用户指定的服务器配置
    Server_user config;
    //后续需要给config赋上命令行传过来的值
    // config.config_file = vm["config"].as<std::string>();
    // config.port = vm["port"].as<int>();
    // config.enable_logging = vm["enable-logging"].as<bool>();
    config.DisableAgent = false;    //用于控制是否启动本地代理并注册本地kubelet
    config.DisableETCD = false;  //用于控制是否禁用etcd
    config.EgressSelectorMode = "pod";  //默认为pod，其实为可配置 "(networking) One of 'agent', 'cluster', 'pod', 'disabled'"
    config.ExtraAPIArgs.push_back("tls-min-version=TLSv1.2");
    // 创建控制器实例
    CustomControllers leaderControllers, controllers;

    // 调用服务器启动函数
    server_run(vm, config, leaderControllers, controllers);

    // 销毁 oatpp 环境
    oatpp::base::Environment::destroy();
}

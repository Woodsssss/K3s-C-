#include <cstdlib>  // 包含 C++ 标准库的 std::getenv
#include "/usr/include/stdlib.h"
#include <iostream>
#include <filesystem>
#include <spdlog/spdlog.h>
#include <sys/prctl.h>
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
#include "server_Struct.h"
#include "agent_Struct.h"

// scheduler.h
void scheduler(Context* ctx, Control* cfg);
// Server 函数定义
void Server(Context *ctx, Control *cfg) {
    // 初始化随机数生成器
    // srand((unsigned int)time(NULL));

    // 准备服务器
    prepare(ctx, cfg);

    // 设置隧道
    // void *tunnel = setupTunnel(ctx, cfg);
    // cfg->Runtime.Tunnel = tunnel;

    // 启动 API 服务器相关的处理
    // if (!cfg->DisableAPIServer) {
    //     // 在后台等待 API 服务器处理程序
    //     // waitForAPIServerHandlers(ctx, &cfg->Runtime);

    //     // 启动 API 服务器
    //     apiServer(ctx, cfg);
    // }

    // 等待 API 服务器在后台可用
    // waitForAPIServerInBackground(ctx, &cfg->Runtime);

    // 启动调度器
    if (!cfg->DisableScheduler) {
        scheduler(ctx, cfg);
    }

    // 启动控制器管理器
    if (!cfg->DisableControllerManager) {
        // controllerManager(ctx, cfg);
    }

    // 启动云控制器管理器
    // if (!cfg->DisableCCM || !cfg->DisableServiceLB) {
    //     cloudControllerManager(ctx, cfg);
    // }
}


void prepare(const Context* ctx, const Control* cfg) {
    // if (ctx.cancelled()) {
    //     // 如果上下文被取消，则不执行任何操作
    //     return -1;
    // }

    // // 设置默认值
    // defaults(*config);


    // // 初始化集群
    // Cluster cluster(*config);
    // if (cluster.Bootstrap(config->ClusterReset) != 0) {
    //     return -1; // 返回错误码
    // }

    // // 生成服务器依赖
    // cluster.GenServerDeps();

    // // 启动集群
    // bool ready = cluster.Start();
    // if (!ready) {
    //     return -1; // 返回错误码
    // }

    // // 设置 ETCDReady 状态
    // config->ETCDReady = ready;

    // return 0; // 成功
}



void setupStorageBackend(std::map<std::string, std::string>& argsMap, const Control& cfg) {
    argsMap["storage-backend"] = "etcd3";

    // specify the endpoints
    if (!cfg.Datastore.Endpoint.empty()) {
        argsMap["etcd-servers"] = cfg.Datastore.Endpoint;
    }

    // storage backend tls configuration
    if (!cfg.Datastore.BackendTLSConfig.CAFile.empty()) {
        argsMap["etcd-cafile"] = cfg.Datastore.BackendTLSConfig.CAFile;
    }
    if (!cfg.Datastore.BackendTLSConfig.CertFile.empty()) {
        argsMap["etcd-certfile"] = cfg.Datastore.BackendTLSConfig.CertFile;
    }
    if (!cfg.Datastore.BackendTLSConfig.KeyFile.empty()) {
        argsMap["etcd-keyfile"] = cfg.Datastore.BackendTLSConfig.KeyFile;
    }
}

// int apiServer(const Context* ctx, Control* cfg) {
//     Runtime runtime = cfg->Runtime;
//     std::unordered_map<std::string, std::string> argsMap;

//     setupStorageBackend(argsMap, *cfg);

//     std::string certDir = filepathJoin(cfg->DataDir, "tls", "temporary-certs");
//     if (MkdirAll(certDir, 0700) != 0) {
//         // 处理错误
//         return -1;
//     };


//     std::vector<std::string> args = GetArgs(argsMap, cfg->ExtraAPIArgs);

//     // logrusInfof("Running kube-apiserver %s", GetArgs(args));

//     // return 0; // 成功
// }

#include <string>
#include <map>
#include <vector>
#include <iostream>
#include <memory>

// 模拟上下文类
class Context {
    // 可以添加上下文相关的成员和方法
};

// 模拟 RuntimeConfig 结构体
struct RuntimeConfig {
    std::string KubeConfigScheduler;
    bool APIServerReady;
};

// 模拟 ControlConfig 结构体
struct ControlConfig {
    RuntimeConfig Runtime;
    bool NoLeaderElect;
    int VLevel;
    std::string VModule;
    std::string Loopback(bool useIPv6);
    std::vector<std::string> ExtraSchedulerAPIArgs;
};

// 模拟 GetArgs 函数
std::vector<std::string> GetArgs(const std::map<std::string, std::string>& argsMap, const std::vector<std::string>& extraArgs) {
    std::vector<std::string> args;
    for (const auto& pair : argsMap) {
        args.push_back("--" + pair.first + "=" + pair.second);
    }
    args.insert(args.end(), extraArgs.begin(), extraArgs.end());
    return args;
}

// 模拟 Scheduler 函数
void Scheduler(const std::shared_ptr<Context>& ctx, const RuntimeConfig& runtime, const std::vector<std::string>& args) {
    std::cout << "Running kube-scheduler with args: ";
    for (const auto& arg : args) {
        std::cout << arg << " ";
    }
    std::cout << std::endl;
}

// 模拟 scheduler 函数
int scheduler(const std::shared_ptr<Context>& ctx, const ControlConfig& cfg) {
    const auto& runtime = cfg.Runtime;

    std::map<std::string, std::string> argsMap = {
        {"kubeconfig", runtime.KubeConfigScheduler},
        {"authorization-kubeconfig", runtime.KubeConfigScheduler},
        {"authentication-kubeconfig", runtime.KubeConfigScheduler},
        {"bind-address", cfg.Loopback(false)},
        {"secure-port", "10259"},
        {"profiling", "false"}
    };

    if (cfg.NoLeaderElect) {
        argsMap["leader-elect"] = "false";
    }

    if (cfg.VLevel != 0) {
        argsMap["v"] = std::to_string(cfg.VLevel);
    }

    if (!cfg.VModule.empty()) {
        argsMap["vmodule"] = cfg.VModule;
    }

    auto args = GetArgs(argsMap, cfg.ExtraSchedulerAPIArgs);

    std::cout << "Running kube-scheduler with args: ";
    for (const auto& arg : args) {
        std::cout << arg << " ";
    }
    std::cout << std::endl;

    Scheduler(ctx, runtime, args);

    return 0; // 返回 0 表示成功
}


// 模拟strconv.Itoa函数
std::string ToString(int value) {
    return std::to_string(value);
}

// 模拟logrus.Infof函数
void LogInfo(const std::string& message) {
    std::cout << message << std::endl;
}

// 模拟executor.ControllerManager函数
// int ControllerManager(const Config::Context& ctx, const std::string& apiServerReady, const std::vector<std::string>& args) {
//     // 实际实现需要根据具体情况来编写
//     std::cout << "Starting controller manager with args: ";
//     for (const auto& arg : args) {
//         std::cout << arg << " ";
//     }
//     std::cout << std::endl;
//     return 0; // 假设成功执行
// }

// 模拟util.JoinIPNets函数
std::string JoinIPNets(const std::vector<std::string>& ipNets) {
    std::string result;
    for (const auto& ipNet : ipNets) {
        if (!result.empty()) result += ",";
        result += ipNet;
    }
    return result;
}

// 主函数，模拟的controllerManager函数
// int ControllerManager(const Config::Context& ctx, Config::Control* cfg) {
//     std::unordered_map<std::string, std::string> argsMap = {
//         {"controllers", "*,tokencleaner"},
//         {"kubeconfig", cfg->Runtime.KubeConfigController},
//         {"authorization-kubeconfig", cfg->Runtime.KubeConfigController},
//         {"authentication-kubeconfig", cfg->Runtime.KubeConfigController},
//         {"service-account-private-key-file", cfg->Runtime.ServiceCurrentKey},
//         {"allocate-node-cidrs", "true"},
//         {"service-cluster-ip-range", JoinIPNets(cfg->ServiceIPRanges)},
//         {"cluster-cidr", JoinIPNets(cfg->ClusterIPRanges)},
//         {"root-ca-file", cfg->Runtime.ServerCA},
//         {"profiling", "false"},
//         {"bind-address", cfg->Loopback(false)},
//         {"secure-port", "10257"},
//         {"use-service-account-credentials", "true"},
//         {"cluster-signing-kube-apiserver-client-cert-file", cfg->Runtime.SigningClientCA},
//         {"cluster-signing-kube-apiserver-client-key-file", cfg->Runtime.ClientCAKey},
//         {"cluster-signing-kubelet-client-cert-file", cfg->Runtime.SigningClientCA},
//         {"cluster-signing-kubelet-client-key-file", cfg->Runtime.ClientCAKey},
//         {"cluster-signing-kubelet-serving-cert-file", cfg->Runtime.SigningServerCA},
//         {"cluster-signing-kubelet-serving-key-file", cfg->Runtime.ServerCAKey},
//         {"cluster-signing-legacy-unknown-cert-file", cfg->Runtime.SigningServerCA},
//         {"cluster-signing-legacy-unknown-key-file", cfg->Runtime.ServerCAKey},
//     };

//     if (cfg->NoLeaderElect) {
//         argsMap["leader-elect"] = "false";
//     }
//     if (!cfg->DisableCCM) {
//         argsMap["configure-cloud-routes"] = "false";
//         argsMap["controllers"] += ",-service,-route,-cloud-node-lifecycle";
//     }

//     if (cfg->VLevel != 0) {
//         argsMap["v"] = ToString(cfg->VLevel);
//     }
//     if (!cfg->VModule.empty()) {
//         argsMap["vmodule"] = cfg->VModule;
//     }

//     std::vector<std::string> args;
//     for (const auto& arg : argsMap) {
//         args.push_back(arg.first + "=" + arg.second);
//     }
//     for (const auto& extraArg : cfg->ExtraControllerArgs) {
//         args.push_back(extraArg);
//     }

//     // 模拟日志输出
//     std::string logMessage = "Running kube-controller-manager ";
//     for (const auto& arg : args) {
//         logMessage += arg + " ";
//     }
//     LogInfo(logMessage);

//     // 调用模拟的ControllerManager函数
//     return ControllerManager(ctx, cfg->Runtime.KubeConfigController, args);
// }








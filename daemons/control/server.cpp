// server.cpp

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
    if (!cfg->DisableAPIServer) {
        // 在后台等待 API 服务器处理程序
        // waitForAPIServerHandlers(ctx, &cfg->Runtime);

        // 启动 API 服务器
        apiServer(ctx, cfg);
    }

    // 等待 API 服务器在后台可用
    waitForAPIServerInBackground(ctx, &cfg->Runtime);

    // 启动调度器
    if (!cfg->DisableScheduler) {
        scheduler(ctx, cfg);
    }

    // 启动控制器管理器
    if (!cfg->DisableControllerManager) {
        controllerManager(ctx, cfg);
    }

    // 启动云控制器管理器
    // if (!cfg->DisableCCM || !cfg->DisableServiceLB) {
    //     cloudControllerManager(ctx, cfg);
    // }
}


int prepare(const Context& ctx, Config_Control* config) {
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

    return 0; // 成功
}



void setupStorageBackend(std::map<std::string, std::string>& argsMap, const ControlConfig& cfg) {
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

int apiServer(const Context& ctx, Config_Control* cfg) {
    Runtime runtime = cfg->Runtime;
    std::unordered_map<std::string, std::string> argsMap;

    setupStorageBackend(argsMap, *cfg);

    std::string certDir = filepathJoin(cfg->DataDir, "tls", "temporary-certs");
    if (MkdirAll(certDir, 0700) != 0) {
        // 处理错误
        return -1;
    }

    // argsMap["cert-dir"] = certDir
	// argsMap["allow-privileged"] = "true"
	// argsMap["enable-bootstrap-token-auth"] = "true"
	// argsMap["authorization-mode"] = strings.Join([]string{modes.ModeNode, modes.ModeRBAC}, ",")
	// argsMap["service-account-signing-key-file"] = runtime.ServiceCurrentKey
	// argsMap["service-cluster-ip-range"] = util.JoinIPNets(cfg.ServiceIPRanges)
	// argsMap["service-node-port-range"] = cfg.ServiceNodePortRange.String()
	// argsMap["advertise-port"] = strconv.Itoa(cfg.AdvertisePort)
	// if cfg.AdvertiseIP != "" {
	// 	argsMap["advertise-address"] = cfg.AdvertiseIP
	// }
	// argsMap["secure-port"] = strconv.Itoa(cfg.APIServerPort)
	// if cfg.APIServerBindAddress == "" {
	// 	argsMap["bind-address"] = cfg.Loopback(false)
	// } else {
	// 	argsMap["bind-address"] = cfg.APIServerBindAddress
	// }
	// if cfg.EgressSelectorMode != config.EgressSelectorModeDisabled {
	// 	argsMap["enable-aggregator-routing"] = "true"
	// 	argsMap["egress-selector-config-file"] = runtime.EgressSelectorConfig
	// }
	// argsMap["tls-cert-file"] = runtime.ServingKubeAPICert
	// argsMap["tls-private-key-file"] = runtime.ServingKubeAPIKey
	// argsMap["service-account-key-file"] = runtime.ServiceKey
	// argsMap["service-account-issuer"] = "https://kubernetes.default.svc." + cfg.ClusterDomain
	// argsMap["api-audiences"] = "https://kubernetes.default.svc." + cfg.ClusterDomain + "," + version.Program
	// argsMap["kubelet-certificate-authority"] = runtime.ServerCA
	// argsMap["kubelet-client-certificate"] = runtime.ClientKubeAPICert
	// argsMap["kubelet-client-key"] = runtime.ClientKubeAPIKey
	// if cfg.FlannelExternalIP {
	// 	argsMap["kubelet-preferred-address-types"] = "ExternalIP,InternalIP,Hostname"
	// } else {
	// 	argsMap["kubelet-preferred-address-types"] = "InternalIP,ExternalIP,Hostname"
	// }
	// argsMap["requestheader-client-ca-file"] = runtime.RequestHeaderCA
	// argsMap["requestheader-allowed-names"] = deps.RequestHeaderCN
	// argsMap["proxy-client-cert-file"] = runtime.ClientAuthProxyCert
	// argsMap["proxy-client-key-file"] = runtime.ClientAuthProxyKey
	// argsMap["requestheader-extra-headers-prefix"] = "X-Remote-Extra-"
	// argsMap["requestheader-group-headers"] = "X-Remote-Group"
	// argsMap["requestheader-username-headers"] = "X-Remote-User"
	// argsMap["client-ca-file"] = runtime.ClientCA
	// argsMap["enable-admission-plugins"] = "NodeRestriction"
	// argsMap["anonymous-auth"] = "false"
	// argsMap["profiling"] = "false"

    std::vector<std::string> args = GetArgs(argsMap, cfg->ExtraAPIArgs);

    // logrusInfof("Running kube-apiserver %s", GetArgs(args));

    return 0; // 成功
}






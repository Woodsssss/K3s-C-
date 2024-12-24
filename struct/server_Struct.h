#include <vector>
#include <string>
#include <chrono>
#include <future>
#include <cctype>
#include <algorithm>
#include <grpcpp/grpcpp.h>  // For gRPC server
#include <stdexcept>
#include <netinet/in.h>
#include <arpa/inet.h>
//#include <prometheus/registry.h>  // For Prometheus metrics

// 定义时间间隔类型，与 Go 中的 time.Duration 对应
using Duration = std::chrono::milliseconds;

struct Server_user {
    std::vector<std::string> ClusterCIDR;
    std::string AgentToken;
    std::string AgentTokenFile;
    std::string Token;
    std::string TokenFile;
    std::string ClusterSecret;
    std::vector<std::string> ServiceCIDR;
    std::string ServiceNodePortRange;
    std::vector<std::string> ClusterDNS;
    std::string ClusterDomain;
    
    int HTTPSPort;
    int SupervisorPort;
    int APIServerPort;
    std::string APIServerBindAddress;
    std::string DataDir;
    bool DisableAgent;
    std::string KubeConfigOutput;
    std::string KubeConfigMode;
    std::string KubeConfigGroup;
    std::string HelmJobImage;
    std::vector<std::string> TLSSan;
    bool TLSSanSecurity;
    std::vector<std::string> ExtraAPIArgs;
    std::vector<std::string> ExtraEtcdArgs;
    std::vector<std::string> ExtraSchedulerArgs;
    std::vector<std::string> ExtraControllerArgs;
    std::vector<std::string> ExtraCloudControllerArgs;
    bool Rootless;
    std::string DatastoreEndpoint;
    std::string DatastoreCAFile;
    std::string DatastoreCertFile;
    std::string DatastoreKeyFile;
    bool KineTLS;
    std::string AdvertiseIP;
    int AdvertisePort;
    bool DisableScheduler;
    std::string ServerURL;
    std::string FlannelBackend;
    bool FlannelIPv6Masq;
    bool FlannelExternalIP;
    std::string EgressSelectorMode;
    std::string DefaultLocalStoragePath;
    bool DisableCCM;
    bool DisableNPC;
    bool DisableHelmController;
    bool DisableKubeProxy;
    bool DisableAPIServer;
    bool DisableControllerManager;
    bool DisableETCD;
    bool EmbeddedRegistry;
    bool ClusterInit;
    bool ClusterReset;
    std::string ClusterResetRestorePath;
    bool EncryptSecrets;
    bool EncryptForce;
    std::string EncryptOutput;
    bool EncryptSkip;
    std::string SystemDefaultRegistry;
    
    // 假设 StartupHook 是一个已定义的类型
    std::vector<std::string> StartupHooks;  // 可以根据需求替换成实际类型
    bool SupervisorMetrics;
    std::string EtcdSnapshotName;
    bool EtcdDisableSnapshots;
    bool EtcdExposeMetrics;
    std::string EtcdSnapshotDir;
    std::string EtcdSnapshotCron;
    int EtcdSnapshotRetention;
    bool EtcdSnapshotCompress;
    std::string EtcdListFormat;
    
    std::shared_ptr<EtcdS3> EtcdS3;
    std::string EtcdS3Endpoint;
    std::string EtcdS3EndpointCA;
    bool EtcdS3SkipSSLVerify;
    std::string EtcdS3AccessKey;
    std::string EtcdS3SecretKey;
    std::string EtcdS3BucketName;
    std::string EtcdS3Region;
    std::string EtcdS3Folder;
    std::string EtcdS3Proxy;
    std::string EtcdS3ConfigSecret;
    Duration EtcdS3Timeout;
    bool EtcdS3Insecure;
    std::string ServiceLBNamespace;
};

struct IP {
    std::vector<uint8_t> bytes;
    
    // Constructor for IPv4
    IP(const std::string& ip) {
        struct sockaddr_in sa;
        if (inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) == 1) {
            bytes.resize(4);
            std::memcpy(bytes.data(), &sa.sin_addr, 4);
        } else {
            throw std::invalid_argument("Invalid IPv4 address");
        }
    }

    // Constructor for IPv6
    IP(const std::string& ip, bool is_ipv6) {
        struct sockaddr_in6 sa;
        if (inet_pton(AF_INET6, ip.c_str(), &(sa.sin6_addr)) == 1) {
            bytes.resize(16);
            std::memcpy(bytes.data(), &sa.sin6_addr, 16);
        } else {
            throw std::invalid_argument("Invalid IPv6 address");
        }
    }

    // Convert IP to string (for debugging or display)
    std::string toString() const {
        if (bytes.size() == 4) {
            struct sockaddr_in sa;
            std::memcpy(&sa.sin_addr, bytes.data(), 4);
            char str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(sa.sin_addr), str, INET_ADDRSTRLEN);
            return std::string(str);
        } else if (bytes.size() == 16) {
            struct sockaddr_in6 sa;
            std::memcpy(&sa.sin6_addr, bytes.data(), 16);
            char str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(sa.sin6_addr), str, INET6_ADDRSTRLEN);
            return std::string(str);
        }
        return "";
    }
};

struct IPNet {
    IP ip;   // network number (IP address)
    std::vector<uint8_t> Mask; // network mask (subnet mask)
    
    // 默认构造函数
    IPNet() : ip(IP("")), Mask() {}  // 空的默认构造函数，IP 使用一个空字符串初始化
    
    IPNet(const IP& ip, const std::vector<uint8_t>& mask) : ip(ip), Mask(mask) {}


    // 转换网络 IPNet 为字符串（调试或显示用）
    std::string toString() const {
        return ip.toString();
    }

    // 打印网络掩码的字符串（为了方便调试）
    std::string maskToString() const {
        std::string mask_str;
        for (const auto& byte : Mask) {
            mask_str += std::to_string(byte) + ".";
        }
        if (!mask_str.empty()) {
            mask_str.pop_back(); // 删除最后一个多余的点
        }
        return mask_str;
    }
    // 计算掩码中的 1 的位数，等价于 Go 中的 Mask.Size() 方法
    int countOnes() const {
        int count = 0;
        for (auto byte : Mask) {
            for (int i = 7; i >= 0; --i) {
                if (byte & (1 << i)) {
                    ++count;
                }
            }
        }
        return count;
    }

    int getBits() const {
        // C++ 没有类似 Go 的 Size 方法，假设 IPv4 或 IPv6 最大
        // 我们使用 Mask 的大小来确定是 32 位 (IPv4) 还是 128 位 (IPv6)
        return Mask.size() == 4 ? 32 : 128;
    }
};

// CriticalControlArgs 结构体
struct CriticalControlArgs {
    std::vector<std::string> ClusterDNSs;        // 用 std::vector<std::string> 表示 IP 地址的列表
    std::vector<std::shared_ptr<IPNet>> ClusterIPRanges; // 使用智能指针来管理 IPNet 对象
    std::string ClusterDNS;                      // 单个 Cluster DNS，使用 std::string
    std::string ClusterDomain;                   // 使用 std::string
    std::shared_ptr<IPNet> ClusterIPRange;       // 单个 IP 网络范围
    bool DisableCCM = false;                     // 禁用云控制管理器
    bool DisableHelmController = false;          // 禁用 Helm 控制器
    bool DisableNPC = false;                     // 禁用网络策略
    bool DisableServiceLB = false;               // 禁用服务负载均衡
    bool EncryptSecrets = false;                 // 启用秘密加密
    bool EmbeddedRegistry = false;               // 启用嵌入式注册表
    std::string FlannelBackend;                  // Flannel 后端，使用 std::string
    bool FlannelIPv6Masq = false;                // 启用 IPv6 地址伪装
    bool FlannelExternalIP = false;              // 启用外部 IP 地址
    std::string EgressSelectorMode;              // 出站选择模式，使用 std::string
    std::shared_ptr<IPNet> ServiceIPRange;       // 服务 IP 范围
    std::vector<std::shared_ptr<IPNet>> ServiceIPRanges; // 服务 IP 范围列表
    bool SupervisorMetrics = false;              // 启用监控指标
};

// ControlRuntimeBootstrap 结构体
struct ControlRuntimeBootstrap {
    std::string ETCDServerCA;       // ETCD 服务器证书
    std::string ETCDServerCAKey;    // ETCD 服务器证书密钥
    std::string ETCDPeerCA;         // ETCD 对等证书
    std::string ETCDPeerCAKey;      // ETCD 对等证书密钥
    std::string ServerCA;           // 服务器证书
    std::string ServerCAKey;        // 服务器证书密钥
    std::string ClientCA;           // 客户端证书
    std::string ClientCAKey;        // 客户端证书密钥
    std::string ServiceKey;         // 服务密钥
    std::string PasswdFile;         // 密码文件路径
    std::string RequestHeaderCA;    // 请求头 CA
    std::string RequestHeaderCAKey; // 请求头 CA 密钥
    std::string IPSECKey;           // IPSEC 密钥
    std::string EncryptionConfig;   // 加密配置
    std::string EncryptionHash;     // 加密哈希值
};

// 用一个简单的结构体来模拟 Go 中的 context.Context
struct Context {
    std::string info;

    Context(const std::string& str) : info(str) {}
};

// 定义 Callback 类型，接受一个 std::shared_ptr<Context> 类型的参数
using Callback = std::function<void(std::shared_ptr<Context>)>;

// 定义 CustomController 类型，类似于 Go 中的 func(ctx, sc) error
using CustomController = std::function<void(std::shared_ptr<Context>)>;

// 将 CustomControllers 转换为结构体形式
struct CustomControllers {
    std::vector<CustomController> controllers;

    // 添加一个控制器
    void addController(const CustomController& controller) {
        controllers.push_back(controller);
    }

    // 执行所有控制器
    void executeAll(std::shared_ptr<Context> ctx) {
        for (auto& controller : controllers) {
            try {
                controller(ctx); // 调用控制器
            } catch (const std::exception& e) {
                std::cerr << "Error while executing controller: " << e.what() << std::endl;
            }
        }
    }
};

// ETCDConfig 结构体
struct ETCDConfig {
    std::vector<std::string> Endpoints;  // 存储 ETCD 节点的地址
    tlsConfig tlsConfig;                // 存储 TLS 配置
    bool LeaderElect;  
};

struct ControlRuntime : public ControlRuntimeBootstrap{
    bool HTTPBootstrap;                      // HTTP 启动标志
    std::shared_ptr<std::promise<void>> APIServerReady;        // 用于 API 服务器就绪通知
    std::shared_ptr<std::promise<void>> ContainerRuntimeReady; // 容器运行时就绪通知
    std::shared_ptr<std::promise<void>> ETCDReady;             // ETCD 就绪通知
    std::shared_ptr<std::mutex> StartupHooksWg;               // 启动钩子同步对象
    std::unordered_map<std::string, Callback> ClusterControllerStarts; // 集群控制器回调
    std::unordered_map<std::string, Callback> LeaderElectedClusterControllerStarts; // 领导选举回调

    std::string ClientKubeAPICert;       // 客户端 API 证书
    std::string ClientKubeAPIKey;        // 客户端 API 密钥
    std::string NodePasswdFile;          // 节点密码文件路径

    std::string SigningClientCA;         // 签名客户端证书
    std::string SigningServerCA;         // 签名服务器证书
    std::string ServiceCurrentKey;       // 当前服务密钥

    std::string KubeConfigAdmin;         // 管理员 KubeConfig
    std::string KubeConfigSupervisor;    // 监督员 KubeConfig
    std::string KubeConfigController;    // 控制器 KubeConfig
    std::string KubeConfigScheduler;     // 调度器 KubeConfig
    std::string KubeConfigAPIServer;     // API 服务器 KubeConfig
    std::string KubeConfigCloudController; // 云控制器 KubeConfig

    std::string ServingKubeAPICert;      // 服务 KubeAPI 证书
    std::string ServingKubeAPIKey;       // 服务 KubeAPI 密钥
    std::string ServingKubeletKey;       // 服务 Kubelet 密钥
    std::string ServerToken;             // 服务器令牌
    std::string AgentToken;              // 代理令牌
    std::shared_ptr<http::Handler> APIServer;  // API 服务器处理器
    std::shared_ptr<http::Handler> Handler;    // 处理器
    std::shared_ptr<http::Handler> Tunnel;     // 隧道处理器
    std::shared_ptr<http::Handler> Authenticator;  // 认证器

    std::string EgressSelectorConfig;    // 出口选择器配置
    std::string CloudControllerConfig;   // 云控制器配置

    std::string ClientAuthProxyCert;     // 客户端认证代理证书
    std::string ClientAuthProxyKey;      // 客户端认证代理密钥

    std::string ClientAdminCert;         // 客户端管理员证书
    std::string ClientAdminKey;          // 客户端管理员密钥
    std::string ClientSupervisorCert;    // 客户端监督员证书
    std::string ClientSupervisorKey;     // 客户端监督员密钥
    std::string ClientControllerCert;    // 客户端控制器证书
    std::string ClientControllerKey;     // 客户端控制器密钥
    std::string ClientSchedulerCert;     // 客户端调度器证书
    std::string ClientSchedulerKey;      // 客户端调度器密钥
    std::string ClientKubeProxyCert;     // 客户端 Kube Proxy 证书
    std::string ClientKubeProxyKey;      // 客户端 Kube Proxy 密钥
    std::string ClientKubeletKey;        // 客户端 Kubelet 密钥
    std::string ClientCloudControllerCert; // 客户端云控制器证书
    std::string ClientCloudControllerKey;  // 客户端云控制器密钥
    std::string ClientK3sControllerCert; // 客户端 K3s 控制器证书
    std::string ClientK3sControllerKey;  // 客户端 K3s 控制器密钥

    std::string ServerETCDCert;          // 服务器 ETCD 证书
    std::string ServerETCDKey;           // 服务器 ETCD 密钥
    std::string PeerServerClientETCDCert; // 对等服务器 ETCD 客户端证书
    std::string PeerServerClientETCDKey;  // 对等服务器 ETCD 客户端密钥
    std::string ClientETCDCert;          // 客户端 ETCD 证书
    std::string ClientETCDKey;           // 客户端 ETCD 密钥

    std::shared_ptr<k3s::Factory> K3s;   // K3s 工厂
    std::shared_ptr<core::Factory> Core; // 核心工厂
    std::shared_ptr<record::EventRecorder> Event; // 事件记录器
    ETCDConfig EtcdConfig;     // ETCD 配置
};

// EtcdS3 结构体
struct EtcdS3 {
    std::string AccessKey;     // 访问密钥
    std::string Bucket;        // S3 桶名称
    std::string ConfigSecret;  // 配置密钥
    std::string Endpoint;      // S3 端点
    std::string EndpointCA;    // S3 端点 CA
    std::string Folder;        // 文件夹路径
    std::string Proxy;         // 代理地址
    std::string Region;        // 区域
    std::string SecretKey;     // 秘密密钥
    bool Insecure = false;     // 是否使用不安全的连接
    bool SkipSSLVerify = false; // 是否跳过 SSL 验证
    Duration Timeout;          // 超时，使用时间间隔表示
};

struct ConnectionPoolConfig {
    int MaxIdle;                 // Zero means defaultMaxIdleConns; negative means 0
    int MaxOpen;                 // <= 0 means unlimited
    std::chrono::seconds MaxLifetime; // Maximum amount of time a connection may be reused

    // 默认构造函数
    ConnectionPoolConfig() : MaxIdle(0), MaxOpen(0), MaxLifetime(std::chrono::seconds(0)) {}

    // 带参数的构造函数
    ConnectionPoolConfig(int maxIdle, int maxOpen, std::chrono::seconds maxLifetime)
        : MaxIdle(maxIdle), MaxOpen(maxOpen), MaxLifetime(maxLifetime) {}
};

struct tlsConfig {
    std::string CAFile;     // 文件路径字符串
    std::string CertFile;   // 文件路径字符串
    std::string KeyFile;    // 文件路径字符串
    bool SkipVerify;        // 跳过验证标志
};

// Assuming appropriate includes are added based on your environment
struct EndpointConfig {
    std::shared_ptr<grpc::Server> GRPCServer;  // gRPC Server (using shared_ptr for memory management)
    std::string Listener;                      // Listener address (string)
    std::string Endpoint;                      // Endpoint address (string)
    ConnectionPoolConfig ConnectionPoolConfig;  // Connection pool configuration
    tlsConfig  ServerTLSConfig;               // TLS configuration for server
    tlsConfig  BackendTLSConfig;              // TLS configuration for backend
    prometheus::Registerer MetricsRegisterer;  // Metrics registerer for Prometheus
    std::chrono::milliseconds NotifyInterval;  // Notification interval (in milliseconds)
    std::string EmulatedETCDVersion;          // Emulated ETCD version string
};

// Control 结构体
struct Control : public CriticalControlArgs{
    int AdvertisePort;
    std::string AdvertiseIP;
    int HTTPSPort;
    int SupervisorPort;
    int APIServerPort;
    std::string APIServerBindAddress;
    std::string AgentToken;
    std::string Token;
    std::shared_ptr<PortRange> ServiceNodePortRange; // 可以使用 std::shared_ptr
    std::string KubeConfigOutput;
    std::string KubeConfigMode;
    std::string KubeConfigGroup;
    std::string HelmJobImage;
    std::string DataDir;
    bool KineTLS;
    EndpointConfig Datastore;  // 假设 `endpoint.Config` 对应的 C++ 结构体
    std::map<std::string, bool> Disables;
    bool DisableAgent;
    bool DisableAPIServer;
    bool DisableControllerManager;
    bool DisableETCD;
    bool DisableKubeProxy;
    bool DisableScheduler;
    bool DisableServiceLB;
    bool Rootless;
    std::string ServiceLBNamespace;
    std::vector<std::string> ExtraAPIArgs;
    std::vector<std::string> ExtraControllerArgs;
    std::vector<std::string> ExtraCloudControllerArgs;
    std::vector<std::string> ExtraEtcdArgs;
    std::vector<std::string> ExtraSchedulerAPIArgs;
    bool NoLeaderElect;
    std::string JoinURL;
    std::string IPSECPSK;
    std::string DefaultLocalStoragePath;
    std::map<std::string, bool> Skips;
    std::string SystemDefaultRegistry;
    bool ClusterInit;
    bool ClusterReset;
    std::string ClusterResetRestorePath;
    std::string MinTLSVersion;
    std::vector<std::string> CipherSuites;
    uint16_t TLSMinVersion;
    std::vector<uint16_t> TLSCipherSuites;
    std::string EtcdSnapshotName;
    bool EtcdDisableSnapshots;
    bool EtcdExposeMetrics;
    std::string EtcdSnapshotDir;
    std::string EtcdSnapshotCron;
    int EtcdSnapshotRetention;
    bool EtcdSnapshotCompress;
    std::string EtcdListFormat;
    std::shared_ptr<EtcdS3> EtcdS3;  // 使用智能指针管理 EtcdS3
    std::string ServerNodeName;
    int VLevel;
    std::string VModule;
    std::string BindAddress;
    std::vector<std::string> SANs;
    bool SANSecurity;
    std::string PrivateIP;
    std::shared_ptr<ControlRuntime> Runtime;  // 使用智能指针管理 ControlRuntime
    bool APIServerReady;
    bool ETCDReady;
};

// StartupHookArgs 结构体
struct StartupHookArgs {
    std::shared_ptr<std::atomic<bool>> APIServerReady;  // 使用 std::atomic<bool> 来模拟 <-chan struct{}
    std::string KubeConfigSupervisor;                   // 使用 std::string 来替代 KubeConfigSupervisor
    std::unordered_map<std::string, bool> Skips;        // 使用 std::unordered_map 来替代 map[string]bool
    std::unordered_map<std::string, bool> Disables;     // 使用 std::unordered_map 来替代 map[string]bool
};

// StartupHook 类型
using StartupHook = std::function<int(std::shared_ptr<void>, std::shared_ptr<std::mutex>, StartupHookArgs)>;

struct Config {
	bool              DisableAgent;      
	Control           ControlConfig;
	int               SupervisorPort;    
	std::vector<StartupHook> StartupHooks;      // 启动时钩子
    CustomControllers LeaderControllers;        // 领导控制器
    CustomControllers Controllers;              // 控制器    
};

struct Version {
    std::string Program;
    std::string ProgramUpper;
    std::string Vsn;
    std::string GitCommit;
    std::string UpstreamGolang;

    // 默认构造函数
    Version(const std::string& program = "k3s", const std::string& version = "dev", 
            const std::string& gitCommit = "HEAD", const std::string& upstreamGolang = "")
        : Program(program), Vsn(version), GitCommit(gitCommit), UpstreamGolang(upstreamGolang) {
        updateProgramUpper();
    }

    // 更新 ProgramUpper 的成员函数
    void updateProgramUpper() {
        ProgramUpper = Program;
        std::transform(ProgramUpper.begin(), ProgramUpper.end(), ProgramUpper.begin(), [](unsigned char c) {
            return std::toupper(c);
        });
    }

    // 设置 Program 后自动更新 ProgramUpper
    void setProgram(const std::string& program) {
        Program = program;
        updateProgramUpper();
    }
};

struct Log {
    int VLevel;          // 日志级别
    std::string VModule; // 模块名
    std::string LogFile; // 日志文件路径
    bool AlsoLogToStderr; // 是否同时输出到标准错误
};

// Structure to represent a port range
struct PortRange {
    int base;  // Base port
    int size;  // Size of the range

    // Constructor to initialize to default values
    PortRange() : base(0), size(0) {}
};
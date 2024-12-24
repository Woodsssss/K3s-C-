#include <iostream>
#include <string>
#include <vector>
#include <functional>

// 模拟 cli.StringSlice 通过 std::vector<string>
using StringSlice = std::vector<std::string>;

struct AgentShared {
    std::string	NodeIP;
};

// C++ 中的 Agent 类
struct Agent:public AgentShared{
    std::string Token;
    std::string TokenFile;
    std::string ClusterSecret;
    std::string ServerURL;
    std::vector<std::string> APIAddressCh; // Go 中是 chan []string
    bool DisableLoadBalancer;
    bool DisableServiceLB;
    bool ETCDAgent;
    int LBServerPort;
    std::string ResolvConf;
    std::string DataDir;
    std::string BindAddress;
    StringSlice NodeIP;
    StringSlice NodeExternalIP;
    StringSlice NodeInternalDNS;
    StringSlice NodeExternalDNS;
    std::string NodeName;
    std::string PauseImage;
    std::string Snapshotter;
    bool Docker;
    bool ContainerdNoDefault;
    std::string ContainerRuntimeEndpoint;
    std::string DefaultRuntime;
    std::string ImageServiceEndpoint;
    std::string FlannelIface;
    std::string FlannelConf;
    std::string FlannelCniConfFile;
    std::string VPNAuth;
    std::string VPNAuthFile;
    bool Debug;
    bool EnablePProf;
    bool Rootless;
    bool RootlessAlreadyUnshared;
    bool WithNodeID;
    bool EnableSELinux;
    bool ProtectKernelDefaults;
    bool ClusterReset;
    std::string PrivateRegistry;
    std::string SystemDefaultRegistry;
    StringSlice AirgapExtraRegistry;
    StringSlice ExtraKubeletArgs;
    StringSlice ExtraKubeProxyArgs;
    StringSlice Labels;
    StringSlice Taints;
    std::string ImageCredProvBinDir;
    std::string ImageCredProvConfig;
    std::function<void()> ContainerRuntimeReady;  // Go 中是 chan<- struct{}

};
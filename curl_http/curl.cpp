//curl.cpp
#include "curl.h"
// 回调函数，用于将服务器响应的内容写入到一个字符串中
size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total_size = size * nmemb;
    std::string *response = static_cast<std::string*>(userp);
    response->append(static_cast<char*>(contents), total_size);
    return total_size;
}

// 封装成一个函数，输入为 curl 和 URL，返回响应内容
std::string perform_http_request(CURL* curl, const std::string& url) {
    CURLcode res;
    std::string response_string;

    if(curl) {
        // 设置请求的 URL
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        // 设置回调函数，将响应数据写入 response_string 中
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
        // 执行请求
        res = curl_easy_perform(curl);
        // 检查请求是否成功
        if(res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
            return "";  // 如果失败，返回空字符串
        }
    }
    return response_string;  // 返回响应内容
}

// 封装请求过程，包括初始化 CURL、请求数据、打印响应等，返回响应内容
std::string send_http_request(const std::string& url) {
     CURL* curl;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    std::string response;
    if(curl) {
        // 调用封装的函数，传入 curl 对象和请求的 URL
        response = perform_http_request(curl, url);
        // 清理 CURL 会话
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    return response;  // 返回响应内容
}

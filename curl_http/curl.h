#ifndef CURL_H
#define CURL_H

#include <curl/curl.h>
#include <iostream>
#include <string>
// 回调函数，用于将服务器响应的内容写入到一个字符串中
size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp);
// 封装成一个函数，输入为 curl 和 URL，返回响应内容
std::string perform_http_request(CURL* curl, const std::string& url);
// 封装请求过程，包括初始化 CURL、请求数据、打印响应等，返回响应内容
std::string send_http_request(const std::string& url);
#endif  // CURL_H


// handler.h
#ifndef HANDLER_H
#define HANDLER_H
 
#include "oatpp/web/server/HttpRequestHandler.hpp"
 
#define O_UNUSED(x) (void)x;
 
// 自定义请求处理程序
class Handler : public oatpp::web::server::HttpRequestHandler
{
public:
    // 处理传入的请求，并返回响应
    std::shared_ptr<OutgoingResponse> handle(const std::shared_ptr<IncomingRequest>& request) override {
        O_UNUSED(request);
        // 响应内容
        std::string responseContent = "欢迎进入容器编排系统首页！";
        // 创建响应，并设置Content-Type为text/plain;charset=UTF-8
        auto response = ResponseFactory::createResponse(Status::CODE_200, responseContent);
        response->getHeaders().put(Header::CONTENT_TYPE, "text/plain; charset=UTF-8");
        return response;
    }
};
 
#endif // HANDLER_H
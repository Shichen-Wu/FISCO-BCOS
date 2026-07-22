/// @file
/// Minimal HTTP server and client for group-simulator ↔ leader-node communication
/// Uses POSIX sockets, zero external dependencies.
/// NOT production-grade — for integration testing only.

#ifndef BCOS_BLS_SIMPLE_HTTP_H_
#define BCOS_BLS_SIMPLE_HTTP_H_

#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <cstring>
#include <functional>
#include <thread>
#include <atomic>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

namespace bcos::bls::net {

inline std::string buildHttpResponse(int code, const std::string& body) {
    std::ostringstream oss;
    oss << "HTTP/1.1 " << code << " " << (code == 200 ? "OK" : "Error") << "\r\n";
    oss << "Content-Type: application/json\r\n";
    oss << "Content-Length: " << body.size() << "\r\n";
    oss << "Connection: close\r\n";
    oss << "\r\n";
    oss << body;
    return oss.str();
}

struct ParsedRequest {
    std::string method;
    std::string path;
    std::string body;
};

inline ParsedRequest parseHttpRequest(const std::string& raw) {
    ParsedRequest req;
    std::istringstream stream(raw);
    std::string line;
    std::getline(stream, line);
    if (!line.empty() && line.back() == '\r') { line.pop_back(); }
    std::istringstream first(line);
    first >> req.method >> req.path;

    size_t contentLength = 0;
    while (std::getline(stream, line) && line != "\r" && !line.empty()) {
        if (line.back() == '\r') { line.pop_back(); }
        auto pos = line.find(':');
        if (pos != std::string::npos) {
            auto key = line.substr(0, pos);
            auto val = line.substr(pos + 2);
            if (key == "Content-Length") { contentLength = std::stoul(val); }
        }
    }
    if (contentLength > 0) {
        req.body.resize(contentLength);
        stream.read(&req.body[0], static_cast<std::streamsize>(contentLength));
    }
    return req;
}

class SimpleHttpServer {
public:
    using Handler = std::function<std::string(const ParsedRequest&)>;
    SimpleHttpServer(int port, Handler handler) : port_(port), handler_(std::move(handler)) {}
    ~SimpleHttpServer() { stop(); }

    bool start() {
        server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd_ < 0) { return false; }
        int opt = 1;
        setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(static_cast<uint16_t>(port_));
        if (bind(server_fd_, (sockaddr*)&addr, sizeof(addr)) < 0) {
            close(server_fd_); return false;
        }
        if (listen(server_fd_, 5) < 0) {
            close(server_fd_); return false;
        }
        running_ = true;
        thread_ = std::thread([this]() { acceptLoop(); });
        std::cout << "[HttpServer] listening on port " << port_ << std::endl;
        return true;
    }

    void stop() {
        running_ = false;
        if (server_fd_ >= 0) { shutdown(server_fd_, SHUT_RDWR); close(server_fd_); server_fd_ = -1; }
        if (thread_.joinable()) { thread_.join(); }
    }

    bool isRunning() const { return running_.load(); }

private:
    void acceptLoop() {
        while (running_) {
            sockaddr_in clientAddr{};
            socklen_t clientLen = sizeof(clientAddr);
            int clientFd = accept(server_fd_, (sockaddr*)&clientAddr, &clientLen);
            if (clientFd < 0) { continue; }
            char buf[65536] = {0};
            ssize_t n = recv(clientFd, buf, sizeof(buf) - 1, 0);
            if (n > 0) {
                std::string request(buf, static_cast<size_t>(n));
                auto parsed = parseHttpRequest(request);
                std::string respBody = handler_(parsed);
                std::string resp = buildHttpResponse(200, respBody);
                send(clientFd, resp.data(), resp.size(), 0);
            }
            close(clientFd);
        }
    }

    int port_;
    Handler handler_;
    int server_fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread thread_;
};

inline std::string httpPost(const std::string& host, int port,
                             const std::string& path, const std::string& body) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { return ""; }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) { close(sock); return ""; }

    std::ostringstream req;
    req << "POST " << path << " HTTP/1.1\r\n";
    req << "Host: " << host << ":" << port << "\r\n";
    req << "Content-Type: application/json\r\n";
    req << "Content-Length: " << body.size() << "\r\n";
    req << "Connection: close\r\n\r\n" << body;
    std::string reqStr = req.str();
    send(sock, reqStr.data(), reqStr.size(), 0);

    char buf[65536] = {0};
    std::string response;
    ssize_t n;
    while ((n = recv(sock, buf, sizeof(buf) - 1, 0)) > 0) {
        response.append(buf, static_cast<size_t>(n));
    }
    close(sock);
    auto pos = response.find("\r\n\r\n");
    return (pos != std::string::npos) ? response.substr(pos + 4) : response;
}

inline std::string httpGet(const std::string& host, int port, const std::string& path) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { return ""; }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) { close(sock); return ""; }

    std::ostringstream req;
    req << "GET " << path << " HTTP/1.1\r\n";
    req << "Host: " << host << ":" << port << "\r\n";
    req << "Connection: close\r\n\r\n";
    std::string reqStr = req.str();
    send(sock, reqStr.data(), reqStr.size(), 0);

    char buf[65536] = {0};
    std::string response;
    ssize_t n;
    while ((n = recv(sock, buf, sizeof(buf) - 1, 0)) > 0) {
        response.append(buf, static_cast<size_t>(n));
    }
    close(sock);
    auto pos = response.find("\r\n\r\n");
    return (pos != std::string::npos) ? response.substr(pos + 4) : response;
}

} // namespace bcos::bls::net
#endif

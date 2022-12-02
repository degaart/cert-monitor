#pragma once

#include <string>
#include <optional>
#include <vector>
#include <netinet/in.h>

namespace certmon {

    struct Socket {
        int _fd;

        Socket();
        Socket(const Socket&) = delete;
        Socket(Socket&&);
        ~Socket();
        Socket& operator=(const Socket&) = delete;
        Socket& operator=(Socket&&);

        void connect(const std::string& address, int port, std::optional<int> timeout = std::nullopt);
        void connect(const sockaddr_in* addr, std::optional<int> timeout = std::nullopt);
    };

    std::vector<sockaddr_in> lookup_host(const std::string& host);
}


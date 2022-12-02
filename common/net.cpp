#include "net.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <fmt/printf.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <system_error>
#include <unistd.h>

namespace certmon {

    Socket::Socket()
        : _fd(::socket(AF_INET, SOCK_STREAM, 0))
    {
        if(_fd == -1) {
            throw std::system_error(errno, std::system_category());
        }
    }

    Socket::Socket(Socket&& sock)
        : _fd(-1)
    {
        std::swap(_fd, sock._fd);
    }


    Socket::~Socket()
    {
        if(_fd != -1)
            ::close(_fd);
    }

    Socket& Socket::operator=(Socket&& sock)
    {
        std::swap(_fd, sock._fd);
        return *this;
    }

    void Socket::connect(const std::string& address, int port, std::optional<int> timeout)
    {
        sockaddr_in sa = {};
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = inet_addr(address.c_str());
        sa.sin_port = htons(port);

        connect(&sa, timeout);
    }

    void Socket::connect(const sockaddr_in* addr, std::optional<int> timeout)
    {
        if(!timeout) {
            auto ret = ::connect(_fd, reinterpret_cast<const sockaddr*>(addr), sizeof(*addr));
            if(ret == -1) {
                throw std::system_error(errno, std::system_category());
            }
        } else {
            int flags = fcntl(_fd, F_GETFL, nullptr);
            if(flags == -1) {
                throw std::system_error(errno, std::system_category());
            }

            int new_flags = flags | O_NONBLOCK;
            if(fcntl(_fd, F_SETFL, new_flags) == -1) {
                throw std::system_error(errno, std::system_category());
            }

            auto ret = ::connect(_fd, reinterpret_cast<const sockaddr*>(addr), sizeof(*addr));
            if(ret == -1) {
                if(errno != EINPROGRESS) {
                    auto ex = std::system_error(errno, std::system_category());
                    fcntl(_fd, F_SETFL, flags);
                    throw ex;
                }

                pollfd fds[1];
                fds[0].fd = _fd;
                fds[0].events = POLLRDNORM|POLLWRNORM;
                do {
                    ret = ::poll(fds, sizeof(fds) / sizeof(fds[0]), *timeout);
                } while(ret == -1 && errno == EINTR);

                if(ret == 0) { /* timeout */
                    auto ex = std::runtime_error("Connect timeout");
                    fcntl(_fd, F_SETFL, flags);
                    throw ex;
                } else if(ret == -1) {
                    auto ex = std::system_error(errno, std::system_category());
                    fcntl(_fd, F_SETFL, flags);
                    throw ex;
                }
            }

            if(fcntl(_fd, F_SETFL, flags) == -1) {
                throw std::system_error(errno, std::system_category());
            }
        }
    }

    std::vector<sockaddr_in> lookup_host(const std::string& host)
    {
        addrinfo hints = {0};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        addrinfo* addresses = nullptr;
        auto ret = ::getaddrinfo(host.c_str(), nullptr, &hints, &addresses);
        if(ret) {
            if(ret == EAI_NONAME)
                throw std::runtime_error("Host not found");
            else
                throw std::runtime_error(fmt::sprintf("getaddrinfo: %s", gai_strerror(ret)));
        }

        std::vector<sockaddr_in> result;
        for(const addrinfo* addr = addresses; addr; addr = addr->ai_next) {
            if(addr->ai_family == AF_INET && addr->ai_socktype == SOCK_STREAM) {
                sockaddr_in sin = {};
                sin.sin_family = addr->ai_family;
                sin.sin_addr = reinterpret_cast<sockaddr_in*>(addr->ai_addr)->sin_addr;
                sin.sin_port = htons(443);
                result.push_back(sin);
            }
        }

        return result;
    }

}


#pragma once

#include <string>
#include <memory>

namespace certmon {

    class Ssl;
    class Cert;

    class Ctx {
        struct Impl;
        std::unique_ptr<Impl> _impl;
    public:
        Ctx();
        ~Ctx();
        Ssl new_ssl();
    };

    class Ssl {
        struct Impl;
        std::unique_ptr<Impl> _impl;
        Ssl(std::unique_ptr<Impl> impl);

        friend Ctx;
    public:
        ~Ssl();
        void set_fd(int fd);
        void connect();
        Cert get_peer_certificate();
    };

    class Cert {
        struct Impl;
        std::unique_ptr<Impl> _impl;
        Cert(std::unique_ptr<Impl> impl);
        friend Ssl;
    public:
        ~Cert();
        time_t get_not_before();
        time_t get_not_after();
    };

    struct HostInfo {
        std::string name;
        time_t not_before;
        bool is_invalid;
        time_t not_after;
        bool is_expired;
    };

    HostInfo get_host_info(const std::string& hostname);


}


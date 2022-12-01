#include <fmt/printf.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <vector>
#include <sys/types.h>
#include <netdb.h>
#include <optional>
#include <BS_thread_pool.hpp>
#include <filesystem>
#include <restinio/all.hpp>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace ssl {

#define SSL_ERR(cond, fn) \
    do { \
    if(!(cond)) \
        throw std::runtime_error(#fn " failed"); \
    } while(false)

    struct Ssl;
    struct Cert;
    struct Time;

    struct Ctx {
        SSL_CTX* _ctx;

        Ctx();
        Ctx(const Ctx&) = delete;
        Ctx(Ctx&&);
        ~Ctx();
        Ctx& operator=(const Ctx&) = delete;
        Ctx& operator=(Ctx&&);
        Ssl new_ssl();
    };

    struct Ssl {
        ::SSL* _ssl;

        Ssl(SSL* ssl);
        Ssl(const Ssl&) = delete;
        Ssl(Ssl&&);
        ~Ssl();
        Ssl& operator=(const Ssl&) = delete;
        Ssl& operator=(Ssl&&);

        void set_fd(int fd);
        void connect();
        Cert get_peer_certificate();
    };

    struct Cert {
        X509* _cert;

        Cert(X509*);
        Cert(const Cert&) = delete;
        Cert(Cert&&);
        ~Cert();
        Cert& operator=(const Cert&);
        Cert& operator=(Cert&&);

        Time get_not_before();
        Time get_not_after();
    };

    struct Time {
        ASN1_TIME* _time;

        Time();
        Time(const ASN1_TIME* time);
        Time(const Time&);
        Time(Time&&);
        ~Time();
        Time& operator=(const Time&);
        Time& operator=(Time&&);
        bool operator<(const Time&);
        bool operator>(const Time&);

        bool check() const;
        std::string print() const;
        int compare(const Time& t) const;
    };

    Ctx::Ctx()
        : _ctx(SSL_CTX_new(SSLv23_method()))
    {
        if(!_ctx)
            throw std::runtime_error("SSL_CTX_new failed");
    }

    Ctx::Ctx(Ctx&& ctx)
        : _ctx(nullptr)
    {
        std::swap(_ctx, ctx._ctx);
    }

    Ctx::~Ctx()
    {
        if(_ctx)
            SSL_CTX_free(_ctx);
    }

    Ctx& Ctx::operator=(Ctx&& ctx)
    {
        std::swap(_ctx, ctx._ctx);
        return *this;
    }

    Ssl Ctx::new_ssl()
    {
        auto ssl = ::SSL_new(_ctx);
        SSL_ERR(ssl != nullptr, "SSL_new");
        return Ssl(ssl);
    }

    Ssl::Ssl(SSL* ssl)
        : _ssl(ssl)
    {
    }

    Ssl::Ssl(Ssl&& ssl)
        : _ssl(nullptr)
    {
        std::swap(_ssl, ssl._ssl);
    }

    Ssl& Ssl::operator=(Ssl&& ssl)
    {
        std::swap(_ssl, ssl._ssl);
        return *this;
    }

    Ssl::~Ssl()
    {
        if(_ssl)
            SSL_free(_ssl);
    }

    void Ssl::set_fd(int fd)
    {
        auto ret = ::SSL_set_fd(_ssl, fd);
        if(!ret) {
            throw std::runtime_error("SSL_set_fd failed");
        }
    }

    void Ssl::connect()
    {
        auto ret = ::SSL_connect(_ssl);
        if(ret <= 0) {
            throw std::runtime_error("SSL_connect failed");
        }
    }

    Cert Ssl::get_peer_certificate()
    {
        auto x509 = ::SSL_get_peer_certificate(_ssl);
        if(!x509) {
            throw std::runtime_error("SSL_get_peer_certificate failed");
        }

        return Cert(x509);
    }

    Cert::Cert(X509* cert)
        : _cert(cert)
    {
    }

    Cert::Cert(Cert&& cert)
        : _cert(nullptr)
    {
        std::swap(_cert, cert._cert);
    }

    Cert::~Cert()
    {
        if(_cert)
            ::X509_free(_cert);
    }

    Cert& Cert::operator=(Cert&& cert)
    {
        std::swap(_cert, cert._cert);
        return *this;
    }

    Time Cert::get_not_before()
    {
        return Time(::X509_get0_notBefore(_cert));
    }

    Time Cert::get_not_after()
    {
        return Time(::X509_get0_notAfter(_cert));
    }

    Time::Time()
    {
        auto t = ::time(nullptr);
        _time = ASN1_TIME_set(nullptr, t);
    }

    Time::Time(const ASN1_TIME* time)
        : _time(ASN1_STRING_dup(time))
    {
    }

    Time::Time(const Time& time)
        : _time(ASN1_STRING_dup(time._time))
    {
    }

    Time::Time(Time&& time)
        : _time(nullptr)
    {
        std::swap(_time, time._time);
    }

    Time::~Time()
    {
        if(_time)
            ASN1_STRING_free(_time);
    }

    Time& Time::operator=(const Time& time)
    {
        if(_time)
            ASN1_STRING_free(_time);
        _time = nullptr;
        if(time._time)
            _time = ASN1_STRING_dup(time._time);
        return *this;
    }

    Time& Time::operator=(Time&& time)
    {
        std::swap(_time, time._time);
        return *this;
    }

    bool Time::operator<(const Time& t)
    {
        return compare(t) < 0;
    }

    bool Time::operator>(const Time& t)
    {
        return compare(t) > 0;
    }

    bool Time::check() const
    {
        auto ret = ::ASN1_TIME_check(_time);
        return ret != 0;
    }
    
    std::string Time::print() const
    {
        auto bio = ::BIO_new(BIO_s_mem());
        SSL_ERR(bio != nullptr, "BIO_new");

        auto ret = ::ASN1_TIME_print(bio, _time);
        SSL_ERR(ret != 0, "ASN1_TIME_print");

        std::string result;
        char buffer[4096];
        while(true) {
            size_t read_bytes;
            int r = ::BIO_read_ex(bio, buffer, sizeof(buffer), &read_bytes);
            if(!r)
                break;

            result.append(buffer, read_bytes);
        }

        ::BIO_free(bio);

        return result;
    }

    int Time::compare(const Time& t) const
    {
        return ::ASN1_TIME_compare(_time, t._time);
    }

}

namespace net {

    struct Socket {
        int _fd;

        Socket();
        Socket(const Socket&) = delete;
        Socket(Socket&&);
        ~Socket();
        Socket& operator=(const Socket&) = delete;
        Socket& operator=(Socket&&);

        void connect(const std::string& address, int port);
        void connect(const sockaddr_in* addr);
    };


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

    void Socket::connect(const std::string& address, int port)
    {
        sockaddr_in sa = {};
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = inet_addr(address.c_str());
        sa.sin_port = htons(port);

        connect(&sa);
    }

    void Socket::connect(const sockaddr_in* addr)
    {
        auto ret = ::connect(_fd, reinterpret_cast<const sockaddr*>(addr), sizeof(*addr));
        if(ret == -1) {
            throw std::system_error(errno, std::system_category());
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

struct HostInfo {
    std::string name;
    std::string not_before;
    bool is_invalid;
    std::string not_after;
    bool is_expired;
};

HostInfo get_host_info(const std::string& hostname)
{
    auto addresses = net::lookup_host(hostname);
    if(addresses.empty()) {
        throw std::runtime_error("Host not found");
    }

    net::Socket sock;
    std::optional<std::string> last_error;
    bool connected = false;
    for(const auto addr : addresses) {
        try {
            sock.connect(&addr);
            connected = true;
            break;
        } catch(const std::exception& ex) {
            last_error = std::make_optional(ex.what());
        }
    }

    if(!connected) {
        throw std::runtime_error(*last_error);
    }

    ssl::Ctx ctx;
    ssl::Ssl ssl = ctx.new_ssl();
    ssl.set_fd(sock._fd);
    ssl.connect();

    ssl::Cert cert = ssl.get_peer_certificate();

    HostInfo result;
    result.name = hostname;

    ssl::Time now;
    ssl::Time not_before = cert.get_not_before();
    result.not_before = not_before.print();
    result.is_invalid = not_before > now;

    ssl::Time not_after = cert.get_not_after();
    result.not_after = not_after.print();
    result.is_expired = not_after < now;

    return result;
}

bool ends_with(std::string_view haystack, std::string_view needle)
{
    return haystack.size() >= needle.size() &&
        haystack.substr(haystack.size() - needle.size()) == needle;
}

std::optional<std::string> get_mimetype(const std::filesystem::path& filename)
{
    static const std::map<std::string,std::string> mimetypes = {
        { ".js", "text/javascript" },
        { ".html", "text/html" },
        { ".htm", "text/html" },
        { ".ico", "image/vnd.microsoft.icon" },
        { ".css", "text/css" },
    };

    auto it = mimetypes.find(filename.extension().string());
    if(it != mimetypes.end())
        return it->second;
    else
        return std::nullopt;
}

int main(int argc, char** argv)
{
    BS::thread_pool pool;

    auto router = std::make_unique<restinio::router::express_router_t<>>();
    router->http_get("/api/v1/host/:hostname",
            [](auto req, auto params) {
                std::string hostname(params["hostname"]);
                auto result = json::object();
                result["name"] = hostname;
                try {
                    HostInfo info = get_host_info(hostname);
                    result["not_before"] = info.not_before;
                    result["not_after"] = info.not_after;
                    result["is_invalid"] = info.is_invalid;
                    result["is_expired"] = info.is_expired;
                } catch(const std::exception& ex) {
                    result["error"] = ex.what();
                }

                return req->create_response()
                    .set_body(result.dump())
                    .append_header(restinio::http_field::content_type, "application/json")
                    .done();
            });
    router->non_matched_request_handler(
            [](auto req) {
                std::string r_path(req->header().path());
                while(!r_path.empty() && r_path.front() == '/')
                    r_path = r_path.substr(1);
                while(!r_path.empty() && r_path.back() == '/')
                    r_path.pop_back();

                std::filesystem::path path = "static";
                path.append(r_path);
                auto status = std::filesystem::status(path);
                if(std::filesystem::is_directory(status))
                    path.append("index.html");
                status = std::filesystem::status(path);

                fmt::fprintf(stderr, "path: %s\n", path.string());
                if(std::filesystem::is_regular_file(status) || std::filesystem::is_symlink(status)) {
                    auto response = req->create_response(restinio::status_ok())
                        .set_body(restinio::sendfile(path.string()))
                        .connection_close();

                    auto mimetype = get_mimetype(path);
                    if(mimetype)
                        response.append_header(restinio::http_field::content_type, *mimetype);
                        
                    return response.done();
                } else {
                    return req->create_response(restinio::status_not_found())
                        .set_body(
                                fmt::sprintf("404 Bâchée not found\nUrl: %s\n", r_path)
                        )
                        .append_header(restinio::http_field::content_type, "text/plain; charset=utf-8")
                        .connection_close()
                        .done();
                }
            });

    struct server_traits : public restinio::default_single_thread_traits_t {
        using request_handler_t = restinio::router::express_router_t<>;
    };

    restinio::run(
            restinio::on_this_thread<server_traits>()
                .port(8080)
                .address("localhost")
                .request_handler(std::move(router)));
    return 0;
}


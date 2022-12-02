#include "ssl.h"
#include "net.h"
#include <ctime>
#include <fmt/printf.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#define SSL_ERR(cond, fn) \
    do { \
    if(!(cond)) \
        throw std::runtime_error(#fn " failed"); \
    } while(false)

namespace certmon {

    struct Ctx::Impl {
        ::SSL_CTX* _ctx;

        Impl();
        Impl(const Impl&) = delete;
        Impl(Impl&&) = delete;
        ~Impl();
        Impl& operator=(const Impl&) = delete;
        Impl& operator=(Impl&&) = delete;
        Ssl new_ssl();
    };

    struct Ssl::Impl {
        ::SSL* _ssl;

        Impl(SSL* ssl);
        Impl(const Impl&) = delete;
        Impl(Impl&&) = delete;
        ~Impl();
        Impl& operator=(const Impl&) = delete;
        Impl& operator=(Impl&&) = delete;

        void set_fd(int fd);
        void connect();
        Cert get_peer_certificate();
    };

    struct Cert::Impl {
        ::X509* _cert;

        Impl(X509*);
        Impl(const Impl&) = delete;
        Impl(Impl&&) = delete;
        ~Impl();
        Impl& operator=(const Impl&) = delete;
        Impl& operator=(Impl&&) = delete;

        time_t get_not_before();
        time_t get_not_after();
    };

    /*************************************** Ctx::Impl ***************************************/
    Ctx::Impl::Impl()
        : _ctx(SSL_CTX_new(SSLv23_method()))
    {
        SSL_ERR(_ctx != nullptr, "SSL_CTX_new");
    }

    Ctx::Impl::~Impl()
    {
        if(_ctx)
            SSL_CTX_free(_ctx);
    }

    Ssl Ctx::Impl::new_ssl()
    {
        auto ssl = ::SSL_new(_ctx);
        SSL_ERR(ssl != nullptr, "SSL_new");
        return Ssl(std::make_unique<Ssl::Impl>(ssl));
    }

    /*************************************** Ssl::Impl ***************************************/
    Ssl::Impl::Impl(SSL* ssl)
        : _ssl(ssl)
    {
    }

    Ssl::Impl::~Impl()
    {
        if(_ssl)
            SSL_free(_ssl);
    }

    void Ssl::Impl::set_fd(int fd)
    {
        auto ret = ::SSL_set_fd(_ssl, fd);
        SSL_ERR(ret != 0, "SSL_set_fd");
    }

    void Ssl::Impl::connect()
    {
        auto ret = ::SSL_connect(_ssl);
        SSL_ERR(ret > 0, "SSL_connect");
    }

    Cert Ssl::Impl::get_peer_certificate()
    {
        auto x509 = ::SSL_get_peer_certificate(_ssl);
        SSL_ERR(x509 != nullptr, "SSL_get_peer_certificate");
        return Cert(std::make_unique<Cert::Impl>(x509));
    }

    /*************************************** Cert::Impl ***************************************/
    Cert::Impl::Impl(X509* cert)
        : _cert(cert)
    {
    }

    Cert::Impl::~Impl()
    {
        if(_cert)
            ::X509_free(_cert);
    }

    time_t asn1_time_to_time_t(const ASN1_TIME* asn1_time)
    {
        struct tm tm;
        auto ret = ::ASN1_TIME_to_tm(asn1_time, &tm);
        SSL_ERR(ret != 0, "ASN1_TIME_to_tm");

        auto result = timegm(&tm);
        return result;
    }

    time_t Cert::Impl::get_not_before()
    {
        auto asn1_time = ::X509_get0_notBefore(_cert);
        return asn1_time_to_time_t(asn1_time);
    }

    time_t Cert::Impl::get_not_after()
    {
        auto asn1_time = ::X509_get0_notAfter(_cert);
        return asn1_time_to_time_t(asn1_time);
    }

    /*************************************** Ctx ***************************************/
    Ctx::Ctx()
        : _impl(std::make_unique<Ctx::Impl>())
    {
    }

    Ctx::~Ctx()
    {
    }

    Ssl Ctx::new_ssl()
    {
        return _impl->new_ssl();
    }

    /*************************************** Ssl ***************************************/
    Ssl::Ssl(std::unique_ptr<Ssl::Impl> impl)
        : _impl(std::move(impl))
    {
    }

    Ssl::~Ssl()
    {
    }

    void Ssl::set_fd(int fd)
    {
        _impl->set_fd(fd);
    }

    void Ssl::connect()
    {
        _impl->connect();
    }

    Cert Ssl::get_peer_certificate()
    {
        return _impl->get_peer_certificate();
    }

    /*************************************** Cert ***************************************/
    Cert::Cert(std::unique_ptr<Cert::Impl> impl)
        : _impl(std::move(impl))
    {
    }

    Cert::~Cert()
    {
    }

    time_t Cert::get_not_before()
    {
        return _impl->get_not_before();
    }

    time_t Cert::get_not_after()
    {
        return _impl->get_not_after();
    }

    /*************************************** get_host_info ***************************************/
    HostInfo get_host_info(const std::string& hostname)
    {
        std::vector<sockaddr_in> addresses = lookup_host(hostname);

        std::optional<Socket> sock;
        std::optional<std::string> last_error;
        bool connected = false;
        for(const auto& addr : addresses) {
            try {
                sock = std::make_optional<Socket>();
                sock->connect(&addr, 2500);
                connected = true;
                break;
            } catch(const std::exception& ex) {
                last_error = std::make_optional(ex.what());
            }
        }
        if(!connected) {
            throw std::runtime_error(*last_error);
        }

        Ctx ctx;
        auto ssl = ctx.new_ssl();
        ssl.set_fd(sock->_fd);
        ssl.connect();

        auto cert = ssl.get_peer_certificate();

        time_t now = time(nullptr);
        HostInfo result;
        result.name = hostname;
        result.not_before = cert.get_not_before();
        result.is_invalid = now < result.not_before;
        result.not_after = cert.get_not_after();
        result.is_expired = now > result.not_after;
        return result;
    }

}


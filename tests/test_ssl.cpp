#include <BS_thread_pool.hpp>
#include <cassert>
#include <common/net.h>
#include <common/ssl.h>
#include <common/util.h>
#include <fmt/printf.h>
#include <list>

using namespace certmon;

int main()
{
    BS::thread_pool pool;

    std::vector<std::string> hostnames = {
        "apple.com",
        "aws.amazon.com",
        "azure.microsoft.com",
        "badssle.com",
        "cloudflare.com",
        "deb.debian.org",
        "doubleclick.net",
        "expired.badssl.com",
        "fbcdn-creative-a.akamaihd.net",
        "fbcdn-profile-a.akamaihd.net",
        "fbcdn-sphotos-a-a.akamaihd.net",
        "fbcdn.net",
        "fbexternal-a.akamaihd.net",
        "fbstatic-a.akamaihd.net",
        "google-analytics.com",
        "googleapis.com",
        "googleusercontent.com",
        "gstatic.com",
        "neverssl.com",
        "smtp.google.com",
        "twitter.com",
        "wikipedia.org",
        "wrong.host.badssl.com",
        "www.debian.org",
        "www.example.com",
        "www.example.org",
        "www.facebook.com",
        "www.github.com",
        "www.google.com",
        "www.microsoft.com",
        "www.reddit.com",
        "www.stackoverflow.com",
        "youtube.com",
    };

    std::list<std::future<void>> tasks;
    for(std::string hostname: hostnames) {
        tasks.push_back(pool.submit([hostname]() {
            std::vector<sockaddr_in> addresses;
            try {
                addresses = lookup_host(hostname);
            } catch(const std::exception& ex) {
                fmt::printf("%-32s %s\n", hostname, ex.what());
                return;
            }

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
                fmt::printf("%-32s %s\n", hostname, *last_error);
                return;
            }

            Ctx ctx;
            auto ssl = ctx.new_ssl();
            ssl.set_fd(sock->_fd);
            ssl.connect();

            auto cert = ssl.get_peer_certificate();
            auto not_before = format_timestamp(cert.get_not_before());
            auto not_after = format_timestamp(cert.get_not_after());

            fmt::printf("%-32s %s     %s\n", hostname, not_before, not_after);
        }));
    }

    for(auto& task: tasks) {
        task.wait();
    }

    return 0;
}


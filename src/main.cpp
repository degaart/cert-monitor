#include <BS_thread_pool.hpp>
#include <common/net.h>
#include <common/ssl.h>
#include <common/util.h>
#include <filesystem>
#include <fmt/printf.h>
#include <nlohmann/json.hpp>
#include <optional>
#include <restinio/all.hpp>
#include <signal.h>
#include <unistd.h>
#include <vector>

using json = nlohmann::json;
using namespace certmon;

int main(int argc, char** argv)
{
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, nullptr);

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
            restinio::on_thread_pool<server_traits>(8)
                .port(8080)
                .address("localhost")
                .request_handler(std::move(router)));
    return 0;
}


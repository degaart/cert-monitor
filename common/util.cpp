#include "util.h"
#include <map>
#include <vector>

namespace certmon {

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

    std::string format_timestamp(time_t ts, const std::string& format, bool utc)
    {
        struct tm tm;
        if(utc)
            gmtime_r(&ts, &tm);
        else
            localtime_r(&ts, &tm);

        std::vector<char> buffer(((format.size() + 4095) / 4096) * 4096);
        while(true) {
            auto ret = ::strftime(buffer.data(), buffer.size(), format.c_str(), &tm);
            if(ret)
                break;
            buffer.resize(buffer.size() + 4096);
        };

        std::string result(buffer.data(), buffer.size() - 1);
        return result;
    }

}


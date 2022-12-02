#pragma once

#include <string>
#include <string_view>
#include <optional>
#include <filesystem>
#include <time.h>

namespace certmon {

    bool ends_with(std::string_view haystack, std::string_view needle);
    std::optional<std::string> get_mimetype(const std::filesystem::path& filename);
    std::string format_timestamp(time_t ts, const std::string& format = "%F %T", bool utc = false);

}


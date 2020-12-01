local char_to_hex = function(c)
    return string.format("%%%02X", string.byte(c))
end

-- local hex_to_char = function(x)
--     return string.char(tonumber(x, 16))
-- end

local function urlencode(url)
    if url == nil then
        return nil
    end
    url = url:gsub("([^%w%-%.%_%~ ])", char_to_hex)
    url = url:gsub(" ", "+")
    return url
end

-- local function urldecode(url)
--     if url == nil then
--         return nil
--     end
--     url = url:gsub("+", " ")
--     url = url:gsub("%%(%x%x)", hex_to_char)
--     return url
-- end

return function(params)
    local str = ""
    local is_first = true
    for k, v in pairs(params) do
        if type(v) == "table" then
            --TODO:
            assert(false)
        else
            str = str .. k .. "=" .. v
        end
        if is_first then
            str = str .. "&"
            is_first = false
        end
    end
    return urlencode(str)
end

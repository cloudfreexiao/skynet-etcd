local concat_tab = table.concat
local tostring = tostring
local select = select
local ipairs = ipairs
local pairs = pairs
local type = type

local _M = {}

function _M.split(input, delimiter)
    input = tostring(input)
    delimiter = tostring(delimiter)
    if (delimiter == "") then
        return false
    end
    local pos, arr = 0, {}
    -- for each divider found
    for st, sp in function()
        return string.find(input, delimiter, pos, true)
    end do
        table.insert(arr, string.sub(input, pos, st - 1))
        pos = sp + 1
    end
    table.insert(arr, string.sub(input, pos))
    return arr
end

local normalize
do
    local items = {}
    local function concat(sep, ...)
        local argc = select("#", ...)
        items = {}
        local len = 0

        for i = 1, argc do
            local v = select(i, ...)
            if v ~= nil then
                len = len + 1
                items[len] = tostring(v)
            end
        end

        return concat_tab(items, sep)
    end

    local segs = {}
    function normalize(...)
        local path = concat("/", ...)
        local names = {}

        segs = _M.split(path, [[/]])
        if not segs then
            return nil
        end

        local len = 0
        for _, seg in ipairs(segs) do
            if seg == ".." then
                if len > 0 then
                    len = len - 1
                end
            elseif seg == "" or seg == "/" and names[len] == "/" then
                -- do nothing
            elseif seg ~= "." then
                len = len + 1
                names[len] = seg
            end
        end

        return "/" .. concat_tab(names, "/", 1, len)
    end
end
_M.normalize = normalize

function _M.get_real_key(prefix, key)
    return (type(prefix) == "string" and prefix or "") .. key
end

function _M.has_value(arr, val)
    for key, value in pairs(arr) do
        if value == val then
            return key
        end
    end

    return false
end

local skynet = require "skynet"
local ngx_log = skynet.error
local function log_error(...)
    return ngx_log("ERR:", ...)
end
_M.log_error = log_error

local function log_info(...)
    return ngx_log("INFO:", ...)
end
_M.log_info = log_info

local function verify_key(key)
    if not key or #key == 0 then
        return false, "key should not be empty"
    end
    return true, nil
end
_M.verify_key = verify_key

local function is_empty_str(input_str)
    return (input_str or "") == ""
end
_M.is_empty_str = is_empty_str

return _M

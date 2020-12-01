local etcdv3 = require "etcd.v3"
local typeof = require "etcd.typeof"
local _M = {version = 0.1}

function _M.new(opts)
    opts = opts or {}
    if not typeof.table(opts) then
        return nil, "opts must be table"
    end

    opts.timeout = opts.timeout or 5 -- 5 sec
    opts.host = opts.host or "127.0.0.1:2379"
    opts.ttl = opts.ttl or -1
    opts.api_prefix = opts and opts.api_prefix or "/v3"

    return etcdv3.new(opts)
end

return _M

return function()
    local etcd = require "etcd.index"
    local cli, err = etcd.new()
    if not cli then
        Log.e("etcd cli error:", err)
        return
    end

    local res, serr = cli:set("/setxs", "abc")
    Log.dump(res, "etcd set:" .. tostring(serr))

    local data, gerr = cli:get("/setxs")
    Log.dump(data, "etcd get1:" .. tostring(gerr))

    res, serr = cli:setx("/setxs", "abd")
    Log.dump(res, "etcd setxs:" .. tostring(serr))

    data, gerr = cli:get("/setxs")
    Log.dump(data, "etcd get2:" .. tostring(gerr))
end


-- skynet.timeout(30 * 100, function ()
--     require("etcd.test")()
-- end)
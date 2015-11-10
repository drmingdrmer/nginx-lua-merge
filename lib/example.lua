local _M = {}

local strutil = require("acid.strutil")
local tableutil = require("acid.tableutil")
local mime = require("acid.ngx.mime")
local merge = require("acid.ngx.merge")


local repr = tableutil.repr

function _M.get_url_argument()

    local uri = ngx.var.request_uri
    local elts = strutil.split( uri, '[?][?]' )
    local uris, objnames = elts[1], elts[2]

    objnames = strutil.split(objnames, ';')

    return uris, objnames
end

function _M.get_ip(host)
    return '127.0.0.1'
end

function _M.doit()

    local uri, objnames = _M.get_url_argument()
    local headers = ngx.req.get_headers()
    local host = headers.host

    local parts = {}
    for i, name in ipairs(objnames) do
        local ip = _M.get_ip(host)
        local port = '9001'
        local url = ip .. ':' .. port .. uri .. '/' .. name
        table.insert(parts, {urls={url}})
    end

    if #parts == 0 then
        ngx.status = 200
        ngx.exit(ngx.HTTP_OK)
    end

    ngx.header['Content-Type'] = mime.by_fn(parts[1].urls[1])

    return merge.multi_part({}, parts)

end
return _M;

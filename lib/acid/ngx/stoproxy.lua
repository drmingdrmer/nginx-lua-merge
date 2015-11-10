local _M = { _VERSION="1" }

local strutil = require( "acid.strutil" )
local tableutil = require( "acid.tableutil" )
local ngx_http = require("acid.ngx.http")

local repr = tableutil.repr

-- NOTE: might be a bug of lua-nginx: when client closes connection,
--       ngx.print() pushes all data meant to send into buffer but
--       never sends, which causes nginx memory to increase
--       unlimitedly and finally hangs everything.
--
--       Thus we have to watch on_abort event.

local function ph(val)
    if val == nil then
        return '-'
    elseif type(val) == 'number' then
        if val % 1 == 0 then
            return tostring(val)
        else
            return string.format('%.3f', val)
        end
    else
        return tostring(val)
    end
end
local function log_str(logs)
    local s = {}
    for _, e in ipairs(logs) do

        local t = e.time or {}

        table.insert( s, table.concat({
            'status=', ph(e.status),
            ';err=', ph(e.err),
            ';url=', ph(e.ip), ':', ph(e.port), ph(e.uri),
            ';range=[', ph(e.range.from), ',', ph(e.range.to),')',
            ';sent=', ph(e.sent),
            ';time=', ph(t.conn), ',', ph(t.recv), ',', ph(t.send)
        }) )
    end

    return table.concat( s, ' ' )
end
local function quit_err(httpcode, errmes)
    -- errmes is ignored
    ngx.status = httpcode
    ngx.eof()
    ngx.exit(ngx.HTTP_OK)
end

local function make_http_connect_arg( loc, opts )

    local elts = strutil.split( loc, "/" )
    local ipport = table.remove( elts, 1 )
    local uri = loc:sub( #ipport + 1 )

    elts = strutil.split( ipport, ':' )
    local ip = elts[ 1 ]
    local port = tonumber( elts[ 2 ] )

    local req_args = {
        ip=ip, port=port, url=uri, method='GET',
        headers={},
    }

    return req_args
end
local function normalize_range(range, parts)
    local total = 0
    for _, p in ipairs(parts) do
        total = total + p.size
    end

    local r = {
        offset = range.offset,
        size = range.size,
        total = total,
    }

    if r.offset ~= nil then
        if r.size == nil then
            r.size = total - r.offset
        else
            r.size = math.min(total - r.offset, r.size)
        end
    end
    return r
end
local function make_download_parts(range, parts)

    local offset, size

    if range.offset == nil then
        offset, size = 0, range.total
    else
        offset, size = range.offset, range.size
    end

    local rst = {}

    for _, p in ipairs(parts) do

        if offset >= p.offset and offset < p.offset + p.size then

            local dl = {
                offset = offset - p.offset,
                size = math.min(size, p.size),
                urls = p.urls,
            }

            if dl.size > 0 then
                table.insert(rst, dl)

                offset = offset + dl.size
                size = size - dl.size

                if size == 0 then
                    break
                end
            end

        end
    end

    return rst
end
local function install_status_headers(range)
    if range.offset == nil then
        ngx.status = 200
        ngx.header['Content-Length'] = tostring(range.total)
    else
        ngx.status = 206
        ngx.header['Content-Length'] = tostring(range.size)
        ngx.header['Content-Range'] = string.format(
            'bytes %d-%d/%d',
            range.offset,
            range.offset + range.size - 1,
            range.total
        )
    end
    ngx.header['Date'] = ngx.http_time(ngx.time())
end
local function install_on_abort()
    local running = true
    local function is_running()
        return running
    end

    local function abort_cb()
        running = false
    end

    local ok, err = ngx.on_abort( abort_cb )
    if err then
        ngx.log( ngx.ERR, tostring( err ), ' while install on_abort' )
        quit_err( "InternalError", "failure to install on_abort" )
    end
    return is_running
end
local function http_connect_backend(req)

    -- connect and request timeout is 500
    local http = ngx_http:new( req.ip, req.port, 500 )
    local err, mes = http:request( req.url, {
        method = req.method,
        headers = req.headers,
    } )

    if err ~= nil then
        ngx.log( ngx.INFO, tostring( err ), ': ', mes, ' while request storage' )
        return http, err
    end

    -- since buf size is 1M. lowest possible client download bandwidth is
    -- 10K/s. There would be 1M/(10K/s) seconds before we start to read next
    -- chunk from storage.
    http:set_timeout(100*1000)

    return http, nil, nil
end
local function pipe_to_client(is_running, http)

    local rst = {
        sent = 0,
        time = {
            recv = 0,
            send = 0,
        }
    }
    local t = rst.time

    while is_running() do

        local t0 = ngx.now()
        local buf, err, mes = http:read_body( 1024*1024 )
        t.recv = t.recv + (ngx.now() - t0)

        if err ~= nil then
            return rst, err, mes
        end
        if buf == '' then
            break
        end

        if not is_running() then
            break
        end

        local t0 = ngx.now()
        ngx.print( buf )
        local _, err = ngx.flush( true )
        t.send = t.send + (ngx.now() - t0)

        if err then
            return rst, 'ClientAborted', err
        end
        rst.sent = rst.sent + #buf
    end
    return rst, nil, nil
end
local function transfer_part(is_running, part, opts, logs)

    -- part = {
    --     offset = 100, size = 10, urls={...}
    -- }

    local p = part
    local from = p.offset
    local to = p.offset + p.size
    local sent = 0

    for _, loc in ipairs(p.urls) do
        -- <ip>:<port>/...

        if from == to then
            break
        end

        if from > to then
            -- bug!
            ngx.log(ngx.ERR, "from > to: ", from, '>', to)
            ngx.exit(499)
        end

        local req = make_http_connect_arg( loc, opts )
        -- Range: bytes=<from>-<to>
        -- <to> is inclusive
        req.headers.Range = 'bytes=' .. from .. '-' .. (to-1)

        local t0 = ngx.now()
        local http, err, errmes = http_connect_backend( req )
        local tconn = (ngx.now() - t0)

        if err == nil and http.status ~= 206 then
            err, errmes = "InvalidResponse", "http code is " .. tostring(http.status)
        end

        local logentry = {
            ip=req.ip, port=req.port, uri=req.url, status=http.status, err=err,
            range = {from=from, to=to},
            time = {
                conn = tconn,
            },
        }
        table.insert(logs, logentry)

        if err == nil then

            local r, err, errmes = pipe_to_client(is_running, http)
            logentry.err = err

            -- If error occurs on client side, no more retry should be made.
            if err == 'ClientAborted' then
                return sent, err, errmes
            end

            -- with or without err:
            from = from + r.sent
            sent = sent + r.sent

            logentry.sent = r.sent
            logentry.time.recv = r.time.recv
            logentry.time.send = r.time.send

        end
    end

    -- after all remote peers being tried, there is still some data unfetched.
    if from == to then
        return sent, nil, nil
    else
        return sent, 'InvalidResponse', nil
    end
end
local function set_log_str(logs)
    if ngx.var.log_sto ~= nil then
        ngx.var.log_sto = log_str(logs)
    end
end

function _M.multi_part(range, parts, opts)

    -- Range: bytes=1-100
    -- local range = {offset=1, size=100}

    -- Range: bytes=1-
    -- local range = {offset=1, size=nil}

    -- no Range header:
    -- local range = {offset=nil, size=nil}

    -- local parts = {
    --     {size=10, urls={'ip:port/a/b', 'ip:port/c/d'}},
    --     {size=20, urls={'ip:port/a/b', 'ip:port/c/d'}},
    -- }

    opts = opts or {}

    -- range is disabled.
    range = {}
    if range.offset ~= nil or range.size ~= nil then
        range = normalize_range(range, parts)
    end

    -- offset: in part offset from where to use.
    -- size:   in part size of bytes that will be used.
    -- local dl_parts = {
    --     {offset=10, size=10, urls={'ip:port/a/b', 'ip:port/c/d'}},
    --     {offset=20, size=20, urls={'ip:port/a/b', 'ip:port/c/d'}},
    -- }
    local dl_parts = make_download_parts(range, parts)
    if #dl_parts == 0 then
        quit_err( "InvalidRange", "Requested Range Not Satisfiable" )
    end

    local logs = {}

    local is_running = install_on_abort()
    install_status_headers(range)

    local total_sent = 0

    for _, p in ipairs(dl_parts) do
        local sent, err, errmes = transfer_part(is_running, p, opts, logs)
        total_sent = total_sent + sent

        if err ~= nil then
            if err == 'ClientAborted' then
                set_log_str(logs)
                ngx.exit(499)
            end
            break
        end
    end

    set_log_str(logs)

    if total_sent > 0 then
        ngx.eof()
        ngx.exit( ngx.HTTP_OK )
    else
        -- Return 404 instead of InternalError
        -- Trying to fetch deleted server-side key would result in not-found
        -- on any of the storage nodes. This is not an error.
        quit_err( "NoSuchKey", "The specified key does not exist." )
    end

end

return _M

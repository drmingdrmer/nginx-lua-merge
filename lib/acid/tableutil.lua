local _M = { _VERSION = '0.1' }

function _M.nkeys(tbl)
    return #_M.keys(tbl)
end
function _M.keys(tbl)
    local ks = {}
    for k, _ in pairs(tbl) do
        table.insert( ks, k )
    end
    return ks
end

function _M.duplist(tbl, deep)
    local t = _M.dup( tbl, deep )
    local rst = {}

    local i = 0
    while true do
        i = i + 1
        if t[i] == nil then
            break
        end
        rst[i] = t[i]
    end
    return rst
end
function _M.dup(tbl, deep, ref_table)

    if type(tbl) ~= 'table' then
        return tbl
    end

    ref_table = ref_table or {}

    if ref_table[ tbl ] ~= nil then
        return ref_table[ tbl ]
    end

    local t = {}
    ref_table[tbl] = t

    for k, v in pairs( tbl ) do
        if deep then
            if type( v ) == 'table' then
                v = _M.dup(v, deep, ref_table)
            end
        end
        t[ k ] = v
    end
    return t
end

local function _contains(a, b, ref_table)

    if type(a) ~= 'table' or type(b) ~= 'table' then
        return a == b
    end

    if a == b then
        return true
    end

    if ref_table[a] == nil then
        ref_table[a] = {}
    end

    if ref_table[a][b] ~= nil then
        return ref_table[a][b]
    end
    ref_table[a][b] = true

    for k, v in pairs( b ) do
        local yes = _contains(a[k], v, ref_table)
        if not yes then
            return false
        end
    end
    return true
end
function _M.contains(a, b)
    return _contains( a, b, {} )
end
function _M.eq(a, b)
    return _M.contains(a, b) and _M.contains(b, a)
end

function _M.sub(tbl, ks)
    ks = ks or {}
    local t = {}
    for _, k in ipairs(ks) do
        t[k] = tbl[k]
    end
    return t
end
function _M.intersection(tables, val)

    local t = {}
    local n = 0

    for i, tbl in ipairs(tables) do
        n = n + 1
        for k, v in pairs(tbl) do
            t[ k ] = ( t[ k ] or 0 ) + 1
        end
    end

    local rst = {}
    for k, v in pairs(t) do
        if v == n then
            rst[ k ] = val or tables[ 1 ][ k ]
        end
    end
    return rst
end
function _M.union(tables, val)
    local t = {}

    for i, tbl in ipairs(tables) do
        for k, v in pairs(tbl) do
            t[ k ] = val or v
        end
    end
    return t
end
function _M.merge(tbl, ...)
    for _, src in ipairs({...}) do
        for k, v in pairs(src) do
            tbl[ k ] = v
        end
    end
    return tbl
end

local function repr_opt(opt)
    opt = opt or {}
    opt.indent = opt.indent or ''
    opt.sep = opt.sep or ''
    return opt
end
local function normkey(k, opt)

    if opt.mode == 'str' then
        return tostring(k)
    end

    local key
    if type(k) == 'string' and string.match( k, '^[%a_][%w_]*$' ) ~= nil then
        key = k
    else
        key = '['.._M.repr(k)..']'
    end
    return key
end
local function extend(lst, sublines, opt)
    for _, sl in ipairs(sublines) do
        table.insert( lst, opt.indent .. sl )
    end
    lst[ #lst ] = lst[ #lst ] .. ','
end
function _M.str(t, opt)
    opt = repr_opt(opt)
    opt.mode = 'str'
    return _M._repr(t, opt)
end
function _M.repr(t, opt)
    opt = repr_opt(opt)
    return _M._repr(t, opt)
end
function _M._repr(t, opt)
    local lst = _M._repr_lines(t, opt)
    local sep = opt.sep
    if opt.indent ~= "" then
        sep = "\n"
    end
    return table.concat( lst, sep )
end
function _M._repr_lines(t, opt)

    local tp = type( t )

    if tp == 'string' then
        local s = string.format('%q', t)
        if opt.mode == 'str' then
            -- strip quotes
            s = s:sub( 2, -2 )
        end
        return { s }

    elseif tp ~= 'table' then
        return { tostring(t) }
    end

    -- table

    local keys = _M.keys(t)
    if #keys == 0 then
        return { '{}' }
    end

    table.sort( keys, function( a, b ) return tostring(a)<tostring(b) end )

    local lst = {'{'}

    local i = 1
    while t[i] ~= nil do
        local sublines = _M._repr_lines(t[i], opt)
        extend(lst, sublines, opt)
        i = i+1
    end

    for _, k in ipairs(keys) do

        if type(k) ~= 'number' or k > i then

            local sublines = _M._repr_lines(t[k], opt)
            sublines[ 1 ] = normkey(k, opt) ..'='.. sublines[ 1 ]
            extend(lst, sublines, opt)
        end
    end

    -- remove the last ','
    lst[ #lst ] = lst[ #lst ]:sub( 1, -2 )

    table.insert( lst, '}' )
    return lst
end

return _M

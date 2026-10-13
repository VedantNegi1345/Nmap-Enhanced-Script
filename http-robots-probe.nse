local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enhanced version of http-robots.txt.

Fetches /robots.txt, extracts every Disallow entry and then sends a request to
each path to find out which ones actually respond. Each path is reported with
its HTTP status code (and the redirect target for 3xx responses). Paths that
return 404/410 are hidden by default so the output only lists entries that
exist on the server. Wildcard entries (containing * or $) cannot be requested
directly and are skipped.

A HEAD request is used first; if the server answers 405/501 or does not
answer, the script falls back to GET.
]]

---
-- @usage
-- nmap -p80 --script ./http-robots-probe.nse <target>
-- nmap -p80 --script ./http-robots-probe.nse --script-args http-robots-probe.maxpaths=50,http-robots-probe.showall=true <target>
--
-- @args http-robots-probe.maxpaths Maximum number of Disallow paths to probe. Default: 20
-- @args http-robots-probe.showall  If true, also list paths returning 404/410. Default: false
--
-- @output
-- 8080/tcp open  http-proxy
-- | http-robots-probe:
-- |   Disallowed entries: 8
-- |   Probed: 6
-- |   Skipped (wildcards): 2
-- |   Responding: 4
-- |   Hidden (404/410): 2
-- |   Live paths:
-- |     /admin/ [200]
-- |     /backup/ [403]
-- |     /old/ [301 -> /new/]
-- |_    /private/ [401]

author = "Eddie Bell; Modified by Vedant Negi"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

-- Collect unique, non-empty Disallow values from the robots.txt body.
local function parse_disallow(body)
  local paths, seen = {}, {}
  for line in body:gmatch("[^\r\n]+") do
    line = line:gsub("#.*$", "")
    local p = line:match("^%s*[Dd][Ii][Ss][Aa][Ll][Ll][Oo][Ww]%s*:%s*(.-)%s*$")
    if p and p ~= "" and not seen[p] then
      seen[p] = true
      paths[#paths + 1] = p
    end
  end
  return paths
end

-- HEAD first, GET as fallback. Redirects are not followed so that the real
-- status code of the path is reported.
local function probe(host, port, path)
  local opts = {redirect_ok = false}
  local resp = http.head(host, port, path, opts)
  if (not resp) or (not resp.status) or resp.status == 405 or resp.status == 501 then
    resp = http.get(host, port, path, opts)
  end
  return resp
end

action = function(host, port)
  local maxpaths = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".maxpaths")) or 20
  local showall = stdnse.get_script_args(SCRIPT_NAME .. ".showall")
  showall = (showall == true or showall == "true" or showall == "1")

  local answer = http.get(host, port, "/robots.txt")
  if not answer or answer.status ~= 200 or not answer.body then
    return nil
  end

  local disallowed = parse_disallow(answer.body)
  if #disallowed == 0 then
    return nil
  end

  local live, hidden, skipped, errors, probed = {}, 0, 0, 0, 0

  for _, path in ipairs(disallowed) do
    if path:find("[%*%$]") then
      skipped = skipped + 1
    elseif probed >= maxpaths then
      break
    else
      probed = probed + 1
      if path:sub(1, 1) ~= "/" then path = "/" .. path end
      local resp = probe(host, port, path)
      if not resp or not resp.status then
        errors = errors + 1
      elseif (resp.status == 404 or resp.status == 410) and not showall then
        hidden = hidden + 1
      else
        local entry = ("%s [%d"):format(path, resp.status)
        local loc = resp.header and resp.header.location
        if resp.status >= 300 and resp.status < 400 and loc then
          entry = entry .. " -> " .. loc
        end
        live[#live + 1] = {status = resp.status, text = entry .. "]"}
      end
    end
  end

  -- Sort by status code, then alphabetically
  table.sort(live, function(a, b)
    if a.status ~= b.status then return a.status < b.status end
    return a.text < b.text
  end)
  local lines = {}
  for _, e in ipairs(live) do lines[#lines + 1] = e.text end

  local out = stdnse.output_table()
  out["Disallowed entries"] = #disallowed
  out["Probed"] = probed
  if skipped > 0 then out["Skipped (wildcards)"] = skipped end
  if errors > 0 then out["No response"] = errors end
  out["Responding"] = #lines
  if hidden > 0 then out["Hidden (404/410)"] = hidden end
  if #lines > 0 then out["Live paths"] = lines end
  if #disallowed > probed + skipped then
    out["Not probed (maxpaths reached)"] = #disallowed - probed - skipped
  end
  return out
end

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enhanced version of http-robots.txt.

The original script only prints Disallow entries. This version parses the
whole robots.txt file:

  * rules are grouped per User-agent block (Disallow, Allow, Crawl-delay)
  * every Sitemap: directive is listed
  * each sitemap that lives on the scanned host is fetched and the first N
    <loc> URLs are shown
  * sitemap index files are followed one level deep

Sitemaps hosted on a different host are listed but never requested.
Compressed sitemaps (.gz) are listed but not downloaded.
]]

---
-- @usage
-- nmap -p80 --script ./http-robots-sitemap.nse <target>
-- nmap -p80 --script ./http-robots-sitemap.nse --script-args http-robots-sitemap.sitemapurls=20 <target>
--
-- @args http-robots-sitemap.sitemapurls Number of URLs to show per sitemap. Default: 10
-- @args http-robots-sitemap.maxsitemaps Maximum child sitemaps followed from an index. Default: 3
-- @args http-robots-sitemap.maxrules    Maximum rules shown per list. Default: 15
-- @args http-robots-sitemap.fetch       Set to false to list Sitemap lines without fetching them. Default: true
--
-- @output
-- 8080/tcp open  http-proxy
-- | http-robots-sitemap:
-- |   User-agent groups (2):
-- |     User-agent *:
-- |       Disallow (3):
-- |         /admin/
-- |         /backup/
-- |         /private/
-- |       Allow (1):
-- |         /public/
-- |       Crawl-delay: 10
-- |     User-agent Googlebot:
-- |       Disallow (1):
-- |         /tmp/
-- |   Sitemaps (1):
-- |     http://127.0.0.1:8080/sitemap.xml
-- |       Type: urlset
-- |       URLs found: 4 (showing 4)
-- |         http://127.0.0.1:8080/
-- |_        http://127.0.0.1:8080/about

author = "Your Name"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local function is_true(v, default)
  if v == nil then return default end
  return (v == true or v == "true" or v == "1")
end

-- Keep at most `max` items and add a "... N more" marker.
local function cap(list, max)
  local res = {}
  for i = 1, math.min(#list, max) do res[i] = list[i] end
  if #list > max then res[#res + 1] = ("... %d more"):format(#list - max) end
  return res
end

-- Parse robots.txt into user-agent groups and a list of sitemap URLs.
local function parse_robots(body)
  local groups, sitemaps, seen_sm = {}, {}, {}
  local current, last_was_ua = nil, false

  for line in body:gmatch("[^\r\n]+") do
    line = line:gsub("#.*$", "")
    local key, val = line:match("^%s*([%w%-]+)%s*:%s*(.-)%s*$")
    if key then
      key = key:lower()
      if key == "user-agent" then
        if not last_was_ua or not current then
          current = {agents = {}, disallow = {}, allow = {}}
          groups[#groups + 1] = current
        end
        current.agents[#current.agents + 1] = val
        last_was_ua = true
      elseif key == "sitemap" then
        if val ~= "" and not seen_sm[val] then
          seen_sm[val] = true
          sitemaps[#sitemaps + 1] = val
        end
      else
        last_was_ua = false
        if current then
          if key == "disallow" and val ~= "" then
            current.disallow[#current.disallow + 1] = val
          elseif key == "allow" and val ~= "" then
            current.allow[#current.allow + 1] = val
          elseif key == "crawl-delay" and val ~= "" then
            current.crawl_delay = val
          end
        end
      end
    end
  end
  return groups, sitemaps
end

-- Split a URL into host (no port) and path+query. Returns nil if not http(s).
local function split_url(url)
  local _, hostpart, path = url:match("^(https?)://([^/]+)(.*)$")
  if not hostpart then return nil end
  hostpart = hostpart:gsub(":%d+$", ""):lower()
  if path == "" then path = "/" end
  return hostpart, path
end

local function same_host(host, name)
  name = name:lower()
  return name == (host.ip or ""):lower()
      or name == (host.targetname or ""):lower()
      or name == (host.name or ""):lower()
end

-- Fetch one sitemap, return type ("urlset"/"sitemapindex") and list of <loc>.
local function fetch_sitemap(host, port, url)
  local hostname, path = split_url(url)
  if not hostname then return nil, "unsupported URL" end
  if not same_host(host, hostname) then return nil, "different host, not fetched" end
  if path:lower():match("%.gz$") then return nil, "compressed, not fetched" end

  local resp = http.get(host, port, path)
  if not resp or resp.status ~= 200 or not resp.body then
    return nil, "HTTP " .. tostring(resp and resp.status or "no response")
  end

  local kind = resp.body:find("<sitemapindex", 1, true) and "sitemapindex" or "urlset"
  local locs = {}
  for loc in resp.body:gmatch("<loc>%s*(.-)%s*</loc>") do
    loc = loc:gsub("&amp;", "&"):gsub("<!%[CDATA%[(.-)%]%]>", "%1")
    locs[#locs + 1] = loc
  end
  return kind, locs
end

action = function(host, port)
  local show_urls = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".sitemapurls")) or 10
  local max_children = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".maxsitemaps")) or 3
  local max_rules = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".maxrules")) or 15
  local do_fetch = is_true(stdnse.get_script_args(SCRIPT_NAME .. ".fetch"), true)

  local answer = http.get(host, port, "/robots.txt")
  if not answer or answer.status ~= 200 or not answer.body then
    return nil
  end

  local groups, sitemaps = parse_robots(answer.body)
  if #groups == 0 and #sitemaps == 0 then
    return nil
  end

  local out = stdnse.output_table()

  -- Per user-agent groups
  if #groups > 0 then
    local gtab = stdnse.output_table()
    for _, g in ipairs(groups) do
      local entry = stdnse.output_table()
      if #g.disallow > 0 then
        entry[("Disallow (%d)"):format(#g.disallow)] = cap(g.disallow, max_rules)
      end
      if #g.allow > 0 then
        entry[("Allow (%d)"):format(#g.allow)] = cap(g.allow, max_rules)
      end
      if g.crawl_delay then entry["Crawl-delay"] = g.crawl_delay end
      if #g.disallow == 0 and #g.allow == 0 and not g.crawl_delay then
        entry["Rules"] = "none (everything allowed)"
      end
      gtab["User-agent " .. table.concat(g.agents, ", ")] = entry
    end
    out[("User-agent groups (%d)"):format(#groups)] = gtab
  end

  -- Sitemaps
  if #sitemaps > 0 then
    local stab = stdnse.output_table()
    for _, url in ipairs(sitemaps) do
      local entry = stdnse.output_table()
      if not do_fetch then
        entry["Status"] = "not fetched (fetch=false)"
      else
        local kind, locs = fetch_sitemap(host, port, url)
        if not kind then
          entry["Status"] = locs
        else
          entry["Type"] = kind
          if kind == "sitemapindex" then
            entry[("Child sitemaps (%d)"):format(#locs)] = cap(locs, show_urls)
            local all_urls = {}
            for i = 1, math.min(#locs, max_children) do
              local ckind, clocs = fetch_sitemap(host, port, locs[i])
              if ckind == "urlset" then
                for _, u in ipairs(clocs) do all_urls[#all_urls + 1] = u end
              end
            end
            if #all_urls > 0 then
              entry[("URLs from first %d child sitemap(s) (%d total, showing %d)")
                :format(math.min(#locs, max_children), #all_urls, math.min(#all_urls, show_urls))] =
                cap(all_urls, show_urls)
            end
          else
            entry[("URLs found: %d (showing %d)"):format(#locs, math.min(#locs, show_urls))] =
              cap(locs, show_urls)
          end
        end
      end
      stab[url] = entry
    end
    out[("Sitemaps (%d)"):format(#sitemaps)] = stab
  end

  return out
end

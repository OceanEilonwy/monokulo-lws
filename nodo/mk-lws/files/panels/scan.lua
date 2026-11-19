-- The light wallet server's scan, from its public GET /daemon_status
-- (crates/monokulo-lws/src/rest/wallet.rs): daemon_reachable, daemon_height, daemon_synced,
-- scanner_height, scanner_error (null, or a fixed sentence when the last step failed),
-- scanner_engine ({ gpu = true, name } or { gpu = false, reason }) and catch_up_lanes (a list of
-- { id, cursor, accounts }). It says nothing of where the node is.

local function thousands(n)
  local s = tostring(math.floor(n))
  local out = ""
  while #s > 3 do
    out = "," .. s:sub(-3) .. out
    s = s:sub(1, -4)
  end
  return s .. out
end

return {
  panel = function(d, history)
    local scanned = d.scanner_height or 0
    local chain = d.daemon_height or 0
    local out = { rows = {}, series = history }
    if chain > 0 and scanned + 1 < chain then
      local pct = math.floor(scanned / chain * 100)
      out.big = pct .. "%"
      out.unit = "scanned"
      out.bar = scanned / chain
      out.status = "busy"
      table.insert(out.rows, { "behind", thousands(chain - scanned) .. " blocks" })
    elseif scanned > 0 then
      out.big = thousands(scanned)
      out.unit = "blocks"
      out.status = "ok"
    else
      out.big = "--"
      out.unit = "starting"
      out.status = "idle"
    end
    out.sample = scanned
    local lanes = d.catch_up_lanes or {}
    local accounts = 0
    for _, lane in ipairs(lanes) do
      accounts = accounts + (lane.accounts or 0)
    end
    if #lanes > 0 then
      table.insert(out.rows, { "catching up", accounts .. (accounts == 1 and " wallet" or " wallets") })
    end
    local engine = d.scanner_engine
    if type(engine) == "table" then
      table.insert(out.rows, { "engine", engine.gpu and "GPU" or "CPU" })
    end
    if d.daemon_reachable == false then
      out.status = "error"
      out.note = "the node does not answer"
    elseif d.scanner_error then
      out.status = "warn"
      out.note = "the last scan step failed"
    elseif d.daemon_synced == false then
      out.status = "busy"
      out.note = "the node is still syncing"
    end
    return out
  end,
}

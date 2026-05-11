local function getService(name)
	local service = game:GetService(name)
	return if cloneref then cloneref(service) else service
end

local Players = getService("Players")
local UserInputService = getService("UserInputService")
local GuiService = getService("GuiService")
local HttpService = getService("HttpService")

-- ── SHA-256 (pure Luau) — privacy-focused one-way hash of UserId ─────────────
-- Produces a 64-char hex digest. The server re-hashes this with a secret key
-- (HMAC-SHA-256) before storage, so even if analytics data leaks the stored
-- hashes cannot be reversed to Roblox UserIds without the server secret.
local function hashUserId(userId)
	local band, bxor, bnot = bit32.band, bit32.bxor, bit32.bnot
	local rshift, lshift, rrotate = bit32.rshift, bit32.lshift, bit32.rrotate

	local K = {
		0x428a2f98,
		0x71374491,
		0xb5c0fbcf,
		0xe9b5dba5,
		0x3956c25b,
		0x59f111f1,
		0x923f82a4,
		0xab1c5ed5,
		0xd807aa98,
		0x12835b01,
		0x243185be,
		0x550c7dc3,
		0x72be5d74,
		0x80deb1fe,
		0x9bdc06a7,
		0xc19bf174,
		0xe49b69c1,
		0xefbe4786,
		0x0fc19dc6,
		0x240ca1cc,
		0x2de92c6f,
		0x4a7484aa,
		0x5cb0a9dc,
		0x76f988da,
		0x983e5152,
		0xa831c66d,
		0xb00327c8,
		0xbf597fc7,
		0xc6e00bf3,
		0xd5a79147,
		0x06ca6351,
		0x14292967,
		0x27b70a85,
		0x2e1b2138,
		0x4d2c6dfc,
		0x53380d13,
		0x650a7354,
		0x766a0abb,
		0x81c2c92e,
		0x92722c85,
		0xa2bfe8a1,
		0xa81a664b,
		0xc24b8b70,
		0xc76c51a3,
		0xd192e819,
		0xd6990624,
		0xf40e3585,
		0x106aa070,
		0x19a4c116,
		0x1e376c08,
		0x2748774c,
		0x34b0bcb5,
		0x391c0cb3,
		0x4ed8aa4a,
		0x5b9cca4f,
		0x682e6ff3,
		0x748f82ee,
		0x78a5636f,
		0x84c87814,
		0x8cc70208,
		0x90befffa,
		0xa4506ceb,
		0xbef9a3f7,
		0xc67178f2,
	}

	local function add32(a, b, c, d, e)
		local sum = a + b
		if c then
			sum = sum + c
		end
		if d then
			sum = sum + d
		end
		if e then
			sum = sum + e
		end
		return band(sum, 0xFFFFFFFF)
	end

	local function sha256(msg)
		local len = #msg
		local bits = len * 8

		-- Padding
		msg = msg .. "\128"
		while (#msg % 64) ~= 56 do
			msg = msg .. "\0"
		end
		-- Append length as 64-bit big-endian
		msg = msg
			.. string.char(
				0,
				0,
				0,
				0,
				band(rshift(bits, 24), 0xFF),
				band(rshift(bits, 16), 0xFF),
				band(rshift(bits, 8), 0xFF),
				band(bits, 0xFF)
			)

		local H = {
			0x6a09e667,
			0xbb67ae85,
			0x3c6ef372,
			0xa54ff53a,
			0x510e527f,
			0x9b05688c,
			0x1f83d9ab,
			0x5be0cd19,
		}

		for i = 1, #msg, 64 do
			local W = {}
			for t = 1, 16 do
				local off = i + (t - 1) * 4
				W[t] = lshift(msg:byte(off), 24)
					+ lshift(msg:byte(off + 1), 16)
					+ lshift(msg:byte(off + 2), 8)
					+ msg:byte(off + 3)
			end
			for t = 17, 64 do
				local s0 = bxor(rrotate(W[t - 15], 7), rrotate(W[t - 15], 18), rshift(W[t - 15], 3))
				local s1 = bxor(rrotate(W[t - 2], 17), rrotate(W[t - 2], 19), rshift(W[t - 2], 10))
				W[t] = add32(W[t - 16], s0, W[t - 7], s1)
			end

			local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
			for t = 1, 64 do
				local S1 = bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25))
				local ch = bxor(band(e, f), band(bnot(e), g))
				local temp1 = add32(h, S1, ch, K[t], W[t])
				local S0 = bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22))
				local maj = bxor(band(a, b), band(a, c), band(b, c))
				local temp2 = add32(S0, maj)

				h = g
				g = f
				f = e
				e = add32(d, temp1)
				d = c
				c = b
				b = a
				a = add32(temp1, temp2)
			end

			H[1] = add32(H[1], a)
			H[2] = add32(H[2], b)
			H[3] = add32(H[3], c)
			H[4] = add32(H[4], d)
			H[5] = add32(H[5], e)
			H[6] = add32(H[6], f)
			H[7] = add32(H[7], g)
			H[8] = add32(H[8], h)
		end

		return string.format("%08x%08x%08x%08x%08x%08x%08x%08x", H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8])
	end

	-- Prefix prevents bare-integer rainbow tables; SHA-256 is one-way.
	-- The server applies a second HMAC layer with a secret before storage.
	return sha256("sirius_analytics:" .. tostring(userId))
end

-- ── Collect system info once per instance ─────────────────────────────────────
local function collectSystemInfo()
	local info = {
		place_id = tostring(game.PlaceId),
		universe_id = tostring(game.GameId),
		executor = "Unknown",
		executor_version = "",
		user_id = "",
		platform = "Computer", -- "pc" | "mobile" | "console"
		is_mobile = false, -- derived from platform, used as fallback
		locale = "",
	}

	local ok, name, ver = pcall(identifyexecutor)
	if ok and name then
		info.executor = tostring(name):sub(1, 64)
	end
	if ok and ver then
		info.executor_version = tostring(ver):sub(1, 32)
	end

	local uidOk, uid = pcall(function()
		return Players.LocalPlayer.UserId
	end)
	if uidOk and uid and uid ~= 0 then
		info.user_id = hashUserId(uid)
	end

	pcall(function()
		if GuiService:IsTenFootInterface() then
			info.platform = "Console"
			info.is_mobile = false
		elseif UserInputService.TouchEnabled then
			info.platform = "Mobile"
			info.is_mobile = true
		end
	end)

	pcall(function()
		info.locale = tostring(Players.LocalPlayer.LocaleId):sub(1, 16)
	end)

	return info
end

-- ── Find whichever HTTP function this executor exposes ────────────────────────
-- Must match how rayfield.luau discovers these — bare globals, no rawget(_G),
-- because executors inject into getgenv(), which may differ from _G.
local function findRequestFunc()
	if syn and syn.request then
		return syn.request
	end
	if fluxus and fluxus.request then
		return fluxus.request
	end
	if http and http.request then
		return http.request
	end
	if http_request then
		return http_request
	end
	if request then
		return request
	end
	return nil
end

-- ── Module ────────────────────────────────────────────────────────────────────
local Analytics = {}
Analytics.__index = Analytics

--[[
	Analytics.new(config)
	config = {
		url          : string   -- Collector endpoint URL (required)
		token        : string   -- X-Analytics-Token value (required)
		product_name : string?  -- Identifies the product/integration, e.g. "Rayfield", "MyHub"
		category     : string?  -- Broad type, e.g. "UILibrary", "Product", "Script"
	}
--]]
function Analytics.new(config)
	assert(type(config.url) == "string", "RayfieldAnalytics: config.url is required")
	assert(type(config.token) == "string", "RayfieldAnalytics: config.token is required")

	return setmetatable({
		_url = config.url,
		_token = config.token,
		_product_name = config.product_name and tostring(config.product_name):sub(1, 64) or nil,
		_category = config.category and tostring(config.category):sub(1, 32) or nil,
		_system = collectSystemInfo(),
		_requestFunc = findRequestFunc(),
	}, Analytics)
end

-- Internal: merge base payload with event-specific fields and fire-and-forget
function Analytics:_send(event, data, extra)
	if not self._requestFunc then
		return
	end

	data = data or {}
	extra = extra or {}

	local payload = {
		event = event,
		script_name = (data.script_name and tostring(data.script_name):sub(1, 128)) or nil,
		script_version = (data.script_version and tostring(data.script_version):sub(1, 64)) or nil,
		interface_version = (data.interface_version and tostring(data.interface_version):sub(1, 64)) or nil,
		script_id = (data.script_id and tostring(data.script_id):sub(1, 20)) or nil,
		place_id = self._system.place_id,
		universe_id = self._system.universe_id,
		executor = self._system.executor,
		executor_version = self._system.executor_version,
		user_id = self._system.user_id,
		platform = self._system.platform,
		locale = self._system.locale,
		product_name = self._product_name,
		category = self._category,
	}

	for k, v in pairs(extra) do
		payload[k] = v
	end

	local requestFunc = self._requestFunc
	local url, token = self._url, self._token

	task.spawn(function()
		pcall(function()
			requestFunc({
				Url = url,
				Method = "POST",
				Headers = {
					["Content-Type"] = "application/json",
					["X-Analytics-Token"] = token,
				},
				Body = HttpService:JSONEncode(payload),
			})
		end)
	end)
end

-- ── Roblox error codes that indicate a genuine kick or ban ──────────────────
-- Only these codes are tracked. Everything else (network drops, timeouts,
-- server shutdowns) is silently ignored.
local KICK_ERROR_CODES = {
	[267] = true, -- Player kicked via :Kick()
	[268] = true, -- Server kicked (unexpected client behavior / exploit)
	[291] = true, -- Player removed from DataModel
	[600] = true, -- In-experience ban API
}

-- Internal: extract Roblox error code from a kick message.
-- Language-agnostic: just finds a standalone number (3+ digits) in the message,
-- since the error code text varies by locale (e.g. "Error Code:", "Código de error:", etc.)
local function extractErrorCode(reason)
	for code in reason:gmatch("(%d%d%d+)") do
		return tonumber(code)
	end
	return nil
end

-- Internal: classify disconnect type from a kick reason string
local function parseDisconnectType(reason)
	local lower = reason:lower()
	if lower:find("ban") or lower:find("perm") then
		return "ban"
	end
	return "kick"
end

-- Internal: determine if an error prompt represents a genuine kick we should track
local function isGenuineKick(reason)
	local code = extractErrorCode(reason)
	if code then
		-- Has an error code — only accept known kick codes
		return KICK_ERROR_CODES[code] == true
	end
	-- No error code — reject network/connection/shutdown messages
	local lower = reason:lower()
	if
		lower:find("internet connection")
		or lower:find("network")
		or lower:find("connection lost")
		or lower:find("timed? ?out")
		or lower:find("shut down")
		or lower:find("maintenance")
		or lower:find("disconnected")
		or lower:find("lost connection")
		or lower:find("server is full")
		or lower:find("key")
	then
		return false
	end
	return true
end

-- Internal: poll CoreGui for the Roblox error/kick overlay.
-- Fires player_kicked when detected, then stops. Guard against duplicate watchers.
-- Gives up after 30 minutes to avoid burning CPU indefinitely.
local KICK_WATCHER_MAX_POLLS = 1800 -- 30 min at 1 poll/sec

function Analytics:_startKickWatcher(baseData)
	if self._kickWatcherRunning then
		return
	end
	self._kickWatcherRunning = true

	local CoreGui = game:GetService("CoreGui")
	local self_ = self

	task.spawn(function()
		for _ = 1, KICK_WATCHER_MAX_POLLS do
			task.wait(1)
			local ok, errorPrompt = pcall(function()
				return CoreGui.RobloxPromptGui.promptOverlay:FindFirstChild("ErrorPrompt")
			end)
			if not ok or not errorPrompt then
				continue
			end

			local reason = ""
			pcall(function()
				reason = errorPrompt.MessageArea.ErrorFrame.ErrorMessage.Text
			end)

			-- Only send genuine kicks, skip network drops / shutdowns
			if isGenuineKick(reason) then
				self_:_send("player_kicked", baseData or {}, {
					kick_reason = reason:sub(1, 256),
					disconnect_type = parseDisconnectType(reason),
				})
			end
			break
		end
		self_._kickWatcherRunning = false
	end)
end

--[[
	reporter:windowCreated(data?)

	Fires a window_created event and automatically arms kick detection.
	All fields are optional; unrecognised lib fields are simply absent.

	data = {
		script_name       : string?
		script_version    : string?
		interface_version : string?
		theme             : string?   -- e.g. "Default", "Ocean", "Custom"
		is_mobile         : boolean?  -- overrides auto-detect when provided
		has_key_system    : boolean?
		discord_invite    : string?   -- invite code only, no URL prefix
		config_saving     : boolean?
	}
--]]
function Analytics:windowCreated(data)
	data = data or {}

	local isMobile
	if data.is_mobile ~= nil then
		isMobile = data.is_mobile and true or false
	else
		isMobile = self._system.is_mobile
	end

	local secureMode = false
	local customAssetId = false
	local ok2, result2 = pcall(function()
		return _getgenv().RAYFIELD_ASSET_ID
	end)
	if ok2 and type(result2) == "number" then
		customAssetId = true
	end
	local ok3, result3 = pcall(function()
		return _getgenv().RAYFIELD_SECURE
	end)
	if ok3 and result3 then
		secureMode = true
	end

	self:_send("window_created", data, {
		theme = data.theme and tostring(data.theme):sub(1, 64) or nil,
		is_mobile = isMobile,
		has_key_system = data.has_key_system ~= nil and (data.has_key_system and true or false) or nil,
		discord_invite = data.discord_invite and tostring(data.discord_invite):sub(1, 64) or nil,
		config_saving = data.config_saving ~= nil and (data.config_saving and true or false) or nil,
		secure_mode = secureMode,
		custom_asset_id = customAssetId,
		script_id = data.script_id and tostring(data.script_id):sub(1, 20) or nil,
		verification_token = data.verification_token and tostring(data.verification_token):sub(1, 72) or nil,
	})

	self:_startKickWatcher(data)
end

--[[
	reporter:watchForKick(data?)

	Standalone kick detection for scripts that don't call windowCreated
	(e.g. plain scripts with no UI lib window). No-ops if already running.

	data = {
		script_name       : string?
		script_version    : string?
		interface_version : string?
	}
--]]
function Analytics:watchForKick(data)
	self:_startKickWatcher(data)
end

return Analytics

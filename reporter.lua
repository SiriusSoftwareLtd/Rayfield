local Players          = game:GetService("Players")
local UserInputService = game:GetService("UserInputService")
local GuiService       = game:GetService("GuiService")
local HttpService      = game:GetService("HttpService")

-- ── MurmurHash2 (32-bit) — deterministic 16-char hex from a UserId ────────────
local function hashUserId(userId)
	local function mul32(a, b)
		local al = bit32.band(a, 0xFFFF)
		local ah = bit32.rshift(a, 16)
		local bl = bit32.band(b, 0xFFFF)
		local bh = bit32.rshift(b, 16)
		return bit32.band(al * bl + bit32.lshift(bit32.band(al * bh + ah * bl, 0xFFFF), 16), 0xFFFFFFFF)
	end

	local function murmur2(input, seed)
		local M = 0x5bd1e995
		local h = bit32.bxor(seed, #input)
		local i, len = 1, #input
		while i + 3 <= len do
			local k = input:byte(i) + input:byte(i+1)*256 + input:byte(i+2)*65536 + input:byte(i+3)*16777216
			k = mul32(k, M)
			k = bit32.bxor(k, bit32.rshift(k, 24))
			k = mul32(k, M)
			h = mul32(h, M)
			h = bit32.bxor(h, k)
			i = i + 4
		end
		local rem = len - i + 1
		if rem >= 3 then h = bit32.bxor(h, input:byte(i+2) * 65536) end
		if rem >= 2 then h = bit32.bxor(h, input:byte(i+1) * 256) end
		if rem >= 1 then h = bit32.bxor(h, input:byte(i)); h = mul32(h, M) end
		h = bit32.bxor(h, bit32.rshift(h, 13))
		h = mul32(h, M)
		h = bit32.bxor(h, bit32.rshift(h, 15))
		return h
	end

	local input = "rf:" .. tostring(userId)
	local h1 = murmur2(input, 0x9747b28c)
	local h2 = murmur2(input, 0x5f4a0bc3)
	return string.format("%08x%08x", h1, h2)
end

-- ── Collect system info once per instance ─────────────────────────────────────
local function collectSystemInfo()
	local info = {
		place_id         = tostring(game.PlaceId),
		universe_id      = tostring(game.GameId),
		executor         = "Unknown",
		executor_version = "",
		user_id          = "",
		platform         = "pc",    -- "pc" | "mobile" | "console"
		is_mobile        = false,   -- derived from platform, used as fallback
		locale           = "",
	}

	local ok, name, ver = pcall(identifyexecutor)
	if ok and name then info.executor         = tostring(name):sub(1, 64) end
	if ok and ver  then info.executor_version = tostring(ver):sub(1, 32)  end

	local uidOk, uid = pcall(function() return Players.LocalPlayer.UserId end)
	if uidOk and uid and uid ~= 0 then
		info.user_id = hashUserId(uid)
	end

	pcall(function()
		if GuiService:IsTenFootInterface() then
			info.platform  = "console"
			info.is_mobile = false
		elseif UserInputService.TouchEnabled then
			info.platform  = "mobile"
			info.is_mobile = true
		end
	end)

	pcall(function()
		info.locale = tostring(Players.LocalPlayer.LocaleId):sub(1, 16)
	end)

	return info
end

-- ── Find whichever HTTP function this executor exposes ────────────────────────
local function findRequestFunc()
	for _, name in ipairs({ "request", "http_request" }) do
		local fn = rawget(_G, name)
		if type(fn) == "function" then return fn end
	end
	local syn = rawget(_G, "syn")
	if type(syn) == "table" and type(syn.request) == "function" then
		return syn.request
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
	assert(type(config.url)   == "string", "RayfieldAnalytics: config.url is required")
	assert(type(config.token) == "string", "RayfieldAnalytics: config.token is required")

	return setmetatable({
		_url          = config.url,
		_token        = config.token,
		_product_name = config.product_name and tostring(config.product_name):sub(1, 64) or nil,
		_category     = config.category     and tostring(config.category):sub(1, 32)     or nil,
		_system       = collectSystemInfo(),
		_requestFunc  = findRequestFunc(),
	}, Analytics)
end

-- Internal: merge base payload with event-specific fields and fire-and-forget
function Analytics:_send(event, data, extra)
	if not self._requestFunc then return end

	data = data or {}

	local payload = {
		event             = event,
		script_name       = (data.script_name and tostring(data.script_name):sub(1, 128)) or nil,
		script_version    = (data.script_version and tostring(data.script_version):sub(1, 64)) or nil,
		interface_version = (data.interface_version and tostring(data.interface_version):sub(1, 64)) or nil,
		place_id          = self._system.place_id,
		universe_id       = self._system.universe_id,
		executor          = self._system.executor,
		executor_version  = self._system.executor_version,
		user_id           = self._system.user_id,
		platform          = self._system.platform,
		locale            = self._system.locale,
		product_name      = self._product_name,
		category          = self._category,
	}

	for k, v in pairs(extra) do
		payload[k] = v
	end

	local requestFunc = self._requestFunc
	local url, token  = self._url, self._token

	task.spawn(function()
		pcall(function()
			requestFunc({
				Url    = url,
				Method = "POST",
				Headers = {
					["Content-Type"]      = "application/json",
					["X-Analytics-Token"] = token,
				},
				Body = HttpService:JSONEncode(payload),
			})
		end)
	end)
end

-- Internal: parse disconnect type from a kick reason string
local function parseDisconnectType(reason)
	local lower = reason:lower()
	if lower:find("ban") or lower:find("perm") then return "ban" end
	if lower:find("internet connection") or lower:find("network") then return "network" end
	return "kick"
end

-- Internal: poll CoreGui for the Roblox error/kick overlay once per second.
-- Fires player_kicked when detected, then stops. Guard against duplicate watchers.
function Analytics:_startKickWatcher(baseData)
	if self._kickWatcherRunning then return end
	self._kickWatcherRunning = true

	local CoreGui = game:GetService("CoreGui")
	local self_ = self

	task.spawn(function()
		while true do
			task.wait(1)
			local ok, errorPrompt = pcall(function()
				return CoreGui.RobloxPromptGui.promptOverlay:FindFirstChild("ErrorPrompt")
			end)
			if not ok or not errorPrompt then continue end

			local reason = ""
			pcall(function()
				reason = errorPrompt.MessageArea.ErrorFrame.ErrorMessage.Text
			end)

			self_:_send("player_kicked", baseData or {}, {
				kick_reason     = reason:sub(1, 256),
				disconnect_type = parseDisconnectType(reason),
			})
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

	self:_send("window_created", data, {
		theme          = data.theme and tostring(data.theme):sub(1, 64) or nil,
		is_mobile      = isMobile,
		has_key_system = data.has_key_system ~= nil and (data.has_key_system and true or false) or nil,
		discord_invite = data.discord_invite and tostring(data.discord_invite):sub(1, 64) or nil,
		config_saving  = data.config_saving ~= nil and (data.config_saving and true or false) or nil,
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

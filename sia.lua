-- SIA client, copied from the sia repo (client/sia.luau).
-- Change it there, then copy it here. source.lua fetches this file at RAYFIELD_COMMIT.

--[[
	SIA client core (docs/design.md, The client module).

	Counts what a script's players do, in memory, and sends it in small
	batches: one after the first minute, then every five minutes, and one
	when the window closes. Nothing here may slow the script or break it:
	every call is pcall-wrapped and never yields the caller's thread, and a
	failed send is dropped, never retried.

	A library (Rayfield Gen1, Gen2) drives it through:
		local sia = SIA.new({ token, lib, libVersion, script = { id, token, name } })
		local id = sia:element(kind, label, tab)   -- an element exists
		sia:used(id, action, value)                -- it was used (value 0..1 where it has one)
		sia:state(id, value)                       -- its current value (toggles: 1 on, 0 off)
		sia:tab(tab)                               -- a tab was shown: its elements were seen
		sia:window("open" | "minimise" | "restore" | "close")
		sia:keyScreen("shown" | "copied" | "attempt" | "accepted")
		sia:error(id)                              -- a callback errored
		sia:track(name)                            -- the author's own event
		sia:disable()                              -- the player turned it off

	Never sent: names, display names, typed text, labels (only a category
	worked out here), kick messages (only a template with names and numbers
	taken out). The Roblox user id goes over HTTPS and is turned into an
	anonymous id on the server, which never stores the number.
]]

local ENDPOINT = "https://sia.sirius.menu"
local FORMAT = 1
local MAX_ORDERED = 50

local function service(name)
	local s = game:GetService(name)
	return if cloneref then cloneref(s) else s
end
local Players = service("Players")
local UserInputService = service("UserInputService")
local GuiService = service("GuiService")
local HttpService = service("HttpService")
local Workspace = service("Workspace")

-- The game never sees SIA. It reads properties and polls, like Gen1's reporter: no signal
-- connections, no instances made, nothing printed, every service and object it keeps
-- passed through cloneref, and every call to the game inside pcall. Requests go through
-- the executor's own request function.
local function clone(instance)
	return if cloneref and instance then cloneref(instance) else instance
end
local function localPlayer()
	return clone(Players.LocalPlayer)
end

local httpRequest = (syn and syn.request) or (fluxus and fluxus.request) or (http and http.request) or http_request or request

-- ── Small hashes (FNV-1a), for ids and fingerprints, never for secrets ──────────
local function fnv(s, seed)
	local h = seed or 0x811C9DC5
	for i = 1, #s do
		h = bit32.bxor(h, string.byte(s, i))
		h = (h * 0x01000193) % 0x100000000
	end
	return h
end
local function hash16(s)
	return string.format("%08x%08x", fnv(s), fnv(s, 0x050C5D1F))
end
local function shortId(s)
	-- Element ids: lowercase base-36, so the server's [a-z0-9] check holds.
	local n, out, digits = fnv(s), "", "0123456789abcdefghijklmnopqrstuvwxyz"
	repeat
		local d = n % 36
		out = string.sub(digits, d + 1, d + 1) .. out
		n = (n - d) / 36
	until n == 0
	return out
end

-- ── Labels become categories here; the words never leave ───────────────────────
local CATEGORY_WORDS = {
	{ "silentaim", { "silent aim", "silentaim" } },
	{ "aimbot", { "aimbot", "aim bot", "aimlock", "aim lock", "lock on", "lockon", "triggerbot" } },
	{ "esp", { "esp", "chams", "tracer", "highlight", "wallhack", "box esp", "name esp" } },
	{ "killaura", { "kill aura", "killaura", "kill all", "auto kill", "autokill" } },
	{ "autofarm", { "auto farm", "autofarm", "farm", "auto collect", "autocollect", "auto grind", "auto quest", "auto level" } },
	{ "autobuy", { "auto buy", "autobuy", "auto purchase", "auto hatch", "auto roll", "auto spin" } },
	{ "autosell", { "auto sell", "autosell", "sell all" } },
	{ "autoequip", { "auto equip", "equip best", "autoequip" } },
	{ "fly", { "fly", "flight" } },
	{ "speed", { "speed", "walkspeed", "walk speed", "jump power", "jumppower" } },
	{ "noclip", { "noclip", "no clip" } },
	{ "teleport", { "teleport", "tp to", " tp", "goto", "go to" } },
	{ "godmode", { "god mode", "godmode", "invincib", "no damage", "infinite health" } },
	{ "infinitejump", { "infinite jump", "inf jump", "infjump" } },
	{ "dupe", { "dupe", "duplicate" } },
	{ "trade", { "trade", "freeze trade" } },
	{ "visual", { "fov", "fullbright", "full bright", "no fog", "nofog", "xray", "x-ray" } },
	{ "settings", { "setting", "config", "keybind", "save", "load", "theme", "destroy ui", "unload", "menu" } },
}
local function categoryOf(label)
	local l = " " .. string.lower(tostring(label or "")) .. " "
	for _, entry in CATEGORY_WORDS do
		for _, w in entry[2] do
			if string.find(l, w, 1, true) then
				return entry[1]
			end
		end
	end
	return "misc"
end

-- ── Device, worked out once ─────────────────────────────────────────────────────
local function device()
	local platform, input = "computer", "keyboard"
	pcall(function()
		if GuiService:IsTenFootInterface() then
			platform, input = "console", "gamepad"
		elseif UserInputService.VREnabled then
			platform, input = "vr", "vr"
		elseif UserInputService.TouchEnabled and not UserInputService.KeyboardEnabled then
			local size = clone(Workspace.CurrentCamera).ViewportSize
			platform = if math.min(size.X, size.Y) >= 600 then "tablet" else "phone"
			input = "touch"
		end
	end)
	local screen, quality, locale, offset = "unknown", 0, "unknown", 0
	pcall(function()
		local s = clone(Workspace.CurrentCamera).ViewportSize
		local w = math.max(s.X, s.Y)
		screen = if w < 900 then "s" elseif w < 1400 then "m" elseif w < 2000 then "l" else "xl"
	end)
	pcall(function()
		quality = clone(UserSettings():GetService("UserGameSettings")).SavedQualityLevel.Value
	end)
	pcall(function()
		locale = string.sub(tostring(localPlayer().LocaleId), 1, 16)
	end)
	pcall(function()
		-- Minutes from UTC, from the player's own clock.
		local now = os.time()
		local u, l = os.date("!*t", now), os.date("*t", now)
		offset = math.floor((os.time(l) - os.time(u)) / 60 + 0.5)
	end)
	return { platform, input, screen, quality, locale, offset }
end

-- ── Kick reasons, made safe here (names and numbers out) ──────────────────────
local function kickTemplate(message)
	local text = tostring(message or "")
	pcall(function()
		local names = {}
		for _, p in Players:GetPlayers() do
			table.insert(names, p.Name)
			table.insert(names, p.DisplayName)
		end
		table.sort(names, function(a, b)
			return #a > #b
		end)
		for _, n in names do
			if #n >= 3 then
				text = string.gsub(text, string.gsub(n, "%p", "%%%0"), "<player>")
			end
		end
	end)
	text = string.gsub(text, "%d+", "#")
	text = string.gsub(text, "%s+", " ")
	text = string.sub(text, 1, 160)
	local l = string.lower(text)
	local category = "game"
	if string.find(l, "ban") then
		category = "ban"
	elseif string.find(l, "exploit") or string.find(l, "cheat") or string.find(l, "hack") or string.find(l, "detect")
		or string.find(l, "suspicious") or string.find(l, "unusual") or string.find(l, "anti") then
		category = "anticheat"
	elseif string.find(l, "idle") or string.find(l, "afk") or string.find(l, "inactiv") then
		category = "idle"
	elseif string.find(l, "shut") or string.find(l, "restart") or string.find(l, "server") or string.find(l, "update") then
		category = "server"
	end
	return text, category, hash16(l)
end

-- ── The instance ────────────────────────────────────────────────────────────────
local SIA = {}
SIA.__index = SIA

local function randomHex(n)
	local t = {}
	for i = 1, n do
		t[i] = string.format("%x", math.random(0, 15))
	end
	return table.concat(t)
end

function SIA.new(opts)
	local self = setmetatable({}, SIA)
	self._token = opts.token
	self._lib = { tostring(opts.lib or "other"), tostring(opts.libVersion or "") }
	self._script = opts.script or {}
	self._run = randomHex(16)
	self._seq = 0
	self._start = os.clock()
	self._elements = {} -- id -> {type, tab, category, uses, onSince, onSeconds, value, seen, rage, lastUse, presses}
	self._order = {} -- element ids in creation order, for the fingerprint
	self._ordered = {}
	self._session = { inView = 0, viewSince = os.clock(), minimised = 0, reopened = 0, closed = false, idle = 0 }
	self._lastInput = os.clock()
	self._lastUsed = nil
	self._lastUsedAt = 0
	self._errors = 0
	self._events = {}
	self._key = { 0, 0, 0, 0, 0 }
	-- opts.request and opts.config are for tests: the executor's request function and the
	-- server's settings, given rather than found. opts.manual skips the timers and watchers,
	-- so a test drives _flush itself.
	self._request = opts.request or httpRequest
	self._disabled = self._request == nil
	self._config = nil
	self._detail = false
	self._fps = 0
	pcall(function()
		self._device = device()
	end)
	if opts.config then
		self:_apply(opts.config)
	end
	if not self._disabled and not opts.manual then
		task.spawn(function()
			self:_start_()
		end)
	end
	return self
end

function SIA:_apply(cfg)
	if type(cfg) ~= "table" or cfg.on == false then
		self._disabled = true
		return false
	end
	self._config = cfg
	self._detail = math.random() < (tonumber(cfg.detail) or 0.1)
	return true
end

function SIA:_start_()
	if not self._config then
		local cfg
		pcall(function()
			local res = self._request({ Url = ENDPOINT .. "/v1/config?k=" .. self._token, Method = "GET" })
			cfg = HttpService:JSONDecode(res.Body)
		end)
		if not self:_apply(cfg) then
			return
		end
	end
	local cfg = self._config
	self:_watchKicks()
	self:_waitFor(tonumber(cfg.firstBatch) or 60)
	while not self._disabled and not self._session.closed do
		self:_sampleFrames()
		self:_flush(false)
		self:_waitFor(tonumber(cfg.every) or 300)
	end
end

-- Waits up to `seconds`, waking every few to stop early once the run is off or closed, so a
-- disabled client lets go of its thread instead of sleeping out a five-minute wait.
function SIA:_waitFor(seconds)
	local left = seconds
	while left > 0 and not self._disabled and not self._session.closed do
		local step = math.min(left, 5)
		task.wait(step)
		left -= step
		self:_sampleInput()
	end
end

-- Idle stretches, for farm detection, read by polling: the pointer and camera are compared
-- every few seconds, and a change counts as input. A minute or more without one is idle.
function SIA:_sampleInput()
	pcall(function()
		local mouse = UserInputService:GetMouseLocation()
		local camera = clone(Workspace.CurrentCamera).CFrame
		local last = self._lastSeen
		self._lastSeen = { mouse, camera }
		if last and last[1] == mouse and last[2] == camera then
			return
		end
		local now = os.clock()
		if now - self._lastInput > 60 then
			self._session.idle += now - self._lastInput
		end
		self._lastInput = now
	end)
end

function SIA:_viewStop()
	if self._session.viewSince then
		self._session.inView += os.clock() - self._session.viewSince
		self._session.viewSince = nil
	end
end

-- Frame rate from how long task.wait() takes to come back, which is once a frame: up to five
-- seconds or 300 frames, with nothing connected to the game.
function SIA:_sampleFrames()
	pcall(function()
		local frames, began = 0, os.clock()
		while frames < 300 and os.clock() - began < 5 do
			task.wait()
			frames += 1
		end
		local total = os.clock() - began
		if total > 0 then
			self._fps = math.floor(frames / total + 0.5)
		end
	end)
end

function SIA:element(kind, label, tab)
	local ok, id = pcall(function()
		local key = tostring(kind) .. "|" .. tostring(label) .. "|" .. tostring(tab or 0)
		local id = shortId(key)
		if not self._elements[id] then
			self._elements[id] = {
				type = tostring(kind), tab = tonumber(tab) or 0, category = categoryOf(label),
				uses = 0, onSince = nil, onSeconds = 0, value = 0, seen = false, rage = 0, presses = {},
			}
			table.insert(self._order, id)
		end
		return id
	end)
	return if ok then id else nil
end

function SIA:used(id, action, value)
	pcall(function()
		local e = id and self._elements[id]
		if not e then
			return
		end
		local now = os.clock()
		e.uses += 1
		e.seen = true
		if value ~= nil then
			self:state(id, value)
		end
		-- Rage: three presses on one element inside a second.
		table.insert(e.presses, now)
		if #e.presses > 3 then
			table.remove(e.presses, 1)
		end
		if #e.presses == 3 and e.presses[3] - e.presses[1] <= 1 then
			e.rage += 1
			e.presses = {}
		end
		self._lastUsed, self._lastUsedAt = id, now
		if self._detail and #self._ordered < MAX_ORDERED then
			table.insert(self._ordered, { math.floor(now - self._start), id, tostring(action or "use") })
		end
	end)
end

function SIA:state(id, value)
	pcall(function()
		local e = id and self._elements[id]
		if not e then
			return
		end
		local v = math.clamp(tonumber(value) or 0, 0, 1)
		if e.type == "toggle" then
			if v >= 1 and not e.onSince then
				e.onSince = os.clock()
			elseif v < 1 and e.onSince then
				e.onSeconds += os.clock() - e.onSince
				e.onSince = nil
			end
		end
		e.value = v
	end)
end

function SIA:tab(tab)
	pcall(function()
		for _, e in self._elements do
			if e.tab == tab then
				e.seen = true
			end
		end
	end)
end

function SIA:window(what)
	pcall(function()
		local s = self._session
		if what == "minimise" then
			s.minimised += 1
			self:_viewStop()
		elseif what == "restore" or what == "open" then
			if what == "restore" then
				s.reopened += 1
			end
			s.viewSince = s.viewSince or os.clock()
		elseif what == "close" then
			self:_viewStop()
			s.closed = true
			task.spawn(function()
				self:_flush(true)
			end)
		end
	end)
end

function SIA:keyScreen(what)
	pcall(function()
		local k = self._key
		if what == "shown" then
			k[1] = 1
		elseif what == "copied" then
			k[2] = 1
		elseif what == "attempt" then
			k[4] += 1
		elseif what == "accepted" then
			k[5] = 1
		end
	end)
end

function SIA:error(_id)
	self._errors += 1
end

function SIA:track(name)
	pcall(function()
		local n = string.lower(string.sub(tostring(name), 1, 32))
		n = string.gsub(n, "[^%w_.-]", "_")
		self._events[n] = (self._events[n] or 0) + 1
	end)
end

function SIA:disable()
	self._disabled = true
end

-- ── Kicks: the Roblox error prompt, read once ───────────────────────────────────
function SIA:_watchKicks()
	task.spawn(function()
		local CoreGui = service("CoreGui")
		for _ = 1, 7200 do
			task.wait(1)
			if self._disabled then
				return
			end
			local prompt
			pcall(function()
				prompt = CoreGui.RobloxPromptGui.promptOverlay:FindFirstChild("ErrorPrompt")
			end)
			if prompt then
				local message = ""
				pcall(function()
					message = prompt.MessageArea.ErrorFrame.ErrorMessage.Text
				end)
				-- Roblox ends the message with "(Error Code: 267)"; a number
				-- earlier on may be a player's name, so the last one counts.
				local code = tonumber(string.match(message, "(%d%d%d+)%)?%s*$"))
					or tonumber(string.match(message, "[Cc]ode%s*:?%s*(%d+)")) or 0
				local template, category, hash = kickTemplate(message)
				local on = {}
				for id, e in self._elements do
					if e.onSince then
						table.insert(on, id)
					end
				end
				self._kick = {
					c = code, k = category, h = hash, w = template, l = self._lastUsed,
					a = if self._lastUsed then math.floor(os.clock() - self._lastUsedAt) else 0,
					n = on, s = math.floor(os.clock() - self._start),
				}
				self:_flush(true)
				return
			end
		end
	end)
end

-- ── Sending ─────────────────────────────────────────────────────────────────────
function SIA:_fingerprint()
	local ids = table.clone(self._order)
	table.sort(ids)
	return hash16(tostring(self._script.name or "") .. "|" .. table.concat(ids, ","))
end

function SIA:_flush(final)
	if self._disabled or not self._config then
		return
	end
	pcall(function()
		local now = os.clock()
		local s = self._session
		local inView = s.inView + (if s.viewSince then now - s.viewSince else 0)
		local idleNow = now - self._lastInput
		local totals, kept = {}, {}
		for id, e in self._elements do
			local onSeconds = e.onSeconds + (if e.onSince then now - e.onSince else 0)
			if e.uses > 0 or e.seen or self._seq == 0 then
				table.insert(totals, { id, e.type, e.tab, e.category, e.uses, math.floor(onSeconds), e.value, if e.seen then 1 else 0, e.rage })
			end
			if final and self._detail then
				table.insert(kept, { id, e.value })
			end
			-- Totals are since the last batch.
			e.uses, e.rage, e.onSeconds = 0, 0, 0
			if e.onSince then
				e.onSince = now
			end
		end
		local events = {}
		for name, n in self._events do
			table.insert(events, { name, n })
		end
		self._events = {}
		local g = { game.PlaceId, game.GameId, 0 }
		pcall(function()
			g[3] = game.PlaceVersion
		end)
		local userId = 0
		pcall(function()
			userId = localPlayer().UserId
		end)
		local ex, exv = "unknown", ""
		pcall(function()
			local a, b = identifyexecutor()
			ex, exv = tostring(a or "unknown"), tostring(b or "")
		end)
		local body = {
			v = FORMAT, k = self._token, s = self._run, q = self._seq, u = if userId > 0 then userId else nil,
			g = g, x = { ex, exv }, l = self._lib,
			c = { i = self._script.id, t = self._script.token, f = self:_fingerprint(), n = self._script.name },
			d = self._device, f = if self._detail then 1 else 0,
			e = { math.floor(now - self._start), math.floor(inView), s.minimised, s.reopened, if s.closed then 1 else 0,
				math.floor(s.idle + (if idleNow > 60 then idleNow else 0)), if idleNow > 7200 then 1 else 0 },
			t = totals, o = if self._detail then self._ordered else nil, z = if #kept > 0 then kept else nil,
			kk = self._kick, ks = if self._key[1] == 1 then self._key else nil,
			h = { self._errors, self._fps or 0 }, ev = if #events > 0 then events else nil,
		}
		self._seq += 1
		self._ordered = {}
		self._errors = 0
		self._kick = nil
		local json = HttpService:JSONEncode(body)
		task.spawn(function()
			pcall(function()
				local res = self._request({
					Url = ENDPOINT .. "/v1/batch", Method = "POST",
					Headers = { ["Content-Type"] = "application/json" }, Body = json,
				})
				-- The server can say stop (a revoked token): stop for this run.
				if res and res.StatusCode == 403 then
					self._disabled = true
				end
			end)
		end)
	end)
end

-- For tests.
SIA._kickTemplate = kickTemplate
SIA._categoryOf = categoryOf

return SIA

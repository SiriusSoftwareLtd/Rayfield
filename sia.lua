-- SIA client, copied from the sia repo (client/sia.luau).
-- Change it there, then copy it here. source.lua fetches this file at RAYFIELD_COMMIT.

--[[
	SIA client core (docs/design.md, The client module).

	Counts what a script's players do, in memory, and sends it in small
	batches: one as the run starts, one shortly after, then every five
	minutes, and one when the window closes or the player teleports. Nothing here may slow the
	script or break it: every call is pcall-wrapped and never yields the
	caller's thread, and a failed send is dropped, never retried.

	A library (Rayfield Gen1, Gen2) drives it through:
		local sia = SIA.new({ token, lib, libVersion, script = { id, token, name } })
		local id = sia:element(kind, label, tab)   -- an element exists
		sia:tabName(tab, name)                     -- a tab's name (tab 0 is Rayfield's settings page)
		sia:section(tab, name)                     -- a section heading on a tab
		sia:describe(id, text)                     -- an element's description line
		sia:used(id, action, value)                -- it was used (value 0..1 where it has one)
		sia:state(id, value)                       -- its current value (toggles: 1 on, 0 off)
		sia:tab(tab)                               -- a tab was shown: its elements were seen
		sia:window("open" | "minimise" | "restore" | "close")
		sia:keyScreen("shown" | "copied" | "attempt" | "accepted")
		sia:error(id)                              -- a callback errored
		sia:track(name)                            -- the author's own event
		sia:disable()                              -- the player turned it off

	Never sent: player names, display names or typed text. The window title,
	element labels and tab names go with player names, rich text and numbers
	taken out (numbers stay in the title), and kick messages only as a
	template. The Roblox user id goes over HTTPS and is turned into an
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
local RunService = service("RunService")
local Workspace = service("Workspace")

-- The game never sees SIA: every service and object it reads or connects to goes through
-- cloneref first, every callback and call into the game runs inside pcall, nothing is
-- printed and no instance is made. Requests go through the executor's own request function.
local function clone(instance)
	return if cloneref and instance then cloneref(instance) else instance
end
local function localPlayer()
	return clone(Players.LocalPlayer)
end
-- A connection whose callback can never raise an error into the game's output.
local function connect(signal, fn)
	return signal:Connect(function(...)
		pcall(fn, ...)
	end)
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
-- Player names in the server, longest first, swapped for <player>.
local function withoutNames(text)
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
	return text
end

-- An element or tab name as sent: the script's own words, with rich text tags, player names
-- and numbers taken out, so a label like "Welcome, Name" or "Coins: 1200" carries nothing personal.
local function cleanLabel(label, max)
	local text = string.gsub(tostring(label or ""), "<[^>]*>", "")
	text = withoutNames(text)
	text = string.gsub(text, "%d+", "#")
	text = string.gsub(text, "%s+", " ")
	text = string.match(text, "^%s*(.-)%s*$") or ""
	return string.sub(text, 1, max or 60)
end

local function kickTemplate(message)
	local text = withoutNames(tostring(message or ""))
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
	self._theme = if opts.theme ~= nil then string.sub(tostring(opts.theme), 1, 32) else nil
	self._tabs = {} -- tab index -> { name, sent }
	self._sections = {} -- tab index -> the current section heading
	self._subtitle = if opts.subtitle ~= nil then opts.subtitle else nil
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
	self._keyAwaySince = nil
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
	-- Outside the sample (config "sample", 0..1): the run sends its first batch, to be counted,
	-- and nothing more. Feature use and sessions come from the sampled runs.
	if not self:_inSample() then
		self:_startBatch()
		self._disabled = true
		return
	end
	-- Input, for idle stretches and farm detection.
	pcall(function()
		connect(UserInputService.InputBegan, function()
			local now = os.clock()
			if now - self._lastInput > 60 then
				self._session.idle += now - self._lastInput
			end
			self._lastInput = now
		end)
		connect(UserInputService.WindowFocusReleased, function()
			self:_viewStop()
			if self._keyAwaySince == nil and self._key[2] == 1 and self._key[5] == 0 then
				self._keyAwaySince = os.clock()
			end
		end)
		connect(UserInputService.WindowFocused, function()
			self._session.viewSince = os.clock()
			if self._keyAwaySince then
				self._key[3] += os.clock() - self._keyAwaySince
				self._keyAwaySince = nil
			end
		end)
	end)
	pcall(function()
		connect(localPlayer().OnTeleport, function(state)
			if state == Enum.TeleportState.Started then
				self:_flush(true)
			end
		end)
	end)
	self:_watchKicks()
	self:_startBatch()
	self:_waitFor(tonumber(cfg.firstBatch) or 60)
	while not self._disabled and not self._session.closed do
		self:_sampleFrames()
		self:_flush(false)
		self:_waitFor(tonumber(cfg.every) or 300)
	end
end

-- Waits up to `seconds`, waking every few to stop early once the run is off or closed, so a
-- disabled client lets go of its thread instead of sleeping out a five-minute wait.
-- Whether this run reports past its first batch (config "sample"); one outside it is marked
-- count-only and sends no detail.
function SIA:_inSample()
	local sample = tonumber(self._config and self._config.sample) or 1
	self._countOnly = math.random() >= sample
	if self._countOnly then
		self._detail = false
	end
	return not self._countOnly
end

-- A run counts the moment it starts (owner, 9 Nov 2026): a first, small batch goes now,
-- before any wait, so a player who leaves within seconds is still counted. The config can
-- turn it off ("start": false).
function SIA:_startBatch()
	if self._config and self._config.start ~= false then
		self:_flush(false)
	end
	-- Forge's environment checks, when the config turns them on (the block near the end).
	if self._envChecks then
		self:_envChecks()
	end
end

function SIA:_waitFor(seconds)
	local left = seconds
	while left > 0 and not self._disabled and not self._session.closed do
		local step = math.min(left, 5)
		task.wait(step)
		left -= step
	end
end

function SIA:_viewStop()
	if self._session.viewSince then
		self._session.inView += os.clock() - self._session.viewSince
		self._session.viewSince = nil
	end
end

-- Five seconds of frame times into two numbers: no table made per frame.
function SIA:_sampleFrames()
	pcall(function()
		local frames, total = 0, 0
		local conn = connect(RunService.RenderStepped, function(dt)
			frames += 1
			total += dt
		end)
		task.wait(5)
		conn:Disconnect()
		if total > 0 then
			self._fps = math.floor(frames / total + 0.5)
		end
	end)
end

-- A section heading: elements made on that tab after it sit under it.
function SIA:section(tab, name)
	pcall(function()
		self._sections[tonumber(tab) or 0] = name
	end)
end

-- Text the library shows with an element: a description line under it (Gen2).
function SIA:describe(id, text)
	pcall(function()
		local e = self._elements[id]
		if e and text and text ~= "" and e.description ~= text then
			e.description = text
			e.labelSent = false
		end
	end)
end

function SIA:element(kind, label, tab)
	local ok, id = pcall(function()
		local key = tostring(kind) .. "|" .. tostring(label) .. "|" .. tostring(tab or 0)
		local id = shortId(key)
		if not self._elements[id] then
			self._elements[id] = {
				type = tostring(kind), tab = tonumber(tab) or 0, category = categoryOf(label), label = label, labelSent = false,
				section = self._sections[tonumber(tab) or 0],
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

-- A tab's name, sent once like element labels.
function SIA:tabName(tab, name)
	pcall(function()
		local i = tonumber(tab)
		if i and not self._tabs[i] then
			self._tabs[i] = { name = name, sent = false }
		end
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
-- The window's title, with player names taken out: some scripts put the player's name in it
-- ("Speed Legends V1 | Name"), which would make it personal and split one script per player.
function SIA:_title()
	return withoutNames(tostring(self._script.name or ""))
end

function SIA:_fingerprint()
	local ids = table.clone(self._order)
	table.sort(ids)
	return hash16(self:_title() .. "|" .. table.concat(ids, ","))
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
			-- An element new since the last batch goes too, so its label arrives with its type and tab.
			if e.uses > 0 or e.seen or self._seq == 0 or not e.labelSent then
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
		-- Labels and tab names go once each, in the first batch that has them.
		local labels, tabNames, extras = {}, {}, {}
		for id, e in self._elements do
			if not e.labelSent and #labels < 300 then
				e.labelSent = true
				table.insert(labels, { id, cleanLabel(e.label) })
				if e.section or e.description then
					table.insert(extras, { id, if e.section then cleanLabel(e.section) else "", if e.description then cleanLabel(e.description, 140) else "" })
				end
			end
		end
		for i, t in self._tabs do
			if not t.sent then
				t.sent = true
				table.insert(tabNames, { i, cleanLabel(t.name) })
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
			c = { i = self._script.id, t = self._script.token, f = self:_fingerprint(), n = self:_title() },
			d = self._device, f = if self._detail then 1 else 0, co = if self._countOnly then 1 else nil,
			e = { math.floor(now - self._start), math.floor(inView), s.minimised, s.reopened, if s.closed then 1 else 0,
				math.floor(s.idle + (if idleNow > 60 then idleNow else 0)), if idleNow > 7200 then 1 else 0 },
			t = totals, o = if self._detail then self._ordered else nil, z = if #kept > 0 then kept else nil,
			kk = self._kick, ks = if self._key[1] == 1 then self._key else nil,
			h = { self._errors, self._fps or 0 }, ev = if #events > 0 then events else nil,
			lb = if #labels > 0 then labels else nil, tn = if #tabNames > 0 then tabNames else nil,
			th = if self._seq == 0 then self._theme else nil,
			sb = if self._seq == 0 and self._subtitle then cleanLabel(self._subtitle) else nil,
			ex = if #extras > 0 then extras else nil,
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

-- BEGIN Forge environment checks (generated)
--[[
	Forge's environment checks, counted by Forge toward its tamper holds. Temporary:
	remove this block and the call in SIA:_startBatch() to take them out.
	Generated by Sirius Forge (apps/runtime/scripts/sia-env-checks.ts) from its
	packages/damascus/src/readings.ts. Don't edit it here: change Forge and generate
	it again. It runs only when the server's config turns it on (checks), sends the
	executor family and each check's value, and nothing about the player or the run.
]]
local ENV_FAMILY_ALIASES = { ["arceusx"] = "arceus x", ["jjsploit"] = "wrd", ["opiumwaremac"] = "opiumware" }
local function envFamily(name)
	if type(name) ~= "string" then
		return nil
	end
	local folded = string.lower(string.match(name, "^%s*(.-)%s*$") or "")
	folded = string.sub((string.gsub(folded, "[^a-z0-9 ._-]", "")), 1, 32)
	if folded == "" then
		return nil
	end
	return ENV_FAMILY_ALIASES[(string.gsub(folded, "%s", ""))] or folded
end

local function envTable()
	return {
		["Enum"] = Enum,
		["Instance"] = Instance,
		["Path2DControlPoint"] = Path2DControlPoint,
		["UDim2"] = UDim2,
		["bit32"] = bit32,
		["buffer"] = buffer,
		["coroutine"] = coroutine,
		["debug"] = debug,
		["game"] = game,
		["getmetatable"] = getmetatable,
		["loadstring"] = loadstring,
		["math"] = math,
		["next"] = next,
		["os"] = os,
		["pcall"] = pcall,
		["print"] = print,
		["rawset"] = rawset,
		["select"] = select,
		["setmetatable"] = setmetatable,
		["string"] = string,
		["table"] = table,
		["task"] = task,
		["tostring"] = tostring,
		["type"] = type,
		["typeof"] = typeof,
		["utf8"] = utf8,
		["xpcall"] = xpcall,
	}
end

local function envHelpers(env)
	local h = {}
	do
	  local s, t, u = env["string"], env["table"], env["utf8"]
	  local b32, pc, ts, ty = env["bit32"], env["pcall"], env["tostring"], env["type"]
	  h["hash"] = function(x)
	    local v, byte, bxor, shl = 2166136261, s["byte"], b32["bxor"], b32["lshift"]
	    for k = 1, #x do
	      v = bxor(v, byte(x, k))
	      v = (shl(v, 24) + v * 403) % 4294967296
	    end
	    return s["format"]("%08x", v)
	  end
	  h["try"] = function(f)
	    local ok, v = pc(f)
	    if ok and ty(v) == "string" then return v end
	    return "x"
	  end
	  h["bare"] = function(e)
	    local m = ts(e)
	    return (s["gsub"](m, "^[^\n]-:%d+: ", "", 1))
	  end
	  h["f"] = function(x) return s["format"]("%08x", s["unpack"]("<I4", s["pack"]("<f", x))) end
	  h["d"] = function(x)
	    local lo, hi = s["unpack"]("<I4I4", s["pack"]("<d", x))
	    return s["format"]("%08x%08x", hi, lo)
	  end
	  h["n"] = function(x) return s["format"]("%d", x) end
	  h["codes"] = function(x)
	    local o = {}
	    for _, c in u["codes"](x) do o[#o + 1] = s["format"]("%d", c) end
	    return t["concat"](o, ".")
	  end
	  local path
	  h["path"] = function()
	    if path == nil then
	      local I, U, P = env["Instance"]["new"], env["UDim2"]["new"], env["Path2DControlPoint"]["new"]
	      local g = I("ScreenGui")
	      local r = I("Frame")
	      r["Position"] = U(0, 0, 0, 0)
	      r["Size"] = U(0, 155, 0, 258)
	      r["Parent"] = g
	      local p = I("Path2D")
	      p["Parent"] = r
	      p["SetControlPoints"](p, {
	        P(U(0.0625, 4, 0, -6), U(0, -2, 0, -1), U(-0.125, 6, 0, 1)),
	        P(U(0, -10, 0.375, -6), U(0, 0, 0, 0), U(-0.125, -1, 0, 2)),
	        P(U(0.125, 0, 0.375, -6), U(-0.125, -2, 0.0625, -8), U(0, 0, 0, 0)),
	        P(U(0, -3, 0.0625, 0), U(0, 0, 0, 0), U(0, -4, 0, 4)),
	      })
	      path = p
	    end
	    return path
	  end
	end
	return h
end

local ENV_CHECKS = {
	{ "env_c_functions", function(env) local info = env["debug"]["info"] local function c(f) return (f ~= nil and info(f, "s") == "[C]") and "1" or "0" end return c(env["print"]) .. c(env["pcall"]) .. c(env["tostring"]) .. c(env["select"]) .. c(env["string"]["format"]) .. c(env["table"]["insert"]) .. c(env["Instance"]["new"]) end },
	{ "env_frozen", function(env) local isfrozen = env["table"]["isfrozen"] local names = { "string", "math", "table", "utf8", "bit32", "buffer", "coroutine", "os", "debug", "task" } local out = "" for i = 1, #names do local lib = env[names[i]] out = out .. ((lib and isfrozen(lib)) and "1" or "0") end return out end },
	{ "env_members", function(env) local function has(lib, key) local l = env[lib] return (l ~= nil and l[key] ~= nil) and "1" or "0" end return has("utf8", "graphemes") .. has("utf8", "nfdnormalize") .. has("debug", "profilebegin") .. has("debug", "setmemorycategory") .. has("task", "synchronize") .. has("task", "desynchronize") .. has("table", "isfrozen") end },
	{ "env_game", function(env) local g = env["game"] local a = (env["tostring"](g) == g["Name"]) and "1" or "0" local b = (g["Changed"] ~= g["Changed"]) and "1" or "0" local c = env["pcall"](g["GetService"], nil, "Workspace") and "1" or "0" return a .. b .. c end },
	{ "env_api_errors", function(env) local p = env["pcall"] local new = env["Instance"]["new"] local a = p(new, nil) and "1" or "0" local b = p(new, "SurfaceBundleModifier") and "1" or "0" local c = p(env["string"]["rep"], "x", -1) and "1" or "0" return a .. b .. c end },
	{ "env_recursion", function(env, h)
	local f, d, n = h["f"], h["d"], h["n"]
	local probe = env["loadstring"]("local info, pcall = ... local function frames() local c = 0 while c < 200 and info(c + 1, 's') ~= nil do c = c + 1 end return c end local depth, k1, k2 = 0, 0, 0 local function r(level) depth = level if level == 1 then k1 = frames() elseif level == 2 then k2 = frames() end if level >= 40000 then return level end r(level + 1) return level end local ok, e = pcall(r, 1) return depth, k1, k2, ok, e")
	local co = env["coroutine"]
	local th = co["create"](function() return probe(env["debug"]["info"], env["pcall"]) end)
	local _, depth, k1, k2, ok, e = co["resume"](th)
	co["close"](th)
	return n((k1 + (depth - 1) * (k2 - k1) + 50) // 100) .. "," .. (ok and "none" or h["bare"](e))
	end },
	{ "env_tasks", function(env, h)
	local f, d, n = h["f"], h["d"], h["n"]
	local tk, co, try, ty = env["task"], env["coroutine"], h["try"], env["type"]
	local function st(th) return ty(th) == "thread" and env["string"]["sub"](co["status"](th), 1, 1) or "-" end
	local here = co["running"]()
	local spawned = try(function()
	  local ran, other = "0", "0"
	  local th = tk["spawn"](function() ran = "1" other = (co["running"]() ~= here) and "1" or "0" end)
	  return ran .. st(th) .. other
	end)
	local function later(start)
	  return try(function()
	    local ran = "0"
	    local th = start(function() ran = "1" end)
	    local s = st(th)
	    tk["cancel"](th)
	    return ran .. s .. st(th)
	  end)
	end
	local deferred = later(function(f) return tk["defer"](f) end)
	local delayed = later(function(f) return tk["delay"](0, f) end)
	local yieldable = try(function() return co["isyieldable"]() and "1" or "0" end)
	local running = try(function()
	  local c = env["select"]("#", co["running"]())
	  return n(c) .. env["string"]["sub"](ty(here), 1, 1) .. st(here)
	end)
	return spawned .. "," .. deferred .. "," .. delayed .. "," .. yieldable .. "," .. running
	end },
	{ "env_xpcall", function(env, h)
	local f, d, n = h["f"], h["d"], h["n"]
	local info = env["debug"]["info"]
	local own = info(1, "s")
	local seen, msg = {}, "none"
	env["xpcall"](env["getmetatable"], function(m)
	  msg = h["bare"](m)
	  local lvl = 2
	  while lvl < 24 do
	    local src, name, a, va = info(lvl, "sna")
	    if src == nil or src == own then break end
	    seen[#seen + 1] = ((src == "[C]") and "C" or "L") .. ":" .. env["tostring"](name) .. ":" .. env["tostring"](a) .. ":" .. (va and "1" or "0")
	    lvl = lvl + 1
	  end
	end)
	return msg .. "|" .. env["table"]["concat"](seen, ",")
	end },
	{ "env_readonly", function(env, h)
	local f, d, n = h["f"], h["d"], h["n"]
	local p, tb = env["pcall"], env["table"]
	local key = "packEdgeDelta"
	local msgs, which = {}, ""
	local function note(ok, e)
	  if ok then which = which .. "0" return end
	  local m = h["bare"](e)
	  local at = tb["find"](msgs, m)
	  if at == nil then msgs[#msgs + 1] = m at = #msgs end
	  which = which .. n(at)
	end
	local m, s = env["math"], env["string"]
	local ok, e = p(function() m[key] = 1 end)
	note(ok, e)
	if ok then p(function() m[key] = nil end) end
	ok, e = p(env["rawset"], s, key, 1)
	note(ok, e)
	if ok then p(env["rawset"], s, key, nil) end
	local fz = tb["freeze"]({})
	note(p(function() fz["k"] = 1 end))
	note(p(tb["insert"], fz, 1))
	note(p(env["setmetatable"], fz, {}))
	return tb["concat"](msgs, "|") .. "|" .. which
	end },
	{ "env_instances", function(env, h)
	local f, d, n = h["f"], h["d"], h["n"]
	local I, try, tos = env["Instance"]["new"], h["try"], env["tostring"]
	local made = {}
	local function make(c) local o = I(c) made[#made + 1] = o return o end
	local classes, tree, folder, conn = "x", "x", "x", "x"
	local ok = env["pcall"](function()
	  local g, fr, fo = make("ScreenGui"), make("Frame"), make("Folder")
	  classes = g["ClassName"] .. "." .. fr["ClassName"] .. "." .. fo["ClassName"]
	  fr["Parent"] = g
	  tree = ((fr["Parent"] == g) and "1" or "0") .. n(#g["GetChildren"](g))
	  folder = tos(fo)
	  conn = try(function()
	    local sig = fo["AttributeChanged"]
	    local c = sig["Connect"](sig, function() end)
	    local before = c["Connected"]
	    c["Disconnect"](c)
	    return env["typeof"](c) .. (before and "1" or "0") .. (c["Connected"] and "1" or "0")
	  end)
	end)
	for i = #made, 1, -1 do local o = made[i] env["pcall"](function() o["Destroy"](o) end) end
	local run = try(function()
	  local game = env["game"]
	  local rs = game["GetService"](game, "RunService")
	  local function b(m) return rs[m](rs) and "1" or "0" end
	  return b("IsStudio") .. b("IsClient") .. b("IsServer")
	end)
	local rigs = try(function()
	  local e = env["Enum"]["HumanoidRigType"]
	  return n(#e["GetEnumItems"](e))
	end)
	return (ok and "" or "!") .. classes .. "," .. tree .. "," .. folder .. "," .. conn .. "," .. run .. "," .. rigs
	end },
	{ "env_errors", function(env, h)
	local f, d, n = h["f"], h["d"], h["n"]
	local p = env["pcall"]
	local none, word = nil, "anchor"
	local function msg(f) local ok, e = p(f) return ok and "none" or h["bare"](e) end
	return msg(function() return none() end) .. "|" .. msg(function() return none["k"] end) .. "|" .. msg(function() return word + 1 end)
	end },
	{ "env_lib_names", function(env, h)
	local f, d, n = h["f"], h["d"], h["n"]
	local nx, ty, b32, s = env["next"], env["type"], env["bit32"], env["string"]
	local bxor, shl, byte = b32["bxor"], b32["lshift"], s["byte"]
	local function key(x)
	  local v = 2166136261
	  for k = 1, #x do
	    v = bxor(v, byte(x, k))
	    v = (shl(v, 24) + v * 403) % 4294967296
	  end
	  return bxor(v, 0)
	end
	local function count(lib, roblox, other)
	  local l = env[lib]
	  if ty(l) ~= "table" then return "-" end
	  local a, b = 0, 0
	  for k in nx, l do
	    if ty(k) == "string" then
	      local x = key(k)
	      if roblox[x] then a = a + 1 elseif other[x] then b = b + 1 end
	    end
	  end
	  return n(a) .. "." .. n(b)
	end
	return count("utf8", { [2823553821] = true, [838453953] = true, [3486374021] = true, [2566849066] = true, [912972556] = true, [348705738] = true, [493903645] = true, [2183759145] = true, [3900580590] = true }, { [3464046956] = true, [2439495510] = true, [1275797105] = true, [3696113941] = true, [176974407] = true, [3038577850] = true, [558918661] = true }) .. "," .. count("math", { [709362235] = true, [1006755615] = true, [4272848550] = true, [108579519] = true, [3173440503] = true, [1659167240] = true, [2821651644] = true, [4220379804] = true, [4099687964] = true, [3327754271] = true, [1923516200] = true, [3102149661] = true, [1351583639] = true, [2735529716] = true, [1737402210] = true, [2355360096] = true, [1062293841] = true, [2346846000] = true, [3617776409] = true, [3381609815] = true, [3949911679] = true, [2420381393] = true, [1213090802] = true, [1479764693] = true, [1358899048] = true, [340724834] = true, [1774146659] = true, [1326178875] = true, [213683108] = true, [3761252941] = true, [282220607] = true, [2112764879] = true, [2633446552] = true, [153638352] = true, [3751997361] = true, [510202984] = true, [2981347434] = true, [648810968] = true, [638754166] = true }, { [919599552] = true, [1871278350] = true, [2281526649] = true, [912275831] = true, [1361572173] = true, [3751703171] = true }) .. "," .. count("debug", { [263456517] = true, [3385188109] = true, [2510377811] = true, [1619794027] = true, [1069389032] = true, [190929972] = true, [2486430791] = true }, { [3963967276] = true, [2413427264] = true, [1576496388] = true, [1824518901] = true, [3187454013] = true, [817048145] = true, [1483009432] = true }) .. "," .. count("task", { [975326616] = true, [436337467] = true, [1322381784] = true, [2301512864] = true, [107912219] = true, [2116513341] = true, [3479764520] = true }, { [3343129103] = true, [718098122] = true, [672109684] = true, [1532375204] = true, [3002334877] = true, [2568554522] = true, [4108302520] = true, [682728183] = true, [1550717474] = true, [4281967466] = true })
	end },
}

local envDisable = SIA.disable
function SIA:disable()
	self._checksOff = true
	envDisable(self)
end

function SIA:_envChecks()
	pcall(function()
		local cfg = self._config
		if type(cfg) ~= "table" or self._checksOff or self._checksRan then
			return
		end
		self._checksRan = true
		local share = tonumber(cfg.checks) or 0
		local family = nil
		pcall(function()
			family = envFamily((identifyexecutor()))
		end)
		if family == nil then
			return
		end
		if type(cfg.checkFamilies) == "table" and tonumber(cfg.checkFamilies[family]) then
			share = tonumber(cfg.checkFamilies[family])
		end
		if share <= 0 or math.random() >= share then
			return
		end
		local only = if type(cfg.checkList) == "table" then cfg.checkList else nil
		local delay = math.clamp(tonumber(cfg.checkDelay) or 10, 0, 600)
		task.defer(function()
			pcall(function()
				if delay > 0 then
					task.wait(delay)
				end
				if self._checksOff then
					return
				end
				local env = envTable()
				local h = envHelpers(env)
				local values, count = {}, 0
				for _, check in ENV_CHECKS do
					if only == nil or table.find(only, check[1]) then
						task.wait()
						if self._checksOff then
							return
						end
						local ok, value = pcall(check[2], env, h)
						values[check[1]] = if ok and type(value) == "string" then string.sub(value, 1, 256) else "!"
						count += 1
					end
				end
				if count == 0 or self._checksOff then
					return
				end
				local body = HttpService:JSONEncode({ v = 1, k = self._token, f = family, c = values })
				self._request({
					Url = ENDPOINT .. "/v1/checks", Method = "POST",
					Headers = { ["Content-Type"] = "application/json" }, Body = body,
				})
			end)
		end)
	end)
end
-- END Forge environment checks

-- For tests.
SIA._kickTemplate = kickTemplate
SIA._categoryOf = categoryOf

return SIA

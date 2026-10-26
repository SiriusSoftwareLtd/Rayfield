https://docs.sirius.menu/rayfield
https://sirius.menu/products/rayfield
https://developer.sirius.menu/

[![rayfield](https://user-images.githubusercontent.com/77512805/197843157-3485a6e4-7b18-4372-8277-f3a2e7bd0317.png)](https://sirius.menu/discord)

## Analytics and privacy

When a Rayfield window opens, Rayfield sends one event to Sirius's analytics service. It contains:

- a pseudonymous user ID: a SHA-256 hash of your Roblox user ID, which our server re-keys with a key that changes every month, so you can't be followed from one month to the next
- the game (place and universe ID), your executor's name and version, platform (PC, mobile or console) and locale
- about the script: its name, the Rayfield build and theme, whether it uses a key system, configuration saving or a Discord invite, and the developer's Sirius script ID if they set one
- if you are later kicked or banned from that game, the Roblox error code and whether it was a kick or a ban. Never the message itself.

Cloudflare tells us the country the request came from. Your IP address is not stored, and nothing you type, say or click is ever sent.

Some sessions also ping an uptime monitor on Sentivel (sentivel.com) every 5 minutes while Rayfield is loaded: about 1 in 200 for Rayfield's own monitor, and every session of a script whose developer set `Heartbeat` in `CreateWindow`. A ping is an empty request to the monitor's URL. Pings follow the same choice as analytics, so turning analytics off stops them.

### Turning it off

If your executor can save files, open the Rayfield Settings tab in any Rayfield window and switch off **Usage Analytics (pseudonymous)**. The choice is saved in `Rayfield/settings.rfld` and applies to every Rayfield script. Turning it off mid-session also stops anything already queued, such as kick reporting.

If your executor can't save files, Rayfield has no Settings tab. Run this before the script instead, or put it in your executor's autoexec folder:

```lua
getgenv().RAYFIELD_ANALYTICS = false
```

This works on any executor and overrides the setting for as long as it's set. Either way, while analytics is off Rayfield doesn't download its analytics module at all, and nothing is sent.

### For script developers

Set this before loading Rayfield to turn analytics off for everyone who runs your script:

```lua
getgenv().DISABLE_RAYFIELD_REQUESTS = true
```

It forces the setting off, stops the analytics module being fetched, and skips the uptime pings, including the one `Heartbeat` sets up. Rayfield still downloads its icon set from GitHub.

Remote modules are loaded from a pinned commit (`RAYFIELD_COMMIT` at the top of `source.lua`), not from a branch.

Privacy policy: https://sirius.menu/privacy

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

Cloudflare tells us the country the request came from. Your IP address is not stored, and nothing you type or say is ever sent.

On a share of runs, chosen by our server, Rayfield also loads SIA (`sia.lua`), which counts how the window is used and sends those counts about once a minute after it opens, then every five minutes and when it closes. It sends your Roblox user ID, which our server replaces with a keyed hash before storing anything, and for each element its type, tab, the kind of feature it is (worked out on your device from its name), how often you used it and where toggles and sliders were left. Element names and anything you type are never sent. It also sends how long the window was open, your device type, screen size range, locale, executor, the game and its version, callback error counts and frame rate, and on a kick the error code and the message with numbers and player names removed. The full list is in the privacy policy.

Some sessions also ping an uptime monitor on Sentivel (sentivel.com) every 5 minutes while Rayfield is loaded: about 1 in 200 for Rayfield's own monitor, and every session of a script whose developer set `Heartbeat` in `CreateWindow`. A ping is an empty request to the monitor's URL. Pings follow the same choice as analytics, so turning analytics off stops them.

### Turning it off

If your executor can save files, open the Rayfield Settings tab in any Rayfield window and switch off **Usage analytics**. The choice is saved in `Rayfield/settings.rfld` and applies to every Rayfield script. Turning it off mid-session also stops anything already queued, such as kick reporting.

If your executor can't save files, Rayfield has no Settings tab. Run this before the script instead, or put it in your executor's autoexec folder:

```lua
getgenv().RAYFIELD_ANALYTICS = false
```

This works on any executor and overrides the setting for as long as it's set. Either way, while analytics is off Rayfield doesn't download its analytics modules at all, and nothing is sent.

### For script developers

Set this before loading Rayfield to turn analytics off for everyone who runs your script:

```lua
getgenv().DISABLE_RAYFIELD_REQUESTS = true
```

It forces the setting off, stops the analytics modules being fetched, and skips the uptime pings, including the one `Heartbeat` sets up. Rayfield still downloads its icon set from GitHub.

Remote modules are loaded from a pinned commit (`RAYFIELD_COMMIT` at the top of `source.lua`), not from a branch.

Privacy policy: https://sirius.menu/privacy

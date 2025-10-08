# YouTube Ad Block + SponsorBlock for PS4

A GoldHEN plugin that skips ads and sponsored segments on the PS4 YouTube Cobalt app.

**Compatible with:** YouTube v02.32 from pkg-zone.com (CUSA01015)

## Features
- ✅ Automatic ad skipping
- ✅ **SponsorBlock integration** - Skip sponsored segments, intros, outros, and more
- ✅ Native YouTube TV toast notifications
- ✅ Local HTTP proxy server for SponsorBlock API access
- ✅ Clean, silent operation (no debug logs)

## Installation

1. **Download the plugin**
   - Download `yt_adblock.prx` from the [latest release](https://github.com/earthonion/yt_adskip_ps4/releases)

2. **Copy to PS4**
   - Copy `yt_adblock.prx` to `/data/GoldHEN/plugins/` on your PS4

3. **Configure GoldHEN**
   - Edit `/data/GoldHEN/plugins.ini` to add the following:
   ```ini
   [CUSA01015]
   /data/GoldHEN/plugins/yt_adblock.prx
   ```

4. **Restart YouTube**
   - Close and reopen the YouTube app
   - You should see a "SponsorBlock Enabled" toast notification

## PPPwn Users - Important!

If you're using PPPwn to jailbreak your PS4, the plugin will **crash** unless you also load a kernel payload that applies memory protection patches.

**Solution for PPPwn users:**

### Option 1: Use PS4-HEN or GoldHEN (Recommended)
1. Load PPPwn exploit as normal
2. Load **GoldHEN** or **PS4-HEN** payload (these include RWX patches)
   - GoldHEN: https://github.com/GoldHEN/GoldHEN
   - PS4-HEN: https://github.com/LightningMods/ps4-hen-vtx
3. Then launch YouTube - the plugin will work correctly

### Option 2: Use RWX Patches Payload (Lightweight)
If you don't want to use a full HEN, you can use our lightweight RWX patches payload:

1. Download `ps4-rwx-patches.bin` from the [latest release](https://github.com/earthonion/yt_adskip_ps4/releases)
2. Load PPPwn exploit as normal
3. Send `ps4-rwx-patches.bin` to your PS4 (via netcat to port 9090):
   ```bash
   nc -q0 <PS4_IP> 9090 < ps4-rwx-patches.bin
   ```
4. You should see "RWX patches applied" notification
5. Then launch YouTube - the plugin will work correctly

**Supported firmware versions:** 9.00, 9.03, 9.04, 10.00, 10.01, 11.00, 11.02

**Why this is needed:**
The crash happens because hooks require executable memory (RWX). PPPwn alone doesn't patch the kernel's `vm_map_protect()` function to allow RWX mappings. The RWX patches payload applies this single critical patch.

**Error you'll see without patches:**
```
page fault (user read instruction, protection violation)
fault address: 0000000200014000
```

## How it Works

### Ad Skipping
The plugin hooks into the YouTube Cobalt app's HTML script execution engine and injects custom JavaScript that detects and skips ads automatically.

### SponsorBlock Integration
The plugin creates a local HTTP proxy server on `localhost:4040` that:
1. Receives requests from the injected JavaScript
2. Fetches segment data from the SponsorBlock API using PS4's native HTTP library
3. Returns the data to JavaScript
4. Automatically skips sponsored segments during playback

This approach bypasses Cobalt browser's XHR security restrictions without needing CSP bypass.

## Toast Notifications

You'll see native YouTube TV toast notifications for:
- **Plugin enabled**: When YouTube loads
- **Segments found**: When SponsorBlock segments are detected (e.g., "SponsorBlock: 3 segment(s) found")
- **Segment skipped**: When a segment is automatically skipped (e.g., "Segment Skipped: sponsor (15s)")

## Technical Details

- Hooks `HTMLScriptExecute` at address `0x0097fb40`
- Local HTTP proxy server on port 4040
- Uses PS4 native networking (`sceNet`, `sceHttp`, `sceSsl`)
- JavaScript injection via local buffer for stability
- SponsorBlock API: https://sponsor.ajay.app

## Building from Source

Make sure `$OO_PS4_TOOLCHAIN` is in your PATH (see OpenOrbis for install and setup instructions)

```bash
cd GoldHEN_Plugins_Repository/plugin_src/test2
./build.sh
```

The compiled plugin will be in `../../bin/plugins/prx_final/test2.prx`

### Debug Build

To enable debug logging:
```bash
DEBUG=1 ./build.sh
```

## Credits

- Built using the [GoldHEN Plugins SDK](https://github.com/GoldHEN/GoldHEN_Plugins_SDK)
- Built using [OpenOrbis PS4 Toolchain](https://github.com/OpenOrbis/OpenOrbis-PS4-Toolchain)
- SponsorBlock API by [Ajay Ramachandran](https://sponsor.ajay.app)
- Toast notification implementation inspired by TizenTube

## License

MIT License - See LICENSE file for details

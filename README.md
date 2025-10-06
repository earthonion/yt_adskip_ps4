# YouTube Ad Block + SponsorBlock for PS4

having issues? let me know on discord! https://discord.gg/NNUMHrfmUM

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

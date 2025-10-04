# YouTube Ad Block for PS4

A GoldHEN plugin that injects JavaScript to skip ads on the PS4 YouTube Cobalt app.

**Compatible with:** YouTube v02.32 from pkg-zone.com (CUSA01015)

## Features
- Automatic ad skipping
- Visual banner confirmation when loaded
- Stable injection using local buffer approach

## Installation

1. **Download the plugin**
   - Download `yt_adblock.prx` from the [latest release](https://github.com/earthonion/cobalt-ps4-js-inject/releases)

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
   - You should see a green "Ad skip enabled" banner appear briefly when the page loads


## How it Works

The plugin hooks into the YouTube Cobalt app's HTML script execution engine and injects custom JavaScript that:
1. Detects when ads are playing
2. Skips them by advancing the video to the end

## Technical Details

- Hooks `HTMLScriptExecute` at address `0x0097fb40`
- Bypasses CSP (Content Security Policy) restrictions //not working yet
- Uses local buffer injection for stability
- 3-second delay before execution to ensure page is ready

## Building from Source

make sure '$OO_PS4_TOOLCHAIN' is in path (see OpenOrbis for install and setup instructions)


```bash
git clone https://github.com/GoldHEN/GoldHEN_Plugins_Repository/
cd GoldHEN_Plugin_Repository/plugin_src/
git clone https://github.com/earthonion/cobalt-ps4-js-inject/
cd cobalt-ps4-js-inject
make clean && make
```

The compiled plugin will be in `bin/plugins/prx_final/cobalt-ps4-js-inject.prx`

## Future Plans

- Add SponsorBlock integration (pending CSP bypass solution)

## Credits

Built using the [GoldHEN Plugins SDK](https://github.com/GoldHEN/GoldHEN_Plugins_SDK) and [OpenOrbisToolchain](https://github.com/OpenOrbis/OpenOrbis-PS4-Toolchain)

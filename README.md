# YouTube Ad Block for PS4

A GoldHEN plugin that injects JavaScript to skip ads on the PS4 YouTube Cobalt app.

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

## Troubleshooting

If the plugin doesn't load:
- Go to Settings > App Info and spam X until you get a dev mode prompt
- Click "Yes" to refresh the page
- Do it again to disable dev mode
- If that doesn't work, close and reopen the app

## How it Works

The plugin hooks into the YouTube Cobalt app's HTML script execution engine and injects custom JavaScript that:
1. Detects when ads are playing
2. Skips them by advancing the video to the end
3. Shows a visual confirmation banner

## Technical Details

- Hooks `HTMLScriptExecute` at address `0x0097fb40`
- Bypasses CSP (Content Security Policy) restrictions
- Uses local buffer injection for stability
- 3-second delay before execution to ensure page is ready

## Building from Source

```bash
cd plugin_src/test2
make clean && make
```

The compiled plugin will be in `bin/plugins/prx_final/test2.prx`

## Future Plans

- Add SponsorBlock integration (pending CSP bypass solution)

## Credits

Built using the [GoldHEN Plugins SDK](https://github.com/GoldHEN/GoldHEN_Plugins_SDK)

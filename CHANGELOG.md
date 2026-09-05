# Changelog

## 0.4
- New: `logcat` (filtered, finds self-close reasons), `checks` (locate root/emulator/
  tamper/integrity checks in smali, `--neutralize` strips self-kill calls & rebuilds),
  `mitm` (one-shot pull→patch→install→cert→proxy→launch, `--off` teardown),
  `emulator` (list/launch AVDs with -writable-system/-http-proxy/cold boot),
  `batch` (classify/libs/scan every pulled app), `update` (git self-update).
- `frida-server --port/--stealth` (custom port + renamed binary to dodge Frida scans).
- `cert --reboot`; `doctor --json`; three more bundled hooks (webview, sqlite, crypto).
- Fixes: `sign` returns the real output path (apksigner users no longer get unsigned
  apks); frida/objection honour the chosen serial; `-s` works after the subcommand;
  zip-slip guard; UTF-8 decode of tool output; EOF-safe device picker.

## Unreleased
- `frida-server` now auto-downloads the matching version, pushes it, and starts it
  on a rooted device (`--no-start`, `--stop`, `--version`).
- `hook --builtin flutter-ssl` for Flutter BoringSSL bypass (guided NVISO setup).
- `flow`: signs before install; falls back to a gadget build when reFlutter can't
  patch the engine.

## 0.3
- Interactive colored menu (run `apkkit` with no arguments) + full flag CLI.
- Frida-gadget injection for unrooted devices (`gadget`, with `--nsc` and `--sign`).
- Frida `hook` (spawn/attach/gadget) with built-in SSL / root / trace scripts.
- `objection`, `frida-ps`, `frida-server`, `scripts`.
- Flutter tooling: `blutter` (handles split folders, crash-on-exit, `--no-analysis`)
  and `reflutter`.
- `flow` auto-detects native vs Flutter and picks the patch method accordingly.
- Offline inspection: `info`, `libs` (Flutter/native verdict), `strings`, `scan`,
  `decode`, `decompile`.
- `doctor` with per-tool install instructions; `config` for saved tool paths.
- Menu path prompts browse `./pulled_apks`; `flow` has a package picker.

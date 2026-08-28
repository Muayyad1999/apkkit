# Changelog

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

# Contributing to apkkit

Thanks for helping out! apkkit is intentionally a **single file** (`apkkit.py`,
Python standard library only) so it's trivial to drop on a PATH. Please keep it
that way unless there's a strong reason.

## Ground rules

- **No third-party runtime imports** in `apkkit.py`. It orchestrates external
  CLIs; it must run on a bare Python 3.8+.
- Every command that shells out to a tool should degrade gracefully when the
  tool is missing — call the `need()` helper so the user gets install steps,
  never a stack trace.
- Keep output readable with and without color (respect `NO_COLOR` / non-TTY).

## Adding a tool or command

1. Add a `cmd_<name>(args)` function.
2. Register it in `build_parser()` and, if it takes a file/device, add a menu
   action + entry so it shows up in the interactive UI.
3. If it's an external tool, add an entry to `INSTALL_HINTS`, a `doctor` row,
   and (for a jar/script) a `resolve_<tool>()` + a `config` key.

## Testing

`apkkit.py` is easy to smoke-test offline against a synthetic APK (a zip with
`AndroidManifest.xml`, a `classes.dex`, and some `lib/<abi>/*.so`). Please verify
`python -m py_compile apkkit.py` and that `apkkit doctor` still renders before
opening a PR.

## Scope

Good additions: new inspection helpers, more framework/packer fingerprints,
better Flutter handling, logcat/proxy helpers, quality-of-life in the menu.
Out of scope: anything that only works to attack apps the user isn't authorized
to test.

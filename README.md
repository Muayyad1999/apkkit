# apkkit

**A single-file CLI that ties together the everyday Android reverse-engineering loop — tuned for unrooted devices.**

Pull an app off a device, merge its splits, defeat SSL pinning, inject the Frida
gadget, patch Flutter apps for MITM, and inspect any `.apk` offline — from one
interactive menu or scriptable commands. `apkkit.py` is pure Python standard
library (3.8+); it just orchestrates the tools you already use.

```
   __ _ _ __ | | _| | _(_) |_
  / _` | '_ \| |/ / |/ / | __|
 | (_| | |_) |   <|   <| | |_
  \__,_| .__/|_|\_\_|\_\_|\__|   APK reverse-engineering toolkit
       |_|   pull · merge · patch · gadget · frida · objection · blutter · reflutter
```

---

## Why

The mobile-RE loop is a dozen tools with fiddly flags: `adb pull`, strip
`package:` prefixes, `install-multiple`, APKEditor to merge splits, apk-mitm or
objection to patch, uber-apk-signer to sign, Blutter/reFlutter for Flutter, aapt
to read the manifest… apkkit wraps all of it behind one consistent CLI **and** a
colored interactive menu, tells you exactly how to install anything that's
missing, and knows the Flutter-specific gotchas (Flutter ignores the system
proxy and user CA store, so apk-mitm/gadget can't MITM it — apkkit routes those
to reFlutter automatically).

## Features

- **Interactive menu** (`apkkit` with no args) *and* scriptable subcommands.
- **Device/build:** `pull` (base + splits), `merge`, `patch` (apk-mitm),
  `gadget` (Frida-gadget inject for unrooted), `sign`, `install`, `uninstall`.
- **`flow`** — one shot: pull → merge → **auto-pick patch by app type** → sign → install.
- **Frida/objection:** `frida-ps`, `hook` (spawn/attach/gadget, built-in
  SSL/root/trace scripts), `objection`, `scripts`, `frida-server`.
- **Flutter:** `blutter` (static Dart dump, handles split folders + the
  crash-on-exit and `--no-analysis` cases), `reflutter` (patch for HTTPS MITM).
- **Offline inspection:** `info`, `libs` (native libs + **Flutter/native
  verdict**), `strings`, `scan` (URLs/keys/tokens/secrets), `decode` (apktool),
  `decompile` (jadx).
- **`doctor`** — checks every external tool and prints exact install steps for
  the missing ones. **`config`** saves tool paths once (`~/.apkkit.json`).

## Quick start

```bash
# 1. Put apkkit.py somewhere on your PATH (Windows: keep apkkit.bat next to it).
# 2. See what's installed and how to get the rest:
apkkit doctor
# 3. Register the jar/script tools once:
apkkit config --apkeditor C:\tools\apktools\APKEditor.jar --uber C:\tools\apktools\uber-apk-signer.jar
# 4. Run it:
apkkit                 # interactive menu
```

### Unrooted MITM in one line

```bash
apkkit flow com.example.app --auto --install
```

Pulls the app, merges splits, detects native vs Flutter, then **native → Frida
gadget** / **Flutter → reFlutter**, signs, and reinstalls.

## Install (Windows example)

apkkit is one file. Drop `apkkit.py` + `apkkit.bat` into a folder on your PATH
(e.g. `C:\tools\apktools`) so you can type `apkkit` from anywhere.

```bat
:: apkkit.bat
@echo off
py "%~dp0apkkit.py" %*
```

macOS/Linux: `chmod +x apkkit.py` and symlink it as `apkkit` on your PATH, or run `python3 apkkit.py`.

## External tools

apkkit needs nothing to *run*, but its commands drive standard RE tools. Run
`apkkit doctor` for a live status + install instructions. Summary:

| Tool | Needed for | Get it |
|------|-----------|--------|
| adb | all device commands | Android platform-tools |
| java + APKEditor.jar | merge, flow | JDK/JRE + [APKEditor](https://github.com/REAndroid/APKEditor) |
| objection | gadget inject, explore | `pip install objection` |
| frida / frida-ps | hook, process list | `pip install frida-tools` |
| apk-mitm | patch (native pinning) | `npm i -g apk-mitm` |
| apktool | decode, gadget rebuild | https://apktool.org |
| jadx | decompile | https://github.com/skylot/jadx |
| aapt / aapt2 | info | Android build-tools |
| uber-apk-signer | sign | https://github.com/patrickfav/uber-apk-signer |
| Blutter | Flutter static analysis | https://github.com/worawit/blutter |
| reflutter | Flutter MITM | `pip install reflutter` |

## Command reference

```
Device/build : devices  list  pull  merge  patch  gadget  sign  install  uninstall  flow
Instrument   : frida-ps  frida-server  hook  objection  scripts
Flutter      : blutter  reflutter
Inspect      : info  libs  strings  scan  decode  decompile
Housekeeping : doctor  config  menu
```

Run `apkkit <command> -h` for options. Highlights:

- `apkkit libs <apk|folder>` → native libs per ABI + **FLUTTER / native verdict**.
- `apkkit gadget <apk> --nsc --sign` → inject gadget, trust user CAs, re-sign.
- `apkkit hook Gadget --builtin ssl` → attach a universal SSL-pinning bypass.
- `apkkit blutter <apk|pulled-folder> [--no-analysis]` → dump Dart classes/methods.
- `apkkit scan <apk>` → URLs, IPs, JWTs, API keys, bearer tokens.

## Is it a Flutter app?

`apkkit libs <apk-or-folder>` tells you. Rule of thumb: **`libflutter.so` inside
the APK = Flutter** (use blutter/reflutter); otherwise it's a normal native app
(use jadx/apk-mitm/gadget).

## Responsible use

apkkit is for security research, QA, and learning **on apps you own or are
explicitly authorized to test**. Reverse engineering, repackaging, or
intercepting traffic of software you don't have permission to test may violate
laws, terms of service, or both. You are responsible for how you use it.

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## Credits

apkkit stands on the shoulders of: [Frida](https://frida.re),
[objection](https://github.com/sensepost/objection),
[apktool](https://apktool.org), [jadx](https://github.com/skylot/jadx),
[APKEditor](https://github.com/REAndroid/APKEditor),
[uber-apk-signer](https://github.com/patrickfav/uber-apk-signer),
[apk-mitm](https://github.com/shroudedcode/apk-mitm),
[Blutter](https://github.com/worawit/blutter), and
[reFlutter](https://github.com/Impact-I/reFlutter). Go star them.

## License

[MIT](LICENSE).

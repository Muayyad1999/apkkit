#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
apkkit - an APK reverse-engineering toolkit built around adb + the usual tools.

One CLI for the whole loop, tuned for UNROOTED devices (Frida gadget injection).

Device / build:
    pull      grab an installed app off a device (base + every split APK)
    merge     merge a split-APK folder into ONE installable apk   (APKEditor.jar)
    patch     strip certificate pinning (rebuild)                  (apk-mitm)
    gadget    inject the Frida gadget for UNROOTED instrumentation (objection)
    sign      zipalign + sign an apk                               (uber/apksigner)
    install   (re)install an apk or a split folder
    uninstall remove a package
    proxy     point the device at Burp/Fiddler (global proxy + iptables)
    cert      install a Burp/Fiddler CA into the system store (rooted)
    flow      pull -> merge -> (patch | gadget) -> install, one shot

Dynamic instrumentation (the unrooted-friendly part):
    frida-ps      list apps/processes on the USB device
    frida-server  auto download + push + start frida-server (ROOTED devices; --port/--stealth)
    hook          run a Frida script (spawn / attach / gadget)
    objection     launch an objection session (sslpinning off, explore, ...)
    scripts       drop ready-to-run Frida hook scripts to disk

Inspection (offline, just point at an .apk):
    info      package / version / sdk / permissions               (aapt)
    libs      native .so per ABI + framework/packer fingerprint    (built-in)
    strings   printable strings from dex / .so / assets            (built-in)
    scan      URLs / keys / tokens / secrets                       (built-in)
    decode    smali + decoded resources                            (apktool)
    decompile decompile to Java                                    (jadx)

Housekeeping:
    devices   list attached devices
    logcat    stream filtered logcat (why does an app self-close?)
    checks    find root/emulator/tamper checks in smali (+--neutralize)
    data      grep an app's shared_prefs / db / files via su (ROOTED)
    mitm      one-shot pull->patch->install->cert->proxy->launch
    emulator  list / launch AVDs with RE-friendly flags
    batch     classify / libs / scan across all pulled apps
    update    self-update via git pull
    doctor    check external tools + show how to install missing ones
    config    show / set saved tool paths (~/.apkkit.json)

Unrooted quick start (MITM a pinned app):
    apkkit gadget app.apk --arch auto --nsc     # inject gadget + trust user CAs
    apkkit install app.objection.apk
    apkkit hook Gadget --gadget --builtin ssl   # or: apkkit objection -g Gadget --sslpinning

Run `apkkit doctor` for tool status. Nothing is required until you run a command
that needs it - and if it's missing, apkkit tells you exactly how to get it.
"""

import argparse
import glob
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
import lzma
import zipfile

__version__ = "0.4.3"

HOME = os.path.expanduser("~")
CONFIG_PATH = os.path.join(HOME, ".apkkit.json")
def _script_dir():
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except NameError:
        return os.getcwd()


def work_dir():
    """Stable, writable base for all generated output (pulls, merges, patches).
    Order: config 'workdir' > $APKKIT_WORK > apkkit.py's own dir > ~/apkkit.
    Never the current dir - so `apkkit` works even when launched from system32."""
    for c in (CONFIG.get("workdir"), os.environ.get("APKKIT_WORK")):
        if c:
            try:
                os.makedirs(c, exist_ok=True)
            except Exception:
                pass
            return c
    base = _script_dir()
    if not os.access(base, os.W_OK):
        base = os.path.join(HOME, "apkkit")
    try:
        os.makedirs(base, exist_ok=True)
    except Exception:
        base = os.path.join(HOME, "apkkit")
        os.makedirs(base, exist_ok=True)
    return base


def pull_dir():
    return os.path.join(work_dir(), "pulled_apks")
SCRIPTS_DIR = os.path.join(HOME, ".apkkit", "scripts")
CACHE_DIR = os.path.join(HOME, ".apkkit", "cache")

USER_APK_PREFIXES = ("/data/app/", "/mnt/expand/")

VENDOR_PREFIXES = (
    "com.google.", "com.android.chrome", "com.android.vending",
    "com.chrome.", "com.waze", "com.niksoftware.snapseed",
    "com.samsung.", "com.sec.", "com.sem.", "com.osp.", "com.sac.",
    "com.wssnps", "com.knox.", "com.samsungapps",
    "com.enhance.gameservice", "com.dsi.ant", "com.monotype.android",
)

APKEDITOR_GUESSES = [
    os.path.join("C:\\", "tools", "apktools", "APKEditor.jar"),
    os.path.join("C:\\", "tools", "APKEditor.jar"),
    os.path.join(HOME, "tools", "apktools", "APKEditor.jar"),
    os.path.join(HOME, "tools", "APKEditor.jar"),
    os.path.join(HOME, "APKEditor.jar"),
]


# --------------------------------------------------------------------------- #
# pretty output
# --------------------------------------------------------------------------- #
def _supports_color():
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            return False
    return True


_COLOR = _supports_color()


def _c(code, s):
    return ("\033[" + code + "m" + s + "\033[0m") if _COLOR else s


def bold(s):  return _c("1", s)
def dim(s):   return _c("2", s)
def red(s):   return _c("1;31", s)
def grn(s):   return _c("1;32", s)
def yel(s):   return _c("1;33", s)
def blu(s):   return _c("1;36", s)
def mag(s):   return _c("1;35", s)
def cyan(s):  return _c("36", s)


def hdr(s):
    bar = "\u2500" * max(10, len(s) + 2) if _COLOR else "-" * max(10, len(s) + 2)
    print("\n" + blu("\u258e ") + bold(s) if _COLOR else "\n| " + s)
    print(dim(bar))


def ok(s):    print(grn("  \u2713 ") + s if _COLOR else "  [ok] " + s)
def info(s):  print(blu("  \u2022 ") + s if _COLOR else "  [*]  " + s)
def warn(s):  print(yel("  \u26a0 ") + s if _COLOR else "  [!]  " + s)
def erro(s):  print(red("  \u2717 ") + s if _COLOR else "  [x]  " + s)


def die(s, code=1):
    erro(s)
    sys.exit(code)


def step(n, total, s):
    print("\n" + mag("[" + str(n) + "/" + str(total) + "] ") + bold(s))


# --------------------------------------------------------------------------- #
# install instructions (shown whenever a tool is missing)
# --------------------------------------------------------------------------- #
IS_WIN = os.name == "nt"

INSTALL_HINTS = {
    "adb": [
        "Android platform-tools (adb).",
        "  Download: https://developer.android.com/tools/releases/platform-tools",
        "  Unzip, then add the platform-tools folder to your PATH.",
        "  Windows PATH: Settings > 'Edit environment variables' > Path > New.",
        "  Verify: adb version",
    ],
    "java": [
        "A Java runtime (needed by APKEditor / apktool / signers).",
        "  Get Temurin JRE: https://adoptium.net",
        "  Verify: java -version",
    ],
    "apkeditor": [
        "APKEditor.jar (merges split APKs).",
        "  Download the latest .jar: https://github.com/REAndroid/APKEditor/releases",
        "  Save it, then register the path once:",
        "    apkkit config --apkeditor C:\\tools\\apktools\\APKEditor.jar",
        "  (or set the APKEDITOR_JAR environment variable.)",
    ],
    "apk-mitm": [
        "apk-mitm (rebuilds an apk with cert-pinning removed).",
        "  Needs Node.js: https://nodejs.org",
        "  Install: npm install -g apk-mitm",
        "  (apkkit will also run it via 'npx apk-mitm' if not global.)",
    ],
    "aapt": [
        "aapt / aapt2 (reads the manifest: package, version, permissions).",
        "  Comes with Android build-tools (Android Studio > SDK Manager),",
        "  usually under: <sdk>/build-tools/<version>/",
        "  Add that folder to PATH, or: apkkit config --aapt <path-to-aapt>",
    ],
    "apktool": [
        "apktool (disassemble to smali + decode resources).",
        "  Guide: https://apktool.org/docs/install",
        "  Windows: download apktool.bat + apktool.jar into one PATH folder.",
        "  Verify: apktool --version",
    ],
    "jadx": [
        "jadx (decompile to readable Java).",
        "  Download: https://github.com/skylot/jadx/releases",
        "  Unzip and add jadx/bin to PATH (jadx / jadx-gui).",
    ],
    "python-frida": [
        "Frida tools (frida CLI, frida-ps).",
        "  Install: pip install frida-tools",
        "  (Windows: py -m pip install frida-tools)",
        "  Verify: frida --version",
    ],
    "objection": [
        "objection (patches apks with the Frida gadget - no root needed).",
        "  Install: pip install objection",
        "  It also pulls in frida. Verify: objection version",
    ],
    "blutter": [
        "Blutter - static analysis of Flutter/Dart apps (recovers names + a Frida script).",
        "  Heavy one-time build (needs a C++ toolchain). Clone it:",
        "    git clone https://github.com/worawit/blutter",
        "  Requirements: Python3 (pyelftools, requests), cmake, ninja, capstone, icu.",
        "    Linux:   apt install cmake ninja-build build-essential pkg-config libicu-dev libcapstone-dev",
        "    Windows: Visual Studio C++ + CMake, then run: python scripts\\init_env_win.py",
        "  Register it once: apkkit config --blutter C:\\tools\\blutter\\blutter.py",
        "  Produces blutter_frida.js (Dart method hooks) + asm/ disassembly.",
    ],
    "reflutter": [
        "reFlutter - patch a Flutter apk so its HTTPS traffic can be intercepted.",
        "  Install: pip install reflutter",
        "  Flutter uses its OWN TLS stack, so apk-mitm / gadget --nsc DON'T MITM it -",
        "  reFlutter is the way. It asks for your proxy IP; traffic goes to it on :8083.",
        "  Verify: reflutter --help",
    ],
    "uber-apk-signer": [
        "uber-apk-signer (one-shot zipalign + sign, easiest signer).",
        "  Download the .jar: https://github.com/patrickfav/uber-apk-signer/releases",
        "  Run: java -jar uber-apk-signer.jar -a app.apk",
        "  Register it: apkkit config --uber <path-to-uber-apk-signer.jar>",
    ],
    "apksigner": [
        "apksigner + zipalign (from Android build-tools).",
        "  Same folder as aapt: <sdk>/build-tools/<version>/",
        "  Add it to PATH so 'apksigner' and 'zipalign' resolve.",
    ],
}


def hint(tool):
    lines = INSTALL_HINTS.get(tool)
    if not lines:
        return
    print(yel("  How to install:"))
    print("  " + bold(lines[0]))
    for ln in lines[1:]:
        print(dim("  " + ln))


def need(tool, human=None):
    """Print a friendly 'missing tool' block and exit."""
    erro((human or tool) + " is required for this command but wasn't found.")
    hint(tool)
    sys.exit(1)


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #
def load_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        return True
    except Exception as e:
        warn("Couldn't save config: " + str(e))
        return False


CONFIG = load_config()


# --------------------------------------------------------------------------- #
# process helpers
# --------------------------------------------------------------------------- #
def have(tool):
    return shutil.which(tool)


def _quote(a):
    return ('"' + a + '"') if (" " in a or "\\" in a) else a


def _su(serial, command):
    """adb argv to run `command` as root via su -c, correctly quoted as ONE token.
    (command must not contain a single quote.)"""
    return ["adb", "-s", serial, "shell", "su -c '" + command + "'"]


def run_live(cmd, env=None, cwd=None):
    print(dim("  $ " + " ".join(_quote(a) for a in cmd)))
    try:
        return subprocess.run(cmd, env=env, cwd=cwd).returncode
    except FileNotFoundError:
        erro("Not found: " + cmd[0])
        return 127
    except KeyboardInterrupt:
        print("\n" + yel("  interrupted."))
        return 130


def adb(args, serial=None, check=False):
    cmd = ["adb"] + (["-s", serial] if serial else []) + args
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    except FileNotFoundError:
        need("adb")
    if check and p.returncode != 0:
        warn("adb " + " ".join(args) + " -> " + (p.stderr or "").strip())
    return p.returncode, (p.stdout or ""), (p.stderr or "")


# --------------------------------------------------------------------------- #
# device / package discovery
# --------------------------------------------------------------------------- #
def list_devices():
    _, out, _ = adb(["devices"])
    devs = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if line and "\t" in line and line.split("\t", 1)[1].strip() == "device":
            devs.append(line.split("\t", 1)[0].strip())
    return devs


def prop(serial, name):
    _, out, _ = adb(["shell", "getprop", name], serial=serial)
    return out.strip()


def device_abi(serial):
    return prop(serial, "ro.product.cpu.abi") or "arm64-v8a"


def resolve_serial(args, interactive=True):
    if getattr(args, "serial", None):
        return args.serial
    devs = list_devices()
    if not devs:
        die("No device found. Start the emulator / plug in the phone (`adb devices`).")
    if len(devs) == 1:
        return devs[0]
    print("Multiple devices connected:")
    for i, d in enumerate(devs, 1):
        print("  " + str(i) + ". " + d + "  (" + (prop(d, "ro.product.model") or "?") + ")")
    if not interactive:
        die("Several devices attached - pass -s <serial>.")
    while True:
        try:
            c = input("Use which device?  # ").strip()
        except EOFError:
            die("Several devices attached - pass -s <serial>.")
        if c.isdigit() and 1 <= int(c) <= len(devs):
            return devs[int(c) - 1]
        print("  Enter a number from the list.")


def list_all_packages(serial):
    _, out, _ = adb(["shell", "pm", "list", "packages"], serial=serial)
    return {l.strip()[len("package:"):].strip()
            for l in out.splitlines() if l.strip().startswith("package:")}


def list_third_party(serial):
    _, out, _ = adb(["shell", "pm", "list", "packages", "-3"], serial=serial)
    return {l.strip()[len("package:"):].strip()
            for l in out.splitlines() if l.strip().startswith("package:")}


def list_by_apk_location(serial):
    _, out, _ = adb(["shell", "pm", "list", "packages", "-f"], serial=serial)
    pkgs = set()
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("package:") or "=" not in line:
            continue
        body = line[len("package:"):].strip()
        path, _, name = body.rpartition("=")
        if name and path.startswith(USER_APK_PREFIXES):
            pkgs.add(name.strip())
    return pkgs


def is_vendor(pkg):
    return pkg.startswith(VENDOR_PREFIXES)


def discover_packages(serial, include_system=False, include_vendor=False):
    if include_system:
        pkgs = list_all_packages(serial)
    else:
        pkgs = list_third_party(serial) | list_by_apk_location(serial)
        if not pkgs:
            warn("Couldn't identify user apps - falling back to the full list.")
            pkgs = list_all_packages(serial)
    if not include_vendor:
        kept = {p for p in pkgs if not is_vendor(p)}
        hidden = len(pkgs) - len(kept)
        if hidden:
            info("Hiding " + str(hidden) + " Google/Samsung package(s) (--vendor to show).")
        pkgs = kept
    return sorted(pkgs)


def choose_package(serial):
    """Interactive: filter -> numbered list -> pick. Retries if nothing matches."""
    pkgs = discover_packages(serial)
    if not pkgs:
        warn("No user packages found on the device.")
        return None
    while True:
        kw = input("  Filter by keyword (Enter = all, q = cancel): ").strip().lower()
        if kw == "q":
            return None
        shown = [p for p in pkgs if kw in p.lower()] if kw else pkgs
        if not shown:
            print("  nothing matched '" + kw + "' - try again.")
            continue
        for i, p in enumerate(shown, 1):
            print("  " + str(i).rjust(3) + ". " + p)
        sel = input("  Pick # (Enter = filter again): ").strip()
        if not sel:
            continue
        if sel.isdigit() and 1 <= int(sel) <= len(shown):
            return shown[int(sel) - 1]
        if sel in pkgs:
            return sel
        print("  invalid choice - try again.")


def apk_paths(serial, pkg):
    _, out, _ = adb(["shell", "pm", "path", pkg], serial=serial)
    return [l.strip()[len("package:"):].strip()
            for l in out.splitlines() if l.strip().startswith("package:")]


def parse_selection(text, count):
    text = text.strip().lower()
    if text in ("all", "*"):
        return list(range(count))
    chosen = set()
    for part in text.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            if a.isdigit() and b.isdigit():
                for n in range(int(a), int(b) + 1):
                    if 1 <= n <= count:
                        chosen.add(n - 1)
        elif part.isdigit() and 1 <= int(part) <= count:
            chosen.add(int(part) - 1)
    return sorted(chosen)


# --------------------------------------------------------------------------- #
# tool path resolution
# --------------------------------------------------------------------------- #
def resolve_apkeditor(explicit=None):
    for cand in [explicit, os.environ.get("APKEDITOR_JAR"), CONFIG.get("apkeditor")]:
        if cand and os.path.isfile(cand):
            return cand
    for cand in APKEDITOR_GUESSES:
        if os.path.isfile(cand):
            return cand
    return None


def resolve_apkmitm():
    direct = have("apk-mitm")
    if direct:
        return [direct]
    if have("npx"):
        return ["npx", "--yes", "apk-mitm"]
    return None


def resolve_aapt():
    for t in ("aapt2", "aapt"):
        p = have(t)
        if p:
            return p
    c = CONFIG.get("aapt")
    return c if (c and os.path.isfile(c)) else None


def resolve_uber():
    c = CONFIG.get("uber")
    return c if (c and os.path.isfile(c)) else None


BLUTTER_GUESSES = [
    os.path.join(os.getcwd(), "blutter", "blutter.py"),
    os.path.join(HOME, "blutter", "blutter.py"),
    os.path.join("C:\\", "tools", "blutter", "blutter.py"),
]


def resolve_blutter():
    for cand in [os.environ.get("BLUTTER_PY"), CONFIG.get("blutter")]:
        if cand and os.path.isfile(cand):
            return cand
    for g in BLUTTER_GUESSES:
        if os.path.isfile(g):
            return g
    return None


# --------------------------------------------------------------------------- #
# commands: device side
# --------------------------------------------------------------------------- #
def cmd_devices(args):
    devs = list_devices()
    hdr("Devices")
    if not devs:
        warn("None attached.")
        hint("adb")
        return
    for d in devs:
        model = prop(d, "ro.product.model") or "?"
        rel = prop(d, "ro.build.version.release") or "?"
        sdk = prop(d, "ro.build.version.sdk") or "?"
        abi = prop(d, "ro.product.cpu.abi") or "?"
        print("  " + bold(d) + dim("  " + model + "  Android " + rel +
                                   " (sdk " + sdk + ", " + abi + ")"))


def cmd_list(args):
    serial = resolve_serial(args)
    pkgs = discover_packages(serial, args.system, args.vendor or args.system)
    if args.grep:
        kw = args.grep.lower()
        pkgs = [p for p in pkgs if kw in p.lower()]
    hdr("Packages on " + serial + " (" + str(len(pkgs)) + ")")
    for i, p in enumerate(pkgs, 1):
        print("  " + dim(str(i).rjust(3) + ".") + " " + p)


def _pull_one(serial, pkg, out_dir):
    print("\n" + bold("=== " + pkg + " ==="))
    remote = apk_paths(serial, pkg)
    if not remote:
        warn("No APK paths returned; skipping.")
        return None
    info(str(len(remote)) + " APK(s): " + ", ".join(os.path.basename(p) for p in remote))
    dest = os.path.join(out_dir, pkg)
    os.makedirs(dest, exist_ok=True)
    for rpath in remote:
        fname = os.path.basename(rpath)
        info("pulling " + fname + " ...")
        rc, _, e = adb(["pull", rpath, os.path.join(dest, fname)], serial=serial)
        if rc != 0:
            erro("pull failed: " + e.strip())
            return None
    ok("saved to " + dest)
    return dest


def cmd_pull(args):
    serial = resolve_serial(args)
    out_dir = args.out or pull_dir()
    if args.packages:
        results = [_pull_one(serial, p, out_dir) for p in args.packages]
        _print_pull_footer([r for r in results if r])
        return
    pkgs = discover_packages(serial, args.system, args.vendor or args.system)
    if not pkgs:
        die("No packages found. (Try --vendor, or --system.)")
    kw = input("Filter by keyword (Enter for full list): ").strip().lower()
    if kw:
        pkgs = [p for p in pkgs if kw in p.lower()]
        if not pkgs:
            die("Nothing matched '" + kw + "'.")
    hdr("Apps on " + serial + " (" + str(len(pkgs)) + ")")
    for i, p in enumerate(pkgs, 1):
        print("  " + dim(str(i).rjust(3) + ".") + " " + p)
    print("\nPick: numbers like " + bold("1,3,5") + "  a range " + bold("4-8") + "  or " + bold("all") + ".")
    sel = parse_selection(input("Selection: "), len(pkgs))
    if not sel:
        die("Nothing selected.")
    results = [_pull_one(serial, pkgs[i], out_dir) for i in sel]
    _print_pull_footer([r for r in results if r])


def _print_pull_footer(dests):
    if not dests:
        return
    hdr("Done")
    for d in dests:
        print("  " + d)
    print(dim("\n  Next: ") + "apkkit merge " + _quote(dests[0]) + " -o merged.apk")


def cmd_uninstall(args):
    serial = resolve_serial(args)
    hdr("Uninstall " + args.package)
    rc = run_live(["adb", "-s", serial, "uninstall", args.package])
    (ok if rc == 0 else warn)("adb uninstall exited " + str(rc))


def cmd_install(args):
    serial = resolve_serial(args)
    target = args.target
    hdr("Install onto " + serial)
    if os.path.isdir(target):
        apks = sorted(glob.glob(os.path.join(target, "*.apk")))
        if not apks:
            die("No .apk files in " + target)
        info("install-multiple with " + str(len(apks)) + " split(s)")
        cmd = ["adb", "-s", serial, "install-multiple", "-r"]
        if args.grant:
            cmd.append("-g")
        cmd += apks
    else:
        if not os.path.isfile(target):
            die("Not found: " + target)
        cmd = ["adb", "-s", serial, "install", "-r"]
        if args.grant:
            cmd.append("-g")
        cmd.append(target)
    rc = run_live(cmd)
    (ok if rc == 0 else erro)("install exited " + str(rc))


# --------------------------------------------------------------------------- #
# commands: build / transform
# --------------------------------------------------------------------------- #
def _der_from_cert(path):
    """Return the DER bytes of a certificate given a PEM or DER file."""
    import base64
    with open(path, "rb") as f:
        data = f.read()
    if b"-----BEGIN" in data:
        m = re.search(rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", data, re.S)
        if not m:
            raise ValueError("no PEM certificate found")
        return base64.b64decode(b"".join(m.group(1).split()))
    return data


def _subject_hash_old(der):
    """OpenSSL X509_NAME_hash_old of the subject: md5(subject DER), 4 bytes LE, hex."""
    def rd(b, i):
        j = i + 1
        l = b[j]; j += 1
        if l & 0x80:
            n = l & 0x7F; l = int.from_bytes(b[j:j + n], "big"); j += n
        return j, l
    vs, _ = rd(der, 0)              # outer cert SEQUENCE -> value start
    ts, _ = rd(der, vs)            # tbsCertificate SEQUENCE -> value start
    i = ts
    if der[i] == 0xA0:             # optional [0] version
        vv, vl = rd(der, i); i = vv + vl
    for _ in range(4):            # serialNumber, signature, issuer, validity
        vv, vl = rd(der, i); i = vv + vl
    start = i                      # subject Name SEQUENCE (full TLV)
    vv, vl = rd(der, i); end = vv + vl
    import hashlib
    h = hashlib.md5(der[start:end]).digest()
    return "%08x" % int.from_bytes(h[:4], "little")


def cmd_cert(args):
    """Install a Burp/Fiddler CA into the device's SYSTEM trust store (rooted)."""
    import base64
    if not have("adb"):
        need("adb")
    serial = resolve_serial(args)
    cert = args.cert
    if not cert or not os.path.isfile(cert):
        die("Give the exported CA file: apkkit cert <burp-cacert.der | fiddler.cer | ca.pem>")
    try:
        der = _der_from_cert(cert)
        h = _subject_hash_old(der)
    except Exception as e:
        die("Couldn't parse the certificate: " + str(e))

    name = h + ".0"
    pem = ("-----BEGIN CERTIFICATE-----\n" +
           base64.encodebytes(der).decode().strip() +
           "\n-----END CERTIFICATE-----\n")
    local = os.path.join(CACHE_DIR, name)
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(local, "w") as f:
        f.write(pem)

    api = 0
    try:
        api = int(prop(serial, "ro.build.version.sdk") or "0")
    except ValueError:
        pass
    hdr("Install CA -> system store  (" + name + ", sdk " + str(api) + ")")
    dev_tmp = "/data/local/tmp/" + name
    if run_live(["adb", "-s", serial, "push", local, dev_tmp]) != 0:
        return erro("push failed.")

    store = "/system/etc/security/cacerts"
    if api >= 34:
        warn("Android 14+ keeps CA certs in an APEX - a plain copy may not stick.")
        info("trying the tmpfs overlay method ...")
        script = (
            "set -e; d=" + store + "; "
            "mkdir -p -m 700 /data/local/tmp/cacopy; "
            "cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/cacopy/ 2>/dev/null || true; "
            "mount -t tmpfs tmpfs $d; "
            "cp /data/local/tmp/cacopy/* $d/ 2>/dev/null || true; "
            "cp " + dev_tmp + " $d/" + name + "; "
            "chown 0:0 $d/*; chmod 644 $d/*; "
            "chcon u:object_r:system_security_cacerts_file:s0 $d/* 2>/dev/null || true; "
            "echo OK")
    else:
        script = (
            "set -e; "
            "mount -o rw,remount / 2>/dev/null || mount -o rw,remount /system; "
            "cp " + dev_tmp + " " + store + "/" + name + "; "
            "chown 0:0 " + store + "/" + name + "; chmod 644 " + store + "/" + name + "; "
            "chcon u:object_r:system_security_cacerts_file:s0 " + store + "/" + name + " 2>/dev/null || true; "
            "echo OK")

    rc = run_live(_su(serial, script))
    if rc == 0:
        ok("installed as " + store + "/" + name)
        print(dim("  Reboot the emulator (or the app) so the store is re-read: apkkit ... adb reboot"))
        if api >= 34:
            print(dim("  If apps still reject it, use the Magisk module route (AlwaysTrustUserCerts)."))
    else:
        erro("system install failed (device not rooted? su denied?).")
        print(dim("  Fallback (no root, user store): apkkit cert " + _quote(cert) + " --user"))

    if args.user:
        info("also pushing to /sdcard for manual user-store install ...")
        run_live(["adb", "-s", serial, "push", local, "/sdcard/" + name + ".crt"])
        print(dim("  On device: Settings > Security > Install a certificate > CA cert > pick /sdcard/" + name + ".crt"))

    if args.reboot:
        info("rebooting device so the trust store is re-read ...")
        run_live(["adb", "-s", serial, "reboot"])
        run_live(["adb", "-s", serial, "wait-for-device"])
        ok("device back up.")


def cmd_proxy(args):
    """Point the device's traffic at your Burp/Fiddler proxy (and optionally
    force it with iptables for apps that ignore the proxy, e.g. Flutter)."""
    if not have("adb"):
        need("adb")
    serial = resolve_serial(args)
    target = (args.target or "").strip()

    if target in ("off", "clear", "reset"):
        hdr("Clearing proxy on " + serial)
        run_live(["adb", "-s", serial, "shell", "settings", "put", "global", "http_proxy", ":0"])
        info("flushing iptables nat OUTPUT (rooted) ...")
        run_live(_su(serial, "iptables -t nat -F OUTPUT"))
        ok("global proxy cleared; transparent redirect removed (if it was set).")
        print(dim("  (restart the target app so it drops the old proxy.)"))
        return

    if target in ("status", ""):
        if target == "":
            info("no argument - showing status. Use: apkkit proxy <ip:port> | off | status")
        hdr("Proxy status on " + serial)
        _, out, _ = adb(["shell", "settings", "get", "global", "http_proxy"], serial=serial)
        print("  global http_proxy: " + bold(out.strip() or "(unset)"))
        rc, out, _ = adb(["shell", "su -c 'iptables -t nat -S OUTPUT'"], serial=serial)
        if rc == 0 and out.strip():
            print(dim("  nat OUTPUT rules:"))
            for line in out.splitlines():
                if "DNAT" in line:
                    print("    " + line.strip())
        else:
            print(dim("  iptables: not readable (device not rooted, or none set)"))
        return

    if ":" not in target:
        target = "10.0.2.2:" + target
        info("no host given - assuming the emulator host 10.0.2.2")
    port = target.rpartition(":")[2]

    hdr("Set proxy -> " + target + "  on " + serial)
    run_live(["adb", "-s", serial, "shell", "settings", "put", "global", "http_proxy", target])
    ok("global http_proxy = " + target)
    print(dim("  restart the app so it picks up the new proxy."))

    if args.transparent:
        info("adding iptables DNAT for 80/443 -> " + target + " (needs root) ...")
        ok_all = True
        for dport in ("80", "443"):
            rc = run_live(_su(serial,
                           "iptables -t nat -A OUTPUT -p tcp --dport " + dport +
                           " -j DNAT --to-destination " + target))
            ok_all = ok_all and rc == 0
        if ok_all:
            ok("transparent redirect added for ports 80 and 443.")
            print(dim("  Enable your proxy's INVISIBLE/transparent listener on port " + port + ":"))
            print(dim("    Burp: Proxy settings > listener > Request handling > Support invisible proxying"))
            print(dim("    Fiddler: accepts non-proxy connections once 'Allow remote computers to connect' is on"))
        else:
            warn("iptables failed - is the device rooted (su available)?")

    print(dim("\n  Cert: install your Burp/Fiddler CA on the device. Rooted -> put it in the"))
    print(dim("  SYSTEM store so apps that ignore user certs still trust it. Undo: apkkit proxy off"))


def cmd_merge(args):
    jar = resolve_apkeditor(args.apkeditor)
    if not jar:
        need("apkeditor", "APKEditor.jar")
    if not have("java"):
        need("java")
    src = args.input
    if not os.path.exists(src):
        die("Input not found: " + src)
    out = args.out or (_base(src) + "-merged.apk")
    hdr("Merge -> " + out)
    cmd = ["java", "-jar", jar, "m", "-i", src, "-o", out]
    if args.force:
        cmd.append("-f")
    rc = run_live(cmd)
    if rc == 0 and os.path.isfile(out):
        ok("merged: " + out + dim("  (" + _human(os.path.getsize(out)) + ")"))
        print(dim("  Next: ") + "apkkit patch " + _quote(out) + dim("   (or) ") +
              "apkkit gadget " + _quote(out))
    else:
        erro("merge failed (exit " + str(rc) + ")")


def cmd_patch(args):
    runner = resolve_apkmitm()
    if not runner:
        need("apk-mitm")
    apk = args.apk
    if not os.path.isfile(apk):
        die("Not found: " + apk)
    hdr("Patch (strip cert pinning) " + apk)
    rc = run_live(runner + [apk])
    patched = _base(apk) + "-patched.apk"
    if rc == 0 and os.path.isfile(patched):
        ok("patched: " + patched)
        print(dim("  Next: ") + "apkkit install " + _quote(patched))
    elif rc == 0:
        ok("apk-mitm finished (look for *-patched.apk beside the input).")
    else:
        erro("apk-mitm exited " + str(rc))


def cmd_decode(args):
    if not have("apktool"):
        need("apktool")
    apk = args.apk
    if not os.path.isfile(apk):
        die("Not found: " + apk)
    out = args.out or (_base(apk) + ".decoded")
    hdr("apktool decode -> " + out)
    cmd = ["apktool", "d", apk, "-o", out, "-f"]
    if args.no_res:
        cmd.append("-r")
    if args.no_src:
        cmd.append("-s")
    rc = run_live(cmd)
    (ok if rc == 0 else erro)("apktool exited " + str(rc))


def cmd_decompile(args):
    if not have("jadx"):
        need("jadx")
    apk = args.apk
    if not os.path.isfile(apk):
        die("Not found: " + apk)
    out = args.out or (_base(apk) + ".jadx")
    hdr("jadx decompile -> " + out)
    rc = run_live(["jadx", "-d", out, apk])
    (ok if rc == 0 else warn)("jadx exited " + str(rc) + dim("  (partial output is normal)"))


# --------------------------------------------------------------------------- #
# commands: dynamic instrumentation (Frida / objection)  -- unrooted-friendly
# --------------------------------------------------------------------------- #
def cmd_gadget(args):
    """objection patchapk: inject the Frida gadget so an UNROOTED device can be
    instrumented. Produces <name>.objection.apk (already zipaligned + signed)."""
    if not have("objection"):
        need("objection")
    if not have("apktool"):
        warn("objection needs apktool on PATH to rebuild the apk.")
        hint("apktool")
    apk = args.apk
    if not os.path.isfile(apk):
        die("Not found: " + apk)

    arch = args.arch
    if arch == "auto":
        try:
            arch = device_abi(resolve_serial(args, interactive=False))
            info("device ABI detected: " + bold(arch))
        except SystemExit:
            arch = "arm64-v8a"
            warn("no device to detect ABI - defaulting gadget arch to " + arch)

    hdr("Inject Frida gadget (unrooted) -> " + apk)
    cmd = ["objection", "patchapk", "-s", apk, "-a", arch]
    if args.nsc:
        cmd.append("-N")   # add network_security_config that trusts user CAs (MITM)
        info("adding a network-security-config that trusts user-added CAs (MITM ready).")
    if args.gadget_version:
        cmd += ["-V", args.gadget_version]
    if args.startup_script:
        cmd += ["-c", args.startup_script]
    if args.skip_resources:
        cmd.append("--skip-resources")
    rc = run_live(cmd, cwd=os.path.dirname(os.path.abspath(apk)))
    out = _base(apk) + ".objection.apk"
    if os.path.isfile(out):
        ok("patched apk: " + out)
        install_target = out
        if args.sign:
            print()
            info("re-signing with uber-apk-signer (objection's own signing is flaky on Windows) ...")
            signed = _sign(out)
            if signed:
                install_target = signed
        else:
            print(dim("  If install fails with a certificate error, run: ") + "apkkit sign " + _quote(out))
        print(dim("\n  The app PAUSES on launch until you attach Frida.\n  Next:"))
        print("    apkkit install " + _quote(install_target))
        print("    apkkit hook Gadget --gadget --builtin ssl")
        print("    apkkit objection -g Gadget --sslpinning")
    else:
        erro("objection patchapk exited " + str(rc) + " - no output apk.")
        print(dim("  Common fixes: ensure apktool + a JDK are on PATH; try --skip-resources."))


def cmd_frida_ps(args):
    if not have("frida-ps"):
        need("python-frida", "frida-ps")
    serial = resolve_serial(args)
    hdr("Apps / processes on " + serial)
    mode = "-ai" if args.apps else "-a"
    if args.all:
        mode = ""
    run_live(["frida-ps", "-D", serial] + ([mode] if mode else []))


def cmd_hook(args):
    if not have("frida"):
        need("python-frida", "frida")
    # collect one or more scripts: built-ins first, then explicit -l paths
    scripts = []
    for b in (args.builtin or []):
        scripts.append(_ensure_builtin_script(b))
    for s in (args.script or []):
        scripts.append(s)
    scripts = [s for s in scripts if s]
    missing = [s for s in scripts if not os.path.isfile(s)]
    if missing:
        die("Script not found: " + ", ".join(missing))
    if not scripts:
        die("No script to run. Pass -l <script.js> (repeatable) or --builtin ssl|root|...")

    target = args.target
    serial = resolve_serial(args)
    hdr("Frida hook: " + target + ("  (" + str(len(scripts)) + " scripts)" if len(scripts) > 1 else ""))
    lflags = []
    for s in scripts:
        lflags += ["-l", s]
    base = ["frida", "-D", serial]
    if args.gadget:
        cmd = base + [target] + lflags
        info("attaching to gadget process '" + target + "'")
    elif args.attach:
        cmd = base + ["-n", target] + lflags
        info("attaching to running process by name")
    else:
        cmd = base + ["-f", target] + lflags
        info("spawning package and injecting at startup")
        info("(Frida 17 auto-resumes; if it sits at the prompt, type %resume)")
    for s in scripts:
        info("script: " + s)
    print(dim("  (Ctrl+C / 'exit' to detach)\n"))
    run_live(cmd)


def cmd_objection(args):
    if not have("objection"):
        need("objection")
    target = args.gadget or args.package
    if not target:
        die("Pass -g <gadget-name> (unrooted) or -p <package> (rooted frida-server).")
    serial = resolve_serial(args)
    hdr("objection explore: " + target)
    cmd = ["objection", "-S", serial, "-g", target, "explore"]
    startups = []
    if args.sslpinning:
        startups.append("android sslpinning disable")
    if args.root:
        startups.append("android root disable")
    if args.startup_command:
        startups.append(args.startup_command)
    for s in startups:
        cmd += ["--startup-command", s]
    if startups:
        info("startup: " + "; ".join(startups))
    print(dim("  Inside objection try: android hooking list classes | memory search | help\n"))
    run_live(cmd)


def _frida_version():
    if not have("frida"):
        return None
    p = subprocess.run(["frida", "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace")
    return (p.stdout or "").strip() or None


def _download(url, dest):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "apkkit"})
    with urllib.request.urlopen(req, timeout=90) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)
    return dest


def cmd_frida_server(args):
    """ROOTED-device helper: download the matching frida-server, push it, run it."""
    if not have("adb"):
        need("adb")
    serial = resolve_serial(args)
    import random
    devname = "frida-server"
    port = args.port
    if args.stealth:
        devname = "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(8))
        port = port or random.randint(20000, 60000)
        info("stealth: binary '" + devname + "', port " + str(port))
    dev_path = "/data/local/tmp/" + devname

    if args.stop:
        hdr("Stopping frida-server on " + serial)
        run_live(_su(serial, "pkill -f frida-server; pkill -f /data/local/tmp/" + devname))
        ok("stop signal sent.")
        return

    abi = device_abi(serial)
    farch = {"arm64-v8a": "arm64", "armeabi-v7a": "arm",
             "x86_64": "x86_64", "x86": "x86"}.get(abi, "arm64")
    ver = args.version or _frida_version()
    if not ver:
        need("python-frida", "frida")

    hdr("frida-server " + ver + "  (" + abi + " -> " + farch + ")")
    warn("ROOTED devices only - this runs frida-server as root. Unrooted? use `gadget`.")

    name = "frida-server-" + ver + "-android-" + farch
    cached = os.path.join(CACHE_DIR, name)
    if os.path.isfile(cached):
        info("using cached binary: " + cached)
    else:
        url = ("https://github.com/frida/frida/releases/download/" + ver + "/" + name + ".xz")
        info("downloading " + url)
        xz = cached + ".xz"
        try:
            _download(url, xz)
        except Exception as e:
            erro("download failed: " + str(e))
            print(dim("  Get it manually from https://github.com/frida/frida/releases,"))
            print(dim("  decompress the .xz, and save the binary as: " + cached))
            return
        info("decompressing ...")
        try:
            with lzma.open(xz) as fin, open(cached, "wb") as fout:
                shutil.copyfileobj(fin, fout)
            os.remove(xz)
        except Exception as e:
            return erro("decompress failed: " + str(e))
        ok("cached: " + cached)

    info("pushing to " + dev_path + " ...")
    if run_live(["adb", "-s", serial, "push", cached, dev_path]) != 0:
        return erro("push failed.")
    run_live(_su(serial, "chmod 755 " + dev_path))

    if args.no_start:
        ok("installed (not started). Start later with: apkkit frida-server")
        return

    listen = (" -l 0.0.0.0:" + str(port)) if port else ""
    info("starting frida-server as root (background) ...")
    try:
        subprocess.Popen(_su(serial, "nohup " + dev_path + listen + " >/dev/null 2>&1 &"))
    except Exception as e:
        return erro("failed to launch: " + str(e))
    time.sleep(2)
    if port:
        run_live(["adb", "-s", serial, "forward", "tcp:" + str(port), "tcp:" + str(port)])
        info("verifying with frida-ps -H 127.0.0.1:" + str(port) + " ...")
        rc = run_live(["frida-ps", "-H", "127.0.0.1:" + str(port)])
        if rc == 0:
            ok("up on port " + str(port) + ". Attach with: frida -H 127.0.0.1:" + str(port) + " -f <pkg> -l <script>")
        else:
            warn("couldn't confirm - check: adb shell su -c \"ps -A | grep " + devname + "\"")
    else:
        info("verifying with frida-ps -D " + serial + " ...")
        rc = run_live(["frida-ps", "-D", serial])
        if rc == 0:
            ok("frida-server is up. Attach: apkkit hook <pkg> -l <script.js>")
        else:
            warn("couldn't confirm - check: adb shell su -c \"ps -A | grep frida\"")


def _sign(apk, keystore=None):
    """Sign an apk and return the PATH of the produced signed apk, or None.
    Works with uber-apk-signer (preferred) or apksigner+zipalign - callers must
    use the returned path, not guess the filename."""
    if not os.path.isfile(apk):
        erro("Not found: " + apk)
        return None
    uber = resolve_uber()
    if uber and have("java"):
        info("signing with uber-apk-signer ...")
        rc = run_live(["java", "-jar", uber, "-a", apk, "--allowResign"])
        cands = glob.glob(_base(apk) + "-aligned*Signed.apk")
        if rc == 0 and cands:
            return sorted(cands)[0]
        erro("uber-apk-signer exited " + str(rc))
        return None
    if have("apksigner") and have("zipalign"):
        aligned = _base(apk) + "-aligned.apk"
        info("zipalign -> " + aligned)
        if run_live(["zipalign", "-f", "-p", "4", apk, aligned]) != 0:
            erro("zipalign failed")
            return None
        ks = keystore or os.path.join(HOME, ".apkkit", "debug.keystore")
        if not os.path.isfile(ks):
            os.makedirs(os.path.dirname(ks), exist_ok=True)
            info("creating a debug keystore at " + ks)
            run_live(["keytool", "-genkey", "-v", "-keystore", ks, "-alias", "apkkit",
                      "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
                      "-storepass", "apkkit", "-keypass", "apkkit",
                      "-dname", "CN=apkkit"])
        rc = run_live(["apksigner", "sign", "--ks", ks, "--ks-pass", "pass:apkkit",
                       "--key-pass", "pass:apkkit", aligned])
        if rc == 0 and os.path.isfile(aligned):
            return aligned
        erro("apksigner exited " + str(rc))
        return None
    erro("No signer found.")
    hint("uber-apk-signer")
    hint("apksigner")
    return None


def cmd_sign(args):
    apk = args.apk
    if not os.path.isfile(apk):
        die("Not found: " + apk)
    hdr("Sign " + apk)
    out = _sign(apk, args.keystore)
    if out:
        ok("signed: " + out)
    return out


def cmd_scripts(args):
    out = args.out or SCRIPTS_DIR
    os.makedirs(out, exist_ok=True)
    hdr("Frida hook scripts -> " + out)
    for name, body in BUILTIN_SCRIPTS.items():
        path = os.path.join(out, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(body)
        ok(name + dim("  (" + BUILTIN_DESC.get(name, "") + ")"))
    print(dim("\n  Run one with: ") + "apkkit hook <pkg> -l " + _quote(os.path.join(out, "ssl-bypass.js")))
    print(dim("  Or shortcut:  ") + "apkkit hook <pkg> --builtin ssl")


def _ensure_builtin_script(kind):
    if kind == "flutter-ssl":
        for cand in (os.path.join(SCRIPTS_DIR, "disable-flutter-tls.js"),
                     os.path.join(os.getcwd(), "disable-flutter-tls.js")):
            if os.path.isfile(cand):
                return cand
        erro("Flutter TLS-bypass script not found (it's a maintained community script, not bundled).")
        print(dim("  Flutter uses BoringSSL - the normal 'ssl' script won't work. Instead:"))
        print("   1) Download " + bold("disable-flutter-tls.js") + " from")
        print("      https://github.com/NVISOsecurity/disable-flutter-tls-verification")
        print("   2) Save it to: " + SCRIPTS_DIR)
        print("   3) Re-run:  apkkit hook Gadget --gadget --builtin flutter-ssl")
        sys.exit(1)
    fname = {"ssl": "ssl-bypass.js", "root": "root-bypass.js", "trace": "trace.js",
             "webview": "webview.js", "sqlite": "sqlite.js", "crypto": "crypto.js"}.get(kind)
    if not fname:
        die("Unknown built-in '" + kind + "'. Choose: ssl|root|trace|flutter-ssl|webview|sqlite|crypto.")
    os.makedirs(SCRIPTS_DIR, exist_ok=True)
    path = os.path.join(SCRIPTS_DIR, fname)
    if not os.path.isfile(path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(BUILTIN_SCRIPTS[fname])
    return path


# --------------------------------------------------------------------------- #
# bundled Frida scripts
# --------------------------------------------------------------------------- #
SSL_BYPASS_JS = r"""/*
 * apkkit :: universal-ish Android SSL/TLS pinning bypass
 * Run:  frida -U -f <pkg> -l ssl-bypass.js   (or via: apkkit hook <pkg> --builtin ssl)
 *   or (gadget):  frida -U Gadget -l ssl-bypass.js
 */
setTimeout(function () {
  Java.perform(function () {
    var log = function (m) { console.log('[ssl] ' + m); };

    // 1) Default SSLContext TrustManager -> trust everything
    try {
      var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
      var SSLContext = Java.use('javax.net.ssl.SSLContext');
      var TrustAll = Java.registerClass({
        name: 'com.apkkit.TrustAll',
        implements: [X509TrustManager],
        methods: {
          checkClientTrusted: function (chain, authType) {},
          checkServerTrusted: function (chain, authType) {},
          getAcceptedIssuers: function () { return []; }
        }
      });
      var tms = [TrustAll.$new()];
      var init = SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom');
      init.implementation = function (km, tm, sr) { init.call(this, km, tms, sr); };
      log('SSLContext.init hooked');
    } catch (e) { log('SSLContext: ' + e); }

    // 2) OkHttp3 CertificatePinner.check
    ['okhttp3.CertificatePinner'].forEach(function (cn) {
      try {
        var CP = Java.use(cn);
        ['check', 'check$okhttp'].forEach(function (m) {
          if (CP[m]) {
            CP[m].overloads.forEach(function (ov) {
              ov.implementation = function () { return; };
            });
          }
        });
        log(cn + '.check neutralised');
      } catch (e) {}
    });

    // 3) TrustManagerImpl (Conscrypt) - verifyChain / checkTrustedRecursive
    try {
      var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
      if (TMI.checkTrustedRecursive) {
        TMI.checkTrustedRecursive.implementation = function () {
          return Java.use('java.util.ArrayList').$new();
        };
      }
      if (TMI.verifyChain) {
        TMI.verifyChain.implementation = function (certs) { return certs; };
      }
      log('Conscrypt TrustManagerImpl hooked');
    } catch (e) {}

    // 4) HttpsURLConnection hostname verifier
    try {
      var HUC = Java.use('javax.net.ssl.HttpsURLConnection');
      HUC.setDefaultHostnameVerifier.implementation = function () { return; };
      HUC.setHostnameVerifier.implementation = function () { return; };
      log('HttpsURLConnection verifiers disabled');
    } catch (e) {}

    // 5) TrustKit / Appmattus / WebViewClient common pins
    ['com.datatheorem.android.trustkit.pinning.OkHostnameVerifier',
     'com.android.org.conscrypt.Platform'].forEach(function (cn) {
      try {
        var C = Java.use(cn);
        if (C.checkServerTrusted) {
          C.checkServerTrusted.overloads.forEach(function (ov) {
            ov.implementation = function () { return; };
          });
          log(cn + ' checkServerTrusted disabled');
        }
      } catch (e) {}
    });

    log('bypass installed.');
  });
}, 0);
"""

ROOT_BYPASS_JS = r"""/*
 * apkkit :: common Android root-detection bypass
 * Run:  frida -U -f <pkg> -l root-bypass.js   (or via: apkkit hook <pkg> --builtin root)
 */
setTimeout(function () {
  Java.perform(function () {
    var log = function (m) { console.log('[root] ' + m); };
    var badPaths = ['su', 'busybox', 'magisk', 'supersu', 'xposed', 'frida'];

    // File.exists() lies about su/magisk paths
    try {
      var F = Java.use('java.io.File');
      F.exists.implementation = function () {
        var p = this.getAbsolutePath().toLowerCase();
        for (var i = 0; i < badPaths.length; i++) {
          if (p.indexOf(badPaths[i]) >= 0) { log('hide ' + p); return false; }
        }
        return this.exists();
      };
    } catch (e) { log('File.exists: ' + e); }

    // Runtime.exec('su' / 'which su') -> throw
    try {
      var Rt = Java.use('java.lang.Runtime');
      Rt.exec.overload('java.lang.String').implementation = function (cmd) {
        if (cmd && cmd.toLowerCase().indexOf('su') >= 0) {
          log('block exec ' + cmd);
          throw Java.use('java.io.IOException').$new('not found');
        }
        return this.exec(cmd);
      };
    } catch (e) {}

    // RootBeer library -> everything false
    try {
      var RB = Java.use('com.scottyab.rootbeer.RootBeer');
      RB.isRooted.overloads.forEach(function (ov) {
        ov.implementation = function () { log('RootBeer.isRooted -> false'); return false; };
      });
    } catch (e) {}

    // Build tags "test-keys"
    try {
      var Build = Java.use('android.os.Build');
      Build.TAGS.value = 'release-keys';
    } catch (e) {}

    log('root-detection bypass installed.');
  });
}, 0);
"""

TRACE_JS = r"""/*
 * apkkit :: quick method tracer.
 * Set TARGET_CLASS / TARGET_METHOD below (or hook a whole class).
 * Run:  frida -U -f <pkg> -l trace.js   (or via: apkkit hook <pkg> --builtin trace)
 */
var TARGET_CLASS  = 'com.example.YourClass';   // <-- edit me
var TARGET_METHOD = null;                       // null = trace ALL methods

setTimeout(function () {
  Java.perform(function () {
    try {
      var C = Java.use(TARGET_CLASS);
      var methods = TARGET_METHOD
        ? [TARGET_METHOD]
        : C.class.getDeclaredMethods().map(function (m) { return m.getName(); });
      var uniq = {};
      methods.forEach(function (name) {
        if (uniq[name]) return; uniq[name] = 1;
        if (!C[name]) return;
        C[name].overloads.forEach(function (ov) {
          ov.implementation = function () {
            var args = [].slice.call(arguments);
            console.log('[trace] ' + TARGET_CLASS + '.' + name + '(' +
                        args.map(String).join(', ') + ')');
            var ret = ov.apply(this, arguments);
            console.log('[trace]   -> ' + ret);
            return ret;
          };
        });
      });
      console.log('[trace] hooked ' + TARGET_CLASS +
                  ' (' + Object.keys(uniq).length + ' methods)');
    } catch (e) { console.log('[trace] ' + e); }
  });
}, 0);
"""

WEBVIEW_JS = r"""/* apkkit :: WebView inspector - logs URLs, JS bridges, enables debugging */
setTimeout(function () { Java.perform(function () {
  var WV = Java.use('android.webkit.WebView');
  try { WV.setWebContentsDebuggingEnabled(true);
        console.log('[wv] WebContents debugging enabled (chrome://inspect)'); } catch (e) {}
  ['loadUrl'].forEach(function (m) {
    WV[m].overloads.forEach(function (ov) {
      ov.implementation = function () {
        console.log('[wv] loadUrl: ' + arguments[0]); return ov.apply(this, arguments);
      };
    });
  });
  try {
    WV.addJavascriptInterface.implementation = function (obj, name) {
      console.log('[wv] addJavascriptInterface: ' + name + ' -> ' + obj.$className);
      return this.addJavascriptInterface(obj, name);
    };
  } catch (e) {}
  try {
    WV.evaluateJavascript.overload('java.lang.String', 'android.webkit.ValueCallback')
      .implementation = function (js, cb) {
        console.log('[wv] evaluateJavascript: ' + (js.length > 160 ? js.substr(0,160)+'...' : js));
        return this.evaluateJavascript(js, cb);
      };
  } catch (e) {}
  console.log('[wv] WebView hooks installed.');
}); }, 0);
"""

SQLITE_JS = r"""/* apkkit :: SQLite logger - dumps SQL statements + queries */
setTimeout(function () { Java.perform(function () {
  var DB = Java.use('android.database.sqlite.SQLiteDatabase');
  ['execSQL', 'rawQuery', 'query'].forEach(function (m) {
    if (!DB[m]) return;
    DB[m].overloads.forEach(function (ov) {
      ov.implementation = function () {
        var a = [].slice.call(arguments).map(String).join(' | ');
        console.log('[sql] ' + m + ': ' + (a.length > 300 ? a.substr(0,300)+'...' : a));
        return ov.apply(this, arguments);
      };
    });
  });
  console.log('[sql] SQLite hooks installed.');
}); }, 0);
"""

CRYPTO_JS = r"""/* apkkit :: crypto monitor - logs Cipher / Mac / MessageDigest input+output */
setTimeout(function () { Java.perform(function () {
  function b64(bytes) {
    try { return Java.use('android.util.Base64').encodeToString(bytes, 2); } catch (e) { return '<'+bytes.length+' bytes>'; }
  }
  try {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function (data) {
      var out = this.doFinal(data);
      console.log('[crypto] Cipher(' + this.getAlgorithm() + ')\n  in : ' + b64(data) + '\n  out: ' + b64(out));
      return out;
    };
  } catch (e) {}
  try {
    var MD = Java.use('java.security.MessageDigest');
    MD.digest.overload('[B').implementation = function (data) {
      var out = this.digest(data);
      console.log('[crypto] ' + this.getAlgorithm() + '(' + b64(data) + ') = ' + b64(out));
      return out;
    };
  } catch (e) {}
  console.log('[crypto] crypto hooks installed.');
}); }, 0);
"""

BUILTIN_SCRIPTS = {
    "ssl-bypass.js": SSL_BYPASS_JS,
    "root-bypass.js": ROOT_BYPASS_JS,
    "trace.js": TRACE_JS,
    "webview.js": WEBVIEW_JS,
    "sqlite.js": SQLITE_JS,
    "crypto.js": CRYPTO_JS,
}
BUILTIN_DESC = {
    "ssl-bypass.js": "universal SSL/TLS pinning bypass",
    "root-bypass.js": "common root-detection bypass",
    "trace.js": "method call tracer (edit target)",
    "webview.js": "WebView URL / JS-bridge inspector",
    "sqlite.js": "SQLite query logger",
    "crypto.js": "Cipher / hash monitor",
}


# --------------------------------------------------------------------------- #
# commands: inspection (offline)
# --------------------------------------------------------------------------- #
def _open_apk(path):
    if not os.path.isfile(path):
        die("Not found: " + path)
    try:
        return zipfile.ZipFile(path, "r")
    except zipfile.BadZipFile:
        die("Not a valid APK/zip: " + path)


ABI_NOTE = {
    "arm64-v8a": "64-bit ARM (modern phones)",
    "armeabi-v7a": "32-bit ARM (older)",
    "x86": "32-bit Intel (emulators)",
    "x86_64": "64-bit Intel (emulators)",
}

FRAMEWORK_LIBS = [
    ("libflutter.so", "Flutter (Dart; logic in libapp.so, not smali)"),
    ("libapp.so", "Flutter app code (Dart AOT snapshot)"),
    ("libreactnativejni.so", "React Native (JS in index.android.bundle)"),
    ("libhermes.so", "React Native + Hermes bytecode"),
    ("libjsc.so", "React Native + JavaScriptCore"),
    ("libmonodroid.so", "Xamarin/.NET (assemblies under assemblies/)"),
    ("libunity.so", "Unity (IL2CPP -> libil2cpp.so / global-metadata.dat)"),
    ("libil2cpp.so", "Unity IL2CPP"),
    ("libcocos2d", "Cocos2d-x"),
    ("libcordova", "Cordova/PhoneGap (web assets under assets/www)"),
    ("libcrashlytics", "Firebase Crashlytics present"),
    ("libtersafe", "Tencent security / anti-tamper"),
    ("libDexHelper", "SecNeo/Bangcle packer (app is protected/packed)"),
    ("libjiagu", "360 Jiagu packer (packed)"),
    ("libshell", "possible packer/shell (packed)"),
]

WEBASSET_HINTS = [
    ("assets/index.android.bundle", "React Native JS bundle"),
    ("assets/www/", "Cordova/PhoneGap web app"),
    ("assets/flutter_assets/", "Flutter assets"),
    ("assets/bin/Data/", "Unity data"),
    ("assemblies/", "Xamarin .NET assemblies"),
    ("assets/global-metadata.dat", "Unity IL2CPP metadata (great for RE)"),
]


def _apk_members(path):
    """(name, size) pairs across a single apk OR every .apk in a folder."""
    if os.path.isdir(path):
        apks = sorted(glob.glob(os.path.join(path, "*.apk")))
        if not apks:
            die("No .apk files in " + path)
    elif os.path.isfile(path):
        apks = [path]
    else:
        die("Not found: " + path)
    out = []
    for apk in apks:
        try:
            z = zipfile.ZipFile(apk)
        except Exception:
            continue
        for zi in z.infolist():
            out.append((zi.filename, zi.file_size))
        z.close()
    return out, apks


def cmd_libs(args):
    members, apks = _apk_members(args.apk)
    names = [n for n, _ in members]
    label = os.path.basename(args.apk.rstrip("/\\"))
    if len(apks) > 1:
        label += "  (" + str(len(apks)) + " split APKs)"
    hdr("Native libraries: " + label)
    libs = {}
    for n, size in members:
        if n.startswith("lib/") and n.endswith(".so"):
            parts = n.split("/")
            if len(parts) >= 3:
                libs.setdefault(parts[1], {})[parts[-1]] = size
    if not libs:
        info("No native .so libraries (pure-Java/Kotlin app, or packed).")
    for abi in sorted(libs):
        note = ABI_NOTE.get(abi, "")
        print("\n  " + bold(abi) + (dim("  " + note) if note else ""))
        for name in sorted(libs[abi]):
            print("    " + name.ljust(34) + dim(_human(libs[abi][name])))
    dex = [(n, s) for n, s in members if n.endswith(".dex")]
    if dex:
        total = sum(s for _, s in dex)
        print("\n  " + bold("DEX") + dim("  " + str(len(dex)) + " file(s), " + _human(total) + " total"))
    all_so = {p.split("/")[-1] for p in names if p.endswith(".so")}
    hits = []
    for frag, desc in FRAMEWORK_LIBS:
        if any(frag in s for s in all_so):
            hits.append(desc)
    for prefix, desc in WEBASSET_HINTS:
        if any(n.startswith(prefix) or n == prefix.rstrip("/") for n in names):
            hits.append(desc)
    hdr("Framework / packer fingerprint")
    if hits:
        for h in _dedup_keep(hits):
            print("  " + yel("→ ") + h)
    else:
        print("  " + dim("Standard native Android app (Java/Kotlin + smali)."))
    is_flut = any("flutter" in h.lower() or "Dart" in h for h in hits)
    print("\n  " + bold("Verdict: ") + (mag("FLUTTER app") if is_flut else grn("native Java/Kotlin app")))
    if is_flut:
        print("  " + dim("• static:  ") + "apkkit blutter <apk/folder>   " + dim("(Dart names)"))
        print("  " + dim("• MITM:    ") + "apkkit reflutter <apk>        " + dim("(apk-mitm/gadget WON'T work on Flutter TLS)"))
    else:
        print("  " + dim("• decompile: ") + "apkkit decompile <apk>    " + dim("(jadx → Java)"))
        print("  " + dim("• MITM:      ") + "apkkit patch <apk>  or  apkkit gadget <apk> --nsc --sign")


def iter_ascii_strings(data, minlen=4):
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                yield cur.decode("ascii", "replace")
            cur = bytearray()
    if len(cur) >= minlen:
        yield cur.decode("ascii", "replace")


def iter_utf16le_strings(data, minlen=4):
    cur = []
    i, n = 0, len(data)
    while i + 1 < n:
        lo, hi = data[i], data[i + 1]
        if hi == 0 and 32 <= lo < 127:
            cur.append(chr(lo))
        else:
            if len(cur) >= minlen:
                yield "".join(cur)
            cur = []
        i += 2
    if len(cur) >= minlen:
        yield "".join(cur)


def _interesting_for_strings(name):
    if name.endswith("/"):
        return False
    low = name.lower()
    if low.endswith((".png", ".jpg", ".jpeg", ".webp", ".gif", ".ttf",
                     ".otf", ".mp3", ".mp4", ".ogg", ".woff", ".woff2")):
        return False
    return True


def cmd_strings(args):
    z = _open_apk(args.apk)
    minlen = args.min
    grep = args.grep.lower() if args.grep else None
    only = None
    if args.dex:
        only = lambda n: n.endswith(".dex")
    elif args.libs:
        only = lambda n: n.endswith(".so")
    hdr("Strings: " + os.path.basename(args.apk) +
        dim("  (min " + str(minlen) + ("" if not grep else ", grep '" + args.grep + "'") + ")"))
    seen, count = set(), 0
    for zi in z.infolist():
        n = zi.filename
        if not _interesting_for_strings(n) or (only and not only(n)):
            continue
        try:
            data = z.read(n)
        except Exception:
            continue
        gen = iter_ascii_strings(data, minlen)
        if args.utf16:
            gen = _chain(gen, iter_utf16le_strings(data, minlen))
        for s in gen:
            if grep and grep not in s.lower():
                continue
            if s in seen:
                continue
            seen.add(s)
            print(s)
            count += 1
            if args.limit and count >= args.limit:
                warn("hit --limit " + str(args.limit) + "; stopping.")
                z.close()
                return
    z.close()
    print(dim("\n  " + str(count) + " unique string(s)."))


SECRET_PATTERNS = [
    ("url_http",     re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}")),
    ("ws_url",       re.compile(rb"wss?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}")),
    ("ip_addr",      re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("jwt",          re.compile(rb"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")),
    ("google_api",   re.compile(rb"AIza[0-9A-Za-z_-]{35}")),
    ("gcp_oauth",    re.compile(rb"[0-9]+-[0-9A-Za-z_]{20,}\.apps\.googleusercontent\.com")),
    ("firebase_db",  re.compile(rb"[a-z0-9-]+\.firebaseio\.com")),
    ("aws_akid",     re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("slack_token",  re.compile(rb"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("stripe_key",   re.compile(rb"(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{16,}")),
    ("bearer",       re.compile(rb"[Bb]earer\s+[A-Za-z0-9._-]{12,}")),
    ("priv_key",     re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("s3_bucket",    re.compile(rb"[a-z0-9.-]+\.s3[.-][a-z0-9-]*\.amazonaws\.com")),
    ("keyword_kv",   re.compile(rb"(?i)(?:api[_-]?key|secret|passwd|password|token|client[_-]?secret)"
                                rb"['\"]?\s*[:=]\s*['\"][A-Za-z0-9._/+-]{6,}['\"]")),
]

URL_NOISE = re.compile(rb"(?:w3\.org|schemas\.android\.com|apache\.org|"
                       rb"xmlpull\.org|java\.sun\.com|localhost|127\.0\.0\.1|"
                       rb"example\.com|googleapis\.com/robots)")


def cmd_scan(args):
    z = _open_apk(args.apk)
    hdr("Secret scan: " + os.path.basename(args.apk))
    findings = {label: set() for label, _ in SECRET_PATTERNS}
    cap = args.cap
    for zi in z.infolist():
        n = zi.filename
        if not _interesting_for_strings(n):
            continue
        try:
            data = z.read(n)
        except Exception:
            continue
        for label, rx in SECRET_PATTERNS:
            bucket = findings[label]
            if len(bucket) >= cap:
                continue
            for m in rx.finditer(data):
                val = m.group(0)
                if label.startswith("url") and URL_NOISE.search(val):
                    continue
                if label == "ip_addr" and not _plausible_ip(val):
                    continue
                try:
                    bucket.add(val.decode("utf-8", "replace"))
                except Exception:
                    pass
                if len(bucket) >= cap:
                    break
    any_hit = False
    for label, _ in SECRET_PATTERNS:
        vals = sorted(findings[label])
        if not vals:
            continue
        any_hit = True
        capped = " (capped)" if len(vals) >= cap else ""
        print("\n  " + bold(mag(label)) + dim("  " + str(len(vals)) + capped))
        for v in vals[: args.show]:
            print("    " + v)
        if len(vals) > args.show:
            print(dim("    ... " + str(len(vals) - args.show) + " more (raise --show)"))
    if not any_hit:
        print("  " + dim("Nothing matched. Try `strings`, or scan decoded smali."))
    z.close()


def _plausible_ip(b):
    try:
        parts = b.decode().split(".")
        return all(0 <= int(p) <= 255 for p in parts) and b != b"0.0.0.0"
    except Exception:
        return False


def cmd_info(args):
    aapt = resolve_aapt()
    apk = args.apk
    if not os.path.isfile(apk):
        die("Not found: " + apk)
    hdr("Info: " + os.path.basename(apk))
    if not aapt:
        warn("aapt/aapt2 not found - showing zip-level facts only.")
        z = _open_apk(apk)
        n = z.namelist()
        print("  entries:      " + str(len(n)))
        print("  has manifest: " + ("yes" if "AndroidManifest.xml" in n else "no"))
        print("  dex files:    " + str(sum(1 for x in n if x.endswith('.dex'))))
        abis = sorted({x.split('/')[1] for x in n if x.startswith('lib/') and x.count('/') >= 2})
        print("  native abis:  " + (", ".join(abis) if abis else "(none)"))
        z.close()
        hint("aapt")
        return
    p = subprocess.run([aapt, "dump", "badging", apk], capture_output=True, text=True, encoding="utf-8", errors="replace")
    out = p.stdout or ""
    pkg = re.search(r"package: name='([^']+)'.*versionCode='([^']*)'.*versionName='([^']*)'", out)
    sdk = re.search(r"sdkVersion:'([^']*)'", out)
    tsdk = re.search(r"targetSdkVersion:'([^']*)'", out)
    if pkg:
        print("  package:      " + bold(pkg.group(1)))
        print("  versionName:  " + pkg.group(3) + dim("  (code " + pkg.group(2) + ")"))
    if sdk:
        print("  minSdk:       " + sdk.group(1) + (dim("   targetSdk " + tsdk.group(1)) if tsdk else ""))
    perms = re.findall(r"uses-permission: name='([^']+)'", out)
    if perms:
        print("\n  " + bold("permissions") + dim("  (" + str(len(perms)) + ")"))
        for pm in perms:
            print("    " + pm)


# --------------------------------------------------------------------------- #
# doctor / config
# --------------------------------------------------------------------------- #
def _mitm_status():
    r = resolve_apkmitm()
    if not r:
        return None
    return "via npx" if r[0] == "npx" else r[0]


def cmd_doctor(args):
    checks = [
        ("adb", have("adb"), "adb", "everything device-side"),
        ("java", have("java"), "java", "merge / gadget / sign"),
        ("APKEditor.jar", resolve_apkeditor(), "apkeditor", "merge / flow"),
        ("apk-mitm", _mitm_status(), "apk-mitm", "patch / flow"),
        ("frida", have("frida"), "python-frida", "hook (dynamic instrumentation)"),
        ("frida-ps", have("frida-ps"), "python-frida", "list device processes"),
        ("objection", have("objection"), "objection", "gadget inject (UNROOTED) / explore"),
        ("apktool", have("apktool"), "apktool", "decode / gadget rebuild"),
        ("jadx", have("jadx"), "jadx", "decompile"),
        ("aapt/aapt2", resolve_aapt(), "aapt", "info"),
        ("apksigner", have("apksigner"), "apksigner", "sign"),
        ("uber-apk-signer", resolve_uber(), "uber-apk-signer", "sign (easiest)"),
        ("blutter", resolve_blutter(), "blutter", "Flutter static analysis"),
        ("reflutter", have("reflutter"), "reflutter", "Flutter MITM patch"),
    ]
    if getattr(args, "json", False):
        import json as _json
        print(_json.dumps({name: bool(found) for name, found, _, _ in checks}, indent=2))
        return
    hdr("apkkit doctor")
    w = max(len(c[0]) for c in checks)
    missing = []
    for name, found, key, needed in checks:
        status = grn("● found ") if found else red("○ missing")
        detail = (str(found) if isinstance(found, str) else "") if found else ""
        print("  " + name.ljust(w) + "  " + status + "  " + dim(detail or ("used for: " + needed)))
        if not found:
            missing.append((key, name))
    if missing:
        print(dim("\n  Missing tools & how to get them:"))
        seen = set()
        for key, name in missing:
            if key in seen:
                continue
            seen.add(key)
            print("\n  " + bold(name) + ":")
            hint(key)
    else:
        ok("all tools present - you're fully loaded.")
    print(dim("\n  config:  " + CONFIG_PATH + (" (present)" if os.path.isfile(CONFIG_PATH) else " (none yet)")))
    print(dim("  scripts: " + SCRIPTS_DIR))
    print(dim("  workdir: " + work_dir() + "   (pulls/merges/patches land here)"))


def cmd_config(args):
    changed = False
    for attr, key in (("apkeditor", "apkeditor"), ("aapt", "aapt"), ("uber", "uber"), ("blutter", "blutter"), ("workdir", "workdir")):
        val = getattr(args, attr, None)
        if val:
            CONFIG[key] = os.path.abspath(val)
            changed = True
    if changed and save_config(CONFIG):
        ok("saved " + CONFIG_PATH)
    hdr("Current config")
    if not CONFIG:
        print("  " + dim("(empty - using auto-detection / env vars)"))
    for k, v in CONFIG.items():
        exists = "" if (v and os.path.exists(v)) else red("  (path missing)")
        print("  " + k.ljust(12) + " " + str(v) + exists)


# --------------------------------------------------------------------------- #
# commands: flow
# --------------------------------------------------------------------------- #
def _flow_gadget(merged, serial, no_nsc):
    """Inject the Frida gadget and return a signed, installable apk path."""
    if not have("objection"):
        need("objection")
    cmd = ["objection", "patchapk", "-s", merged, "-a", device_abi(serial)]
    if not no_nsc:
        cmd.append("-N")
    run_live(cmd, cwd=os.path.dirname(os.path.abspath(merged)))
    cand = _base(merged) + ".objection.apk"
    if not os.path.isfile(cand):
        warn("no *.objection.apk produced; using merged apk.")
        return merged
    ok("gadget injected: " + cand)
    signed = _sign(cand)
    return signed or cand


def _static_flutter_patch(apk):
    """Static libflutter.so TLS bypass (auto-detect). Returns a signed apk, or None."""
    z = _open_apk(apk)
    if "lib/arm64-v8a/libflutter.so" not in z.namelist():
        z.close()
        return None
    so = z.read("lib/arm64-v8a/libflutter.so")
    z.close()
    foff = _auto_find_flutter_ssl(so)
    if foff is None or foff + 8 > len(so):
        return None
    info("static patch: ssl_verify_peer_cert @ file off " + hex(foff))
    patch = bytes([0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6])   # mov w0,#0 ; ret
    out = _base(apk) + "-flutterpatched.apk"
    _zip_replace(apk, out, "lib/arm64-v8a/libflutter.so", so[:foff] + patch + so[foff + 8:])
    return _sign(out) or out


def _flow_reflutter(merged):
    """Run reFlutter, sign the result. Returns a signed apk, or None."""
    if not have("reflutter"):
        hint("reflutter")
        return None
    info("reFlutter will ask for your proxy IP (traffic -> that IP on :8083).")
    run_live(["reflutter", merged], cwd=os.path.dirname(os.path.abspath(merged)))
    cands = []
    for d in {os.path.dirname(os.path.abspath(merged)), work_dir()}:
        cands += glob.glob(os.path.join(d, "*.RE.apk"))
    if not cands:
        return None
    out = sorted(cands)[0]
    return _sign(out) or out


def _apply_patch(choice, merged, flut, serial, args):
    """Run the chosen patch method. Returns (final_apk_path, method_label).
    choice: auto | static | reflutter | gadget | none."""
    if choice == "none":
        info("skipping patch.")
        return merged, "none"

    if choice == "gadget":
        return _flow_gadget(merged, serial, args.no_nsc), "gadget"

    if choice == "reflutter":
        r = _flow_reflutter(merged)
        if r:
            ok("reFlutter patched: " + r)
            return r, "reflutter"
        warn("reFlutter unavailable / can't patch this engine - falling back to gadget.")
        return _flow_gadget(merged, serial, args.no_nsc), "gadget-fallback"

    if choice == "static":
        if flut:
            info("static libflutter TLS patch (no Frida, no root) ...")
            r = _static_flutter_patch(merged)
            if r:
                ok("static patch done: " + r)
                return r, "flutter-patch"
            warn("static patch couldn't auto-locate ssl_verify (new build or no arm64 lib).")
            return merged, "static-failed"
        runner = resolve_apkmitm()
        if not runner:
            warn("apk-mitm not installed.")
            hint("apk-mitm")
            return merged, "static-failed"
        info("native: apk-mitm static pinning strip (no Frida) ...")
        run_live(runner + [merged])
        cand = _base(merged) + "-patched.apk"
        if os.path.isfile(cand):
            ok("patched: " + cand)
            return cand, "apk-mitm"
        warn("apk-mitm produced no output; using merged apk.")
        return merged, "static-failed"

    # choice == "auto": least-invasive first, with fallbacks
    if flut:
        info("Flutter: static libflutter patch first (no Frida/root) ...")
        r = _static_flutter_patch(merged)
        if r:
            ok("static patch done: " + r)
            return r, "flutter-patch"
        warn("static patch couldn't locate ssl_verify - trying reFlutter ...")
        r = _flow_reflutter(merged)
        if r:
            ok("reFlutter patched: " + r)
            return r, "reflutter"
        warn("reFlutter failed - falling back to Frida gadget.")
        return _flow_gadget(merged, serial, args.no_nsc), "gadget-fallback"
    runner = resolve_apkmitm()
    if runner:
        info("native: apk-mitm static pinning strip (no Frida) ...")
        run_live(runner + [merged])
        cand = _base(merged) + "-patched.apk"
        if os.path.isfile(cand):
            ok("patched: " + cand)
            return cand, "apk-mitm"
        warn("apk-mitm produced no output; using merged apk.")
        return merged, "apk-mitm-failed"
    warn("apk-mitm not found - using Frida gadget instead.")
    hint("apk-mitm")
    return _flow_gadget(merged, serial, args.no_nsc), "gadget"


def cmd_flow(args):
    serial = resolve_serial(args)
    pkg = args.package
    out_dir = args.out or pull_dir()
    mode = "none" if args.no_patch else ("gadget" if args.gadget else (args.method or "auto"))
    total = 3 + (1 if args.install else 0)

    hdr("FLOW: " + pkg + dim("   (patch mode: " + mode + ")"))

    step(1, total, "Pull")
    dest = _pull_one(serial, pkg, out_dir)
    if not dest:
        die("pull failed.")

    step(2, total, "Merge splits")
    jar = resolve_apkeditor(args.apkeditor)
    if not jar:
        need("apkeditor", "APKEditor.jar")
    if not have("java"):
        need("java")
    merged = os.path.join(work_dir(), pkg + "-merged.apk")
    if run_live(["java", "-jar", jar, "m", "-i", dest, "-o", merged, "-f"]) != 0 \
            or not os.path.isfile(merged):
        die("merge failed.")
    ok("merged: " + merged)

    final = merged
    step(3, total, "Patch")
    flut = is_flutter(merged)
    print("  " + dim("app type: ") + (mag("Flutter (Dart)") if flut else grn("native Java/Kotlin")))

    # pick + run the patch method
    choice = "none" if args.no_patch else ("gadget" if args.gadget else (args.method or "auto"))
    info("patch method: " + bold(choice))
    final, method = _apply_patch(choice, merged, flut, serial, args)

    # never try to install an unsigned apk (raw APKEditor output won't verify)
    if args.install and not (final.endswith("Signed.apk") or final.endswith("-aligned.apk") or final.endswith("-patched.apk")):
        info("signing the apk before install ...")
        signed = _sign(final)
        if signed:
            final = signed
        else:
            warn("couldn't sign - install may fail. Set a signer: apkkit config --uber <path>")

    if args.install:
        step(total, total, "Install")
        adb(["uninstall", pkg], serial=serial)
        rc = run_live(["adb", "-s", serial, "install", "-r"] +
                      (["-g"] if args.grant else []) + [final])
        (ok if rc == 0 else erro)("install exited " + str(rc))

    hdr("Flow complete")
    print("  final apk: " + bold(final))
    if method == "flutter-patch":
        print(dim("  Frida-free: set a device proxy + install your CA - the app trusts any cert now."))
        print(dim("  If it self-closes on launch, it has tamper detection (a TLS patch can't fix that)."))
    elif method == "apk-mitm":
        print(dim("  Set a device proxy + install the apk-mitm CA - no Frida needed."))
    elif method == "reflutter":
        print(dim("  Set the device proxy to <your-ip>:8083 and watch traffic in Burp."))
    elif method in ("gadget", "gadget-fallback"):
        print(dim("  Attach Frida: ") + "apkkit hook Gadget --gadget --builtin ssl")
        if method == "gadget-fallback":
            print(dim("  (Flutter: for TRAFFIC use --builtin flutter-ssl, not the Java ssl script.)"))


# --------------------------------------------------------------------------- #
# small utils
# --------------------------------------------------------------------------- #
def _base(path):
    b = os.path.basename(path)
    return os.path.join(os.path.dirname(path), re.sub(r"\.apk$", "", b, flags=re.I))


def _human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%.0f %s" if unit == "B" else "%.1f %s") % (n, unit)
        n /= 1024.0


def _dedup_keep(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _chain(*gens):
    for g in gens:
        for x in g:
            yield x


# --------------------------------------------------------------------------- #
# arg parsing + banner
# --------------------------------------------------------------------------- #
BANNER = r"""
   __ _ _ __ | | _| | _(_) |_
  / _` | '_ \| |/ / |/ / | __|
 | (_| | |_) |   <|   <| | |_
  \__,_| .__/|_|\_\_|\_\_|\__|   """ + "v" + __version__ + r"""
       |_|   APK reverse-engineering toolkit  ·  unrooted-ready
             pull · merge · patch · gadget · frida · objection
"""


def is_flutter(apk):
    z = _open_apk(apk)
    names = z.namelist()
    z.close()
    return any(n.endswith("libflutter.so") or n.endswith("libapp.so")
               or n.startswith("assets/flutter_assets/") for n in names)


def _extract_dir(apk, subdir, out):
    z = _open_apk(apk)
    got = []
    out_root = os.path.realpath(out)
    for n in z.namelist():
        if n.startswith(subdir) and not n.endswith("/"):
            dest = os.path.join(out, n.replace("/", os.sep))
            if not os.path.realpath(dest).startswith(out_root + os.sep):
                warn("skipping suspicious zip entry: " + n)
                continue
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as f:
                f.write(z.read(n))
            got.append(os.path.basename(n))
    z.close()
    return got


def _find_libapp_dir(root):
    for dirpath, _, files in os.walk(root):
        if "libapp.so" in files:
            return dirpath
    return None


def _extract_flutter_from_apks(apks, outroot):
    """Pull lib/arm64-v8a/*.so out of one or more (split) APKs into one folder."""
    libdir = os.path.join(outroot, "lib", "arm64-v8a")
    os.makedirs(libdir, exist_ok=True)
    found_app = False
    for apk in apks:
        try:
            z = zipfile.ZipFile(apk)
        except Exception:
            continue
        for n in z.namelist():
            if n.startswith("lib/arm64-v8a/") and n.endswith(".so"):
                with open(os.path.join(libdir, os.path.basename(n)), "wb") as f:
                    f.write(z.read(n))
                if os.path.basename(n) == "libapp.so":
                    found_app = True
        z.close()
    return libdir if found_app else None


def cmd_blutter(args):
    blutter = resolve_blutter()
    if not blutter:
        need("blutter", "Blutter (blutter.py)")
    src = args.target.rstrip("/\\")

    if os.path.isdir(src):
        # (a) already a lib dir with libapp.so, or one nested inside
        cand = src if os.path.isfile(os.path.join(src, "libapp.so")) else _find_libapp_dir(src)
        if cand:
            libdir = cand
            outdir = args.out or (src + ".blutter")
        else:
            # (b) a folder of split APKs (e.g. a pulled_apks/<pkg> dir) - extract
            apks = sorted(glob.glob(os.path.join(src, "*.apk")))
            if not apks:
                die("That folder has no libapp.so and no .apk files.\n"
                    "      Point me at: an .apk, a split folder, or a lib/arm64-v8a dir.")
            info("no libapp.so directly - extracting arm64 libs from " +
                 str(len(apks)) + " APK(s) in the folder ...")
            work = args.out or (src + ".blutter")
            libdir = _extract_flutter_from_apks(apks, os.path.join(work, "_libs"))
            if not libdir:
                die("None of the split APKs contain lib/arm64-v8a/libapp.so.\n"
                    "      Blutter only supports arm64-v8a - make sure the arm64 split was pulled.")
            outdir = os.path.join(work, "out")
    elif os.path.isfile(src) and src.lower().endswith(".apk"):
        if not is_flutter(src):
            warn("This doesn't look like a Flutter app - Blutter needs libapp.so.")
        work = args.out or (_base(src) + ".blutter")
        info("extracting lib/arm64-v8a from the apk ...")
        got = _extract_dir(src, "lib/arm64-v8a/", os.path.join(work, "_libs"))
        if "libapp.so" not in got:
            die("No libapp.so under lib/arm64-v8a in this apk.\n"
                "      For a split app the arm64 libs live in split_config.arm64_v8a.apk - "
                "merge first (apkkit merge <folder>) or point me at the pulled folder.")
        libdir = os.path.join(work, "_libs", "lib", "arm64-v8a")
        outdir = os.path.join(work, "out")
    else:
        die("Give an .apk, a pulled split folder, or a lib/arm64-v8a folder.")
    hdr("Blutter (Flutter/Dart static analysis) -> " + outdir)
    os.makedirs(outdir, exist_ok=True)
    cmd = [sys.executable, blutter, libdir, outdir]
    if args.rebuild:
        cmd.append("--rebuild")
    if args.no_analysis:
        cmd.append("--no-analysis")
        info("--no-analysis: skipping code analysis (faster; dodges some crashes).")
    warn("first run may build a matching Dart VM - can take a few minutes.")
    rc = run_live(cmd)
    frida_js = os.path.join(outdir, "blutter_frida.js")
    # What actually landed on disk matters more than the exit code: Blutter's exe
    # can crash on the Frida-script step yet still have written all the dumps.
    other = [n + "/" for n in ("asm", "ida_script") if os.path.isdir(os.path.join(outdir, n))]
    other += [n for n in ("pp.txt", "objs.txt") if os.path.isfile(os.path.join(outdir, n))]

    if os.path.isfile(frida_js):
        if rc != 0:
            warn("blutter exited " + str(rc) + " but the full output is written - fine.")
        ok("done. Output in " + outdir)
        print(dim("  Dart method hooks: ") + frida_js)
        print(dim("  Run them: ") + "apkkit hook Gadget --gadget -l " + _quote(frida_js))
        print(dim("  Also see: ") + "asm/ (disassembly), pp.txt / objs.txt (object pool)")
    elif other:
        warn("blutter crashed on the Frida-script step (exit " + str(rc) +
             ") - a known Blutter bug on some Dart snapshots. NOT your setup.")
        ok("static output IS written: " + ", ".join(sorted(other)) + "  in " + outdir)
        print(dim("  You have the disassembly + object pool - that's the substance."))
        print(dim("  Only blutter_frida.js is missing; --no-analysis produces the same"))
        print(dim("  files without crashing. Grep asm/ + pp.txt, or hook via objection."))
    else:
        erro("blutter exited " + str(rc) + " with no output produced.")
        print(dim("  This app crashes Blutter's analyzer. Try, in order:"))
        print(dim("   1) apkkit blutter <src> --no-analysis   (skip the step that's crashing)"))
        print(dim("   2) cd C:\\tools\\blutter && git pull   then   apkkit blutter <src> --rebuild"))
        print(dim("   3) fall back to reFlutter for this app (dynamic dump.dart + MITM)."))


def cmd_reflutter(args):
    if not have("reflutter"):
        need("reflutter")
    apk = args.apk
    if not os.path.isfile(apk):
        die("Not found: " + apk)
    if not is_flutter(apk):
        warn("This doesn't look like a Flutter app - reFlutter may not apply.")
    hdr("reFlutter: patch for HTTPS interception")
    info("reFlutter will ask for your Burp/proxy IP. Patched traffic -> that IP on port 8083.")
    print(dim("  Note: Flutter >= 3.24 drops the baked-in proxy; also set a device proxy manually."))
    rc = run_live(["reflutter", apk], cwd=os.path.dirname(os.path.abspath(apk)))
    cands = []
    for d in {os.path.dirname(os.path.abspath(apk)), work_dir()}:
        cands += glob.glob(os.path.join(d, "*.RE.apk"))
    out = sorted(cands)[0] if cands else None
    if not out:
        warn("Couldn't locate release.RE.apk - check reFlutter's output above.")
        return
    ok("patched: " + out)
    if args.sign:
        signed = _sign(out)
        if signed:
            ok("signed: " + signed)
    else:
        print(dim("  Next: ") + "apkkit sign " + _quote(out) + dim("  then  ") + "apkkit install <signed>")
    print(dim("  On the device: set proxy to <your-ip>:8083 (or manual proxy) and trust your CA."))


def _elf_vaddr_to_off(data, vaddr):
    """Map a virtual offset (what Frida reports) to a file offset in an ELF64 .so."""
    if data[:4] != b"\x7fELF" or data[4] != 2:
        return None
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    for i in range(e_phnum):
        b = e_phoff + i * e_phentsize
        if struct.unpack_from("<I", data, b)[0] != 1:   # PT_LOAD
            continue
        p_offset = struct.unpack_from("<Q", data, b + 8)[0]
        p_vaddr = struct.unpack_from("<Q", data, b + 0x10)[0]
        p_filesz = struct.unpack_from("<Q", data, b + 0x20)[0]
        if p_vaddr <= vaddr < p_vaddr + p_filesz:
            return vaddr - p_vaddr + p_offset
    return None


def _zip_replace(src_apk, out_apk, entry_name, new_bytes):
    """Copy src_apk to out_apk, replacing one entry's bytes and PRESERVING each
    entry's original compression (resources.arsc and *.so must stay STORED for
    Android R+, or install fails with -124)."""
    zin = zipfile.ZipFile(src_apk, "r")
    zout = zipfile.ZipFile(out_apk, "w")
    try:
        for item in zin.infolist():
            data = new_bytes if item.filename == entry_name else zin.read(item.filename)
            zout.writestr(item, data)   # item keeps its original compress_type
    finally:
        zin.close()
        zout.close()


# Masked byte signatures for ssl_verify_peer_cert (Android arm64), sourced from
# NVISO's disable-flutter-tls-verification project. Used to auto-locate the
# function for a static patch. Credit: https://github.com/NVISOsecurity/disable-flutter-tls-verification
FLUTTER_SSL_PATTERNS_ARM64 = [
    "F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9",
    "F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 F4 03 00 AA 68 1A 40 F9",
    "FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 15 15 41 F9 B5 00 00 B4 B6 4A 40 F9",
    "FF ?3 01 D1 F? ?? 01 A9 ?? ?? ?? 94 ?? ?? ?? 52 48 00 00 39 1A 50 40 F9 DA 02 00 B4 48 03 40 F9",
]


def _parse_masked_pattern(patstr):
    """'F? 43 ?? D1' -> (values bytes, masks bytes), nibble-aware."""
    vals, masks = bytearray(), bytearray()
    for tok in patstr.split():
        v = m = 0
        if tok[0] != "?":
            v |= int(tok[0], 16) << 4; m |= 0xF0
        if tok[1] != "?":
            v |= int(tok[1], 16); m |= 0x0F
        vals.append(v); masks.append(m)
    return bytes(vals), bytes(masks)


def _exec_ranges(data):
    """File [start,end) ranges of executable PT_LOAD segments (PF_X)."""
    ranges = []
    if data[:4] != b"\x7fELF" or data[4] != 2:
        return [(0, len(data))]
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    for i in range(e_phnum):
        b = e_phoff + i * e_phentsize
        if struct.unpack_from("<I", data, b)[0] != 1:            # PT_LOAD
            continue
        p_flags = struct.unpack_from("<I", data, b + 4)[0]
        if not (p_flags & 0x1):                                  # PF_X
            continue
        p_offset = struct.unpack_from("<Q", data, b + 8)[0]
        p_filesz = struct.unpack_from("<Q", data, b + 0x20)[0]
        ranges.append((p_offset, p_offset + p_filesz))
    return ranges or [(0, len(data))]


def _scan_pattern(data, vals, masks, start, end):
    """Return file offsets in [start,end) where the masked pattern matches."""
    n = len(vals)
    # anchor on the longest run of fully-fixed bytes for a fast bytes.find
    best_i = best_len = 0
    i = 0
    while i < n:
        if masks[i] == 0xFF:
            j = i
            while j < n and masks[j] == 0xFF:
                j += 1
            if j - i > best_len:
                best_len, best_i = j - i, i
            i = j
        else:
            i += 1
    anchor = vals[best_i:best_i + best_len]
    hits = []
    pos = start
    while True:
        idx = data.find(anchor, pos, end)
        if idx < 0:
            break
        cand = idx - best_i
        if cand >= start and cand + n <= end:
            if all((data[cand + k] & masks[k]) == vals[k] for k in range(n)):
                hits.append(cand)
        pos = idx + 1
    return hits


def _auto_find_flutter_ssl(so):
    """Auto-locate ssl_verify_peer_cert file offset in libflutter.so, or None."""
    ranges = _exec_ranges(so)
    fallback = None
    for patstr in FLUTTER_SSL_PATTERNS_ARM64:
        vals, masks = _parse_masked_pattern(patstr)
        hits = []
        for (a, b) in ranges:
            hits += _scan_pattern(so, vals, masks, a, b)
        if len(hits) == 1:
            return hits[0]                 # unambiguous - best case
        if hits and fallback is None:
            fallback = hits[0]
    return fallback


def cmd_flutter_patch(args):
    """Static Flutter TLS bypass: NOP ssl_verify_peer_cert in libflutter.so. No Frida, no root."""
    apk = args.apk
    if os.path.isdir(apk):
        die("Point at a single merged .apk (run `apkkit merge <folder>` first).")
    if not os.path.isfile(apk):
        die("Not found: " + apk)

    z = _open_apk(apk)
    target = "lib/arm64-v8a/libflutter.so"
    if target not in z.namelist():
        z.close()
        die("No " + target + " in this apk (arm64 Flutter only).")
    so = z.read(target)
    z.close()

    if args.offset:
        try:
            vaddr = int(args.offset, 16) if isinstance(args.offset, str) else int(args.offset)
        except ValueError:
            die("--offset must be hex like 0x753dc8")
        foff = _elf_vaddr_to_off(so, vaddr)
        if foff is None or foff + 8 > len(so):
            die("Offset " + hex(vaddr) + " doesn't map into libflutter.so - right value/app?")
        info("using supplied offset " + hex(vaddr) + " (file off " + hex(foff) + ")")
    else:
        info("auto-detecting ssl_verify_peer_cert (NVISO arm64 signatures) ...")
        foff = _auto_find_flutter_ssl(so)
        if foff is None:
            die("Couldn't auto-detect the function (new/unusual Flutter build).\n"
                "      Get the offset from a live run and pass it:\n"
                "        apkkit hook <pkg> --gadget --builtin flutter-ssl   (prints the offset)\n"
                "        apkkit flutter-patch " + _quote(apk) + " --offset 0xXXXXXX")
        if foff + 8 > len(so):
            die("auto-detected offset out of range - pass --offset manually.")
        ok("auto-detected ssl_verify_peer_cert at file offset " + hex(foff))

    hdr("Static Flutter TLS patch  (file off " + hex(foff) + ")")
    # arm64: mov w0, #0 (ssl_verify_ok) ; ret
    patch = bytes([0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6])
    info("original bytes: " + so[foff:foff + 8].hex() + "  ->  " + patch.hex())
    patched = so[:foff] + patch + so[foff + 8:]

    out = _base(apk) + "-flutterpatched.apk"
    info("rebuilding apk with patched libflutter.so ...")
    _zip_replace(apk, out, target, patched)
    ok("patched apk: " + out)
    signed = _sign(out)
    if signed:
        ok("signed: " + signed)
        print(dim("  Install it, set a proxy, and the app trusts any cert - no Frida, no root."))
    else:
        warn("apk is unsigned - run: apkkit sign " + _quote(out))
    print(dim("  NOTE: this repackages the apk. If the app self-closes on launch, it has"))
    print(dim("  tamper detection - a TLS patch won't help; that check must be removed too."))


# --------------------------------------------------------------------------- #
# commands: diagnostics / analysis / orchestration (v0.4)
# --------------------------------------------------------------------------- #
DETECTION_REGEX = ("root|magisk|superuser|supersu|xposed|riru|zygisk|"
                   "emulator|qemu|goldfish|ranchu|genymotion|sdk_gphone|"
                   "integrity|safetynet|attest|droidguard|playintegrity|"
                   "frida|gadget|27042|tamper|repackag|signature|debugger|"
                   "SecurityException|finishAffinity|System\\.exit")


def cmd_logcat(args):
    """Stream filtered logcat for one package - great for finding why an app self-closes."""
    if not have("adb"):
        need("adb")
    serial = resolve_serial(args)
    if not args.no_clear:
        adb(["logcat", "-c"], serial=serial)
    pid = ""
    if args.package:
        _, out, _ = adb(["shell", "pidof", args.package], serial=serial)
        pid = out.strip().split()[0] if out.strip() else ""
    pat = None
    if not args.all:
        pat = re.compile(args.grep or DETECTION_REGEX, re.I)
    hdr("logcat" + (" pid " + pid if pid else "") + (" ~ /" + (args.grep or "detection") + "/" if pat else ""))
    if args.package and not pid:
        info("app not running yet - launch it now; showing filtered full logcat.")
    cmd = ["adb", "-s", serial, "logcat", "-v", "brief"]
    if pid:
        cmd += ["--pid", pid]
    print(dim("  $ " + " ".join(cmd) + "   (Ctrl+C to stop)\n"))
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True,
                             encoding="utf-8", errors="replace", bufsize=1)
        for line in p.stdout:
            line = line.rstrip("\n")
            if pat is None:
                print(line)
            elif pat.search(line):
                print(yel(line) if _COLOR else "! " + line)
    except KeyboardInterrupt:
        print("\n" + yel("  stopped."))
    finally:
        try:
            p.terminate()
        except Exception:
            pass


# smali patterns that usually mean "detect X then bail"
CHECK_PATTERNS = [
    ("root", r'"/system/(xbin|bin)/su"|"su"|magisk|Superuser|RootBeer|test-keys|which su'),
    ("emulator", r'goldfish|ranchu|generic_x86|sdk_gphone|ro\.kernel\.qemu|"unknown"|Genymotion'),
    ("signature/tamper", r'GET_SIGNATURES|getSignatures|signingInfo|GET_SIGNING_CERTIFICATES|PackageManager;->getPackageInfo'),
    ("integrity", r'SafetyNet|DroidGuard|IntegrityManager|attest'),
    ("frida", r'frida|gadget|re\.frida|LIBFRIDA|27042|linjector'),
    ("debugger", r'isDebuggerConnected|waitingForDebugger|Debug;->'),
    ("self-close", r'Ljava/lang/System;->exit|Ljava/lang/Runtime;->halt|Landroid/os/Process;->killProcess|->finishAffinity'),
]

# smali invoke lines that terminate the app - safe to strip (all return void)
_KILL_RX = re.compile(
    r'^\s*invoke-\w+\s*\{[^}]*\},\s*L'
    r'(java/lang/System;->exit\(I\)V'
    r'|java/lang/Runtime;->halt\(I\)V'
    r'|android/os/Process;->killProcess\(I\)V'
    r'|android/app/Activity;->finishAffinity\(\)V)')


def cmd_checks(args):
    """Decompile to smali and locate root/emulator/tamper/integrity self-checks.
    With --neutralize, strip the self-kill calls (System.exit/killProcess/...) and rebuild."""
    if not have("apktool"):
        need("apktool")
    apk = args.apk
    if not os.path.isfile(apk):
        die("Not found: " + apk)
    decoded = args.decoded or (_base(apk) + ".decoded")
    if not os.path.isdir(decoded):
        hdr("apktool decode -> " + decoded)
        if run_live(["apktool", "d", apk, "-o", decoded, "-f"]) != 0:
            die("apktool decode failed.")
    else:
        info("using existing decode: " + decoded)

    smali_files = []
    for root, _, files in os.walk(decoded):
        for f in files:
            if f.endswith(".smali"):
                smali_files.append(os.path.join(root, f))

    hdr("Anti-analysis checks in " + os.path.basename(apk) + "  (" + str(len(smali_files)) + " smali files)")
    compiled = [(label, re.compile(rx, re.I)) for label, rx in CHECK_PATTERNS]
    hits = {label: [] for label, _ in CHECK_PATTERNS}
    for path in smali_files:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, 1):
                    for label, rx in compiled:
                        if rx.search(line):
                            hits[label].append((path, i, line.strip()))
        except Exception:
            continue

    rel = lambda p: os.path.relpath(p, decoded)
    any_hit = False
    for label, _ in CHECK_PATTERNS:
        rows = hits[label]
        if not rows:
            continue
        any_hit = True
        print("\n  " + bold(mag(label)) + dim("  (" + str(len(rows)) + " hits)"))
        for path, ln, txt in rows[: args.show]:
            print("    " + rel(path) + ":" + str(ln) + dim("  " + (txt[:90])))
        if len(rows) > args.show:
            print(dim("    ... " + str(len(rows) - args.show) + " more (raise --show)"))
    if not any_hit:
        print("  " + dim("No obvious checks found in smali (native check, or packed)."))

    if args.neutralize:
        hdr("Neutralizing self-kill calls (System.exit / killProcess / halt / finishAffinity)")
        patched = 0
        for path in smali_files:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()
            except Exception:
                continue
            changed = False
            for i, line in enumerate(lines):
                if _KILL_RX.match(line):
                    lines[i] = "    # apkkit-neutralized: " + line.lstrip()
                    changed = True
                    patched += 1
            if changed:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.writelines(lines)
        ok("commented out " + str(patched) + " self-kill call(s).")
        if not patched:
            warn("nothing to neutralize (the check may exit via native code or a different API).")
        out = _base(apk) + "-nokill.apk"
        info("rebuilding with apktool ...")
        if run_live(["apktool", "b", decoded, "-o", out]) != 0:
            die("apktool build failed.")
        signed = _sign(out)
        final = signed or out
        ok("built: " + final)
        print(dim("  Install it: apkkit install " + _quote(final)))
        print(dim("  Best-effort - if the app still bails, the check kills via native code or"))
        print(dim("  a path this doesn't cover; inspect the hits above and patch the method."))


def cmd_mitm(args):
    """One-shot: pull -> merge -> patch -> install -> trust CA -> set proxy -> launch."""
    serial = resolve_serial(args)
    pkg = args.package
    hdr("MITM setup for " + pkg)
    # reuse the flow to pull/merge/patch/install
    cmd_flow(A(package=pkg, serial=serial, out=None, method=args.method or "auto",
               gadget=False, no_patch=False, no_nsc=False, install=True, grant=True))
    if args.cert:
        cmd_cert(A(cert=args.cert, user=False, serial=serial))
    if args.proxy:
        cmd_proxy(A(target=args.proxy, transparent=args.transparent, serial=serial))
    if args.launch:
        info("launching " + pkg + " ...")
        run_live(["adb", "-s", serial, "shell", "monkey", "-p", pkg,
                  "-c", "android.intent.category.LAUNCHER", "1"])
    hdr("MITM ready")
    print("  Watch requests in Burp/Fiddler. Reset later with: apkkit mitm " + pkg + " --off")


def cmd_mitm_off(serial, pkg):
    hdr("MITM teardown for " + pkg)
    cmd_proxy(A(target="off", serial=serial))
    run_live(["adb", "-s", serial, "uninstall", pkg])
    ok("proxy cleared + app uninstalled.")


def _resolve_emulator():
    p = have("emulator")
    if p:
        return p
    for g in (os.path.join(os.environ.get("ANDROID_HOME", ""), "emulator", "emulator"),
              os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk", "emulator", "emulator.exe"),
              os.path.join(HOME, "Android", "Sdk", "emulator", "emulator")):
        if g and os.path.isfile(g):
            return g
    return None


def cmd_emulator(args):
    """List AVDs, or launch one with RE-friendly flags (writable system, proxy, cold boot)."""
    emu = _resolve_emulator()
    if not emu:
        erro("'emulator' not found. It's in <android-sdk>/emulator.")
        print(dim("  Add that folder to PATH, or set ANDROID_HOME."))
        return
    if not args.name:
        hdr("Available AVDs")
        run_live([emu, "-list-avds"])
        print(dim("\n  Launch: apkkit emulator <name> [--writable-system] [--proxy ip:port] [--cold]"))
        return
    hdr("Launching AVD: " + args.name)
    cmd = [emu, "-avd", args.name]
    if args.writable_system:
        cmd.append("-writable-system")
    if args.cold:
        cmd += ["-no-snapshot-load"]
    if args.proxy:
        cmd += ["-http-proxy", "http://" + args.proxy]
    if args.extra:
        cmd += args.extra.split()
    info("starting (detached) ...")
    print(dim("  $ " + " ".join(cmd)))
    try:
        subprocess.Popen(cmd)
        ok("emulator starting. Give it a moment, then: apkkit devices")
    except Exception as e:
        erro("failed to launch: " + str(e))


def cmd_batch(args):
    """Run an inspection across every app folder / apk under a directory."""
    root = args.dir or pull_dir()
    if not os.path.isdir(root):
        die("Not a directory: " + root + "  (pull some apps first, or pass --dir)")
    targets = []
    for name in sorted(os.listdir(root)):
        p = os.path.join(root, name)
        if os.path.isdir(p) and glob.glob(os.path.join(p, "*.apk")):
            targets.append(p)
        elif p.lower().endswith(".apk"):
            targets.append(p)
    if not targets:
        die("No apk folders or files under " + root)
    hdr(args.action + " across " + str(len(targets)) + " target(s) in " + root)

    if args.action == "classify":
        w = max(len(os.path.basename(t.rstrip("/\\"))) for t in targets)
        for t in targets:
            try:
                members, _ = _apk_members(t)
                names = [n for n, _ in members]
                flut = any(n.endswith("libflutter.so") or n.startswith("assets/flutter_assets/") for n in names)
                abis = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and n.count("/") >= 2})
                tag = mag("FLUTTER") if flut else grn("native ")
                print("  " + os.path.basename(t.rstrip("/\\")).ljust(w) + "  " + tag +
                      dim("  " + (",".join(abis) or "no-abi")))
            except SystemExit:
                print("  " + os.path.basename(t.rstrip("/\\")).ljust(w) + "  " + red("(unreadable)"))
        return

    for t in targets:
        print("\n" + bold("### " + os.path.basename(t.rstrip("/\\"))))
        apk = t
        if os.path.isdir(t):
            apks = sorted(glob.glob(os.path.join(t, "*.apk")))
            apk = next((a for a in apks if "arm64" in a), apks[0])
        try:
            if args.action == "libs":
                cmd_libs(A(apk=apk))
            elif args.action == "scan":
                cmd_scan(A(apk=apk, show=8, cap=200))
        except SystemExit:
            warn("skipped (unreadable).")


def cmd_update(args):
    """git pull the repo apkkit.py lives in (self-update)."""
    here = os.path.dirname(os.path.abspath(__file__))
    if not os.path.isdir(os.path.join(here, ".git")):
        erro("apkkit.py isn't inside a git checkout (" + here + ").")
        print(dim("  Clone the repo, or just replace apkkit.py with the latest file."))
        return
    if not have("git"):
        need("git") if "git" in INSTALL_HINTS else die("git not found.")
    hdr("Updating apkkit (git pull) in " + here)
    run_live(["git", "-C", here, "pull", "--ff-only"])


DATA_GREP_DEFAULT = ("push|token|registration|moengage|fcm|gcm|firebase|"
                     "secret|password|passwd|api[_-]?key|apikey|auth|bearer|jwt|"
                     "session|refresh|client_secret|device_id|deviceid|uuid")


def _su_ok(serial):
    """True if Magisk su grants root to the shell."""
    rc, out, _ = adb(["shell", "su -c 'id -u'"], serial=serial)
    return rc == 0 and out.strip().splitlines()[-1:] == ["0"]


def cmd_data(args):
    """Inspect an app's /data/data/<pkg> via Magisk su (shared_prefs, databases, files)."""
    if not have("adb"):
        need("adb")
    serial = resolve_serial(args)
    pkg = args.package
    base = "/data/data/" + pkg

    if not _su_ok(serial):
        erro("root (su) not available to the shell on " + serial + ".")
        print(dim("  'adb root' can't work on Play/production images - root comes from Magisk."))
        print(dim("  Open Magisk on the device, grant su to 'shell', then retry."))
        print(dim("  (run-as only works on debuggable apps, which production apps aren't.)"))
        return

    # confirm the app has a data dir
    rc, out, _ = adb(["shell", "su -c 'ls -d " + base + "'"], serial=serial)
    if rc != 0 or "No such" in out or not out.strip():
        die("No data dir for " + pkg + " (is it installed? has it been launched once?)")

    if args.pull:
        dest = args.out or os.path.join(work_dir(), pkg + "_data")
        tmp = "/data/local/tmp/" + pkg + "_data"
        hdr("Pull app data -> " + dest)
        run_live(_su(serial, "rm -rf " + tmp + "; cp -a " + base + " " + tmp +
                             " 2>/dev/null; chmod -R 777 " + tmp))
        os.makedirs(dest, exist_ok=True)
        run_live(["adb", "-s", serial, "pull", tmp, dest])
        run_live(_su(serial, "rm -rf " + tmp))
        ok("pulled to " + dest + "  (grep it with: apkkit scan / your editor)")
        return

    if args.list:
        hdr("Data tree: " + base)
        run_live(_su(serial, "ls -laR " + base + " 2>/dev/null"))
        return

    if args.prefs:
        hdr("shared_prefs: " + pkg)
        run_live(_su(serial, "for f in " + base + "/shared_prefs/*.xml; do "
                             "echo; echo \"==== $f ====\"; cat \"$f\"; done"))
        return

    # default / --grep: search the text-y parts of the data dir
    rx = args.grep or DATA_GREP_DEFAULT
    hdr("grep " + pkg + " data  ~ /" + rx + "/")
    for sub in ("shared_prefs", "files", "no_backup"):
        run_live(_su(serial, "grep -rniE \"" + rx + "\" " + base + "/" + sub + " 2>/dev/null"))
    info("databases (pull + open in a viewer, or use `apkkit data " + pkg + " --pull`):")
    run_live(_su(serial, "ls -la " + base + "/databases 2>/dev/null"))


def build_parser():
    p = argparse.ArgumentParser(
        prog="apkkit",
        description="APK RE toolkit: pull / merge / patch / gadget-inject / hook / inspect.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run `apkkit doctor` to check tools. Missing ones come with install steps.",
    )
    p.add_argument("-s", "--serial", help="target device serial")
    p.add_argument("-V", "--version", action="version", version="apkkit " + __version__)
    sub = p.add_subparsers(dest="cmd", metavar="<command>")

    # shared options every subcommand accepts (so `apkkit install app.apk -s <serial>` works)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-s", "--serial", help="target device serial")

    def add(name, help):
        return sub.add_parser(name, help=help, parents=[common])

    sp = add("menu", "launch the interactive menu (default when no command)"); sp.set_defaults(func=lambda a: interactive_menu())
    sp = add("devices", "list attached devices");                sp.set_defaults(func=cmd_devices)

    sp = add("list", "list packages on a device")
    sp.add_argument("--vendor", action="store_true"); sp.add_argument("--system", action="store_true")
    sp.add_argument("-g", "--grep"); sp.set_defaults(func=cmd_list)

    sp = add("pull", "pull app APKs off a device (base + splits)")
    sp.add_argument("packages", nargs="*"); sp.add_argument("-o", "--out")
    sp.add_argument("--vendor", action="store_true"); sp.add_argument("--system", action="store_true")
    sp.set_defaults(func=cmd_pull)

    sp = add("merge", "merge a split-APK folder into one apk (APKEditor)")
    sp.add_argument("input"); sp.add_argument("-o", "--out")
    sp.add_argument("-f", "--force", action="store_true"); sp.add_argument("--apkeditor")
    sp.set_defaults(func=cmd_merge)

    sp = add("patch", "strip certificate pinning (apk-mitm)")
    sp.add_argument("apk"); sp.set_defaults(func=cmd_patch)

    sp = add("gadget", "inject Frida gadget for UNROOTED instrumentation (objection)")
    sp.add_argument("apk")
    sp.add_argument("-a", "--arch", default="auto",
                    help="gadget ABI: auto|arm64-v8a|armeabi-v7a|x86|x86_64")
    sp.add_argument("-N", "--nsc", action="store_true",
                    help="add network-security-config trusting user CAs (MITM)")
    sp.add_argument("-V", "--gadget-version", help="specific frida-gadget version")
    sp.add_argument("-c", "--startup-script", help="Frida JS to bundle + auto-run")
    sp.add_argument("--skip-resources", action="store_true", help="faster rebuild")
    sp.add_argument("--sign", action="store_true",
                    help="re-sign the result with uber-apk-signer (recommended on Windows)")
    sp.set_defaults(func=cmd_gadget)

    sp = add("sign", "zipalign + sign an apk")
    sp.add_argument("apk"); sp.add_argument("--keystore")
    sp.set_defaults(func=cmd_sign)

    sp = add("install", "install an apk, or install-multiple a split folder")
    sp.add_argument("target"); sp.add_argument("-g", "--grant", action="store_true")
    sp.set_defaults(func=cmd_install)

    sp = add("uninstall", "uninstall a package")
    sp.add_argument("package"); sp.set_defaults(func=cmd_uninstall)

    sp = add("proxy", "point the device at Burp/Fiddler (global proxy + optional iptables)")
    sp.add_argument("target", nargs="?",
                    help="ip:port (or just a port -> emulator host 10.0.2.2), or 'off' / 'status'")
    sp.add_argument("-t", "--transparent", action="store_true",
                    help="also add iptables DNAT for 80/443 (ROOTED; catches proxy-ignoring apps like Flutter)")
    sp.set_defaults(func=cmd_proxy)

    sp = add("cert", "install a Burp/Fiddler CA into the device SYSTEM trust store (rooted)")
    sp.add_argument("cert", nargs="?", help="exported CA file (.der / .cer / .pem / .crt)")
    sp.add_argument("--user", action="store_true", help="also push to /sdcard for manual user-store install")
    sp.add_argument("--reboot", action="store_true", help="reboot the device after install (store re-read)")
    sp.set_defaults(func=cmd_cert)

    sp = add("flow", "pull -> merge -> (patch|gadget) -> install, one shot")
    sp.add_argument("package"); sp.add_argument("-o", "--out"); sp.add_argument("--apkeditor")
    sp.add_argument("--auto", action="store_true",
                    help="(default) pick patch by app type: native->apk-mitm, Flutter->static patch")
    sp.add_argument("--method", choices=["auto", "static", "reflutter", "gadget", "none"],
                    help="force the patch method (default: auto)")
    sp.add_argument("--gadget", action="store_true", help="inject Frida gadget instead of apk-mitm")
    sp.add_argument("--no-patch", action="store_true", help="skip patching entirely")
    sp.add_argument("--no-nsc", action="store_true", help="(gadget) don't add network-security-config")
    sp.add_argument("--install", action="store_true"); sp.add_argument("-g", "--grant", action="store_true")
    sp.set_defaults(func=cmd_flow)

    # --- instrumentation ---
    sp = add("frida-ps", "list apps/processes on the USB device")
    sp.add_argument("--apps", action="store_true", help="installed apps (-Uai)")
    sp.add_argument("--all", action="store_true", help="all processes (-U)")
    sp.set_defaults(func=cmd_frida_ps)

    sp = add("frida-server", "download + push + start frida-server (ROOTED devices)")
    sp.add_argument("--version", help="frida-server version (default: your local frida version)")
    sp.add_argument("--no-start", action="store_true", help="install but don't launch it")
    sp.add_argument("--stop", action="store_true", help="stop a running frida-server")
    sp.add_argument("--port", type=int, help="listen on a custom TCP port (anti-Frida evasion)")
    sp.add_argument("--stealth", action="store_true", help="rename the binary + random port to dodge scans")
    sp.set_defaults(func=cmd_frida_server)

    sp = add("hook", "run a Frida script (spawn / attach / gadget)")
    sp.add_argument("target", help="package name, process name, or 'Gadget'")
    sp.add_argument("-l", "--script", action="append", metavar="SCRIPT",
                    help="Frida JS script (repeat -l to load several)")
    sp.add_argument("--builtin", action="append",
                    choices=["ssl", "root", "trace", "flutter-ssl", "webview", "sqlite", "crypto"],
                    help="bundled script (repeatable; flutter-ssl needs the NVISO script)")
    sp.add_argument("--attach", action="store_true", help="attach by process name (-n)")
    sp.add_argument("--gadget", action="store_true", help="attach to a gadget-patched app")
    sp.set_defaults(func=cmd_hook)

    sp = add("objection", "launch an objection session")
    sp.add_argument("-g", "--gadget", help="gadget name (unrooted), e.g. Gadget or the package")
    sp.add_argument("-p", "--package", help="package (rooted frida-server)")
    sp.add_argument("--sslpinning", action="store_true", help="disable SSL pinning on startup")
    sp.add_argument("--root", action="store_true", help="disable root detection on startup")
    sp.add_argument("--startup-command", help="extra objection command to run on startup")
    sp.set_defaults(func=cmd_objection)

    sp = add("scripts", "write ready-to-run Frida hook scripts to disk")
    sp.add_argument("-o", "--out"); sp.set_defaults(func=cmd_scripts)

    # --- inspection ---
    sp = add("info", "package/version/sdk/permissions (aapt)")
    sp.add_argument("apk"); sp.set_defaults(func=cmd_info)

    sp = add("libs", "native .so per ABI + Flutter/native verdict (apk or split folder)")
    sp.add_argument("apk", help="an .apk or a pulled split folder"); sp.set_defaults(func=cmd_libs)

    sp = add("strings", "dump printable strings from inside the apk")
    sp.add_argument("apk"); sp.add_argument("--min", type=int, default=4)
    sp.add_argument("-g", "--grep"); sp.add_argument("--dex", action="store_true")
    sp.add_argument("--libs", action="store_true"); sp.add_argument("--utf16", action="store_true")
    sp.add_argument("--limit", type=int, default=0); sp.set_defaults(func=cmd_strings)

    sp = add("scan", "hunt for URLs / keys / tokens / secrets")
    sp.add_argument("apk"); sp.add_argument("--show", type=int, default=25)
    sp.add_argument("--cap", type=int, default=500); sp.set_defaults(func=cmd_scan)

    sp = add("decode", "apktool: smali + decoded resources")
    sp.add_argument("apk"); sp.add_argument("-o", "--out")
    sp.add_argument("--no-res", action="store_true"); sp.add_argument("--no-src", action="store_true")
    sp.set_defaults(func=cmd_decode)

    sp = add("decompile", "jadx: decompile to Java")
    sp.add_argument("apk"); sp.add_argument("-o", "--out"); sp.set_defaults(func=cmd_decompile)

    sp = add("blutter", "Flutter: dump Dart classes/methods + Frida script (Blutter)")
    sp.add_argument("target", help="an .apk, a pulled split folder, or a lib/arm64-v8a folder")
    sp.add_argument("-o", "--out"); sp.add_argument("--rebuild", action="store_true")
    sp.add_argument("--no-analysis", action="store_true",
                    help="skip code analysis (faster; works around analyzer crashes)")
    sp.set_defaults(func=cmd_blutter)

    sp = add("reflutter", "Flutter: patch apk to intercept HTTPS traffic (reFlutter)")
    sp.add_argument("apk"); sp.add_argument("--sign", action="store_true",
                    help="sign the patched apk afterwards")
    sp.set_defaults(func=cmd_reflutter)

    sp = add("flutter-patch", "Flutter: static libflutter.so TLS bypass (no Frida, no root)")
    sp.add_argument("apk", help="a merged .apk")
    sp.add_argument("--offset", help="ssl_verify_peer_cert offset (optional; auto-detected if omitted)")
    sp.set_defaults(func=cmd_flutter_patch)

    sp = add("logcat", "stream filtered logcat (find why an app self-closes)")
    sp.add_argument("package", nargs="?", help="package to follow (by pid); omit for full log")
    sp.add_argument("-g", "--grep", help="custom filter regex (default: detection keywords)")
    sp.add_argument("--all", action="store_true", help="don't filter - show everything")
    sp.add_argument("--no-clear", action="store_true", help="don't clear the buffer first")
    sp.set_defaults(func=cmd_logcat)

    sp = add("checks", "find root/emulator/tamper/integrity checks in smali (apktool)")
    sp.add_argument("apk")
    sp.add_argument("--decoded", help="use an existing apktool-decoded dir")
    sp.add_argument("--show", type=int, default=12, help="max hits shown per category")
    sp.add_argument("--neutralize", action="store_true",
                    help="strip self-kill calls (System.exit/killProcess/...) and rebuild+sign")
    sp.set_defaults(func=cmd_checks)

    sp = add("mitm", "one-shot: pull->merge->patch->install->cert->proxy->launch")
    sp.add_argument("package")
    sp.add_argument("--method", choices=["auto", "static", "reflutter", "gadget", "none"])
    sp.add_argument("--cert", help="CA file to install into the system store")
    sp.add_argument("--proxy", help="proxy ip:port to set on the device")
    sp.add_argument("-t", "--transparent", action="store_true", help="iptables transparent redirect (rooted)")
    sp.add_argument("--launch", action="store_true", help="launch the app when done")
    sp.add_argument("--off", action="store_true", help="teardown: clear proxy + uninstall the app")
    sp.set_defaults(func=lambda a: (cmd_mitm_off(resolve_serial(a), a.package) if a.off else cmd_mitm(a)))

    sp = add("emulator", "list AVDs, or launch one with RE-friendly flags")
    sp.add_argument("name", nargs="?", help="AVD name (omit to list)")
    sp.add_argument("--writable-system", action="store_true", help="mountable /system (persist system certs)")
    sp.add_argument("--proxy", help="launch with -http-proxy ip:port")
    sp.add_argument("--cold", action="store_true", help="cold boot (no snapshot)")
    sp.add_argument("--extra", help="extra raw flags passed to the emulator")
    sp.set_defaults(func=cmd_emulator)

    sp = add("batch", "run an inspection across every app under a folder")
    sp.add_argument("action", choices=["classify", "libs", "scan"], help="what to run on each")
    sp.add_argument("--dir", help="folder of apks / pulled_apks (default ./pulled_apks)")
    sp.set_defaults(func=cmd_batch)

    sp = add("update", "self-update: git pull the apkkit checkout")
    sp.set_defaults(func=cmd_update)

    sp = add("data", "inspect an app's /data/data (shared_prefs/db/files) via su - ROOTED")
    sp.add_argument("package")
    sp.add_argument("-g", "--grep", help="regex to search (default: common secret keys)")
    sp.add_argument("--prefs", action="store_true", help="dump all shared_prefs xml")
    sp.add_argument("--list", action="store_true", help="recursive listing of the data dir")
    sp.add_argument("--pull", action="store_true", help="copy the whole data dir to your work dir")
    sp.add_argument("-o", "--out", help="pull destination")
    sp.set_defaults(func=cmd_data)

    sp = add("doctor", "check external tools + show install steps")
    sp.add_argument("--json", action="store_true", help="machine-readable tool status")
    sp.set_defaults(func=cmd_doctor)

    sp = add("config", "show / set saved tool paths")
    sp.add_argument("--apkeditor"); sp.add_argument("--aapt"); sp.add_argument("--uber")
    sp.add_argument("--blutter", help="path to blutter.py")
    sp.add_argument("--workdir", help="where pulls/merges/patches are written (default: apkkit's own folder)")
    sp.set_defaults(func=cmd_config)

    return p



# --------------------------------------------------------------------------- #
# INTERACTIVE MENU  (run `apkkit` with no arguments)
# --------------------------------------------------------------------------- #
_ANIM = sys.stdout.isatty() and not os.environ.get("APKKIT_NOANIM")


class A:
    """Tiny args shim: any attribute not set defaults to None."""
    def __init__(self, **kw):
        self.__dict__.update(kw)
    def __getattr__(self, _):
        return None


def cls():
    if sys.stdout.isatty():
        os.system("cls" if os.name == "nt" else "clear")


def pause():
    try:
        input(dim("\n  press Enter to continue "))
    except (EOFError, KeyboardInterrupt):
        pass


def ask(q, default=""):
    suffix = dim(" [" + default + "]") if default else ""
    try:
        val = input(blu("  ? ") + q + suffix + ": ").strip()
    except (EOFError, KeyboardInterrupt):
        return default
    return val or default


def ask_yn(q, default=False):
    d = "Y/n" if default else "y/N"
    v = ask(q + " (" + d + ")").lower()
    if not v:
        return default
    return v.startswith("y")


def _browsable():
    """Folders under ./pulled_apks + loose .apk files in the current dir."""
    items = []
    pull = pull_dir()
    if os.path.isdir(pull):
        for name in sorted(os.listdir(pull)):
            p = os.path.join(pull, name)
            if os.path.isdir(p):
                items.append(p)
    items += sorted(glob.glob(os.path.join(work_dir(), "*.apk")))
    return items


def ask_target(prompt):
    """Ask for a path; if left blank, offer a numbered browse of ./pulled_apks + *.apk."""
    val = ask(prompt + dim(" (blank to browse)"))
    if val:
        return val
    items = _browsable()
    if not items:
        warn("Nothing to browse here - run apkkit from the folder with your pulled_apks.")
        return ask(prompt)
    print()
    for i, it in enumerate(items, 1):
        tag = "dir" if os.path.isdir(it) else "apk"
        print("  " + mag(str(i).rjust(2)) + ". " + dim("[" + tag + "] ") +
              (os.path.basename(it.rstrip("/\\")) or it))
    sel = ask("pick #")
    if sel.isdigit() and 1 <= int(sel) <= len(items):
        return items[int(sel) - 1]
    return sel


def banner_small():
    if _COLOR:
        print(blu(BANNER))
    else:
        print(BANNER)


def box(title):
    inner = " " + title + " "
    top = "╭" + "─" * len(inner) + "╮"
    mid = "│" + inner + "│"
    bot = "╰" + "─" * len(inner) + "╯"
    if _COLOR:
        print(blu(top) + "\n" + blu("│") + bold(inner) + blu("│") + "\n" + blu(bot))
    else:
        print("+" + "-" * len(inner) + "+\n|" + inner + "|\n+" + "-" * len(inner) + "+")


def startup_animation():
    if not _ANIM:
        return
    import time
    colors = [red, blu, grn]
    art = [
        r"   __ _ _ __ | | _| | _(_) |_",
        r"  / _` | '_ \| |/ / |/ / | __|",
        r" | (_| | |_) |   <|   <| | |_",
        r"  \__,_| .__/|_|\_\_|\_\_|\__|",
        r"       |_|",
    ]
    tags = ["booting", "loading tools", "ready"]
    for i, col in enumerate(colors):
        cls()
        print("\n")
        for line in art:
            print("  " + col(line))
        print("\n  " + dim(tags[i] + " ..."))
        time.sleep(0.22)


def _safe(fn):
    """Run a menu action; keep the menu alive even if it calls die()/need()."""
    try:
        fn()
    except SystemExit:
        pass
    except KeyboardInterrupt:
        print("\n" + yel("  cancelled."))
    except Exception as e:
        erro(str(e))
    pause()


def env_summary():
    tools = [("adb", have("adb")), ("frida", have("frida")),
             ("objection", have("objection")), ("apktool", have("apktool")),
             ("APKEditor", resolve_apkeditor()), ("java", have("java")),
             ("jadx", have("jadx")), ("aapt", resolve_aapt())]
    parts = []
    for name, found in tools:
        parts.append((grn if found else red)(("● " if found else "○ ") + name))
    print("  " + dim("environment: ") + "  ".join(parts))
    missing = [n for n, f in tools if not f]
    if missing:
        print("  " + dim("missing: " + ", ".join(missing) + "  → menu 6 (Doctor) for install steps"))


def run_menu(title, items, back_label="Back"):
    """items: list of (label, hint, action). action = callable or submenu func."""
    while True:
        cls()
        banner_small()
        box(title)
        print()
        for i, (label, hint, _) in enumerate(items, 1):
            print("  " + bold(mag(str(i).rjust(2))) + ". " + label)
            if hint:
                print("      " + dim(hint))
        print("  " + bold(mag(" 0")) + ". " + back_label + "\n")
        choice = ask("choose")
        if choice in ("0", "", "q"):
            return
        if not choice.isdigit() or not (1 <= int(choice) <= len(items)):
            warn("pick a number from the list.")
            pause()
            continue
        action = items[int(choice) - 1][2]
        if getattr(action, "_is_submenu", False):
            action()
        else:
            _safe(action)


def submenu(fn):
    fn._is_submenu = True
    return fn


# ---- pickers ------------------------------------------------------------- #
def pick_script():
    """Let the user choose a Frida script: built-ins + anything in SCRIPTS_DIR."""
    os.makedirs(SCRIPTS_DIR, exist_ok=True)
    builtins = [("ssl", "universal SSL pinning bypass (Java/OkHttp)"),
                ("root", "root-detection bypass"),
                ("trace", "method tracer (edit target)"),
                ("flutter-ssl", "Flutter BoringSSL bypass (needs NVISO script)"),
                ("webview", "WebView URL / JS-bridge inspector"),
                ("sqlite", "SQLite query logger"),
                ("crypto", "Cipher / hash monitor")]
    customs = sorted(f for f in os.listdir(SCRIPTS_DIR)
                     if f.endswith(".js") and f not in BUILTIN_SCRIPTS)
    print()
    for i, (k, d) in enumerate(builtins, 1):
        print("  " + mag(str(i)) + ". " + k.ljust(12) + dim(d))
    for j, f in enumerate(customs, len(builtins) + 1):
        print("  " + mag(str(j)) + ". " + f)
    print("  " + mag("p") + ". type a custom path")
    print(dim("  (pick one or several, comma-separated e.g. 1,3)"))
    sel = ask("script(s)")
    bkeys, paths = [], []
    for tok in sel.replace(" ", "").split(","):
        if not tok:
            continue
        if tok == "p":
            pth = ask("path to .js")
            if pth:
                paths.append(pth)
        elif tok.isdigit():
            n = int(tok)
            if 1 <= n <= len(builtins):
                bkeys.append(builtins[n - 1][0])
            elif len(builtins) < n <= len(builtins) + len(customs):
                paths.append(os.path.join(SCRIPTS_DIR, customs[n - len(builtins) - 1]))
    return bkeys, paths


def add_custom_script_interactive():
    box("Add a custom Frida script")
    print(dim("  Paste your JS. Finish with a single line containing only: EOF\n"))
    name = ask("script name (no .js)")
    if not name:
        return warn("name required.")
    lines = []
    while True:
        try:
            ln = input()
        except EOFError:
            break
        if ln.strip() == "EOF":
            break
        lines.append(ln)
    code = "\n".join(lines).strip()
    if not code:
        return warn("empty script, nothing saved.")
    os.makedirs(SCRIPTS_DIR, exist_ok=True)
    path = os.path.join(SCRIPTS_DIR, name + ".js")
    with open(path, "w", encoding="utf-8") as f:
        f.write(code + "\n")
    ok("saved " + path)


# ---- leaf actions -------------------------------------------------------- #
def act_pull():
    box("Pull an app")
    pkg = ask("package name (blank = browse installed apps)")
    cmd_pull(A(packages=[pkg] if pkg else [], out=None, vendor=False, system=False))


def act_merge():
    box("Merge split APKs")
    src = ask_target("folder of splits (or .xapk)")
    out = ask("output apk", "merged.apk")
    cmd_merge(A(input=src, out=out, force=True))


def act_patch():
    box("Strip cert pinning (apk-mitm)")
    cmd_patch(A(apk=ask_target("apk to patch")))


def act_gadget():
    box("Inject Frida gadget (UNROOTED)")
    apk = ask_target("apk to patch")
    nsc = ask_yn("add network-security-config so a proxy CA is trusted (MITM)?", True)
    sgn = ask_yn("re-sign with uber-apk-signer after? (recommended)", True)
    cmd_gadget(A(apk=apk, arch="auto", nsc=nsc, gadget_version=None,
                 startup_script=None, skip_resources=False, sign=sgn))


def act_sign():
    box("Sign an apk")
    cmd_sign(A(apk=ask_target("apk to sign"), keystore=None))


def act_install():
    box("Install")
    cmd_install(A(target=ask_target("apk file or split folder"),
                  grant=ask_yn("grant all runtime permissions?", False)))


def act_uninstall():
    box("Uninstall")
    cmd_uninstall(A(package=ask("package name")))


def act_flow():
    box("Full flow: pull → merge → patch → install")
    serial = resolve_serial(A())
    pkg = ask("package name (blank = browse the device)")
    if not pkg:
        pkg = choose_package(serial)
        if not pkg:
            return warn("no package chosen.")
    print("\n  " + bold("Patch method:"))
    opts = [
        ("auto", "recommended - by app type (Flutter → static, native → apk-mitm)"),
        ("static", "no Frida / no root (Flutter libflutter patch, or native apk-mitm)"),
        ("reflutter", "Flutter: reFlutter engine patch (traffic → proxy :8083)"),
        ("gadget", "Frida gadget (active instrumentation; pauses app to attach)"),
        ("none", "just pull → merge → install, no patching"),
    ]
    for i, (k, d) in enumerate(opts, 1):
        print("  " + mag(str(i)) + ". " + k.ljust(10) + dim(d))
    sel = ask("choose", "1")
    method = opts[int(sel) - 1][0] if sel.isdigit() and 1 <= int(sel) <= len(opts) else "auto"
    do_install = ask_yn("reinstall the result on the device?", True)
    cmd_flow(A(package=pkg, serial=serial, out=None, method=method, gadget=False,
               no_patch=False, no_nsc=False, install=do_install, grant=False))


def act_frida_ps():
    box("Processes on device")
    cmd_frida_ps(A(apps=ask_yn("only installed apps?", True), all=False))


def act_hook():
    box("Run a Frida hook")
    target = ask("target (package, process name, or 'Gadget')", "Gadget")
    bkeys, paths = pick_script()
    if not bkeys and not paths:
        return warn("no script chosen.")
    mode = ask("mode: [s]pawn  [a]ttach  [g]adget", "g").lower()
    cmd_hook(A(target=target, script=paths, builtin=bkeys,
               attach=mode.startswith("a"), gadget=mode.startswith("g")))


def act_objection():
    box("objection session")
    target = ask("gadget name (unrooted) or package", "Gadget")
    ssl = ask_yn("disable SSL pinning on startup?", True)
    root = ask_yn("disable root detection on startup?", False)
    cmd_objection(A(gadget=target, package=None, sslpinning=ssl, root=root,
                    startup_command=None))


def act_frida_server():
    box("frida-server (ROOTED devices)")
    cmd_frida_server(A(version=None))


@submenu
def menu_scripts():
    items = [
        ("Write the built-in scripts to disk", "ssl / root / trace / webview / sqlite / crypto",
         lambda: cmd_scripts(A(out=None))),
        ("Add a custom script (paste code)", "saved to " + SCRIPTS_DIR,
         add_custom_script_interactive),
        ("List saved scripts", None, _list_scripts),
    ]
    run_menu("Frida scripts", items)


def _list_scripts():
    os.makedirs(SCRIPTS_DIR, exist_ok=True)
    box("Saved scripts in " + SCRIPTS_DIR)
    files = sorted(f for f in os.listdir(SCRIPTS_DIR) if f.endswith(".js"))
    if not files:
        print(dim("  (none yet - use 'Write built-in scripts')"))
    for f in files:
        print("  • " + f)


def act_info():
    cmd_info(A(apk=ask("apk")))


def act_libs():
    cmd_libs(A(apk=ask("apk")))


def act_strings():
    box("Strings")
    apk = ask("apk")
    grep = ask("filter keyword (blank = all)")
    mn = ask("min length", "4")
    cmd_strings(A(apk=apk, min=int(mn) if mn.isdigit() else 4,
                  grep=grep or None, dex=False, libs=False, utf16=False, limit=0))


def act_scan():
    cmd_scan(A(apk=ask("apk"), show=25, cap=500))


def act_decode():
    cmd_decode(A(apk=ask("apk"), out=None, no_res=False, no_src=False))


def act_decompile():
    cmd_decompile(A(apk=ask("apk"), out=None))


def act_config():
    box("Set tool paths")
    j = ask("APKEditor.jar path (blank = skip)")
    u = ask("uber-apk-signer.jar path (blank = skip)")
    ap = ask("aapt/aapt2 path (blank = skip)")
    cmd_config(A(apkeditor=j or None, uber=u or None, aapt=ap or None))


# ---- submenus ------------------------------------------------------------ #
def act_cert():
    box("Install CA into system store (rooted)")
    c = ask_target("exported CA file (.der/.cer/.pem/.crt)")
    if not c:
        return warn("no file given.")
    also = ask_yn("also push to /sdcard for manual user-store install?", False)
    cmd_cert(A(cert=c, user=also))


def act_proxy():
    box("Device proxy for Burp / Fiddler")
    print("  " + mag("1") + ". set proxy    " + mag("2") + ". clear (off)    " + mag("3") + ". status")
    c = ask("choose", "1")
    if c == "2":
        return cmd_proxy(A(target="off"))
    if c == "3":
        return cmd_proxy(A(target="status"))
    tgt = ask("proxy ip:port (or just a port for an emulator)")
    if not tgt:
        return warn("nothing entered.")
    tr = ask_yn("also add iptables transparent redirect? (ROOTED; for Flutter/proxy-ignoring apps)", False)
    cmd_proxy(A(target=tgt, transparent=tr))


@submenu
def menu_device():
    run_menu("Device & packages", [
        ("List devices", "attached emulators/phones", lambda: cmd_devices(A())),
        ("List packages", "user apps (Google/Samsung hidden)",
         lambda: cmd_list(A(vendor=False, system=False, grep=ask("filter (blank=all)") or None))),
        ("Pull app(s)", "grab base + split APKs off the device", act_pull),
        ("Proxy (Burp/Fiddler)", "set/clear device proxy + iptables redirect", act_proxy),
        ("Install CA cert", "push a Burp/Fiddler CA into the system store (rooted)", act_cert),
    ])


@submenu
def menu_build():
    run_menu("Build, patch & install", [
        ("Merge splits", "split folder → one apk (APKEditor)", act_merge),
        ("Patch: strip cert pinning", "apk-mitm rebuild", act_patch),
        ("Inject Frida gadget (unrooted)", "objection patchapk + trust user CAs", act_gadget),
        ("Sign apk", "zipalign + sign", act_sign),
        ("Install", "apk or split folder", act_install),
        ("Uninstall", "remove a package", act_uninstall),
        ("FULL FLOW", "pull → merge → patch/gadget → install", act_flow),
    ])


@submenu
def menu_frida():
    run_menu("Frida & objection", [
        ("List processes", "frida-ps on the USB device", act_frida_ps),
        ("Run a hook script", "SSL / root bypass, tracer, or your own", act_hook),
        ("objection session", "interactive explore, sslpinning off", act_objection),
        ("Manage scripts", "write built-ins / add your own", menu_scripts),
        ("frida-server (rooted)", "download/push/run steps", act_frida_server),
    ])


def act_blutter():
    box("Blutter - Flutter/Dart static analysis")
    src = ask_target("apk, pulled split folder, or lib/arm64-v8a folder")
    na = ask_yn("skip code analysis? (faster; use if it crashed before)", False)
    cmd_blutter(A(target=src, out=None, rebuild=False, no_analysis=na))


def act_reflutter():
    box("reFlutter - intercept Flutter HTTPS traffic")
    apk = ask_target("apk to patch")
    sign = ask_yn("sign the patched apk afterwards?", True)
    cmd_reflutter(A(apk=apk, sign=sign))


def act_flutter_patch():
    box("Static Flutter TLS patch (no Frida / no root)")
    apk = ask_target("merged apk")
    off = ask("ssl_verify offset (blank = auto-detect)")
    cmd_flutter_patch(A(apk=apk, offset=off or None))


@submenu
def menu_flutter():
    run_menu("Flutter (Dart) tools", [
        ("Detect / native libs", "is it Flutter? which ABIs?",
         lambda: cmd_libs(A(apk=ask_target("apk or folder")))),
        ("Blutter — static analysis", "Dart class/method names + blutter_frida.js", act_blutter),
        ("reFlutter — MITM patch", "patch engine for HTTPS interception", act_reflutter),
        ("Static TLS patch", "NOP libflutter ssl_verify (no Frida/root)", act_flutter_patch),
    ])


@submenu
def menu_inspect():
    run_menu("Inspect an apk (no device needed)", [
        ("Info", "package / version / sdk / permissions", act_info),
        ("Native libs + framework", "ABIs, Flutter/RN/Unity/packer fingerprint", act_libs),
        ("Strings", "printable strings, with keyword filter", act_strings),
        ("Secret scan", "URLs, keys, tokens, JWTs", act_scan),
        ("Decode (apktool)", "smali + resources", act_decode),
        ("Decompile (jadx)", "readable Java", act_decompile),
    ])


def act_logcat():
    box("logcat (find why an app self-closes)")
    pkg = ask("package to follow (blank = full log)")
    cmd_logcat(A(package=pkg or None, grep=None, all=False, no_clear=False))


def act_checks():
    box("Anti-analysis checks (smali)")
    apk = ask_target("apk to inspect")
    if not apk:
        return warn("no apk.")
    neut = ask_yn("also strip self-kill calls (System.exit/killProcess) and rebuild?", False)
    cmd_checks(A(apk=apk, decoded=None, show=12, neutralize=neut))


def act_mitm():
    box("MITM setup (pull -> patch -> install -> cert -> proxy -> launch)")
    serial = resolve_serial(A())
    pkg = ask("package name (blank = browse)")
    if not pkg:
        pkg = choose_package(serial)
        if not pkg:
            return warn("no package chosen.")
    method = ask("patch method [auto/static/reflutter/gadget/none]", "auto")
    cert = ask("CA file to trust (blank = skip)")
    prox = ask("proxy ip:port (blank = skip)")
    tr = ask_yn("iptables transparent redirect (rooted)?", False) if prox else False
    launch = ask_yn("launch the app when done?", True)
    cmd_mitm(A(package=pkg, serial=serial, method=method, cert=cert or None,
               proxy=prox or None, transparent=tr, launch=launch, off=False))


def act_emulator():
    box("Emulator (AVDs)")
    name = ask("AVD name (blank = list)")
    if not name:
        return cmd_emulator(A(name=None))
    ws = ask_yn("writable system? (persist system certs)", True)
    prox = ask("launch with proxy ip:port (blank = none)")
    cold = ask_yn("cold boot?", False)
    cmd_emulator(A(name=name, writable_system=ws, proxy=prox or None, cold=cold, extra=None))


def act_batch():
    box("Batch inspect (all apps under a folder)")
    print("  " + mag("1") + ". classify (Flutter/native)   " + mag("2") + ". libs   " + mag("3") + ". scan")
    c = ask("choose", "1")
    action = {"1": "classify", "2": "libs", "3": "scan"}.get(c, "classify")
    d = ask("folder (blank = ./pulled_apks)")
    cmd_batch(A(action=action, dir=d or None))


def act_data():
    box("App data (shared_prefs / db / files) - ROOTED")
    serial = resolve_serial(A())
    pkg = ask("package (blank = browse)")
    if not pkg:
        pkg = choose_package(serial)
        if not pkg:
            return warn("no package chosen.")
    print("  " + mag("1") + ". grep secrets   " + mag("2") + ". dump shared_prefs   "
          + mag("3") + ". list tree   " + mag("4") + ". pull all")
    c = ask("choose", "1")
    if c == "2":
        cmd_data(A(package=pkg, serial=serial, prefs=True))
    elif c == "3":
        cmd_data(A(package=pkg, serial=serial, list=True))
    elif c == "4":
        cmd_data(A(package=pkg, serial=serial, pull=True))
    else:
        g = ask("grep regex (blank = default secret keys)")
        cmd_data(A(package=pkg, serial=serial, grep=g or None))


@submenu
def menu_diag():
    run_menu("Diagnostics & analysis", [
        ("logcat", "stream filtered logs (why does it close?)", act_logcat),
        ("checks", "find root/emulator/tamper checks in smali", act_checks),
        ("batch", "classify / libs / scan across all pulled apps", act_batch),
        ("app data", "shared_prefs / db / files grep (rooted)", act_data),
    ])


@submenu
def menu_net():
    run_menu("MITM & network", [
        ("MITM setup (one shot)", "patch + install + cert + proxy + launch", act_mitm),
        ("Proxy (Burp/Fiddler)", "set/clear device proxy + iptables", act_proxy),
        ("Install CA cert", "push a CA into the system store (rooted)", act_cert),
        ("Emulator (AVDs)", "list / launch a rooted AVD", act_emulator),
    ])


def interactive_menu():
    startup_animation()
    while True:
        cls()
        banner_small()
        env_summary()
        box("Main menu")
        print()
        rows = [
            ("Device & packages", "list, pull apps", menu_device),
            ("Build, patch & install", "merge / gadget / apk-mitm / sign / flow", menu_build),
            ("Frida & objection", "hooks, gadget attach, scripts", menu_frida),
            ("Inspect an apk", "info, libs, strings, scan, decode", menu_inspect),
            ("Flutter (Dart) tools", "Blutter static / reFlutter MITM", menu_flutter),
            ("MITM & network", "proxy, CA cert, emulator, one-shot MITM", menu_net),
            ("Diagnostics & analysis", "logcat, checks, batch", menu_diag),
            ("Doctor", "check tools + install instructions", lambda: cmd_doctor(A())),
            ("Config", "save tool paths", act_config),
        ]
        for i, (label, hint, _) in enumerate(rows, 1):
            print("  " + bold(mag(str(i))) + ". " + bold(label))
            print("     " + dim(hint))
        print("  " + bold(mag("0")) + ". Exit\n")
        choice = ask("choose")
        if choice in ("0", "q", "exit"):
            cls()
            print(grn("  stay sharp. ✓") if _COLOR else "  bye")
            return
        if not choice.isdigit() or not (1 <= int(choice) <= len(rows)):
            warn("pick a number.")
            pause()
            continue
        action = rows[int(choice) - 1][2]
        if getattr(action, "_is_submenu", False):
            action()
        else:
            _safe(action)


def main():
    parser = build_parser()
    args = parser.parse_args()
    if not getattr(args, "cmd", None):
        # No subcommand -> friendly interactive menu.
        try:
            interactive_menu()
        except KeyboardInterrupt:
            print("\n" + yel("bye."))
        return
    if args.cmd == "menu":
        try:
            interactive_menu()
        except KeyboardInterrupt:
            print("\n" + yel("bye."))
        return
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n" + yel("interrupted."))
        sys.exit(130)


if __name__ == "__main__":
    main()

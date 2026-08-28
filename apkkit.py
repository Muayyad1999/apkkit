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
    flow      pull -> merge -> (patch | gadget) -> install, one shot

Dynamic instrumentation (the unrooted-friendly part):
    frida-ps      list apps/processes on the USB device
    frida-server  download + push + start frida-server (ROOTED devices)
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
    doctor    check external tools + show how to install missing ones
    config    show / set saved tool paths (~/.apkkit.json)

Unrooted quick start (MITM a pinned app):
    apkkit gadget app.apk --arch auto --nsc     # inject gadget + trust user CAs
    apkkit install app.objection.apk
    apkkit hook Gadget --builtin ssl            # or: apkkit objection -g Gadget --sslpinning

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
import subprocess
import sys
import tempfile
import zipfile

__version__ = "0.3"

HOME = os.path.expanduser("~")
CONFIG_PATH = os.path.join(HOME, ".apkkit.json")
DEFAULT_PULL_DIR = os.path.join(os.getcwd(), "pulled_apks")
SCRIPTS_DIR = os.path.join(HOME, ".apkkit", "scripts")

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


def run_live(cmd, env=None):
    print(dim("  $ " + " ".join(_quote(a) for a in cmd)))
    try:
        return subprocess.run(cmd, env=env).returncode
    except FileNotFoundError:
        erro("Not found: " + cmd[0])
        return 127
    except KeyboardInterrupt:
        print("\n" + yel("  interrupted."))
        return 130


def adb(args, serial=None, check=False):
    cmd = ["adb"] + (["-s", serial] if serial else []) + args
    try:
        p = subprocess.run(cmd, capture_output=True, text=True)
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
        c = input("Use which device?  # ").strip()
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
    out_dir = args.out or DEFAULT_PULL_DIR
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
    rc = run_live(cmd)
    out = _base(apk) + ".objection.apk"
    if os.path.isfile(out):
        ok("patched apk: " + out)
        install_target = out
        if args.sign:
            print()
            info("re-signing with uber-apk-signer (objection's own signing is flaky on Windows) ...")
            cmd_sign(A(apk=out, keystore=None))
            signed = _base(out) + "-aligned-debugSigned.apk"
            if os.path.isfile(signed):
                install_target = signed
        else:
            print(dim("  If install fails with a certificate error, run: ") + "apkkit sign " + _quote(out))
        print(dim("\n  The app PAUSES on launch until you attach Frida.\n  Next:"))
        print("    apkkit install " + _quote(install_target))
        print("    apkkit hook Gadget --builtin ssl")
        print("    apkkit objection -g Gadget --sslpinning")
    else:
        erro("objection patchapk exited " + str(rc) + " - no output apk.")
        print(dim("  Common fixes: ensure apktool + a JDK are on PATH; try --skip-resources."))


def cmd_frida_ps(args):
    if not have("frida-ps"):
        need("python-frida", "frida-ps")
    hdr("Apps / processes on USB device")
    mode = "-Uai" if args.apps else "-Ua"
    if args.all:
        mode = "-U"
    run_live(["frida-ps", mode])


def cmd_hook(args):
    if not have("frida"):
        need("python-frida", "frida")
    script = args.script
    if args.builtin:
        script = _ensure_builtin_script(args.builtin)
        info("using built-in script: " + script)
    if not script or not os.path.isfile(script):
        die("No script to run. Pass -l <script.js> or --builtin ssl|root|trace.")

    target = args.target
    hdr("Frida hook: " + target)
    base = ["frida", "-U"]
    if args.gadget:
        # gadget is already running inside the app; attach by its name (Gadget)
        cmd = base + [target, "-l", script]
        info("attaching to gadget process '" + target + "'")
    elif args.attach:
        cmd = base + ["-n", target, "-l", script]
        info("attaching to running process by name")
    else:
        cmd = base + ["-f", target, "-l", script, "--no-pause"]
        info("spawning package and injecting at startup")
    print(dim("  (Ctrl+C / 'exit' to detach)\n"))
    run_live(cmd)


def cmd_objection(args):
    if not have("objection"):
        need("objection")
    target = args.gadget or args.package
    if not target:
        die("Pass -g <gadget-name> (unrooted) or -p <package> (rooted frida-server).")
    hdr("objection explore: " + target)
    cmd = ["objection", "-g", target, "explore"]
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


def cmd_frida_server(args):
    """ROOTED-device helper: download frida-server for the device ABI, push, run."""
    if IS_WIN and not have("adb"):
        need("adb")
    serial = resolve_serial(args)
    abi = device_abi(serial)
    fmap = {"arm64-v8a": "arm64", "armeabi-v7a": "arm", "x86_64": "x86_64", "x86": "x86"}
    farch = fmap.get(abi, "arm64")
    hdr("frida-server setup (ROOTED only)")
    warn("This pushes and runs frida-server as root. Unrooted device? Use `gadget` instead.")
    ver = args.version
    if not ver:
        if not have("frida"):
            need("python-frida", "frida")
        p = subprocess.run(["frida", "--version"], capture_output=True, text=True)
        ver = (p.stdout or "").strip() or "16.0.0"
    info("matching frida-server " + ver + " for " + abi + " (" + farch + ")")
    print(dim("  Download the matching binary from:"))
    print("    https://github.com/frida/frida/releases  ->  frida-server-" + ver + "-android-" + farch + ".xz")
    print(dim("  Then, with the device rooted:"))
    for line in [
        "adb -s %s push frida-server /data/local/tmp/frida-server" % serial,
        "adb -s %s shell \"su -c 'chmod 755 /data/local/tmp/frida-server'\"" % serial,
        "adb -s %s shell \"su -c '/data/local/tmp/frida-server &'\"" % serial,
    ]:
        print("    " + line)
    print(dim("  Verify from your PC: ") + "frida-ps -U")


def cmd_sign(args):
    apk = args.apk
    if not os.path.isfile(apk):
        die("Not found: " + apk)
    hdr("Sign " + apk)
    uber = resolve_uber()
    if uber and have("java"):
        info("using uber-apk-signer (zipalign + sign in one step)")
        rc = run_live(["java", "-jar", uber, "-a", apk, "--allowResign"])
        if rc == 0:
            ok("signed. Look for *-aligned-*Signed.apk beside the input.")
        else:
            erro("uber-apk-signer exited " + str(rc))
        return
    if have("apksigner") and have("zipalign"):
        aligned = _base(apk) + "-aligned.apk"
        info("zipalign -> " + aligned)
        if run_live(["zipalign", "-f", "-p", "4", apk, aligned]) != 0:
            return erro("zipalign failed")
        ks = args.keystore or os.path.join(HOME, ".apkkit", "debug.keystore")
        if not os.path.isfile(ks):
            os.makedirs(os.path.dirname(ks), exist_ok=True)
            info("creating a debug keystore at " + ks)
            run_live(["keytool", "-genkey", "-v", "-keystore", ks, "-alias", "apkkit",
                      "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
                      "-storepass", "apkkit", "-keypass", "apkkit",
                      "-dname", "CN=apkkit"])
        rc = run_live(["apksigner", "sign", "--ks", ks, "--ks-pass", "pass:apkkit",
                       "--key-pass", "pass:apkkit", aligned])
        (ok if rc == 0 else erro)("apksigner exited " + str(rc) + " -> " + aligned)
        return
    erro("No signer found.")
    hint("uber-apk-signer")
    hint("apksigner")


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
        print("   3) Re-run:  apkkit hook Gadget --builtin flutter-ssl")
        sys.exit(1)
    fname = {"ssl": "ssl-bypass.js", "root": "root-bypass.js", "trace": "trace.js"}.get(kind)
    if not fname:
        die("Unknown built-in '" + kind + "'. Choose: ssl | root | trace | flutter-ssl.")
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
 * Run:  frida -U -f <pkg> -l ssl-bypass.js --no-pause
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
 * Run:  frida -U -f <pkg> -l root-bypass.js --no-pause
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
 * Run:  frida -U -f <pkg> -l trace.js --no-pause
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

BUILTIN_SCRIPTS = {
    "ssl-bypass.js": SSL_BYPASS_JS,
    "root-bypass.js": ROOT_BYPASS_JS,
    "trace.js": TRACE_JS,
}
BUILTIN_DESC = {
    "ssl-bypass.js": "universal SSL/TLS pinning bypass",
    "root-bypass.js": "common root-detection bypass",
    "trace.js": "method call tracer (edit target)",
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
    p = subprocess.run([aapt, "dump", "badging", apk], capture_output=True, text=True)
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
    hdr("apkkit doctor")
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
    print(dim("\n  config: " + CONFIG_PATH + (" (present)" if os.path.isfile(CONFIG_PATH) else " (none yet)")))
    print(dim("  scripts: " + SCRIPTS_DIR))


def cmd_config(args):
    changed = False
    for attr, key in (("apkeditor", "apkeditor"), ("aapt", "aapt"), ("uber", "uber"), ("blutter", "blutter")):
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
    run_live(cmd)
    cand = _base(merged) + ".objection.apk"
    if not os.path.isfile(cand):
        warn("no *.objection.apk produced; using merged apk.")
        return merged
    ok("gadget injected: " + cand)
    if resolve_uber():
        cmd_sign(A(apk=cand, keystore=None))
        signed = _base(cand) + "-aligned-debugSigned.apk"
        if os.path.isfile(signed):
            return signed
    return cand


def cmd_flow(args):
    serial = resolve_serial(args)
    pkg = args.package
    out_dir = args.out or DEFAULT_PULL_DIR
    mode = "gadget" if args.gadget else ("none" if args.no_patch else "apk-mitm")
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
    merged = os.path.join(os.getcwd(), pkg + "-merged.apk")
    if run_live(["java", "-jar", jar, "m", "-i", dest, "-o", merged, "-f"]) != 0 \
            or not os.path.isfile(merged):
        die("merge failed.")
    ok("merged: " + merged)

    final = merged
    step(3, total, "Patch")
    flut = is_flutter(merged)
    print("  " + dim("app type: ") + (mag("Flutter (Dart)") if flut else grn("native Java/Kotlin")))

    # choose the patch method
    if args.no_patch:
        method = "none"
    elif args.auto:
        method = "reflutter" if flut else "gadget"
        info("auto-selected: " + bold(method) +
             (dim("  (Flutter TLS needs reFlutter)") if flut else dim("  (unrooted MITM via Frida gadget)")))
    elif args.gadget:
        method = "gadget"
    else:
        method = "apk-mitm"

    if flut and method == "apk-mitm":
        warn("apk-mitm can't intercept Flutter traffic - switching to reFlutter.")
        method = "reflutter"
    if flut and method == "gadget":
        warn("gadget lets you run Frida, but Flutter TLS won't be intercepted - "
             "use reFlutter for traffic.")

    if method == "gadget":
        final = _flow_gadget(merged, serial, args.no_nsc)
    elif method == "reflutter":
        if not have("reflutter"):
            warn("reflutter not installed - skipping patch.")
            hint("reflutter")
        else:
            info("reFlutter will ask for your proxy IP (traffic -> that IP on :8083).")
            run_live(["reflutter", merged])
            cands = []
            for d in {os.getcwd(), os.path.dirname(os.path.abspath(merged))}:
                cands += glob.glob(os.path.join(d, "*.RE.apk"))
            if cands:
                final = sorted(cands)[0]
                ok("reFlutter patched: " + final)
                cmd_sign(A(apk=final, keystore=None))
                signed = _base(final) + "-aligned-debugSigned.apk"
                if os.path.isfile(signed):
                    final = signed
            else:
                warn("reFlutter can't patch this app's engine (unsupported/debug snapshot).")
                info("falling back to Frida gadget so you still get an instrumentable build.")
                info("for traffic you'll need a Flutter TLS bypass - see the notes after this run.")
                final = _flow_gadget(merged, serial, args.no_nsc)
                method = "gadget-fallback"
    elif method == "none":
        info("skipping patch (--no-patch).")
    else:
        runner = resolve_apkmitm()
        if not runner:
            warn("apk-mitm not found - skipping patch.")
            hint("apk-mitm")
        else:
            run_live(runner + [merged])
            cand = _base(merged) + "-patched.apk"
            if os.path.isfile(cand):
                final = cand
                ok("patched: " + cand)

    # never try to install an unsigned apk (raw APKEditor output won't verify)
    if args.install and not (final.endswith("Signed.apk") or final.endswith("-patched.apk")):
        if resolve_uber():
            info("signing the apk before install ...")
            cmd_sign(A(apk=final, keystore=None))
            s = _base(final) + "-aligned-debugSigned.apk"
            if os.path.isfile(s):
                final = s
        else:
            warn("apk is unsigned and uber-apk-signer isn't set - install may fail. "
                 "Run: apkkit config --uber <path>")

    if args.install:
        step(total, total, "Install")
        adb(["uninstall", pkg], serial=serial)
        rc = run_live(["adb", "-s", serial, "install", "-r"] +
                      (["-g"] if args.grant else []) + [final])
        (ok if rc == 0 else erro)("install exited " + str(rc))

    hdr("Flow complete")
    print("  final apk: " + bold(final))
    if method in ("gadget", "gadget-fallback"):
        print(dim("  Attach Frida: ") + "apkkit hook Gadget --builtin ssl")
        if method == "gadget-fallback":
            print(dim("  (Flutter app: for TRAFFIC you need a Flutter TLS bypass, not the Java ssl script.)"))
    elif method == "reflutter":
        print(dim("  Set the device proxy to <your-ip>:8083 and watch traffic in Burp."))


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
    for n in z.namelist():
        if n.startswith(subdir) and not n.endswith("/"):
            data = z.read(n)
            dest = os.path.join(out, n.replace("/", os.sep))
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as f:
                f.write(data)
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
        print(dim("  Run them: ") + "apkkit hook <pkg-or-Gadget> -l " + _quote(frida_js))
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
    rc = run_live(["reflutter", apk])
    cands = []
    for d in {os.getcwd(), os.path.dirname(os.path.abspath(apk))}:
        cands += glob.glob(os.path.join(d, "*.RE.apk"))
    out = sorted(cands)[0] if cands else None
    if not out:
        warn("Couldn't locate release.RE.apk - check reFlutter's output above.")
        return
    ok("patched: " + out)
    if args.sign:
        cmd_sign(A(apk=out, keystore=None))
    else:
        print(dim("  Next: ") + "apkkit sign " + _quote(out) + dim("  then  ") + "apkkit install <signed>")
    print(dim("  On the device: set proxy to <your-ip>:8083 (or manual proxy) and trust your CA."))


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

    def add(name, help):
        return sub.add_parser(name, help=help)

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

    sp = add("flow", "pull -> merge -> (patch|gadget) -> install, one shot")
    sp.add_argument("package"); sp.add_argument("-o", "--out"); sp.add_argument("--apkeditor")
    sp.add_argument("--auto", action="store_true",
                    help="pick the patch method from the app type (native->gadget, Flutter->reFlutter)")
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

    sp = add("frida-server", "download/push/start frida-server (ROOTED devices)")
    sp.add_argument("--version"); sp.set_defaults(func=cmd_frida_server)

    sp = add("hook", "run a Frida script (spawn / attach / gadget)")
    sp.add_argument("target", help="package name, process name, or 'Gadget'")
    sp.add_argument("-l", "--script", help="path to a Frida JS script")
    sp.add_argument("--builtin", choices=["ssl", "root", "trace", "flutter-ssl"],
                    help="bundled script (flutter-ssl = Flutter BoringSSL bypass, needs the NVISO script)")
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

    sp = add("doctor", "check external tools + show install steps")
    sp.set_defaults(func=cmd_doctor)

    sp = add("config", "show / set saved tool paths")
    sp.add_argument("--apkeditor"); sp.add_argument("--aapt"); sp.add_argument("--uber")
    sp.add_argument("--blutter", help="path to blutter.py")
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
    pull = os.path.join(os.getcwd(), "pulled_apks")
    if os.path.isdir(pull):
        for name in sorted(os.listdir(pull)):
            p = os.path.join(pull, name)
            if os.path.isdir(p):
                items.append(p)
    items += sorted(glob.glob(os.path.join(os.getcwd(), "*.apk")))
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
                ("flutter-ssl", "Flutter BoringSSL bypass (needs NVISO script)")]
    customs = sorted(f for f in os.listdir(SCRIPTS_DIR)
                     if f.endswith(".js") and f not in BUILTIN_SCRIPTS)
    print()
    for i, (k, d) in enumerate(builtins, 1):
        print("  " + mag(str(i)) + ". " + k.ljust(8) + dim(d))
    for j, f in enumerate(customs, len(builtins) + 1):
        print("  " + mag(str(j)) + ". " + f)
    print("  " + mag("p") + ". type a custom path")
    c = ask("script")
    if c == "p":
        return None, ask("path to .js")
    if c.isdigit():
        n = int(c)
        if 1 <= n <= len(builtins):
            return builtins[n - 1][0], None            # builtin key
        if len(builtins) < n <= len(builtins) + len(customs):
            return None, os.path.join(SCRIPTS_DIR, customs[n - len(builtins) - 1])
    return None, None


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
    box("Full flow: pull → merge → auto-patch → install")
    serial = resolve_serial(A())
    pkg = ask("package name (blank = browse the device)")
    if not pkg:
        pkg = choose_package(serial)
        if not pkg:
            return warn("no package chosen.")
    do_install = ask_yn("reinstall the result on the device?", True)
    info("patch method will be auto-picked from the app type (native → gadget, Flutter → reFlutter).")
    cmd_flow(A(package=pkg, serial=serial, out=None, auto=True, gadget=False,
               no_patch=False, no_nsc=False, install=do_install, grant=False))


def act_frida_ps():
    box("Processes on device")
    cmd_frida_ps(A(apps=ask_yn("only installed apps?", True), all=False))


def act_hook():
    box("Run a Frida hook")
    target = ask("target (package, process name, or 'Gadget')", "Gadget")
    builtin, path = pick_script()
    mode = ask("mode: [s]pawn  [a]ttach  [g]adget", "g").lower()
    cmd_hook(A(target=target, script=path, builtin=builtin,
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
        ("Write the 3 built-in scripts to disk", "ssl-bypass / root-bypass / trace",
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
@submenu
def menu_device():
    run_menu("Device & packages", [
        ("List devices", "attached emulators/phones", lambda: cmd_devices(A())),
        ("List packages", "user apps (Google/Samsung hidden)",
         lambda: cmd_list(A(vendor=False, system=False, grep=ask("filter (blank=all)") or None))),
        ("Pull app(s)", "grab base + split APKs off the device", act_pull),
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


@submenu
def menu_flutter():
    run_menu("Flutter (Dart) tools", [
        ("Detect / native libs", "is it Flutter? which ABIs?",
         lambda: cmd_libs(A(apk=ask("apk")))),
        ("Blutter — static analysis", "Dart class/method names + blutter_frida.js", act_blutter),
        ("reFlutter — MITM patch", "the only way to intercept Flutter HTTPS", act_reflutter),
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

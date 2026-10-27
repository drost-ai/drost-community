"""Android debugging helpers for the Drost container."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Sequence

FRIDA_DIR = Path("/opt/drost-android/frida")
DEFAULT_PROXY_PORT = 8080


class AndroidError(RuntimeError):
    """Raised when an Android command cannot complete."""


def _run(
    argv: Sequence[str],
    *,
    check: bool = True,
    capture: bool = True,
    **kwargs: Any,
) -> subprocess.CompletedProcess[str]:
    command = [str(item) for item in argv]
    try:
        result = subprocess.run(command, text=True, capture_output=capture, **kwargs)
    except FileNotFoundError as exc:
        raise AndroidError(f"required command not found: {command[0]}") from exc
    if check and result.returncode != 0:
        detail = ((result.stderr or "") + (result.stdout or "")).strip()
        message = f"command failed ({result.returncode}): {' '.join(command)}"
        if detail:
            message += f"\n{detail}"
        raise AndroidError(message)
    return result


def _adb(
    serial: str,
    *args: str,
    check: bool = True,
    capture: bool = True,
    **kwargs: Any,
) -> subprocess.CompletedProcess[str]:
    return _run(["adb", "-s", serial, *args], check=check, capture=capture, **kwargs)


def _parse_devices(output: str) -> list[dict[str, str]]:
    devices: list[dict[str, str]] = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 2:
            continue
        entry = {"serial": parts[0], "state": parts[1]}
        for token in parts[2:]:
            if ":" in token:
                key, value = token.split(":", 1)
                entry[key] = value
        devices.append(entry)
    return devices


def adb_devices() -> list[dict[str, str]]:
    return _parse_devices(_run(["adb", "devices", "-l"]).stdout)


def resolve_serial(explicit: str | None = None) -> str:
    serial = explicit or os.environ.get("DROST_ANDROID_SERIAL")
    if serial:
        return serial
    devices = adb_devices()
    ready = [item for item in devices if item.get("state") == "device"]
    if len(ready) == 1:
        return ready[0]["serial"]
    if not ready:
        found = ", ".join(f"{item['serial']} ({item['state']})" for item in devices)
        suffix = f"; found: {found}" if found else ""
        raise AndroidError(
            "no authorized Android device is connected"
            f"{suffix}; run `drost-android connect <host:port>` or "
            "`drost-android pair <host:port> <code>`"
        )
    serials = ", ".join(item["serial"] for item in ready)
    raise AndroidError(f"multiple Android devices are connected; pass --serial: {serials}")


def state_dir() -> Path:
    configured = os.environ.get("DROST_ANDROID_STATE")
    candidates = [Path(configured)] if configured else []
    workspace = Path("/workspace")
    if workspace.is_dir():
        candidates.append(workspace / ".drost-android")
    candidates.append(Path.home() / ".drost-android")
    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
        except OSError:
            continue
        if os.access(candidate, os.W_OK):
            return candidate
    raise AndroidError("no writable state directory; set DROST_ANDROID_STATE")


def _print_json(payload: Any) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _terminate(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return
    for _ in range(20):
        if not _pid_alive(pid):
            return
        time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def _checked(
    result: subprocess.CompletedProcess[str],
    command: str,
    check: bool,
) -> subprocess.CompletedProcess[str]:
    if check and result.returncode != 0:
        detail = ((result.stderr or "") + (result.stdout or "")).strip()
        message = f"device command failed ({result.returncode}): {command}"
        if detail:
            message += f"\n{detail}"
        raise AndroidError(message)
    return result


def _is_root(serial: str) -> bool:
    if "uid=0" in (_adb(serial, "shell", "id", check=False).stdout or ""):
        return True
    result = _adb(serial, "shell", "su", "-c", "id", check=False)
    return "uid=0" in (result.stdout or "")


def root_shell(
    serial: str,
    command: str,
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    if "uid=0" in (_adb(serial, "shell", "id", check=False).stdout or ""):
        return _checked(_adb(serial, "shell", command, check=False), command, check)
    _adb(serial, "root", check=False)
    time.sleep(1)
    if "uid=0" in (_adb(serial, "shell", "id", check=False).stdout or ""):
        return _checked(_adb(serial, "shell", command, check=False), command, check)
    su_id = _adb(serial, "shell", "su", "-c", "id", check=False)
    if "uid=0" not in (su_id.stdout or ""):
        raise AndroidError(
            "root is required for this command; use a rooted device or emulator, "
            "or patch the APK with `drost-android patch-apk`"
        )
    return _checked(_adb(serial, "shell", "su", "-c", command, check=False), command, check)


def _props(serial: str) -> dict[str, str]:
    text = _adb(serial, "shell", "getprop").stdout or ""
    props: dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith("[") and "]: [" in line:
            key, value = line[1:].split("]: [", 1)
            props[key] = value[:-1] if value.endswith("]") else value
    return props


def _emit(result: subprocess.CompletedProcess[str]) -> int:
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    return result.returncode


def _error_detail(result: subprocess.CompletedProcess[str]) -> str:
    text = ((result.stderr or "") + (result.stdout or "")).strip()
    lines = [line for line in text.splitlines() if "error" in line.casefold()]
    return "\n".join(lines[-10:]) if lines else text[-2000:]


def _run_with_timeout(argv: Sequence[str], timeout: int) -> int:
    try:
        process = subprocess.Popen(
            [str(item) for item in argv],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except FileNotFoundError as exc:
        raise AndroidError(f"required command not found: {argv[0]}") from exc
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except OSError:
            process.terminate()
        output, _ = process.communicate()
        if output:
            print(output, end="")
        print(f"\n[stopped after {timeout}s]", file=sys.stderr)
        return 124
    if output:
        print(output, end="")
    return process.returncode


def cmd_devices(args: argparse.Namespace) -> int:
    _print_json(adb_devices())
    return 0


def cmd_connect(args: argparse.Namespace) -> int:
    result = _run(["adb", "connect", args.address], check=False)
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    if result.returncode != 0 or "connected" not in output.lower():
        raise AndroidError(output or f"failed to connect to {args.address}")
    print(output)
    _print_json(adb_devices())
    return 0


def cmd_pair(args: argparse.Namespace) -> int:
    result = _run(["adb", "pair", args.address, args.code], check=False)
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    if result.returncode != 0:
        raise AndroidError(output or "pairing failed")
    print(output)
    return 0


def cmd_disconnect(args: argparse.Namespace) -> int:
    argv = ["adb", "disconnect"]
    if args.address:
        argv.append(args.address)
    result = _run(argv, check=False)
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    if output:
        print(output)
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    props = _props(serial)
    proxy = (_adb(serial, "shell", "settings", "get", "global", "http_proxy", check=False).stdout or "").strip()
    reverse = [
        line
        for line in (_adb(serial, "reverse", "--list", check=False).stdout or "").splitlines()
        if line.strip()
    ]
    _print_json(
        {
            "serial": serial,
            "root": _is_root(serial),
            "model": props.get("ro.product.model"),
            "manufacturer": props.get("ro.product.manufacturer"),
            "android": props.get("ro.build.version.release"),
            "sdk": props.get("ro.build.version.sdk"),
            "abi": props.get("ro.product.cpu.abi"),
            "build_tags": props.get("ro.build.tags"),
            "debuggable": props.get("ro.debuggable"),
            "secure": props.get("ro.secure"),
            "http_proxy": None if proxy in ("", "null", ":0") else proxy,
            "reverse": reverse,
        }
    )
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    commands: dict[str, list[str]] = {
        "adb": ["adb", "--version"],
        "frida": ["frida", "--version"],
        "frida-ps": ["frida-ps", "--version"],
        "frida-trace": ["frida-trace", "--version"],
        "objection": ["objection", "version"],
        "apktool": ["apktool", "--version"],
        "jadx": ["jadx", "--version"],
        "mitmdump": ["mitmdump", "--version"],
        "openssl": ["openssl", "version"],
        "java": ["java", "-version"],
        "aapt": ["aapt", "version"],
        "aapt2": ["aapt2", "version"],
        "zipalign": ["zipalign"],
        "apksigner": ["apksigner", "--version"],
    }
    report: dict[str, Any] = {}
    for name, argv in commands.items():
        path = shutil.which(name)
        entry: dict[str, Any] = {"path": path}
        if path:
            result = _run(argv, check=False)
            text = ((result.stdout or "") + (result.stderr or "")).strip()
            entry["version"] = text.splitlines()[0] if text else None
        report[name] = entry
    report["frida_server_binaries"] = (
        sorted(str(item) for item in FRIDA_DIR.glob("frida-server-*")) if FRIDA_DIR.is_dir() else []
    )
    try:
        report["state_dir"] = str(state_dir())
    except AndroidError:
        report["state_dir"] = None
    _print_json(report)
    return 0


def cmd_shell(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    return _emit(_adb(serial, "shell", *args.command, check=False))


def cmd_install(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    apks = [str(Path(item)) for item in args.apks]
    for apk in apks:
        if not Path(apk).is_file():
            raise AndroidError(f"APK not found: {apk}")
    if len(apks) == 1:
        argv = ["adb", "-s", serial, "install", "-r", "-d", "-g", apks[0]]
    else:
        argv = ["adb", "-s", serial, "install-multiple", "-r", "-d", "-g", *apks]
    result = _run(argv, check=False)
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    if output:
        print(output)
    if result.returncode != 0:
        raise AndroidError("APK installation failed")
    return 0


def cmd_uninstall(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    argv = ["adb", "-s", serial, "uninstall"]
    if args.keep_data:
        argv.append("-k")
    argv.append(args.package)
    result = _run(argv, check=False)
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    if output:
        print(output)
    if result.returncode != 0:
        raise AndroidError(f"uninstall failed: {args.package}")
    return 0


def cmd_clear(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    result = _adb(serial, "shell", "pm", "clear", args.package, check=False)
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    if output:
        print(output)
    if result.returncode != 0 or "Success" not in output:
        raise AndroidError(f"clear failed: {args.package}")
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    return _emit(_adb(serial, "shell", "am", "force-stop", args.package, check=False))


def _resolve_launcher_activity(serial: str, package: str) -> str | None:
    result = _adb(
        serial,
        "shell",
        "cmd",
        "package",
        "resolve-activity",
        "--brief",
        package,
        check=False,
    )
    for line in reversed((result.stdout or "").splitlines()):
        candidate = line.strip()
        if candidate.startswith(f"{package}/"):
            return candidate
    return None


def cmd_launch(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    if args.activity:
        component = f"{args.package}/{args.activity}"
    else:
        component = _resolve_launcher_activity(serial, args.package)
    if component:
        result = _adb(serial, "shell", "am", "start", "-n", component, check=False)
    else:
        result = _adb(
            serial,
            "shell",
            "monkey",
            "-p",
            args.package,
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
            check=False,
        )
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    if output:
        print(output)
    if result.returncode != 0 or "Error" in output or "No activities found" in output:
        message = f"launch failed: {args.package}"
        if args.activity:
            message += (
                "; check the activity name with "
                "`adb shell cmd package resolve-activity --brief <package>`."
            )
        else:
            message += (
                "; no launcher activity was resolved. Pass --activity <activity> or inspect "
                "`adb shell cmd package resolve-activity --brief <package>`."
            )
        detail = _error_detail(result)
        if detail:
            message += f"\n{detail}"
        raise AndroidError(message)
    return 0


def cmd_packages(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    argv = ["adb", "-s", serial, "shell", "pm", "list", "packages"]
    if args.system:
        argv.append("-s")
    if args.third_party:
        argv.append("-3")
    result = _run(argv, check=False)
    packages = sorted(
        line.removeprefix("package:").strip()
        for line in (result.stdout or "").splitlines()
        if line.startswith("package:")
    )
    if args.filter:
        needle = args.filter.casefold()
        packages = [item for item in packages if needle in item.casefold()]
    print("\n".join(packages))
    return 0


def cmd_logcat(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    if args.clear:
        _adb(serial, "logcat", "-c", check=False)
        print("logcat cleared")
        return 0
    base = ["adb", "-s", serial, "logcat"]
    if args.follow:
        argv = [*base, "-v", args.format, *args.filters]
        if args.output:
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("w", encoding="utf-8") as handle:
                result = _run(
                    argv,
                    check=False,
                    capture=False,
                    stdout=handle,
                    stderr=subprocess.STDOUT,
                )
            print(output)
            return result.returncode
        result = _run(argv, check=False, capture=False)
        return result.returncode
    argv = [*base, "-d", "-v", args.format, *args.filters]
    result = _run(argv, check=False)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(result.stdout or "", encoding="utf-8")
        print(output)
    else:
        print(result.stdout or "", end="")
    return result.returncode


def cmd_screenshot(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    argv = ["adb", "-s", serial, "exec-out", "screencap", "-p"]
    try:
        with output.open("wb") as handle:
            result = subprocess.run(argv, stdout=handle, stderr=subprocess.PIPE)
    except FileNotFoundError as exc:
        raise AndroidError("required command not found: adb") from exc
    if result.returncode != 0:
        raise AndroidError(result.stderr.decode(errors="replace").strip() or "screenshot failed")
    print(output)
    return 0


def cmd_ui_dump(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    remote = "/sdcard/drost-window.xml"
    _adb(serial, "shell", "rm", "-f", remote, check=False)
    result = _adb(serial, "shell", "uiautomator", "dump", remote, check=False)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    pull = _adb(serial, "pull", remote, str(output), check=False)
    if pull.returncode != 0:
        detail = ((result.stdout or "") + (result.stderr or "")).strip()
        raise AndroidError(detail or f"failed to pull {remote}")
    print(output)
    return 0


def cmd_tap(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    return _emit(_adb(serial, "shell", "input", "tap", str(args.x), str(args.y), check=False))


def cmd_swipe(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    return _emit(
        _adb(
            serial,
            "shell",
            "input",
            "swipe",
            str(args.x1),
            str(args.y1),
            str(args.x2),
            str(args.y2),
            str(args.duration),
            check=False,
        )
    )


def cmd_text(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    text = shlex.quote(args.text.replace(" ", "%s"))
    return _emit(_adb(serial, "shell", "input", "text", text, check=False))


def cmd_keyevent(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    return _emit(_adb(serial, "shell", "input", "keyevent", str(args.key), check=False))


def cmd_pull_apk(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    result = _adb(serial, "shell", "pm", "path", args.package, check=False)
    paths = [
        line.removeprefix("package:").strip()
        for line in (result.stdout or "").splitlines()
        if line.startswith("package:")
    ]
    if not paths:
        raise AndroidError(f"package not found: {args.package}")
    output_dir = Path(args.output) / args.package
    output_dir.mkdir(parents=True, exist_ok=True)
    pulled: list[str] = []
    for remote in paths:
        local = output_dir / Path(remote).name
        pull = _adb(serial, "pull", remote, str(local), check=False)
        if pull.returncode != 0:
            raise AndroidError(f"failed to pull {remote}")
        pulled.append(str(local))
    _print_json({"package": args.package, "apks": pulled})
    return 0


def cmd_decompile(args: argparse.Namespace) -> int:
    apk = Path(args.apk)
    if not apk.is_file():
        raise AndroidError(f"APK not found: {apk}")
    if args.apktool_only and args.jadx_only:
        raise AndroidError("choose one of --apktool-only or --jadx-only")
    output_root = Path(args.output) / apk.stem
    output_root.mkdir(parents=True, exist_ok=True)
    results: dict[str, dict[str, Any]] = {}
    if not args.jadx_only:
        destination = output_root / "apktool"
        result = _run(["apktool", "d", "-f", "-o", str(destination), str(apk)], check=False)
        results["apktool"] = {
            "returncode": result.returncode,
            "output": str(destination),
            "manifest": str(destination / "AndroidManifest.xml"),
        }
        if result.returncode != 0:
            results["apktool"]["error"] = _error_detail(result)
    if not args.apktool_only:
        destination = output_root / "jadx"
        result = _run(["jadx", "-d", str(destination), str(apk)], check=False)
        results["jadx"] = {
            "returncode": result.returncode,
            "output": str(destination),
            "sources": str(destination / "sources"),
        }
        if result.returncode != 0:
            results["jadx"]["error"] = _error_detail(result)
    _print_json(results)
    if all(item["returncode"] != 0 for item in results.values()):
        raise AndroidError("decompilation failed")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    apk = Path(args.apk)
    if not apk.is_file():
        raise AndroidError(f"APK not found: {apk}")
    try:
        from drost_ai.android_scan import scan_apk
    except ModuleNotFoundError as exc:
        raise AndroidError("androguard is not installed in this image") from exc
    try:
        report = scan_apk(apk)
    except ModuleNotFoundError as exc:
        raise AndroidError(f"missing Python dependency: {exc.name}") from exc
    payload = json.dumps(report, indent=2, sort_keys=True, default=str)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload + "\n", encoding="utf-8")
        print(output)
    else:
        print(payload)
    return 0


def cmd_frida_server(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    if args.action == "status":
        result = _adb(serial, "shell", "ps", "-A", check=False)
        _print_json({"serial": serial, "running": "frida-server" in (result.stdout or "")})
        return 0
    if args.action == "stop":
        root_shell(serial, "pkill -f frida-server || true", check=False)
        print("frida-server stopped")
        return 0
    props = _props(serial)
    abi = props.get("ro.product.cpu.abi", "")
    binary = FRIDA_DIR / f"frida-server-{abi}"
    if not binary.is_file():
        raise AndroidError(f"no bundled frida-server for ABI {abi!r}; expected {binary}")
    remote = "/data/local/tmp/frida-server"
    root_shell(serial, "pkill -f frida-server || true", check=False)
    _adb(serial, "push", str(binary), remote)
    root_shell(serial, f"chmod 755 {remote}")
    root_shell(serial, f"nohup {remote} >/dev/null 2>&1 &", check=False)
    time.sleep(2)
    result = _run(["frida-ps", "-D", serial], check=False)
    if result.returncode != 0:
        result = _run(["frida-ps", "-U"], check=False)
    if result.returncode != 0:
        raise AndroidError(
            "frida-server started but frida-ps could not connect; "
            "check `adb shell ps -A | grep frida`"
        )
    lines = [line for line in (result.stdout or "").splitlines() if line.strip()]
    processes = sum(1 for line in lines if line.strip()[0].isdigit())
    _print_json(
        {
            "serial": serial,
            "abi": abi,
            "binary": str(binary),
            "running": True,
            "processes": processes,
        }
    )
    return 0


def cmd_frida_ps(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    result = _run(["frida-ps", "-D", serial], check=False)
    if result.returncode != 0:
        result = _run(["frida-ps", "-U"], check=False)
    if result.returncode != 0:
        detail = ((result.stderr or "") + (result.stdout or "")).strip()
        raise AndroidError(detail or "frida-ps failed")
    print(result.stdout or "", end="")
    return 0


def cmd_frida(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    script = Path(args.script)
    if not script.is_file():
        raise AndroidError(f"Frida script not found: {script}")
    if not args.package and not args.name:
        raise AndroidError("pass --package to spawn an app or --name to attach to a running process")
    argv = ["frida", "-D", serial]
    if args.package:
        argv.extend(["-f", args.package])
    else:
        argv.extend(["-n", args.name])
    argv.extend(["-l", str(script)])
    if args.pause:
        argv.append("--pause")
    if args.timeout:
        return _run_with_timeout(argv, args.timeout)
    result = _run(argv, check=False, capture=False)
    return result.returncode


def cmd_frida_trace(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    argv = ["frida-trace", "-D", serial, *args.args]
    if args.timeout:
        return _run_with_timeout(argv, args.timeout)
    result = _run(argv, check=False, capture=False)
    return result.returncode


def cmd_objection(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    if not args.name and not args.foremost:
        raise AndroidError("pass --name <package> (or --foremost) so objection knows what to attach to")
    argv = ["objection", "-S", serial]
    if args.name:
        argv.extend(["-n", args.name])
    if args.spawn:
        argv.append("-s")
    if args.foremost:
        argv.append("-f")
    if args.uid:
        argv.extend(["--uid", args.uid])
    if args.command:
        argv.extend(["run", args.command])
        result = _run(argv, check=False, capture=False)
        return result.returncode
    if not sys.stdin.isatty():
        raise AndroidError("interactive objection requires a TTY; pass --command '...'")
    argv.append("explore")
    os.execvp(argv[0], argv)
    return 0


def cmd_patch_apk(args: argparse.Namespace) -> int:
    source = Path(args.apk)
    if not source.is_file():
        raise AndroidError(f"APK not found: {source}")
    workdir = Path(args.output_dir) if args.output_dir else source.parent
    workdir.mkdir(parents=True, exist_ok=True)
    argv = ["objection", "patchapk", "-s", str(source.resolve()), "-V", args.gadget_version]
    if args.architecture:
        argv.extend(["-a", args.architecture])
    if args.network_security_config:
        argv.append("-N")
    if args.enable_debug:
        argv.append("-d")
    if args.aapt2:
        argv.append("-2")
    if args.skip_resources:
        argv.append("-D")
    result = _run(argv, check=False, capture=False, cwd=str(workdir))
    output = workdir / f"{source.stem}.objection.apk"
    if result.returncode != 0 or not output.is_file():
        raise AndroidError("patchapk failed; see the command output above")
    print(output)
    return 0


def cmd_proxy(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    state_path = state_dir() / "proxy.json"
    if args.action == "status":
        state = _read_json(state_path)
        if not state:
            _print_json({"running": False})
            return 0
        proxy = (
            _adb(serial, "shell", "settings", "get", "global", "http_proxy", check=False).stdout or ""
        ).strip()
        reverse = [
            line
            for line in (_adb(serial, "reverse", "--list", check=False).stdout or "").splitlines()
            if line.strip()
        ]
        log_path = Path(state["log"])
        tail = (
            log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-20:]
            if log_path.is_file()
            else []
        )
        _print_json(
            {
                "running": _pid_alive(int(state["pid"])),
                "pid": state["pid"],
                "port": state["port"],
                "ca_cert": state["ca_cert"],
                "http_proxy": None if proxy in ("", "null", ":0") else proxy,
                "reverse": reverse,
                "log_tail": tail,
            }
        )
        return 0
    if args.action == "stop":
        state = _read_json(state_path)
        if state:
            _terminate(int(state["pid"]))
            _adb(serial, "reverse", "--remove", f"tcp:{state['port']}", check=False)
            _adb(serial, "shell", "settings", "put", "global", "http_proxy", ":0", check=False)
            state_path.unlink(missing_ok=True)
            print(f"proxy stopped (port {state['port']})")
        else:
            _adb(serial, "shell", "settings", "put", "global", "http_proxy", ":0", check=False)
            print("proxy was not running")
        return 0
    state = _read_json(state_path)
    if state and _pid_alive(int(state["pid"])):
        raise AndroidError(f"proxy already running on port {state['port']} (pid {state['pid']})")
    if state:
        state_path.unlink(missing_ok=True)
    mitm = shutil.which("mitmdump")
    if not mitm:
        raise AndroidError("mitmdump not found in PATH")
    directory = state_dir()
    confdir = directory / "mitm"
    confdir.mkdir(parents=True, exist_ok=True)
    log_path = directory / "mitmdump.log"
    log_handle = log_path.open("a", encoding="utf-8")
    try:
        process = subprocess.Popen(
            [mitm, "-p", str(args.port), "--set", f"confdir={confdir}"],
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
    except FileNotFoundError as exc:
        log_handle.close()
        raise AndroidError("mitmdump not found in PATH") from exc
    log_handle.close()
    time.sleep(2)
    if process.poll() is not None:
        tail = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-20:]
        raise AndroidError("mitmdump exited early:\n" + "\n".join(tail))
    try:
        _adb(serial, "reverse", f"tcp:{args.port}", f"tcp:{args.port}")
        _adb(serial, "shell", "settings", "put", "global", "http_proxy", f"127.0.0.1:{args.port}")
    except AndroidError:
        _terminate(process.pid)
        raise
    ca_cert = confdir / "mitmproxy-ca-cert.pem"
    state = {
        "pid": process.pid,
        "port": args.port,
        "confdir": str(confdir),
        "ca_cert": str(ca_cert),
        "log": str(log_path),
    }
    state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    _print_json(
        {
            **state,
            "running": True,
            "http_proxy": f"127.0.0.1:{args.port}",
            "hint": "run `drost-android ca-install` after mitmproxy generates the CA certificate",
        }
    )
    return 0


def cmd_ca_install(args: argparse.Namespace) -> int:
    serial = resolve_serial(args.serial)
    state = _read_json(state_dir() / "proxy.json")
    cert = Path(state["ca_cert"]) if state else state_dir() / "mitm" / "mitmproxy-ca-cert.pem"
    if not cert.is_file():
        raise AndroidError(
            f"CA certificate not found: {cert}; start the proxy and generate traffic first"
        )
    result = _run(["openssl", "x509", "-subject_hash_old", "-in", str(cert), "-noout"])
    hash_value = (result.stdout or "").strip().splitlines()[0] if (result.stdout or "").strip() else ""
    if not hash_value:
        raise AndroidError("could not compute the certificate hash")
    remote = f"/data/local/tmp/{hash_value}.0"
    _adb(serial, "push", str(cert), remote)
    if args.system:
        _adb(serial, "remount", check=False)
        root_shell(
            serial,
            f"mkdir -p /system/etc/security/cacerts && "
            f"cp {remote} /system/etc/security/cacerts/{hash_value}.0 && "
            f"chmod 644 /system/etc/security/cacerts/{hash_value}.0",
        )
        target = f"/system/etc/security/cacerts/{hash_value}.0"
        mode = "system"
    else:
        root_shell(
            serial,
            f"mkdir -p /data/misc/user/0/cacerts-added && "
            f"cp {remote} /data/misc/user/0/cacerts-added/{hash_value}.0 && "
            f"chmod 644 /data/misc/user/0/cacerts-added/{hash_value}.0",
        )
        target = f"/data/misc/user/0/cacerts-added/{hash_value}.0"
        mode = "user"
    _print_json(
        {
            "serial": serial,
            "mode": mode,
            "hash": hash_value,
            "target": target,
            "source": str(cert),
        }
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="drost-android",
        description="Android debugging helpers for the Drost container.",
        epilog=(
            "The container includes adb, Apktool, JADX, Frida, objection, and mitmproxy. "
            "Use `drost-android doctor` to verify the toolchain."
        ),
    )
    parser.add_argument(
        "--serial",
        help="adb device serial (default: $DROST_ANDROID_SERIAL or the only connected device)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    sub = subparsers.add_parser("devices", help="list connected devices")
    sub.set_defaults(func=cmd_devices)

    sub = subparsers.add_parser("connect", help="connect to a device over TCP/IP")
    sub.add_argument("address", help="host:port, for example 192.0.2.10:5555")
    sub.set_defaults(func=cmd_connect)

    sub = subparsers.add_parser("pair", help="pair with an Android wireless-debugging device")
    sub.add_argument("address", help="pairing host:port")
    sub.add_argument("code", help="six-digit pairing code")
    sub.set_defaults(func=cmd_pair)

    sub = subparsers.add_parser("disconnect", help="disconnect a device")
    sub.add_argument("address", nargs="?")
    sub.set_defaults(func=cmd_disconnect)

    sub = subparsers.add_parser("info", help="show device properties and proxy state")
    sub.set_defaults(func=cmd_info)

    sub = subparsers.add_parser("doctor", help="check the Android toolchain")
    sub.set_defaults(func=cmd_doctor)

    sub = subparsers.add_parser("shell", help="run a shell command on the device")
    sub.add_argument("command", nargs="+")
    sub.set_defaults(func=cmd_shell)

    sub = subparsers.add_parser("install", help="install one APK or a split APK set")
    sub.add_argument("apks", nargs="+")
    sub.set_defaults(func=cmd_install)

    sub = subparsers.add_parser("uninstall", help="uninstall a package")
    sub.add_argument("package")
    sub.add_argument("-k", "--keep-data", action="store_true")
    sub.set_defaults(func=cmd_uninstall)

    sub = subparsers.add_parser("clear", help="clear app data")
    sub.add_argument("package")
    sub.set_defaults(func=cmd_clear)

    sub = subparsers.add_parser("stop", help="force-stop an app")
    sub.add_argument("package")
    sub.set_defaults(func=cmd_stop)

    sub = subparsers.add_parser("launch", help="launch an app")
    sub.add_argument("package")
    sub.add_argument("--activity", help="activity name, for example .MainActivity")
    sub.set_defaults(func=cmd_launch)

    sub = subparsers.add_parser("packages", help="list installed packages")
    sub.add_argument("--filter", help="case-insensitive package-name filter")
    sub.add_argument("--system", action="store_true", help="only system packages")
    sub.add_argument("--third-party", action="store_true", help="only third-party packages")
    sub.set_defaults(func=cmd_packages)

    sub = subparsers.add_parser("logcat", help="dump or follow logcat")
    sub.add_argument("--clear", action="store_true")
    sub.add_argument("--follow", action="store_true")
    sub.add_argument("--format", default="threadtime")
    sub.add_argument("--output")
    sub.add_argument("filters", nargs="*")
    sub.set_defaults(func=cmd_logcat)

    sub = subparsers.add_parser("screenshot", help="capture a PNG screenshot")
    sub.add_argument("output", nargs="?", default="screenshot.png")
    sub.set_defaults(func=cmd_screenshot)

    sub = subparsers.add_parser("ui-dump", help="dump the UI hierarchy XML")
    sub.add_argument("output", nargs="?", default="window.xml")
    sub.set_defaults(func=cmd_ui_dump)

    sub = subparsers.add_parser("tap", help="tap screen coordinates")
    sub.add_argument("x", type=int)
    sub.add_argument("y", type=int)
    sub.set_defaults(func=cmd_tap)

    sub = subparsers.add_parser("swipe", help="swipe between coordinates")
    sub.add_argument("x1", type=int)
    sub.add_argument("y1", type=int)
    sub.add_argument("x2", type=int)
    sub.add_argument("y2", type=int)
    sub.add_argument("--duration", type=int, default=300)
    sub.set_defaults(func=cmd_swipe)

    sub = subparsers.add_parser("text", help="type text into the focused field")
    sub.add_argument("text")
    sub.set_defaults(func=cmd_text)

    sub = subparsers.add_parser("keyevent", help="send a key event")
    sub.add_argument("key", help="for example KEYCODE_HOME or 3")
    sub.set_defaults(func=cmd_keyevent)

    sub = subparsers.add_parser("pull-apk", help="pull all APK splits for a package")
    sub.add_argument("package")
    sub.add_argument("-o", "--output", default="apks")
    sub.set_defaults(func=cmd_pull_apk)

    sub = subparsers.add_parser("decompile", help="decompile an APK with Apktool and JADX")
    sub.add_argument("apk")
    sub.add_argument("-o", "--output", default="decompiled")
    sub.add_argument("--apktool-only", action="store_true")
    sub.add_argument("--jadx-only", action="store_true")
    sub.set_defaults(func=cmd_decompile)

    sub = subparsers.add_parser("scan", help="static APK triage as JSON")
    sub.add_argument("apk")
    sub.add_argument("-o", "--output")
    sub.set_defaults(func=cmd_scan)

    sub = subparsers.add_parser("frida-server", help="manage the bundled frida-server")
    sub.add_argument("action", choices=["start", "stop", "status"])
    sub.set_defaults(func=cmd_frida_server)

    sub = subparsers.add_parser("frida-ps", help="list processes through Frida")
    sub.set_defaults(func=cmd_frida_ps)

    sub = subparsers.add_parser("frida", help="run a Frida script")
    sub.add_argument("script")
    sub.add_argument("-f", "--package", help="spawn this package")
    sub.add_argument("-n", "--name", help="attach to this running process name")
    sub.add_argument("--pause", action="store_true", help="leave a spawned process paused")
    sub.add_argument("--timeout", type=int, default=0, help="stop after this many seconds")
    sub.set_defaults(func=cmd_frida)

    sub = subparsers.add_parser("frida-trace", help="run frida-trace")
    sub.add_argument("--timeout", type=int, default=0)
    sub.add_argument("args", nargs=argparse.REMAINDER)
    sub.set_defaults(func=cmd_frida_trace)

    sub = subparsers.add_parser("objection", help="run objection headlessly or interactively")
    sub.add_argument("-n", "--name", help="package or process name")
    sub.add_argument("-s", "--command", help="single objection command to run")
    sub.add_argument("--spawn", action="store_true", help="spawn the target")
    sub.add_argument("--foremost", action="store_true", help="use the foremost application")
    sub.add_argument("--uid", help="Android uid to run as")
    sub.set_defaults(func=cmd_objection)

    sub = subparsers.add_parser("patch-apk", help="patch an APK with the Frida gadget")
    sub.add_argument("apk")
    sub.add_argument("--output-dir", help="directory for the patched APK")
    sub.add_argument("--architecture", help="target ABI, for example arm64-v8a")
    sub.add_argument("--gadget-version", default="17.24.3")
    sub.add_argument("-N", "--network-security-config", action="store_true")
    sub.add_argument("-d", "--enable-debug", action="store_true")
    sub.add_argument("--aapt2", action="store_true")
    sub.add_argument("--skip-resources", action="store_true")
    sub.set_defaults(func=cmd_patch_apk)

    sub = subparsers.add_parser("proxy", help="manage mitmproxy and the device proxy")
    sub.add_argument("action", choices=["start", "stop", "status"])
    sub.add_argument("--port", type=int, default=DEFAULT_PROXY_PORT)
    sub.set_defaults(func=cmd_proxy)

    sub = subparsers.add_parser("ca-install", help="install the mitmproxy CA certificate")
    sub.add_argument("--system", action="store_true", help="install into the system CA store")
    sub.set_defaults(func=cmd_ca_install)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = args.func(args)
    except AndroidError as exc:
        print(f"drost-android: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return int(result) if result is not None else 0


if __name__ == "__main__":
    raise SystemExit(main())

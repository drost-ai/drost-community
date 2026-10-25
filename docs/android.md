# Android app and device testing with Drost

The `drost_android` tool adds an Android workflow to the Drost container. It
combines device control, APK triage and decompilation, dynamic instrumentation,
and HTTPS interception behind one MCP tool and one CLI:

- **adb** for device discovery, shell access, package management, logcat,
  screenshots, and UI automation.
- **Apktool 3.0.3** and **JADX 1.5.6** for resource and Java decompilation.
- **Frida 17.24.3**, **frida-tools 14.11.0**, and **objection 1.12.5** for
  dynamic instrumentation and APK patching.
- **androguard 4.1.4** for static APK triage.
- **mitmproxy** from the Kali base image for HTTPS interception.

Use these tools only on devices and applications you own or are explicitly
authorized to test. Frida, `frida-server`, and CA installation modify the
device; remove them when the engagement ends.

## Invoke the tool

In full MCP mode, call `drost_android` with an engagement and an argv list:

```text
drost_android(
  engagement_id="<engagement-id>",
  arguments=["devices"]
)
```

The tool runs the `drost-android` executable directly. There is no shell
parsing, so pass one argv token per list element. Relative paths are resolved
inside the engagement workspace.

The same CLI is available inside the container:

```sh
docker exec -it drost-ai drost-android doctor
docker exec -it drost-ai drost-android devices
```

In compact MCP mode, discover the tool and run it through `drost_execute`:

```text
drost_catalog(query="android")
drost_execute(
  tool="drost_android",
  engagement_id="<engagement-id>",
  arguments=["devices"]
)
```

## Connect a device

The container must be able to reach the device's adb endpoint. The address
below is always environment-specific; do not assume a fixed host address.

### Wireless debugging on Android 11 and newer

1. Enable **Developer options** and **Wireless debugging** on the device.
2. Choose **Pair device with pairing code**. Keep the pairing address, port,
   and six-digit code.
3. Pair and connect from the container:

```sh
drost-android pair <device-ip>:<pair-port> <six-digit-code>
drost-android connect <device-ip>:<debug-port>
drost-android devices
```

The pairing port and the debugging port are different. Use the values shown
on the device.

### USB or emulator

If a host already has USB access, expose adb over TCP from that host:

```sh
adb tcpip 5555
drost-android connect <host-address>:5555
```

For an emulator, connect to the host address and the emulator's adb port:

```sh
drost-android connect <host-address>:<emulator-adb-port>
```

On Docker Desktop, the host is often reachable as `host.docker.internal`. On
Linux, use the host's LAN address, a reachable interface address, or run the
container with host networking. Confirm reachability with `drost-android
devices` before running other commands.

### Verify the connection

```sh
drost-android doctor
drost-android info
```

`doctor` reports every tool path and version, the bundled Frida server
binaries, and the state directory. `info` reports device properties, root
status, the global HTTP proxy, and active adb reverses.

## Device and app control

```sh
drost-android packages --third-party
drost-android install app.apk
drost-android install base.apk split.config.arm64_v8a.apk split.config.xxhdpi.apk
drost-android launch com.example.app
drost-android launch com.example.app --activity .MainActivity
drost-android logcat --clear
drost-android logcat --format threadtime --output logcat.txt ActivityManager:I '*:S'
drost-android screenshot screen.png
drost-android ui-dump window.xml
drost-android tap 540 1200
drost-android swipe 540 1800 540 600 --duration 300
drost-android text "hello world"
drost-android keyevent KEYCODE_HOME
drost-android shell getprop ro.product.cpu.abi
```

`install` accepts one APK or a split APK set. `launch` uses the launcher
activity when one exists; if the app has no launcher activity, pass
`--activity`. `logcat --follow` runs until the caller cancels it, which is
useful through an MCP client that supports cancellation.

## Pull, scan, and decompile APKs

Pull every installed split for a package:

```sh
drost-android pull-apk com.example.app -o apks
```

The command writes `apks/com.example.app/<split>.apk` and prints the local
paths as JSON.

Run static triage:

```sh
drost-android scan apks/com.example.app/base.apk -o report.json
```

The JSON report includes the package name, version, SDK levels, permissions,
declared permissions, activities, services, receivers, providers, exported
components, deep links, native libraries, and signing certificates. Treat the
`exported_components` and `deep_links` fields as leads for authorization and
intent-handling tests, not as findings by themselves.

Decompile resources and Java sources:

```sh
drost-android decompile apks/com.example.app/base.apk -o decompiled
```

The output is `decompiled/<apk-stem>/apktool` for resources and
`decompiled/<apk-stem>/jadx` for Java sources. Use `--apktool-only` or
`--jadx-only` to run one tool. Apktool 3.0.3 is required for recent Android
APKs; the older Debian package can hang on Android 15 resources.

## Frida and objection

`frida-server` must run on the device. The container includes server binaries
for `arm64-v8a` and `x86_64` and selects the one matching the device ABI:

```sh
drost-android frida-server start
drost-android frida-server status
drost-android frida-ps
drost-android frida-server stop
```

Starting the server requires a rooted device or emulator. If the device is not
rooted, use an objection-patched APK or another authorized instrumentation
path instead.

Run a Frida script by spawning a package or attaching to a running process:

```sh
drost-android frida hook.js -f com.example.app --timeout 30
drost-android frida hook.js -n com.example.app
```

Use `-f` for a package name when spawning. Use `-n` for an existing process
name, not a package name. `--timeout` stops the session after the requested
number of seconds; without it, the command runs until the caller cancels it.

Trace calls with `frida-trace`:

```sh
drost-android frida-trace --timeout 20 -- -f com.example.app -i "open*"
```

Run objection headlessly:

```sh
drost-android objection -n com.example.app --command "env"
drost-android objection -n com.example.app --spawn --command "env"
```

Interactive `objection explore` requires a TTY. Through MCP, pass
`--command` with one command instead. The `android sslpinning disable` command
is version- and target-dependent; it can fail with Frida script errors on
Android 15. Use a target-specific Frida script when the built-in command does
not apply.

Patch an APK with the Frida gadget:

```sh
drost-android patch-apk app.apk --output-dir patched --architecture arm64-v8a
```

The output is `patched/<apk-stem>.objection.apk`. Objection uses the bundled
Apktool, `apksigner`, and `zipalign`; it does not accept an output filename, so
the CLI reports the path it produced.

## HTTPS interception

Start mitmproxy, route the device through it, and install its CA:

```sh
drost-android proxy start --port 8080
# Generate traffic from the target app.
drost-android proxy status
drost-android ca-install
```

`proxy start` starts `mitmdump` in the background, creates an adb reverse for
the proxy port, and sets the device's global `http_proxy` to
`127.0.0.1:<port>`. State and logs are kept in the Drost state directory
(`/workspace/.drost-android` by default, or `$DROST_ANDROID_STATE`).

`ca-install` copies the generated mitmproxy CA into the device's user CA store
at `/data/misc/user/0/cacerts-added/<hash>.0`. Root is required. Pass
`--system` to try the system CA store instead; the system partition may be
read-only or use dynamic partitions on modern Android, so that path is
device-specific.

Stop the proxy and restore the device settings:

```sh
drost-android proxy stop
```

This terminates `mitmdump`, removes the adb reverse, and resets `http_proxy` to
`:0`.

Android 7 and newer do not trust user-installed CAs for apps that target API
24 or higher by default. For those apps, use an authorized debuggable build,
a network security config, a rooted test device with the CA in the system
store, or a target-specific Frida/objection script. Certificate pinning is a
separate control; installing a CA does not bypass it.

## Troubleshooting

- **`adb devices` shows `unauthorized`.** Unlock the device and accept the USB
  debugging prompt.
- **`connect` succeeds but no device appears.** Check the debugging port, the
  device's network, and whether the container can reach the host address.
- **`frida-server start` fails.** The device must be rooted; check
  `drost-android info` for root status.
- **`frida -n` cannot find the app.** Use `-f <package>` to spawn it, or pass
  the running process name from `frida-ps`.
- **Apktool hangs or reports resource errors.** Confirm `drost-android doctor`
  shows Apktool 3.0.3 and JADX 1.5.6.
- **The proxy starts but the app ignores it.** Some apps do not honor the
  global proxy. Use a target-specific network configuration or a patched build.
- **The CA is installed but TLS still fails.** Check the app's target SDK,
  network security config, and certificate pinning.
- **`objection` reports a Frida script error.** The built-in command may not
  support the target Android version; use a target-specific script.

## Cleanup

When the engagement ends:

```sh
drost-android proxy stop
drost-android frida-server stop
drost-android uninstall <package>
```

Remove any CA you installed, especially on a shared or non-test device. See
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) and
[SOURCE_OFFER.md](../SOURCE_OFFER.md) for the licenses and source information
of the bundled Android tooling.

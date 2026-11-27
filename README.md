# Boot-Sniffer-2.4
turns flipper zero+wifi dev board into a pmf hunter and lets you know what is able to get booted off the network aka deauthed

A WiFi audit tool for the Flipper Zero + WiFi Devboard (ESP32-S2). Hit
scan and see two groups of findings: **things that are exploitable**
and **things you should protect better** — each finding with a
plain-language fix next to it.

Example findings:

- **EXPLOITABLE:** Open network → "Set WPA2 or WPA3 with a strong password."
- **EXPLOITABLE:** Deauth-vulnerable → "Turn on Protected Management Frames (PMF) and set it to Required."
- **EXPLOITABLE:** WPS enabled → "Turn off WPS — its PIN can be brute-forced."
- **PROTECT BETTER:** WPA2 only → "Move to WPA3 if your devices support it."

## What it is

Two parts that work together:

1. **`firmware/` — Boot Sniffer 2.4 firmware for the ESP32-S2 devboard.**
   Passive listener: hops 2.4 GHz channels 1–11, parses beacon frames,
   and reports per-AP facts over UART — SSID, BSSID, channel, signal,
   encryption (Open / WEP / WPA / WPA2 / WPA3 / WPA2-WPA3 transition /
   OWE), PMF flags (MFPC capable / MFPR required, from the RSN IE),
   WPS presence, and how many clients are visible. Detection only: it
   never transmits and never associates. See `firmware/README.md` for
   the serial protocol and the full findings rules.
2. **`flipper-app/` — Boot Sniffer 2.4 app for the Flipper Zero (uFBT .fap).**
   Drives the board over UART, runs the scan, and shows the results on
   the Flipper screen: an EXPLOITABLE group, a PROTECT BETTER group, a
   per-AP detail view with the fix, and an "All APs" browse. See
   `flipper-app/README.md`.

`research/marauder-notes.md` records why this is standalone firmware
instead of a Marauder fork: Marauder's AP scan already parses beacons
but never reads the RSN Capabilities field, and its scan API has no PMF
data at all.

## Why this exists

Marauder (the usual WiFi Devboard firmware) can run a deauth attack but
cannot tell you which networks are immune to one. The immunity signal
is in the beacon: the RSN IE's MFPC/MFPR bits. This tool reads those
bits and turns them into findings. The user tried deauthing his own
network once and nothing dropped — this tool answers *why* (PMF
required, or the devices were on 5 GHz) without guessing.

## Use it on your own networks only

This is an audit tool for networks you own or have explicit permission
to test. Scanning reads broadcast beacons, which is passive, but
everything after that — deauth testing included — needs authorization.
Keep it to your own stuff.

## Limits — read these first

- **2.4 GHz only.** The ESP32-S2 has no 5 GHz radio. 5 GHz networks are
  invisible to this tool.
- **Untested on real hardware.** The WiFi Devboard had not arrived when
  this was built. The firmware and the Flipper app compile (see build
  status below), but no scan has ever run on a real board. The first
  live run is a smoke test: `PING`, then `SCAN 15` in a serial terminal,
  and compare the AP list with your phone's WiFi list.
- **Passive capture misses things.** Promiscuous mode drops packets and
  an AP is only seen if a beacon lands while the scanner is on its
  channel. Run 30–60 s if the list looks thin.
- **At most 64 APs, 8 clients per AP.** Busy areas overflow the table.
- **MFPR is what the AP advertises.** A beacon's claim, not a verified
  enforcement test.

## Quick start (once the board arrives)

1. Flash the Boot Sniffer 2.4 firmware onto the devboard — see
   `firmware/README.md` (ESP-IDF build, `idf.py flash`). To go back to
   Marauder, flash Marauder again; nothing here touches the Flipper.
2. Install the Boot Sniffer 2.4 app on the Flipper — see
   `flipper-app/README.md` (uFBT build, copy the `.fap` to the SD card).
3. Plug the devboard into the Flipper, open the app, hit Scan.

Or skip the Flipper app entirely: plug the flashed board into any USB
serial terminal at 115200, type `SCAN 15`, and read the `AP|...` lines
directly (protocol in `firmware/README.md`).

## Build status (2026-11-27, this VM)

- **Firmware (ESP-IDF v5.3, esp32s2): COMPILES CLEAN.** `idf.py build`
  exit 0, zero warnings in the build log. Output:
  `firmware/build/pmf_audit.bin` (652,224 bytes, 38% free in the 1 MB
  app partition), plus bootloader and partition table. Protocol strings
  (`PMF-AUDIT READY`, `PONG PMF-AUDIT 1.0`, `DONE`) confirmed present
  in the binary. Toolchain: ESP-IDF v5.3 installed at `~/esp-idf-v5.3`
  with `install.sh esp32s2`. Note: the first build stalled because the
  non-recursive clone left the `esp_wifi/lib` submodule empty and cmake
  tried a full 2.6 GB clone of it at ~800 KB/s; fixed with
  `git submodule update --init --recursive --depth 1` (all 23
  submodules now at their recorded v5.3 commits, wifi-lib shallow at
  24 MB) and a rebuild.
- **Flipper app (uFBT, SDK 1.5.1): COMPILES CLEAN.** Clean rebuild
  from scratch, zero warnings, APPCHK passed (Target 7, API 88.2).
  Output: `flipper-app/dist/pmf_audit.fap` (17,812 bytes). Host tests
  for the protocol + findings logic all pass
  (`gcc tests/host_test.c pmf_logic.c`, "All host tests passed").
  The UART API was verified against the installed SDK headers
  (`furi_hal_serial_*`); the old `furi_hal_uart_*` API is gone.
- **NOT tested on real hardware.** The WiFi Devboard has not arrived.
  Neither binary has ever run on a Flipper + devboard. First live run
  is a smoke test (see Limits above).

## Build log

- 2026-11-27 ~03:46 UTC: ESP-IDF v5.3 cloned (`--depth 1 --branch
  v5.3`) and `install.sh esp32s2` completed (exit 0).
- 2026-11-27 ~04:05 UTC: first `idf.py build` stalled in cmake
  configure on a full clone of the `esp32-wifi-lib` submodule
  (repo is 2.6 GB; link was ~800 KB/s). Killed, submodules fetched
  shallow (`--depth 1`, all at recorded commits), rebuilt.
- 2026-11-27 ~04:17 UTC: firmware build succeeded, zero warnings.
- 2026-11-27 ~03:54 UTC: Flipper app built by the app worker (clean,
  APPCHK passed); 2026-11-27 ~03:56 UTC: rebuilt after the
  Deauth-vulnerable rule was widened to cover WPA2-ENT/WPA3-ENT and
  the firmware README example base64 was corrected — host tests pass,
  APPCHK passed.
- Two discrepancies found during the app build and fixed the same day:
  (1) the Deauth-vulnerable rule originally excluded enterprise
  networks — widened in `firmware/README.md`, `flipper-app/pmf_logic.c`,
  and the host tests; (2) the firmware README example base64 decoded
  to "HomeWIFi" — corrected to `SG9tZVdpRmk=` ("HomeWiFi").

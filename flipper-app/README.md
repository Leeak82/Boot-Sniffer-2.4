# Boot Sniffer 2.4 — Flipper Zero app

A Flipper Zero app (`.fap`, built with uFBT) that drives the WiFi
Devboard over UART and shows which nearby WiFi networks are immune to
deauth attacks.

**Detection only.** This app never transmits 802.11 frames, never
associates to any network, and has no deauth or other attack feature.
It only reads what the board reports.

> **UNTESTED ON REAL HARDWARE.** The WiFi Devboard had not arrived
> when this was written. The app compiles cleanly under uFBT
> (SDK 1.5.1, API 88.2, zero warnings) and its parsing/findings logic
> is host-tested (see `tests/`), but **no scan has ever run on a real
> Flipper + board**. Treat the first live run as a smoke test: run
> PING, then a scan, and compare the AP list with your phone's WiFi
> list. Nothing in this README should be read as "tested on hardware".

## What it does

1. Talks to the ESP32-S2 WiFi Devboard over the GPIO UART
   (USART1, 115200 baud, Flipper pins 13 TX / 14 RX).
2. Sends `SCAN 15`, collects the board's per-AP beacon facts.
3. Groups the results into findings:
   - **EXPLOITABLE** — an attacker can act on this now
     (open network, WEP, outdated WPA/TKIP, WPS enabled,
     deauth-vulnerable because PMF is not Required).
   - **PROTECT BETTER** — not immediately exploitable, harden it
     (WPA2-only with PMF required, WPA2/WPA3 transition mode,
     Enhanced Open).
   - APs with no findings are counted as clean in the footer
     (`N APs scanned, M clean`) and are still viewable under
     **All APs**.
4. Each AP has a detail view: SSID, BSSID, channel, signal,
   encryption, PMF capable/required, BIP, WPS on/off, clients seen,
   an explicit **Deauth-immune: YES/NO** verdict, and each finding
   with its plain-language fix.

The deauth-immunity rule is: **an AP is deauth-immune iff MFPR == 1**
(PMF Required, from the RSN IE). See `../firmware/README.md` for the
full findings table — the firmware README is the source of truth for
the rules, and this app implements them exactly.

## How to use

1. Flash the **Boot Sniffer 2.4 firmware** from `../firmware/` onto the
   WiFi Devboard (not Marauder — the board must speak the protocol
   below). Plug the board into the Flipper's GPIO header.
2. On the Flipper: Apps → GPIO → **Boot Sniffer 2.4**.
3. **Scan** — the app PINGs the board first, then runs a 15-second
   scan. The screen shows elapsed time, a progress bar, and APs found
   so far. Press **Back** to abort (sends `STOP`).
4. Results: two groups, **EXPLOITABLE (n)** and
   **PROTECT BETTER (n)**. Each row shows the SSID (or BSSID if the
   SSID is hidden) and the short finding label. Press OK on a row for
   the detail view; the last row, **All APs (N)**, lists every AP
   found, including clean ones.
5. **About** explains the limits (2.4 GHz only, your own networks,
   untested on hardware).

### If the board does not respond

The app shows:

> Board not responding — check wiring / flash PMF firmware

Check that the devboard is seated on the GPIO header, powered, and
flashed with the Boot Sniffer 2.4 firmware from `../firmware/` (a board
still running Marauder or the Black Magic debug firmware will not
answer `PING`).

### If no networks are found

The app says so and suggests moving closer to an access point. Note
that 5 GHz networks are invisible to this tool — the ESP32-S2 has no
5 GHz radio, so a 5 GHz-only AP simply will not appear.

## Build

Requires Python 3 and uFBT:

```sh
pip install --user ufbt
ufbt update          # fetch the Flipper SDK (1.5.1 used here)
cd flipper-app
ufbt                 # -> dist/pmf_audit.fap
```

Last verified build: clean rebuild from scratch, SDK 1.5.1,
API 88.2, `dist/pmf_audit.fap` (17,796 bytes), zero compiler
warnings, `APPCHK` passed. Build log: `/tmp/pmf_audit_final_build.log`
on the build machine (not shipped).

## Install on the Flipper

Copy `dist/pmf_audit.fap` to `/ext/apps/GPIO/` on the Flipper's
microSD card (e.g. with `ufbt launch` while the Flipper is connected
over USB, which builds, uploads, and runs it), then open
Apps → GPIO → Boot Sniffer 2.4.

## Serial protocol (summary)

115200 8N1, LF-terminated lines. Board prints `PMF-AUDIT READY` on boot.

| App sends | Board replies |
|---|---|
| `PING` | `PONG PMF-AUDIT 1.0` |
| `SCAN [seconds]` (5–60, this app always sends `SCAN 15`) | one `AP\|...` line per AP, then `DONE <n>` |
| `STOP` | `STOPPED` |

AP line:

```
AP|<bssid>|<ssid_b64>|<ch>|<rssi>|<enc>|<mfpc>|<mfpr>|<bip>|<wps>|<clients>
```

- `bssid`: lowercase hex with colons, e.g. `aa:bb:cc:dd:ee:ff`
- `ssid_b64`: SSID base64-encoded (standard alphabet, `=` padding);
  empty = hidden SSID. The app base64-decodes it for display and
  replaces non-printable bytes with `?`.
- `enc`: `OPEN WEP WPA WPA2 WPA2-ENT WPA3 WPA3-ENT WPA2-WPA3 OWE`
- `mfpc mfpr bip wps`: `0`/`1`. MFPC = PMF capable, MFPR = PMF
  required (RSN IE Capabilities bits 6/7). `bip` = BIP group
  management cipher present.
- `clients`: distinct client MACs seen on that AP (shown in the
  detail view; never creates a finding by itself).

Full spec: `../firmware/README.md`.

## Findings rules (implemented in `pmf_logic.c`)

| Finding | Group | Trigger |
|---|---|---|
| Open network | Exploitable | `enc == OPEN` |
| WEP is broken | Exploitable | `enc == WEP` |
| Outdated WPA / TKIP | Exploitable | `enc == WPA` |
| WPS enabled | Exploitable | `wps == 1` |
| Deauth-vulnerable | Exploitable | `mfpr == 0` and `enc` in `WPA2, WPA3, WPA2-WPA3` |
| WPA2 only, PMF required | Protect better | `enc == WPA2` and `mfpr == 1` |
| Transition mode | Protect better | `enc == WPA2-WPA3` and `mfpr == 1` |
| Enhanced Open (OWE) | Protect better | `enc == OWE` |

An AP with MFPR == 1 and WPA3 / WPA3-ENT has no findings.

## UART API — what was verified, not assumed

The current Flipper serial API is `furi_hal_serial_*`, verified
against the uFBT SDK 1.5.1 headers shipped with this build
(`furi_hal_serial.h`, `furi_hal_serial_control.h`,
`expansion/expansion.h`) and against the same pattern in the ESP32
Marauder companion app (`0xchocolate/flipperzero-wifi-marauder`,
`wifi_marauder_uart.c`) and the ESP Flasher app:

- `expansion_disable()` on the `RECORD_EXPANSION` record **before**
  `furi_hal_serial_control_acquire(FuriHalSerialIdUsart)` (the
  expansion service owns the USART until disabled), and
  `expansion_enable()` right after
  `furi_hal_serial_control_release()` on exit.
- `furi_hal_serial_init(handle, 115200)` (default framing is 8N1),
  `furi_hal_serial_tx()` to send, `furi_hal_serial_async_rx_start()`
  with an ISR callback that drains bytes with
  `furi_hal_serial_async_rx()` into a `FuriStreamBuffer` — the exact
  pattern the Marauder/ESP-Flasher apps use.
- `furi_hal_power_enable_otg()` powers the devboard from the
  Flipper's 5V pin while the app runs (disabled on exit).
- The old `furi_hal_uart_*` API is gone in current firmware and is
  not used anywhere in this app.

## Files

| File | What it is |
|---|---|
| `application.fam` | uFBT manifest (appid `pmf_audit`, GPIO category) |
| `pmf_audit.c` | App: UI (submenu / scan / results / detail), worker thread, UART driver |
| `pmf_logic.h` / `pmf_logic.c` | Pure protocol + findings logic (no Flipper includes) |
| `pmf_audit_10px.png` | 10×10 app icon (shield) |
| `tests/host_test.c` | Host test for `pmf_logic.c` — `gcc` only, no SDK, no hardware |

Run the host tests with:

```sh
gcc -Wall -Wextra -I. -o /tmp/pmf_logic_test tests/host_test.c pmf_logic.c
/tmp/pmf_logic_test   # "All host tests passed."
```

They cover the firmware README's example AP lines, the full
findings matrix (every row of the table above, including WPA3+MFPR=1
clean and clients-never-create-a-finding), base64 edge cases
(`|` and non-printable bytes in SSIDs, hidden SSIDs), and rejection
of malformed AP lines.

## Limits — read before trusting a scan

- **2.4 GHz only.** The ESP32-S2 has no 5 GHz radio.
- **Untested on real hardware** (see the box at the top).
- **Scan is fixed at 15 seconds.** The firmware supports 5–60 s;
  the app always sends `SCAN 15`. Re-run if the list looks thin —
  passive capture can miss quiet APs.
- **At most 64 APs** are kept (the firmware sends at most 64 lines);
  extras are dropped, strongest APs first in the display. The
  firmware also tracks at most 8 clients per AP.
- **MFPR is what the AP advertises.** The scan reads the beacon's
  claim; it cannot verify PMF is actually enforced.
- **Channels 1–11 only** (firmware default, US-legal 2.4 GHz).
- **Enterprise PMF — fixed 2026-11-27:** the firmware README and this
  app now both list the Deauth-vulnerable trigger as `enc` in
  `WPA2, WPA3, WPA2-ENT, WPA3-ENT, WPA2-WPA3`. (The first build of the
  firmware README narrowed it to `WPA2, WPA3, WPA2-WPA3`, which left
  enterprise APs with MFPR == 0 unflagged; the rule was widened and
  the host test covers WPA2-ENT/WPA3-ENT with MFPR == 0.)
- **Fixed 2026-11-27:** the firmware README's example AP line
  previously used `SG9tZVdJRmk=`, which base64-decodes to `HomeWIFi`.
  It now uses `SG9tZVdpRmk=` (`HomeWiFi`); the decoder was always
  correct.

## Revert to Marauder

Flashing the Boot Sniffer 2.4 firmware replaces Marauder on the board. To go
back, flash Marauder again the same way (see `../firmware/README.md`
for the release link). Nothing in this app or firmware writes to the
Flipper itself.

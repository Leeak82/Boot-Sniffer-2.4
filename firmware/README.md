# Boot Sniffer 2.4 firmware — ESP32-S2 (Flipper WiFi Devboard)

Passive WiFi audit firmware. It listens on 2.4 GHz, parses beacon frames,
and reports per-access-point facts over UART so a host can tell which
networks are immune to deauth attacks.

**Detection only.** This firmware never transmits 802.11 frames, never
associates to any network, and adds no attack features. Deauth testing on
your own networks is Marauder's job; this firmware only reads beacons.

## What it reports per AP (all from beacon frames)

| Field | Source |
|---|---|
| SSID, BSSID, channel, RSSI | Beacon header + fixed params |
| Encryption: OPEN / WEP / WPA / WPA2 / WPA2-ENT / WPA3 / WPA3-ENT / WPA2-WPA3 (transition) / OWE | Privacy bit + WPA vendor IE + RSN IE AKM suites |
| MFPC / MFPR | RSN IE (tag 48) Capabilities field: MFPC = bit 6 (0x40), MFPR = bit 7 (0x80), per IEEE 802.11-2020 §9.4.2.24 |
| BIP | Group management cipher suite in the RSN IE is type 6 (BIP) |
| WPS | Vendor IE, OUI 00:50:F2, type 4 |
| Clients | Distinct client MACs seen sending data frames to this BSSID |

## The deauth-immunity rule (applied by the host)

**An AP is deauth-immune iff MFPR == 1.** MFPR is mandatory in WPA3,
optional in WPA2 — so a WPA2 AP with MFPC == 1 but MFPR == 0 still lets
an attacker kick off any client that doesn't negotiate PMF. BIP is also
reported: broadcast deauth protection additionally needs the BIP group
management cipher, so MFPR == 1 without BIP is noted as "immune, broadcast
protection unconfirmed" in the docs, but the Flipper app treats MFPR == 1
as immune (that is the rule real-world tools use).

## Serial protocol (115200 8N1, LF-terminated lines)

Host → board:

```
PING            -> PONG PMF-AUDIT 1.0
SCAN [seconds]  -> AP lines, then DONE <n>   (seconds 5-60, default 15)
STOP            -> STOPPED (aborts a running scan)
```

Board → host (one AP per line):

```
AP|<bssid>|<ssid_b64>|<ch>|<rssi>|<enc>|<mfpc>|<mfpr>|<bip>|<wps>|<clients>
```

- `<bssid>` is lowercase hex with colons, e.g. `aa:bb:cc:dd:ee:ff`.
- `<ssid_b64>` is the SSID base64-encoded (SSIDs can contain `|` and
  non-printable bytes). Empty string = hidden SSID.
- `<enc>` is one of `OPEN WEP WPA WPA2 WPA2-ENT WPA3 WPA3-ENT WPA2-WPA3 OWE`.
- `<mfpc> <mfpr> <bip> <wps>` are `0`/`1`. MFPC/MFPR are only meaningful
  when an RSN IE was seen; they are `0` otherwise.
- `<clients>` is the count of distinct client MACs seen in data frames.
- The board prints `PMF-AUDIT READY` on boot and `DONE <n>` at the end
  of a scan, where `<n>` is the number of AP lines sent.

Example session (serial terminal):

```
PMF-AUDIT READY
PING
PONG PMF-AUDIT 1.0
SCAN 15
AP|aa:bb:cc:dd:ee:ff|SG9tZVdpRmk=|6|-42|WPA2|1|0|1|0|3
AP|11:22:33:44:55:66||1|-71|OPEN|0|0|0|0|0
DONE 2
```

## Findings rules (implemented in the Flipper app, documented here)

Findings are computed from beacon facts only. Nothing is inferred beyond
what the frames establish.

**EXPLOITABLE — an attacker can act on this now:**

| Finding | Trigger (beacon facts) | Plain-language fix |
|---|---|---|
| Open network | enc == OPEN | Set WPA2 or WPA3 with a strong password — anyone nearby can join and read traffic. |
| WEP is broken | enc == WEP | WEP is broken in minutes — switch to WPA2 or WPA3. |
| Outdated WPA / TKIP | enc == WPA | WPA/TKIP is outdated — switch to WPA2-AES or WPA3. |
| WPS enabled | wps == 1 | Turn off WPS — its PIN can be brute-forced. |
| Deauth-vulnerable | mfpr == 0 (and enc is WPA2/WPA3/WPA2-ENT/WPA3-ENT/WPA2-WPA3) | Turn on Protected Management Frames (PMF) and set it to Required, not just Capable. |

**PROTECT BETTER — not immediately exploitable, but harden it:**

| Finding | Trigger (beacon facts) | Plain-language fix |
|---|---|---|
| WPA2 only, PMF required | enc == WPA2 and mfpr == 1 | Move to WPA3 (or WPA2/WPA3 transition) if your devices support it. |
| Transition mode | enc == WPA2-WPA3 and mfpr == 1 | Move to WPA3-only once all your devices support it — the WPA2 side is the weak part. |
| Enhanced Open (OWE) | enc == OWE | Traffic is encrypted per client, but anyone can join — use WPA3 with a password if this network should be private. |

An AP with MFPR == 1 and WPA3 (or WPA3-ENT) has no findings and is not
listed — the results screen shows a count of clean APs instead. The
client count is shown in the AP detail view but never creates a finding
by itself: it only says deauth would actually hurt someone.

## Build (ESP-IDF v5.3, target esp32s2)

```sh
. ~/esp-idf-v5.3/export.sh        # or wherever you installed ESP-IDF
cd firmware
idf.py set-target esp32s2
idf.py build
```

## Flash onto the WiFi Devboard

The devboard is an ESP32-S2. Flash over USB with esptool (the board
appears as a USB serial device), or use the ESP Web Flasher flow:

```sh
. ~/esp-idf-v5.3/export.sh
cd firmware
idf.py -p /dev/ttyACM0 flash      # use your board's port
```

Hold the devboard's BOOT button (or put it in download mode) if the
flash fails to start. The Flipper talks to the board over its UART at
115200 — no other wiring is needed.

## Revert to Marauder

Flashing this firmware replaces Marauder on the board. To go back, flash
Marauder again the same way: get the latest Marauder `.bin` for the
WiFi Devboard from
<https://github.com/justcallmekoko/ESP32Marauder/releases> (or flash it
from the Flipper with the Marauder companion app / ESP Flasher web tool
at <https://espflasher.unleashedflip.com>), and the board is back to
stock Marauder. Nothing in this firmware writes to the Flipper itself.

## Why standalone firmware instead of a Marauder fork

Read from the Marauder source (justcallmekoko/ESP32Marauder,
`esp32_marauder/WiFiScan.cpp`):

- Marauder's AP scan runs in promiscuous mode (`RunAPScan` →
  `setWiFiMode(WIFI_MODE_NULL, apSnifferCallbackFull)`) and already parses
  beacons, including the RSN IE — but `getSecurityType()` only maps it to
  a coarse security enum (WPA2 / WPA-WPA2 mixed / enterprise). It never
  reads the RSN Capabilities field, and a repo-wide search finds no
  MFPC/MFPR/PMF/802.11w handling anywhere.
- Its other scan path (`WiFi.scanNetworks()`) returns only
  `wifi_ap_record_t`, which has an `authmode` field and no RSN IE at all.
- Adding PMF to Marauder would mean new IE parsing plus threading the
  bits through its `AccessPoint` struct, display code, and serial output
  across a ~450 KB scan file and the whole Marauder build (display,
  settings, all attacks).

A standalone firmware does one job in ~600 lines, builds with plain
ESP-IDF, and the board can be flashed back to Marauder in a minute. That
is the saner path, and the one implemented here.

## Limits (read before trusting a scan)

- **2.4 GHz only.** The ESP32-S2 has no 5 GHz radio. Networks on 5 GHz
  are invisible to this tool. A 5 GHz-only AP will simply not appear.
- **Untested on real hardware.** The WiFi Devboard had not arrived when
  this was written. The code compiles (see top-level README for the build
  result) but no scan has ever run on a real board. Treat the first live
  scan as a smoke test: run `PING`, then `SCAN 15` in a serial terminal
  and compare the AP list with your phone's WiFi list.
- **Passive capture misses things.** Promiscuous mode drops some packets,
  especially on busy channels, and an AP is only seen if a beacon lands
  while the scanner is on its channel. A short scan can miss quiet APs;
  run 30–60 s if the list looks thin.
- **At most 64 APs and 8 clients per AP are tracked.** Busy areas will
  overflow the table; the strongest APs win, and extra clients are not
  counted. This is a memory limit, not a finding.
- **MFPR is what the AP advertises.** The scan reads the beacon's claim.
  A misconfigured or malicious AP could lie; the scan cannot verify that
  PMF is actually enforced.
- **Channels 1–11 only.** US-legal 2.4 GHz channels. Channels 12–13 are
  legal in some regions; change `SCAN_CHANNELS` in `pmf_audit.c` if you
  need them.
- **Hidden SSIDs** are reported with an empty SSID field. The BSSID,
  encryption, and PMF flags are still visible.

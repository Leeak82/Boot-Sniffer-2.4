# Boot-Sniffer-2.4
turns flipper zero+wifi dev board into a pmf hunter and lets you know what is able to get booted off the network aka deauthed

## What it does

Plug the WiFi Devboard into your Flipper Zero, hit **Scan**, and it checks
every 2.4 GHz network nearby for PMF (Protected Management Frames) — the
thing that stops deauth attacks. Results come back in two groups, each
finding with a plain-language fix next to it:

- **EXPLOITABLE:** Open network → "Set WPA2 or WPA3 with a strong password."
- **EXPLOITABLE:** Deauth-vulnerable → "Turn on Protected Management Frames (PMF) and set it to Required."
- **EXPLOITABLE:** WPS enabled → "Turn off WPS — its PIN can be brute-forced."
- **PROTECT BETTER:** WPA2 only → "Move to WPA3 if your devices support it."

Detection only. It never transmits, never connects to anything, and never
attacks anything. It just listens to beacons and reports what they say.

## What you need

- A Flipper Zero
- A WiFi Devboard (ESP32-S2) plugged into it
- A computer to build and flash from (no downloads yet — see below)

## Install

You need **both parts** — neither one works alone. The app on the
Flipper has nothing to talk to without the firmware on the devboard,
and the firmware on the devboard does nothing without the app.

**1. Get the code:**

```sh
git clone https://github.com/Leeak82/Boot-Sniffer-2.4.git
cd Boot-Sniffer-2.4
```

**2. Flash the firmware onto the WiFi Devboard** (needs ESP-IDF v5.3 —
install it from Espressif's guide, then run its `export.sh`):

```sh
cd firmware
idf.py build
idf.py -p /dev/ttyACM0 flash
```

Use your board's port — on macOS it's `/dev/tty.usbserial-*`, on
Windows it's a COM port. To go back to Marauder later, just flash
Marauder again. Nothing here touches the Flipper itself.

**3. Install the app on the Flipper Zero** (needs uFBT —
`pip install ufbt`):

```sh
cd ../flipper-app
ufbt
```

Copy `dist/boot_sniffer_24.fap` to the Flipper's SD card
(Apps → GPIO), or install it with qFlipper.

**4. Plug the devboard into the Flipper, open Boot Sniffer 2.4, hit Scan.**

No Flipper app? You can also plug the flashed board into any USB serial
terminal at 115200 baud, type `SCAN 15`, and read the `AP|...` lines
directly. The serial protocol is documented in `firmware/README.md`.

## Downloads

No prebuilt files yet. The `.fap` and the firmware `.bin` will show up
under [Releases](../../releases) once the first live test on real
hardware passes. Until then, build from source with the two commands
above.

## How it works

Every WiFi network broadcasts beacons. Inside each beacon, the RSN
information element carries two PMF bits: MFPC (capable) and MFPR
(required). A network with MFPR set ignores spoofed deauth frames —
it can't be booted off. This tool reads those bits and turns them into
findings.

Marauder (the usual devboard firmware) can run a deauth attack but
cannot tell you which networks are immune to one. `research/marauder-notes.md`
records why this is standalone firmware instead of a Marauder fork:
Marauder's AP scan parses beacons but never reads the RSN Capabilities
field, and its scan API has no PMF data at all.

## Limits — read these first

- **2.4 GHz only.** The ESP32-S2 has no 5 GHz radio. 5 GHz networks are
  invisible to this tool.
- **Untested on real hardware.** The WiFi Devboard had not arrived when
  this was built. Both parts compile clean (see below), but no scan has
  ever run on a real board. First live run is a smoke test: `PING`,
  then `SCAN 15` in a serial terminal, and compare the AP list with
  your phone's WiFi list.
- **Passive capture misses things.** An AP is only seen if a beacon
  lands while the scanner is on its channel. Run 30–60 s if the list
  looks thin.
- **At most 64 APs, 8 clients per AP.** Busy areas overflow the table.
- **MFPR is what the AP advertises.** A beacon's claim, not a verified
  enforcement test.

## Use it on your own networks only

This is an audit tool for networks you own or have explicit permission
to test. Scanning reads broadcast beacons, which is passive, but
everything after that — deauth testing included — needs authorization.
Keep it to your own stuff.

## What's in this repo

- `firmware/` — ESP32-S2 firmware for the devboard (ESP-IDF v5.3).
  Passive beacon listener, reports per-AP facts over UART. Full serial
  protocol and findings rules in `firmware/README.md`.
- `flipper-app/` — Flipper Zero app (uFBT `.fap`). Drives the board
  over UART and shows the results on the Flipper screen: EXPLOITABLE
  group, PROTECT BETTER group, per-AP detail view, "All APs" browse.
  See `flipper-app/README.md`.
- `research/marauder-notes.md` — why standalone firmware, not a
  Marauder fork.

## Build status

- **Firmware (ESP-IDF v5.3): compiles clean**, zero warnings.
  Output: `firmware/build/pmf_audit.bin` (652,224 bytes).
- **Flipper app (uFBT, SDK 1.5.1): compiles clean**, zero warnings,
  APPCHK passed (Target 7, API 88.2). Output:
  `flipper-app/dist/boot_sniffer_24.fap` (17,844 bytes). Host tests
  for the protocol and findings logic pass
  (`gcc tests/host_test.c pmf_logic.c`).
- **Not tested on real hardware.** See Limits above.

## License

MIT — see `LICENSE`.

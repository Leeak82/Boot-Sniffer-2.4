# Changelog

## 1.0.0 — 2026-11-26

First release.

- ESP32-S2 firmware + Flipper app: scan 2.4 GHz beacons, read PMF flags
  (MFPC/MFPR) from the RSN IE, sort APs into EXPLOITABLE and PROTECT
  BETTER with a plain-language fix beside each finding.
- Per-AP detail view with an explicit Deauth-immune YES/NO verdict.
- Detection only — never transmits, never associates.
- Builds clean (firmware: ESP-IDF v5.3; app: uFBT, APPCHK passed).
  Not yet tested on real hardware.

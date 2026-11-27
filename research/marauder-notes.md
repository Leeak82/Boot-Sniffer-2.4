# Research notes — PMF audit tool (2026-11-27)

Sources read while designing this tool. All claims in the code and READMEs
trace to one of these.

## Marauder source (justcallmekoko/ESP32Marauder, master, 2026-11-27)

Files fetched: `esp32_marauder/WiFiScan.cpp` (453,691 bytes),
`esp32_marauder/WiFiScan.h` (44,893 bytes). A full `git clone` was
attempted first but stalled (no output after 4 minutes); the two files
were fetched directly via raw.githubusercontent.com instead.

Findings:

- `WiFiScan::RunAPScan` (WiFiScan.cpp:4409) runs in promiscuous mode:
  `setWiFiMode(WIFI_MODE_NULL, apSnifferCallbackFull)` (line 4443).
  `setWiFiMode` (line 3880) calls `esp_wifi_set_promiscuous(true)`,
  `esp_wifi_set_promiscuous_filter`, `esp_wifi_set_promiscuous_rx_cb`.
- `apSnifferCallbackFull` (line 7513) parses beacons (`payload[0] ==
  0x80`) and calls `getSecurityType(payload, len)` (line ~7580).
- `getSecurityType` (around line 7922) walks the tagged IEs and sets
  `hasRSN` on tag 48 with the comment "RSN IE (Tag 48) — indicates
  WPA2/WPA3" (line 7937). It only maps the IE to a coarse enum:
  `WIFI_SECURITY_WPA2_ENTERPRISE` / `WIFI_SECURITY_WPA_WPA2_MIXED` /
  `WIFI_SECURITY_WPA2` (lines 8028–8030). The RSN Capabilities field is
  never read.
- Repo-wide grep for `RSN|MFPC|MFPR|PMF|802.11w|rsn_cap` in
  WiFiScan.cpp/h found no PMF handling anywhere. The only `0x30`
  matches are BLE advertisement bytes, not RSN parsing.
- A second scan path uses `WiFi.scanNetworks(...)` (lines 2569, 6321,
  6522) — the Arduino scan API, which returns `wifi_ap_record_t` with
  only an `authmode` field. No RSN IE is available there either.
- `beaconHasWPS` exists (referenced at line ~7558, call commented out),
  so WPS detection via vendor IE is an established pattern in this
  codebase.
- Conclusion: adding PMF reporting to Marauder would require new IE
  parsing in `apSnifferCallbackFull`/`getSecurityType`, threading the
  bits through the `AccessPoint` struct, display code, and serial
  output, and rebuilding the whole Marauder project. A standalone
  ESP-IDF firmware doing one job is the saner path (see firmware/README).

## ESP-IDF promiscuous mode (ESP-IDF Programming Guide v4.4.6 / v6.0.3)

- Init sequence (confirmed in docs + community write-ups):
  `esp_wifi_init` → `esp_wifi_set_storage(WIFI_STORAGE_RAM)` →
  `esp_wifi_set_mode(WIFI_MODE_NULL)` → `esp_wifi_start()` →
  `esp_wifi_set_promiscuous_rx_cb(cb)` → `esp_wifi_set_promiscuous_filter`
  → `esp_wifi_set_promiscuous(true)` → `esp_wifi_set_channel(ch, ...)`.
- Callback: `void cb(void *buf, wifi_promiscuous_pkt_type_t type)`,
  `buf` is `wifi_promiscuous_pkt_t*` with `rx_ctrl` (rssi, channel,
  sig_len) and `payload` (raw 802.11 frame, FCS included).
- Filter masks: `WIFI_PROMIS_FILTER_MASK_MGMT` (beacons, probes, assoc),
  `WIFI_PROMIS_FILTER_MASK_DATA`, `WIFI_PROMIS_FILTER_MASK_CTRL`,
  `WIFI_PROMIS_FILTER_MASK_ALL`.
- Promiscuous mode listens on one channel at a time; channel hopping is
  the application's job. Packet loss in promiscuous mode is real,
  especially under load (Espressif docs + community reports).
- ESP32-S2 is 2.4 GHz only (no 5 GHz radio).

## RSN IE and PMF bits (IEEE 802.11-2020 §9.4.2.24)

- RSN IE is tag 48. Layout: version(2) | group cipher(4) | pairwise
  count(2) | pairwise list(4 each) | AKM count(2) | AKM list(4 each) |
  RSN Capabilities(2, little-endian) | [PMKID count(2) | PMKID list |
  group management cipher(4)].
- RSN Capabilities: **MFPC = bit 6 (0x40), MFPR = bit 7 (0x80)** of the
  first (low) byte. Confirmed by IEEE 802.11-2020, wirelesswithwade.com,
  sageaxe.com, and infishark.com.
- Note: one Cisco doc
  (cisco.com, "Configure 802.11w Management Frame Protection on WLC")
  lists bit 6 as MFPR and bit 7 as MFPC — swapped relative to the IEEE
  text. The IEEE assignment (MFPC bit 6, MFPR bit 7) is used here; it
  matches the other three independent sources and the task brief.
- Modes: MFPC=0/MFPR=0 disabled; MFPC=1/MFPR=0 capable (optional);
  MFPC=1/MFPR=1 required. PMF is mandatory in WPA3; optional in WPA2.
  In WPA2/WPA3 transition mode PMF is typically only "capable", so
  WPA2-only clients on that SSID can still be deauthed.
- Broadcast robust management frame protection additionally needs the
  Group Management Cipher Suite to be BIP (type 6) in the RSN IE.
  Beacons themselves are never protected (no key exists yet).

## AKM suite types (OUI 00:0F:AC)

- 1 = 802.1X (EAP), 2 = PSK, 3 = FT-802.1X, 4 = FT-PSK, 5 = 802.1X-SHA256,
  6 = PSK-SHA256, 8 = SAE, 9 = FT-SAE, 18 = OWE, 24 = SAE (SHA384 /
  SAE-ext family — treated as SAE here).

## WPS detection

- Vendor-specific IE (tag 221), OUI 00:50:F2, type 0x04. WPA IE is the
  same OUI with type 0x01.

## 5Ghost WiFi Lab (context, not used)

- PINGEQUA 5Ghost (RTL8720DN/BW16 board) is the existing Flipper tool
  that flags PMF/WPA3 in scans. It needs its own dual-band board; its
  firmware does not run on the ESP32-S2 devboard. This project is the
  2.4 GHz-only equivalent for the board the user already owns.

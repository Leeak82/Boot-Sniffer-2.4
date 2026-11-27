/*
 * pmf_logic.h — pure protocol + findings logic for Boot Sniffer 2.4.
 *
 * No Furi / Flipper includes: this file compiles on a host with gcc so
 * the AP-line parser, base64 decoder and findings rules can be unit
 * tested without hardware (see tests/host_test.c).
 *
 * Protocol (see ../firmware/README.md, the source of truth):
 *   AP|<bssid>|<ssid_b64>|<ch>|<rssi>|<enc>|<mfpc>|<mfpr>|<bip>|<wps>|<clients>
 * Deauth-immunity rule: an AP is deauth-immune iff MFPR == 1.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PMF_MAX_APS 64
#define PMF_MAX_SSID_LEN 32
/* Worst case findings for one AP: e.g. OPEN + WPS, or WPA2 + WPS +
 * Deauth-vulnerable. 5 slots leaves headroom. */
#define PMF_MAX_FINDINGS 5

typedef enum {
    PmfEncOpen,
    PmfEncWep,
    PmfEncWpa,
    PmfEncWpa2,
    PmfEncWpa2Ent,
    PmfEncWpa3,
    PmfEncWpa3Ent,
    PmfEncWpa2Wpa3,
    PmfEncOwe,
    PmfEncUnknown,
} PmfEnc;

typedef struct {
    const char* label; /* short label, shown in the results list */
    const char* fix; /* plain-language fix, shown in the detail view */
    bool exploitable; /* true = EXPLOITABLE group, false = PROTECT BETTER */
} PmfFinding;

typedef struct {
    char bssid[18]; /* aa:bb:cc:dd:ee:ff */
    char ssid[PMF_MAX_SSID_LEN + 1]; /* decoded, sanitised for display */
    bool hidden; /* true when the SSID field was empty / undecodable */
    uint8_t channel;
    int8_t rssi;
    PmfEnc enc;
    char enc_str[12]; /* raw enc token as sent by the board */
    bool mfpc;
    bool mfpr;
    bool bip;
    bool wps;
    uint8_t clients;
    PmfFinding findings[PMF_MAX_FINDINGS];
    uint8_t finding_count;
    uint8_t exploitable_count; /* findings with exploitable == true */
} PmfAp;

/* Base64-decode `in` (standard alphabet, '=' padding) into `out`.
 * Non-printable / non-ASCII bytes are replaced with '?' so the result
 * is always safe to draw on screen. Returns false on bad input
 * characters (out is still NUL-terminated). Empty input decodes to an
 * empty string (hidden SSID). */
bool pmf_b64_decode(const char* in, char* out, size_t out_size);

/* "WPA2" -> PmfEncWpa2, anything else -> PmfEncUnknown. */
PmfEnc pmf_enc_from_str(const char* s);

/* Canonical label for an encryption enum ("WPA2-WPA3", ...). */
const char* pmf_enc_to_str(PmfEnc enc);

/* Parse one AP line (without the trailing newline) into `ap` and
 * compute its findings. Returns false if the line is malformed. */
bool pmf_parse_ap_line(const char* line, PmfAp* ap);

/* (Re)compute findings from the AP facts. Called by
 * pmf_parse_ap_line; exposed for tests. */
void pmf_compute_findings(PmfAp* ap);

/* True when the AP has no findings at all (clean). */
static inline bool pmf_is_clean(const PmfAp* ap) {
    return ap->finding_count == 0;
}

/*
 * pmf_logic.c — pure protocol + findings logic for Boot Sniffer 2.4.
 *
 * Findings rules (from ../firmware/README.md — the source of truth;
 * computed from beacon facts ONLY, nothing is inferred beyond them):
 *
 * EXPLOITABLE (an attacker can act on this now):
 *   enc == OPEN  -> "Open network"
 *   enc == WEP   -> "WEP is broken"
 *   enc == WPA   -> "Outdated WPA / TKIP"
 *   wps == 1     -> "WPS enabled"
 *   mfpr == 0 and enc in (WPA2, WPA3, WPA2-ENT, WPA3-ENT, WPA2-WPA3)
 *       -> "Deauth-vulnerable"
 *
 * PROTECT BETTER (not immediately exploitable, harden it):
 *   enc == WPA2 and mfpr == 1      -> "WPA2 only, PMF required"
 *   enc == WPA2-WPA3 and mfpr == 1 -> "Transition mode"
 *   enc == OWE                     -> "Enhanced Open (OWE)"
 *
 * An AP with MFPR == 1 and WPA3 / WPA3-ENT has no findings (clean).
 * The client count never creates a finding by itself.
 *
 * The Deauth-vulnerable set covers the -ENT variants too: PMF is
 * optional in WPA2-Enterprise, so a WPA2-ENT AP with MFPR == 0 can
 * still have its clients kicked off. (WPA3-ENT requires PMF, so
 * MFPR == 0 on a WPA3-ENT beacon should not happen in practice —
 * if it does, it is still flagged.)
 */
#include "pmf_logic.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Base64 decode                                                       */
/* ------------------------------------------------------------------ */

static int pmf_b64_value(char c) {
    if(c >= 'A' && c <= 'Z') return c - 'A';
    if(c >= 'a' && c <= 'z') return c - 'a' + 26;
    if(c >= '0' && c <= '9') return c - '0' + 52;
    if(c == '+') return 62;
    if(c == '/') return 63;
    return -1;
}

bool pmf_b64_decode(const char* in, char* out, size_t out_size) {
    size_t o = 0;
    size_t len = strlen(in);
    bool ok = true;

    if(out_size == 0) return false;
    out[0] = '\0';

    for(size_t i = 0; i < len; i += 4) {
        int v[4] = {0, 0, 0, 0};
        int pad = 0;
        for(int k = 0; k < 4; k++) {
            if(i + (size_t)k >= len) {
                v[k] = 0;
                pad++;
            } else if(in[i + k] == '=') {
                v[k] = 0;
                pad++;
            } else {
                v[k] = pmf_b64_value(in[i + k]);
                if(v[k] < 0) {
                    ok = false;
                    v[k] = 0;
                }
            }
        }
        uint8_t bytes[3];
        bytes[0] = (uint8_t)((v[0] << 2) | (v[1] >> 4));
        bytes[1] = (uint8_t)(((v[1] & 0x0F) << 4) | (v[2] >> 2));
        bytes[2] = (uint8_t)(((v[2] & 0x03) << 6) | v[3]);
        int nbytes = 3 - pad;
        for(int k = 0; k < nbytes; k++) {
            if(o + 1 >= out_size) {
                out[o] = '\0';
                return false;
            }
            /* Sanitise for display: printable ASCII only. */
            char c = (char)bytes[k];
            if(c < 0x20 || c >= 0x7F) c = '?';
            out[o++] = c;
        }
    }
    out[o] = '\0';
    return ok;
}

/* ------------------------------------------------------------------ */
/* Encryption                                                          */
/* ------------------------------------------------------------------ */

PmfEnc pmf_enc_from_str(const char* s) {
    if(strcmp(s, "OPEN") == 0) return PmfEncOpen;
    if(strcmp(s, "WEP") == 0) return PmfEncWep;
    if(strcmp(s, "WPA") == 0) return PmfEncWpa;
    if(strcmp(s, "WPA2") == 0) return PmfEncWpa2;
    if(strcmp(s, "WPA2-ENT") == 0) return PmfEncWpa2Ent;
    if(strcmp(s, "WPA3") == 0) return PmfEncWpa3;
    if(strcmp(s, "WPA3-ENT") == 0) return PmfEncWpa3Ent;
    if(strcmp(s, "WPA2-WPA3") == 0) return PmfEncWpa2Wpa3;
    if(strcmp(s, "OWE") == 0) return PmfEncOwe;
    return PmfEncUnknown;
}

const char* pmf_enc_to_str(PmfEnc enc) {
    switch(enc) {
    case PmfEncOpen: return "OPEN";
    case PmfEncWep: return "WEP";
    case PmfEncWpa: return "WPA";
    case PmfEncWpa2: return "WPA2";
    case PmfEncWpa2Ent: return "WPA2-ENT";
    case PmfEncWpa3: return "WPA3";
    case PmfEncWpa3Ent: return "WPA3-ENT";
    case PmfEncWpa2Wpa3: return "WPA2-WPA3";
    case PmfEncOwe: return "OWE";
    default: return "UNKNOWN";
    }
}

/* ------------------------------------------------------------------ */
/* Findings                                                            */
/* ------------------------------------------------------------------ */

static void pmf_add_finding(PmfAp* ap, const char* label, const char* fix, bool exploitable) {
    if(ap->finding_count >= PMF_MAX_FINDINGS) return;
    ap->findings[ap->finding_count].label = label;
    ap->findings[ap->finding_count].fix = fix;
    ap->findings[ap->finding_count].exploitable = exploitable;
    ap->finding_count++;
    if(exploitable) ap->exploitable_count++;
}

void pmf_compute_findings(PmfAp* ap) {
    ap->finding_count = 0;
    ap->exploitable_count = 0;

    /* --- EXPLOITABLE --- */
    if(ap->enc == PmfEncOpen) {
        pmf_add_finding(
            ap,
            "Open network",
            "Set WPA2 or WPA3 with a strong password - anyone nearby can join and read traffic.",
            true);
    }
    if(ap->enc == PmfEncWep) {
        pmf_add_finding(
            ap, "WEP is broken", "WEP is broken in minutes - switch to WPA2 or WPA3.", true);
    }
    if(ap->enc == PmfEncWpa) {
        pmf_add_finding(
            ap,
            "Outdated WPA / TKIP",
            "WPA/TKIP is outdated - switch to WPA2-AES or WPA3.",
            true);
    }
    if(ap->wps) {
        pmf_add_finding(
            ap, "WPS enabled", "Turn off WPS - its PIN can be brute-forced.", true);
    }
    /* Deauth-vulnerable: MFPR == 0 on an RSN network (WPA2 / WPA3 /
     * WPA2-ENT / WPA3-ENT / WPA2-WPA3). */
    if(!ap->mfpr &&
       (ap->enc == PmfEncWpa2 || ap->enc == PmfEncWpa3 || ap->enc == PmfEncWpa2Wpa3 ||
        ap->enc == PmfEncWpa2Ent || ap->enc == PmfEncWpa3Ent)) {
        pmf_add_finding(
            ap,
            "Deauth-vulnerable",
            "Turn on Protected Management Frames (PMF) and set it to Required, not just Capable.",
            true);
    }

    /* --- PROTECT BETTER --- */
    if(ap->enc == PmfEncWpa2 && ap->mfpr) {
        pmf_add_finding(
            ap,
            "WPA2 only, PMF required",
            "Move to WPA3 (or WPA2/WPA3 transition) if your devices support it.",
            false);
    }
    if(ap->enc == PmfEncWpa2Wpa3 && ap->mfpr) {
        pmf_add_finding(
            ap,
            "Transition mode",
            "Move to WPA3-only once all your devices support it - the WPA2 side is the weak part.",
            false);
    }
    if(ap->enc == PmfEncOwe) {
        pmf_add_finding(
            ap,
            "Enhanced Open (OWE)",
            "Traffic is encrypted per client, but anyone can join - use WPA3 with a password if this network should be private.",
            false);
    }
}

/* ------------------------------------------------------------------ */
/* AP line parsing                                                     */
/*                                                                     */
/* AP|<bssid>|<ssid_b64>|<ch>|<rssi>|<enc>|<mfpc>|<mfpr>|<bip>|<wps>|  */
/* <clients>                                                           */
/* ------------------------------------------------------------------ */

static bool pmf_parse_flag(const char* s, bool* out) {
    if(strcmp(s, "0") == 0) {
        *out = false;
        return true;
    }
    if(strcmp(s, "1") == 0) {
        *out = true;
        return true;
    }
    return false;
}

bool pmf_parse_ap_line(const char* line, PmfAp* ap) {
    if(line == NULL || ap == NULL) return false;
    if(strncmp(line, "AP|", 3) != 0) return false;

    /* Split into fields in place (copy first: the caller's line may be
     * reused). 11 fields expected. */
    char buf[256];
    size_t line_len = strlen(line);
    if(line_len >= sizeof(buf)) return false;
    memcpy(buf, line, line_len + 1);

    char* fields[11];
    int nfields = 0;
    char* p = buf;
    fields[nfields++] = p;
    while(nfields < 11) {
        char* sep = strchr(p, '|');
        if(sep == NULL) break;
        *sep = '\0';
        p = sep + 1;
        fields[nfields++] = p;
    }
    if(nfields != 11) return false;
    /* No extra '|' allowed in the last field. */
    if(strchr(fields[10], '|') != NULL) return false;

    memset(ap, 0, sizeof(PmfAp));

    /* BSSID: lowercase hex with colons, 17 chars. */
    if(strlen(fields[1]) != 17) return false;
    strncpy(ap->bssid, fields[1], sizeof(ap->bssid) - 1);

    /* SSID: base64, empty = hidden. */
    if(fields[2][0] == '\0') {
        ap->hidden = true;
        ap->ssid[0] = '\0';
    } else {
        if(!pmf_b64_decode(fields[2], ap->ssid, sizeof(ap->ssid))) {
            /* Undecodable SSID: still keep the AP, show its BSSID. */
            ap->hidden = true;
            ap->ssid[0] = '\0';
        } else if(ap->ssid[0] == '\0') {
            ap->hidden = true;
        }
    }

    long ch = strtol(fields[3], NULL, 10);
    long rssi = strtol(fields[4], NULL, 10);
    if(ch < 1 || ch > 14) return false;
    if(rssi < -127 || rssi > 0) return false;
    ap->channel = (uint8_t)ch;
    ap->rssi = (int8_t)rssi;

    ap->enc = pmf_enc_from_str(fields[5]);
    strncpy(ap->enc_str, fields[5], sizeof(ap->enc_str) - 1);
    ap->enc_str[sizeof(ap->enc_str) - 1] = '\0';

    if(!pmf_parse_flag(fields[6], &ap->mfpc)) return false;
    if(!pmf_parse_flag(fields[7], &ap->mfpr)) return false;
    if(!pmf_parse_flag(fields[8], &ap->bip)) return false;
    if(!pmf_parse_flag(fields[9], &ap->wps)) return false;

    long clients = strtol(fields[10], NULL, 10);
    if(clients < 0 || clients > 255) return false;
    ap->clients = (uint8_t)clients;

    pmf_compute_findings(ap);
    return true;
}

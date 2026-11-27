/*
 * pmf_audit.c — PMF / deauth-immunity audit firmware for the Flipper Zero
 * WiFi Devboard (ESP32-S2).
 *
 * One job: passively listen on 2.4 GHz, parse beacon frames, and report
 * per-AP facts over UART (115200 8N1) so a host (Flipper app, or any
 * serial terminal) can tell which networks are immune to deauth attacks.
 *
 * Detection only. This firmware never transmits 802.11 frames and never
 * associates to any network. It cannot see 5 GHz (the ESP32-S2 has no
 * 5 GHz radio).
 *
 * Facts reported per AP (all read straight from beacon frames):
 *   - SSID, BSSID, channel, RSSI
 *   - Encryption: OPEN / WEP / WPA / WPA2 / WPA2-ENT / WPA3 / WPA3-ENT /
 *     WPA2-WPA3 (transition) / OWE
 *   - PMF flags from the RSN IE (tag 48) Capabilities field:
 *       MFPC = bit 6 (0x40), MFPR = bit 7 (0x80) — IEEE 802.11-2020 9.4.2.24
 *   - BIP (group management cipher suite type 6) present or not
 *   - WPS present (vendor IE, OUI 00:50:F2, type 4)
 *   - Number of distinct client MACs seen sending data frames to the AP
 *
 * Serial protocol (see firmware/README.md for the full spec):
 *   Host -> board:  "PING" / "SCAN [seconds]" / "STOP"
 *   Board -> host:  "PMF-AUDIT READY" (boot)
 *                    "PONG PMF-AUDIT 1.0"
 *                    "AP|<bssid>|<ssid_b64>|<ch>|<rssi>|<enc>|<mfpc>|<mfpr>|<bip>|<wps>|<clients>"
 *                    "DONE <n>"
 *                    "ERR <msg>"
 *
 * Deauth-immunity rule (applied by the host, documented here so the
 * verdict is checkable): an AP is deauth-immune iff MFPR == 1. MFPR is
 * mandatory in WPA3; in WPA2 it is optional, so a WPA2 AP with MFPR == 0
 * can still have its clients kicked off, even if MFPC == 1.
 *
 * Build: ESP-IDF v5.3, target esp32s2. See firmware/README.md.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_log.h"
#include "driver/uart.h"
#include "nvs_flash.h"

#define PMF_AUDIT_VERSION "1.0"

#define MAX_APS            64
#define MAX_CLIENTS_PER_AP 8
#define MAX_SSID_LEN       32
#define SCAN_CHANNELS      11          /* 2.4 GHz channels 1-11 (US legal) */
#define DEFAULT_SCAN_SECS  15
#define MIN_SCAN_SECS      5
#define MAX_SCAN_SECS      60

/* ------------------------------------------------------------------ */
/* AP table                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t bssid[6];
    uint8_t ssid[MAX_SSID_LEN];
    uint8_t ssid_len;               /* 0 = hidden SSID */
    uint8_t channel;
    int8_t  rssi;                   /* strongest RSSI seen */
    bool    privacy;                /* capability "privacy" bit (WEP/WPA) */
    bool    has_rsn;                /* RSN IE (tag 48) seen */
    bool    has_wpa;                /* WPA vendor IE seen */
    bool    akm_psk;
    bool    akm_sae;
    bool    akm_ent;                /* 802.1X AKM */
    bool    akm_owe;
    bool    mfpc;
    bool    mfpr;
    bool    bip;                    /* group mgmt cipher suite = BIP (type 6) */
    bool    wps;
    uint8_t clients[MAX_CLIENTS_PER_AP][6];
    uint8_t client_count;
    bool    used;
} ap_entry_t;

static ap_entry_t ap_table[MAX_APS];
static SemaphoreHandle_t ap_mutex;
static volatile bool scanning = false;
static volatile bool stop_requested = false;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static bool mac_eq(const uint8_t *a, const uint8_t *b) {
    return memcmp(a, b, 6) == 0;
}

static ap_entry_t *find_ap(const uint8_t *bssid) {
    for (int i = 0; i < MAX_APS; i++) {
        if (ap_table[i].used && mac_eq(ap_table[i].bssid, bssid)) return &ap_table[i];
    }
    return NULL;
}

static ap_entry_t *find_or_add_ap(const uint8_t *bssid) {
    ap_entry_t *ap = find_ap(bssid);
    if (ap) return ap;
    for (int i = 0; i < MAX_APS; i++) {
        if (!ap_table[i].used) {
            memset(&ap_table[i], 0, sizeof(ap_entry_t));
            memcpy(ap_table[i].bssid, bssid, 6);
            ap_table[i].rssi = -127;
            ap_table[i].used = true;
            return &ap_table[i];
        }
    }
    return NULL; /* table full — AP is dropped, noted in README */
}

static void add_client(ap_entry_t *ap, const uint8_t *mac) {
    if (mac[0] & 0x01) return;               /* ignore multicast/broadcast */
    for (int i = 0; i < ap->client_count; i++) {
        if (mac_eq(ap->clients[i], mac)) return;
    }
    if (ap->client_count < MAX_CLIENTS_PER_AP) {
        memcpy(ap->clients[ap->client_count], mac, 6);
        ap->client_count++;
    }
}

static const char *b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Small base64 encoder (SSID may contain '|' or non-printable bytes). */
static void b64_encode(const uint8_t *in, size_t len, char *out, size_t out_size) {
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = in[i] << 16;
        if (i + 1 < len) v |= in[i + 1] << 8;
        if (i + 2 < len) v |= in[i + 2];
        if (o + 4 >= out_size) break;
        out[o++] = b64_alphabet[(v >> 18) & 0x3F];
        out[o++] = b64_alphabet[(v >> 12) & 0x3F];
        out[o++] = (i + 1 < len) ? b64_alphabet[(v >> 6) & 0x3F] : '=';
        out[o++] = (i + 2 < len) ? b64_alphabet[v & 0x3F] : '=';
    }
    out[o] = '\0';
}

/* ------------------------------------------------------------------ */
/* Beacon / IE parsing                                                 */
/* ------------------------------------------------------------------ */

/*
 * Parse one RSN IE body (bytes after tag+length).
 * Layout: version(2) | group cipher(4) | pairwise count(2) | pairwise
 * list(4 each) | AKM count(2) | AKM list(4 each) | RSN caps(2) |
 * [PMKID count(2) | PMKID list(16 each) | group mgmt cipher(4)].
 * All multi-byte integers are little-endian. Every step is bounds
 * checked; a truncated IE just yields what could be parsed.
 */
static void parse_rsn_ie(const uint8_t *ie, size_t len, ap_entry_t *ap) {
    size_t p = 0;
    ap->has_rsn = true;
    if (len < 2) return;
    p += 2; /* version */

    if (len - p < 4) return;
    p += 4; /* group cipher suite */

    if (len - p < 2) return;
    uint16_t pairwise_count = ie[p] | (ie[p + 1] << 8);
    p += 2;
    if (len - p < (size_t)pairwise_count * 4) return;
    p += (size_t)pairwise_count * 4;

    if (len - p < 2) return;
    uint16_t akm_count = ie[p] | (ie[p + 1] << 8);
    p += 2;
    if (len - p < (size_t)akm_count * 4) return;
    for (int i = 0; i < akm_count; i++) {
        const uint8_t *akm = ie + p + (size_t)i * 4;
        /* AKM suite: OUI 00:0F:AC + type byte. */
        if (akm[0] == 0x00 && akm[1] == 0x0F && akm[2] == 0xAC) {
            switch (akm[3]) {
                case 1: case 3: case 5: case 6:   /* 802.1X family */
                    ap->akm_ent = true;
                    break;
                case 2: case 4:                   /* PSK family */
                    ap->akm_psk = true;
                    break;
                case 8: case 9: case 24:          /* SAE family */
                    ap->akm_sae = true;
                    break;
                case 18:                          /* OWE */
                    ap->akm_owe = true;
                    break;
                default:
                    break;
            }
        }
    }
    p += (size_t)akm_count * 4;

    if (len - p < 2) return;
    /* RSN Capabilities: little-endian. MFPC = bit 6, MFPR = bit 7. */
    uint16_t rsn_caps = ie[p] | (ie[p + 1] << 8);
    ap->mfpc = (rsn_caps & 0x0040) != 0;
    ap->mfpr = (rsn_caps & 0x0080) != 0;
    p += 2;

    /* Optional: PMKID count + list, then group management cipher suite. */
    if (len - p < 2) return;
    uint16_t pmkid_count = ie[p] | (ie[p + 1] << 8);
    p += 2;
    if (len - p < (size_t)pmkid_count * 16) return;
    p += (size_t)pmkid_count * 16;
    if (len - p >= 4) {
        const uint8_t *gmc = ie + p;
        if (gmc[0] == 0x00 && gmc[1] == 0x0F && gmc[2] == 0xAC && gmc[3] == 6) {
            ap->bip = true;   /* BIP (128) group management cipher */
        }
    }
}

/* Walk the tagged IEs of a beacon body. `ies` points at the first IE. */
static void parse_beacon_ies(const uint8_t *ies, size_t len, ap_entry_t *ap) {
    size_t p = 0;
    while (p + 2 <= len) {
        uint8_t tag = ies[p];
        uint8_t ilen = ies[p + 1];
        if (p + 2 + ilen > len) break;   /* truncated IE: stop */
        const uint8_t *body = ies + p + 2;
        switch (tag) {
            case 0: /* SSID */
                if (ilen <= MAX_SSID_LEN) {
                    memcpy(ap->ssid, body, ilen);
                    ap->ssid_len = ilen;
                }
                break;
            case 48: /* RSN */
                parse_rsn_ie(body, ilen, ap);
                break;
            case 221: /* vendor-specific */
                if (ilen >= 4 && body[0] == 0x00 && body[1] == 0x50 && body[2] == 0xF2) {
                    if (body[3] == 0x01) ap->has_wpa = true;  /* WPA IE */
                    if (body[3] == 0x04) ap->wps = true;      /* WPS IE */
                }
                break;
            default:
                break;
        }
        p += 2 + ilen;
    }
}

static void handle_beacon(const uint8_t *payload, size_t len, int8_t rssi, uint8_t channel) {
    /* 24-byte MAC header + 12-byte fixed params (timestamp 8, interval 2,
     * capability 2). Capability "privacy" bit is 0x0010. */
    if (len < 36) return;
    uint16_t cap = payload[34] | (payload[35] << 8);

    if (xSemaphoreTake(ap_mutex, pdMS_TO_TICKS(10)) != pdTRUE) return;
    ap_entry_t *ap = find_or_add_ap(payload + 10); /* addr2 = BSSID */
    if (ap) {
        ap->channel = channel;
        if (rssi > ap->rssi) ap->rssi = rssi;
        ap->privacy = (cap & 0x0010) != 0;
        parse_beacon_ies(payload + 36, len - 36, ap);
    }
    xSemaphoreGive(ap_mutex);
}

static void handle_data_frame(const uint8_t *payload, size_t len) {
    if (len < 24) return;
    uint8_t fc1 = payload[1];
    bool to_ds = (fc1 & 0x01) != 0;
    bool from_ds = (fc1 & 0x02) != 0;
    const uint8_t *bssid = NULL;
    const uint8_t *client = NULL;

    if (!to_ds && from_ds) {          /* AP -> station */
        bssid = payload + 10;         /* addr2 */
        client = payload + 4;         /* addr1 */
    } else if (to_ds && !from_ds) {   /* station -> AP */
        bssid = payload + 4;          /* addr1 */
        client = payload + 10;        /* addr2 */
    } else {
        return;                       /* WDS / IBSS: not counted */
    }

    if (xSemaphoreTake(ap_mutex, pdMS_TO_TICKS(10)) != pdTRUE) return;
    ap_entry_t *ap = find_ap(bssid);  /* only count clients of known APs */
    if (ap) add_client(ap, client);
    xSemaphoreGive(ap_mutex);
}

static void promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!scanning) return;
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    /* The payload includes the 4-byte FCS at the end; exclude it so the
     * IE walk never mistakes FCS bytes for an information element. */
    size_t len = pkt->rx_ctrl.sig_len;
    if (len > 4) len -= 4;
    if (type == WIFI_PKT_MGMT) {
        if (pkt->payload[0] == 0x80) {   /* beacon */
            handle_beacon(pkt->payload, len,
                          pkt->rx_ctrl.rssi, pkt->rx_ctrl.channel);
        }
    } else if (type == WIFI_PKT_DATA) {
        handle_data_frame(pkt->payload, len);
    }
}

/* ------------------------------------------------------------------ */
/* Encryption classification (from parsed beacon facts only)           */
/* ------------------------------------------------------------------ */

static const char *encryption_string(const ap_entry_t *ap) {
    if (ap->has_rsn) {
        if (ap->akm_owe && !ap->akm_psk && !ap->akm_sae && !ap->akm_ent) return "OWE";
        if (ap->akm_sae && ap->akm_psk) return "WPA2-WPA3";
        if (ap->akm_sae && ap->akm_ent) return "WPA3-ENT";
        if (ap->akm_sae) return "WPA3";
        if (ap->akm_ent) return "WPA2-ENT";
        if (ap->akm_psk) return "WPA2";
        return "WPA2";   /* RSN present but AKM list unparseable: safest label */
    }
    if (ap->has_wpa) return "WPA";
    if (ap->privacy) return "WEP";
    return "OPEN";
}

/* ------------------------------------------------------------------ */
/* Scan control + serial protocol                                      */
/* ------------------------------------------------------------------ */

static void print_ap_line(const ap_entry_t *ap) {
    char bssid_str[18];
    char ssid_b64[48];
    snprintf(bssid_str, sizeof(bssid_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             ap->bssid[0], ap->bssid[1], ap->bssid[2],
             ap->bssid[3], ap->bssid[4], ap->bssid[5]);
    b64_encode(ap->ssid, ap->ssid_len, ssid_b64, sizeof(ssid_b64));
    printf("AP|%s|%s|%d|%d|%s|%d|%d|%d|%d|%d\n",
           bssid_str, ssid_b64, ap->channel, (int)ap->rssi,
           encryption_string(ap),
           ap->mfpc ? 1 : 0, ap->mfpr ? 1 : 0, ap->bip ? 1 : 0,
           ap->wps ? 1 : 0, ap->client_count);
    fflush(stdout);
}

static void run_scan(int seconds) {
    if (seconds < MIN_SCAN_SECS) seconds = MIN_SCAN_SECS;
    if (seconds > MAX_SCAN_SECS) seconds = MAX_SCAN_SECS;

    if (xSemaphoreTake(ap_mutex, portMAX_DELAY) == pdTRUE) {
        memset(ap_table, 0, sizeof(ap_table));
        for (int i = 0; i < MAX_APS; i++) ap_table[i].rssi = -127;
        xSemaphoreGive(ap_mutex);
    }

    int dwell_ms = (seconds * 1000) / SCAN_CHANNELS;
    stop_requested = false;
    scanning = true;

    for (int ch = 1; ch <= SCAN_CHANNELS && !stop_requested; ch++) {
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        /* Dwell in slices so STOP is honored promptly. */
        for (int waited = 0; waited < dwell_ms && !stop_requested; waited += 100) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
    scanning = false;

    int count = 0;
    if (xSemaphoreTake(ap_mutex, portMAX_DELAY) == pdTRUE) {
        for (int i = 0; i < MAX_APS; i++) {
            if (ap_table[i].used) {
                print_ap_line(&ap_table[i]);
                count++;
            }
        }
        xSemaphoreGive(ap_mutex);
    }
    printf("DONE %d\n", count);
    fflush(stdout);
}

static void handle_command(char *line) {
    /* Strip trailing CR/LF. */
    size_t n = strlen(line);
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';

    if (strcmp(line, "PING") == 0) {
        printf("PONG PMF-AUDIT " PMF_AUDIT_VERSION "\n");
        fflush(stdout);
    } else if (strncmp(line, "SCAN", 4) == 0) {
        int secs = DEFAULT_SCAN_SECS;
        if (line[4] == ' ') secs = atoi(line + 5);
        run_scan(secs);
    } else if (strcmp(line, "STOP") == 0) {
        stop_requested = true;
        printf("STOPPED\n");
        fflush(stdout);
    } else if (line[0] != '\0') {
        printf("ERR unknown command: %s\n", line);
        fflush(stdout);
    }
}

static void uart_command_task(void *arg) {
    /* UART0 is the console UART and the Flipper link (115200 8N1). */
    uart_driver_install(UART_NUM_0, 512, 0, 0, NULL, 0);
    char line[64];
    size_t pos = 0;
    uint8_t byte;
    while (1) {
        int r = uart_read_bytes(UART_NUM_0, &byte, 1, pdMS_TO_TICKS(100));
        if (r == 1) {
            if (byte == '\n') {
                line[pos] = '\0';
                handle_command(line);
                pos = 0;
            } else if (pos < sizeof(line) - 1) {
                line[pos++] = (char)byte;
            }
        }
    }
}

void app_main(void) {
    /* Keep the UART clean: no ESP_LOG output on the protocol channel. */
    esp_log_level_set("*", ESP_LOG_NONE);

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    ap_mutex = xSemaphoreCreateMutex();
    for (int i = 0; i < MAX_APS; i++) ap_table[i].rssi = -127;

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
    };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(promiscuous_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

    xTaskCreate(uart_command_task, "uart_cmd", 4096, NULL, 5, NULL);

    printf("PMF-AUDIT READY\n");
    fflush(stdout);
}

/* Host test for pmf_logic.c — compiles with plain gcc, no Flipper SDK.
 * Run:  gcc -Wall -Wextra -I.. -o /tmp/pmf_logic_test host_test.c ../pmf_logic.c && /tmp/pmf_logic_test
 */
#include <stdio.h>
#include <string.h>

#include "../pmf_logic.h"

static int failures = 0;

#define CHECK(cond, msg)                                        \
    do {                                                        \
        if(!(cond)) {                                           \
            printf("FAIL: %s (line %d)\n", msg, __LINE__);      \
            failures++;                                         \
        }                                                       \
    } while(0)

static void check_ap(const char* line, bool want_ok) {
    PmfAp ap;
    bool ok = pmf_parse_ap_line(line, &ap);
    CHECK(ok == want_ok, line);
}

static void test_b64(void) {
    char out[64];
    CHECK(pmf_b64_decode("SG9tZVdpRmk=", out, sizeof(out)) && strcmp(out, "HomeWiFi") == 0,
          "b64 HomeWiFi");
    CHECK(pmf_b64_decode("", out, sizeof(out)) && out[0] == '\0', "b64 empty");
    /* "My|Net" with a pipe byte, and a 0x01 byte -> '?' */
    CHECK(pmf_b64_decode("TXl8TmV0", out, sizeof(out)) && strcmp(out, "My|Net") == 0,
          "b64 pipe in SSID");
    CHECK(pmf_b64_decode("QQE=", out, sizeof(out)) && strcmp(out, "A?") == 0,
          "b64 non-printable sanitised");
    CHECK(!pmf_b64_decode("!!!=", out, sizeof(out)), "b64 bad chars rejected");
}

static void test_parse_example_from_firmware_readme(void) {
    PmfAp ap;
    /* Example straight from ../firmware/README.md. */
    CHECK(pmf_parse_ap_line("AP|aa:bb:cc:dd:ee:ff|SG9tZVdpRmk=|6|-42|WPA2|1|0|1|0|3", &ap),
          "readme example parses");
    CHECK(strcmp(ap.bssid, "aa:bb:cc:dd:ee:ff") == 0, "readme bssid");
    CHECK(strcmp(ap.ssid, "HomeWiFi") == 0 && !ap.hidden, "readme ssid");
    CHECK(ap.channel == 6 && ap.rssi == -42, "readme ch/rssi");
    CHECK(ap.enc == PmfEncWpa2, "readme enc");
    CHECK(ap.mfpc && !ap.mfpr && ap.bip && !ap.wps, "readme flags");
    CHECK(ap.clients == 3, "readme clients");
    CHECK(ap.finding_count == 1 && ap.exploitable_count == 1 &&
              strcmp(ap.findings[0].label, "Deauth-vulnerable") == 0,
          "readme example is Deauth-vulnerable");

    CHECK(pmf_parse_ap_line("AP|11:22:33:44:55:66||1|-71|OPEN|0|0|0|0|0", &ap),
          "readme hidden open parses");
    CHECK(ap.hidden && ap.ssid[0] == '\0', "hidden ssid");
    CHECK(ap.enc == PmfEncOpen, "hidden open enc");
    CHECK(ap.finding_count == 1 && strcmp(ap.findings[0].label, "Open network") == 0,
          "hidden open finding");
}

static void test_findings_matrix(void) {
    PmfAp ap;
    /* WPA3 + MFPR=1 -> clean. */
    CHECK(pmf_parse_ap_line("AP|aa:bb:cc:dd:ee:01|V1BBMw==|6|-50|WPA3|1|1|1|0|2", &ap),
          "wpa3 parses");
    CHECK(ap.finding_count == 0 && pmf_is_clean(&ap), "WPA3 MFPR=1 is clean");

    /* WPA3-ENT + MFPR=1 -> clean. */
    CHECK(pmf_parse_ap_line("AP|aa:bb:cc:dd:ee:02|V1BBMw==|6|-50|WPA3-ENT|1|1|1|0|0", &ap),
          "wpa3-ent parses");
    CHECK(ap.finding_count == 0, "WPA3-ENT MFPR=1 is clean");

    /* WPA3 + MFPR=0 -> Deauth-vulnerable (README set includes WPA3). */
    CHECK(pmf_parse_ap_line("AP|aa:bb:cc:dd:ee:03|V1BBMw==|6|-50|WPA3|1|0|1|0|0", &ap),
          "wpa3 mfpr0 parses");
    CHECK(ap.finding_count == 1 && strcmp(ap.findings[0].label, "Deauth-vulnerable") == 0,
          "WPA3 MFPR=0 is Deauth-vulnerable");

    /* WPA2-ENT + MFPR=0 -> Deauth-vulnerable (PMF is optional in WPA2-ENT). */
    CHECK(pmf_parse_ap_line("AP|aa:bb:cc:dd:ee:05|V1BBMw==|6|-50|WPA2-ENT|1|0|1|0|0", &ap),
          "wpa2-ent mfpr0 parses");
    CHECK(ap.finding_count == 1 && strcmp(ap.findings[0].label, "Deauth-vulnerable") == 0,
          "WPA2-ENT MFPR=0 is Deauth-vulnerable");

    /* WPA3-ENT + MFPR=0 -> Deauth-vulnerable (should not happen in practice,
     * but if the beacon says so, flag it). */
    CHECK(pmf_parse_ap_line("AP|aa:bb:cc:dd:ee:06|V1BBMw==|6|-50|WPA3-ENT|1|0|1|0|0", &ap),
          "wpa3-ent mfpr0 parses");
    CHECK(ap.finding_count == 1 && strcmp(ap.findings[0].label, "Deauth-vulnerable") == 0,
          "WPA3-ENT MFPR=0 is Deauth-vulnerable");

    /* WPA2 + MFPR=1 -> PROTECT BETTER only. */
    CHECK(pmf_parse_ap_line("AP|aa:bb:cc:dd:ee:04|V1BBMw==|6|-50|WPA2|1|1|1|0|1", &ap),
          "wpa2 mfpr1 parses");
    CHECK(ap.finding_count == 1 && ap.exploitable_count == 0 &&
              strcmp(ap.findings[0].label, "WPA2 only, PMF required") == 0,
          "WPA2 MFPR=1 is protect-better");

    /* WPA2-WPA3 + MFPR=1 -> Transition mode. */
    CHECK(pmf_parse_ap_line("AP|aa:bb:cc:dd:ee:05|V1BBMw==|6|-50|WPA2-WPA3|1|1|1|0|0", &ap),
          "transition parses");
    CHECK(ap.finding_count == 1 && strcmp(ap.findings[0].label, "Transition mode") == 0,
          "transition mode finding");

    /* WPA2-WPA3 + MFPR=0 -> Deauth-vulnerable. */
    CHECK(pmf_parse_ap_line("AP|aa:bb:cc:dd:ee:06|V1BBMw==|6|-50|WPA2-WPA3|1|0|1|0|0", &ap),
          "transition mfpr0 parses");
    CHECK(ap.finding_count == 1 && ap.exploitable_count == 1 &&
              strcmp(ap.findings[0].label, "Deauth-vulnerable") == 0,
          "transition MFPR=0 is Deauth-vulnerable");

    /* OWE -> Enhanced Open, protect-better, not exploitable. */
    CHECK(pmf_parse_ap_line("AP|aa:bb:cc:dd:ee:07|T1dF|6|-60|OWE|0|0|0|0|0", &ap),
          "owe parses");
    CHECK(ap.finding_count == 1 && ap.exploitable_count == 0 &&
              strcmp(ap.findings[0].label, "Enhanced Open (OWE)") == 0,
          "OWE finding");

    /* WEP -> exploitable. */
    CHECK(pmf_parse_ap_line("AP|aa:bb:cc:dd:ee:08|T2Fr|6|-60|WEP|0|0|0|0|0", &ap),
          "wep parses");
    CHECK(ap.finding_count == 1 && strcmp(ap.findings[0].label, "WEP is broken") == 0,
          "WEP finding");

    /* WPA -> exploitable. */
    CHECK(pmf_parse_ap_line("AP|aa:bb:cc:dd:ee:09|T2Fr|6|-60|WPA|0|0|0|0|0", &ap),
          "wpa parses");
    CHECK(ap.finding_count == 1 && strcmp(ap.findings[0].label, "Outdated WPA / TKIP") == 0,
          "WPA finding");

    /* WPS on a clean WPA2/MFPR=1 AP adds an exploitable finding. */
    CHECK(pmf_parse_ap_line("AP|aa:bb:cc:dd:ee:0a|V1BBMw==|6|-50|WPA2|1|1|1|1|0", &ap),
          "wps parses");
    CHECK(ap.finding_count == 2 && ap.exploitable_count == 1 &&
              strcmp(ap.findings[0].label, "WPS enabled") == 0,
          "WPS adds exploitable finding on top of protect-better");

    /* Clients never create a finding by themselves. */
    CHECK(pmf_parse_ap_line("AP|aa:bb:cc:dd:ee:0b|V1BBMw==|6|-50|WPA3|1|1|1|0|8", &ap),
          "clients parses");
    CHECK(ap.finding_count == 0 && ap.clients == 8, "8 clients, still clean");

    /* WPA2-ENT + MFPR=0: Deauth-vulnerable (rule widened 2026-11-27;
     * the old test pinned the gap, this pins the fix). */
    CHECK(pmf_parse_ap_line("AP|aa:bb:cc:dd:ee:0c|V1BBMw==|6|-50|WPA2-ENT|1|0|1|0|0", &ap),
          "wpa2-ent parses");
    CHECK(ap.finding_count == 1 && strcmp(ap.findings[0].label, "Deauth-vulnerable") == 0,
          "WPA2-ENT MFPR=0 is Deauth-vulnerable");
}

static void test_malformed(void) {
    check_ap("AP|aa:bb:cc:dd:ee:ff|SG9tZVdJRmk=|6|-42|WPA2|1|0|1|0", false); /* 10 fields */
    check_ap("AP|aa:bb:cc:dd:ee:ff|SG9tZVdJRmk=|6|-42|WPA2|1|0|1|0|3|extra", false); /* 12 fields */
    check_ap("XX|aa:bb:cc:dd:ee:ff|SG9tZVdJRmk=|6|-42|WPA2|1|0|1|0|3", false); /* bad prefix */
    check_ap("AP|aabbccddeeff|SG9tZVdJRmk=|6|-42|WPA2|1|0|1|0|3", false); /* bad bssid */
    check_ap("AP|aa:bb:cc:dd:ee:ff|SG9tZVdJRmk=|99|-42|WPA2|1|0|1|0|3", false); /* bad channel */
    check_ap("AP|aa:bb:cc:dd:ee:ff|SG9tZVdJRmk=|6|-42|WPA2|2|0|1|0|3", false); /* bad flag */
    check_ap("AP|aa:bb:cc:dd:ee:ff|SG9tZVdJRmk=|6|-42|WPA2|1|0|1|0|-1", false); /* bad clients */
    check_ap("AP|aa:bb:cc:dd:ee:ff|SG9tZVdJRmk=|6|-42|WPA9|1|0|1|0|3", true); /* unknown enc: kept */
    PmfAp ap;
    CHECK(pmf_parse_ap_line("AP|aa:bb:cc:dd:ee:ff|SG9tZVdJRmk=|6|-42|WPA9|1|0|1|0|3", &ap) &&
              ap.enc == PmfEncUnknown,
          "unknown enc -> PmfEncUnknown, no crash");
}

int main(void) {
    test_b64();
    test_parse_example_from_firmware_readme();
    test_findings_matrix();
    test_malformed();
    if(failures == 0) {
        printf("All host tests passed.\n");
        return 0;
    }
    printf("%d test(s) FAILED.\n", failures);
    return 1;
}

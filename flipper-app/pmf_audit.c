/*
 * pmf_audit.c — "Boot Sniffer 2.4" Flipper Zero app (.fap, uFBT).
 *
 * Drives the WiFi Devboard (ESP32-S2, Boot Sniffer 2.4 firmware) over the
 * GPIO UART (USART1, 115200 baud, pins 13 TX / 14 RX), scans nearby
 * 2.4 GHz WiFi networks, and shows which ones are immune to deauth
 * attacks (immune iff MFPR == 1).
 *
 * DETECTION ONLY. This app never transmits 802.11 frames and has no
 * deauth or other attack feature. The board only listens.
 *
 * UNTESTED ON REAL HARDWARE: the WiFi Devboard had not arrived when
 * this was written. It compiles under uFBT (SDK 1.5.1) and its
 * parsing/findings logic is host-tested (see tests/host_test.c),
 * but no scan has ever run on a real board. Treat the first live
 * scan as a smoke test.
 *
 * UART API — verified against the uFBT SDK 1.5.1 headers
 * (furi_hal_serial.h, furi_hal_serial_control.h, expansion.h) and
 * the same pattern the ESP32 Marauder companion app and the ESP
 * Flasher app use:
 *   expansion_disable(RECORD_EXPANSION) before
 *   furi_hal_serial_control_acquire(FuriHalSerialIdUsart), then
 *   furi_hal_serial_init(handle, 115200),
 *   furi_hal_serial_async_rx_start() with an ISR callback that
 *   drains bytes via furi_hal_serial_async_rx() into a
 *   FuriStreamBuffer, and furi_hal_serial_tx() to send.
 * The old furi_hal_uart_* API is gone in current firmware; do not use
 * it. 5V power to the devboard is enabled with
 * furi_hal_power_enable_otg() while the app runs.
 */
#include <furi.h>
#include <furi_hal_power.h>
#include <furi_hal_serial.h>
#include <furi_hal_serial_control.h>
#include <expansion/expansion.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_box.h>
#include <gui/canvas.h>
#include <string.h>

#include "pmf_logic.h"

#define PMF_SCAN_SECONDS 15
#define PMF_PING_TIMEOUT_MS 2500
#define PMF_SCAN_GRACE_MS 8000
#define PMF_UART_BAUD 115200
#define PMF_LINE_BUF_SIZE 256
#define PMF_INFO_TEXT_SIZE 1200

#define TAG "PmfAudit"

/* ------------------------------------------------------------------ */
/* Views / events                                                      */
/* ------------------------------------------------------------------ */

typedef enum {
    PmfViewMainMenu,
    PmfViewScan,
    PmfViewResults,
    PmfViewInfo,
} PmfView;

typedef enum {
    PmfEventScanDone,
    PmfEventScanError,
} PmfEvent;

typedef enum {
    PmfWorkerIdle,
    PmfWorkerStartScan,
    PmfWorkerExit,
} PmfWorkerCmd;

/* Results rows (defined before the app struct, which holds them). */
typedef enum {
    PmfRowHeaderExploitable,
    PmfRowHeaderProtect,
    PmfRowHeaderAll,
    PmfRowAp,
    PmfRowAllAps,
} PmfRowKind;

typedef struct {
    uint8_t kind;
    uint8_t ap_index; /* valid for PmfRowAp */
} PmfRow;

/* ------------------------------------------------------------------ */
/* App state                                                           */
/* ------------------------------------------------------------------ */

typedef struct {
    Gui* gui;
    ViewDispatcher* view_dispatcher;
    Submenu* submenu;
    TextBox* text_box;
    View* scan_view;
    View* results_view;
    FuriThread* worker_thread;
    FuriStreamBuffer* rx_stream;
    FuriHalSerialHandle* serial_handle;
    Expansion* expansion;
    bool uart_ok;

    PmfAp aps[PMF_MAX_APS];
    uint8_t ap_count;
    uint8_t clean_count;

    /* Results list rows, rebuilt when entering the results view. */
    PmfRow rows[PMF_MAX_APS + 3];
    uint8_t row_count;
    uint8_t exploitable_count;
    uint8_t protect_count;

    char info_text[PMF_INFO_TEXT_SIZE];
    PmfView info_return_view;
    char error_text[256];

    /* Worker-thread coordination (volatile: written by one thread,
     * read by the other; plain aligned words are safe here). */
    volatile uint8_t worker_cmd;
    volatile bool scan_abort;
    char line_buf[PMF_LINE_BUF_SIZE];
    size_t line_pos;
} PmfAuditApp;

/* Scan view model (locked: written by the worker, drawn by the GUI). */
typedef struct {
    uint32_t start_tick;
    uint8_t aps_found;
    bool waiting_ping;
} PmfScanModel;

/* Results view model. */
typedef enum {
    PmfResultsModeFindings, /* grouped EXPLOITABLE / PROTECT BETTER */
    PmfResultsModeAll, /* every AP, with encryption */
} PmfResultsMode;

typedef struct {
    PmfAuditApp* app; /* back-pointer: the draw callback only gets the model */
    uint8_t mode;
    int16_t selected; /* index into app->rows[] */
    int16_t scroll; /* first visible row */
} PmfResultsModel;

/* ------------------------------------------------------------------ */
/* Small text helpers (ASCII only — the Flipper fonts have no         */
/* guarantee for anything fancier)                                     */
/* ------------------------------------------------------------------ */

static void pmf_text_append(char* dst, size_t dst_size, size_t* pos, const char* src) {
    size_t len = strlen(src);
    if(*pos + len >= dst_size) len = dst_size - *pos - 1;
    memcpy(dst + *pos, src, len);
    *pos += len;
    dst[*pos] = '\0';
}

/* Word-wrap `text` into `dst` at `width` columns. */
static void pmf_append_wrapped(
    char* dst,
    size_t dst_size,
    size_t* pos,
    const char* text,
    uint8_t width) {
    size_t line_len = 0;
    const char* p = text;
    while(*p) {
        /* Skip leading spaces at line start. */
        while(*p == ' ' && line_len == 0) p++;
        if(!*p) break;
        /* Next word. */
        const char* word = p;
        size_t word_len = 0;
        while(p[word_len] && p[word_len] != ' ') word_len++;
        if(line_len > 0 && line_len + 1 + word_len > width) {
            pmf_text_append(dst, dst_size, pos, "\n");
            line_len = 0;
        } else if(line_len > 0) {
            pmf_text_append(dst, dst_size, pos, " ");
            line_len++;
        }
        /* Hard-split words longer than the width. */
        size_t off = 0;
        while(off < word_len) {
            size_t chunk = word_len - off;
            if(line_len + chunk > width) chunk = width - line_len;
            char tmp[32];
            if(chunk >= sizeof(tmp)) chunk = sizeof(tmp) - 1;
            memcpy(tmp, word + off, chunk);
            tmp[chunk] = '\0';
            pmf_text_append(dst, dst_size, pos, tmp);
            line_len += chunk;
            off += chunk;
            if(off < word_len) {
                pmf_text_append(dst, dst_size, pos, "\n");
                line_len = 0;
            }
        }
        p += word_len;
    }
    pmf_text_append(dst, dst_size, pos, "\n");
}

/* Display name for an AP: SSID, or BSSID when hidden. */
static const char* pmf_ap_display_name(const PmfAp* ap) {
    return ap->hidden ? ap->bssid : ap->ssid;
}

/* ------------------------------------------------------------------ */
/* UART                                                                */
/* ------------------------------------------------------------------ */

static void pmf_uart_rx_callback(
    FuriHalSerialHandle* handle,
    FuriHalSerialRxEvent event,
    void* context) {
    PmfAuditApp* app = context;
    if(event & FuriHalSerialRxEventData) {
        while(furi_hal_serial_async_rx_available(handle)) {
            uint8_t byte = furi_hal_serial_async_rx(handle);
            /* ISR context: zero timeout, as the ESP Flasher /
             * Marauder companion apps do. */
            furi_stream_buffer_send(app->rx_stream, &byte, 1, 0);
        }
    }
}

static bool pmf_uart_init(PmfAuditApp* app) {
    app->rx_stream = furi_stream_buffer_alloc(512, 1);
    if(app->rx_stream == NULL) return false;

    app->expansion = furi_record_open(RECORD_EXPANSION);
    if(app->expansion == NULL) {
        FURI_LOG_E(TAG, "No expansion record");
        return false;
    }
    /* The expansion service owns the USART until we disable it. */
    expansion_disable(app->expansion);

    app->serial_handle = furi_hal_serial_control_acquire(FuriHalSerialIdUsart);
    if(app->serial_handle == NULL) {
        FURI_LOG_E(TAG, "Could not acquire USART");
        expansion_enable(app->expansion);
        return false;
    }

    /* Power the devboard from the Flipper 5V pin. */
    furi_hal_power_enable_otg();
    furi_hal_serial_init(app->serial_handle, PMF_UART_BAUD);
    furi_hal_serial_async_rx_start(app->serial_handle, pmf_uart_rx_callback, app, false);
    return true;
}

static void pmf_uart_deinit(PmfAuditApp* app) {
    if(app->serial_handle != NULL) {
        furi_hal_serial_async_rx_stop(app->serial_handle);
        furi_hal_serial_deinit(app->serial_handle);
        furi_hal_serial_control_release(app->serial_handle);
        app->serial_handle = NULL;
    }
    if(app->expansion != NULL) {
        expansion_enable(app->expansion);
        furi_record_close(RECORD_EXPANSION);
        app->expansion = NULL;
    }
    furi_hal_power_disable_otg();
    if(app->rx_stream != NULL) {
        furi_stream_buffer_free(app->rx_stream);
        app->rx_stream = NULL;
    }
}

static void pmf_uart_tx(PmfAuditApp* app, const char* str) {
    if(app->serial_handle == NULL) return;
    furi_hal_serial_tx(app->serial_handle, (const uint8_t*)str, strlen(str));
}

/* Read one LF-terminated line from the board, honouring the timeout.
 * Partial lines survive across calls (app->line_buf). Returns false
 * on timeout or when the scan was aborted. */
static bool
    pmf_uart_read_line(PmfAuditApp* app, char* out, size_t out_size, uint32_t timeout_ms) {
    uint32_t start = furi_get_tick();
    while(true) {
        uint32_t elapsed = furi_get_tick() - start;
        if(elapsed >= timeout_ms) return false;
        uint32_t chunk = timeout_ms - elapsed;
        if(chunk > 50) chunk = 50;
        uint8_t byte;
        if(furi_stream_buffer_receive(app->rx_stream, &byte, 1, chunk) == 1) {
            if(byte == '\n') {
                app->line_buf[app->line_pos] = '\0';
                app->line_pos = 0;
                /* Strip a trailing CR. */
                size_t n = strlen(app->line_buf);
                while(n > 0 && app->line_buf[n - 1] == '\r') app->line_buf[--n] = '\0';
                strncpy(out, app->line_buf, out_size - 1);
                out[out_size - 1] = '\0';
                return true;
            } else if(byte != '\r') {
                if(app->line_pos < sizeof(app->line_buf) - 1) {
                    app->line_buf[app->line_pos++] = (char)byte;
                } else {
                    /* Line too long: drop it and start over. */
                    app->line_pos = 0;
                }
            }
        }
        if(app->scan_abort) return false;
    }
}

/* ------------------------------------------------------------------ */
/* Scan worker thread                                                  */
/* ------------------------------------------------------------------ */

static bool pmf_wait_for_pong(PmfAuditApp* app, uint32_t timeout_ms) {
    uint32_t start = furi_get_tick();
    char line[PMF_LINE_BUF_SIZE];
    while(true) {
        uint32_t elapsed = furi_get_tick() - start;
        if(elapsed >= timeout_ms) return false;
        if(!pmf_uart_read_line(app, line, sizeof(line), timeout_ms - elapsed)) return false;
        if(strncmp(line, "PONG", 4) == 0) return true;
        /* Ignore anything else (e.g. "PMF-AUDIT READY" on boot). */
    }
}

static int32_t pmf_worker_thread(void* context) {
    PmfAuditApp* app = context;
    char line[PMF_LINE_BUF_SIZE];

    while(true) {
        if(app->worker_cmd == PmfWorkerExit) break;
        if(app->worker_cmd != PmfWorkerStartScan) {
            furi_delay_ms(50);
            continue;
        }
        app->worker_cmd = PmfWorkerIdle;
        app->scan_abort = false;
        app->ap_count = 0;
        app->clean_count = 0;
        app->line_pos = 0;

        if(!app->uart_ok) {
            snprintf(
                app->error_text,
                sizeof(app->error_text),
                "Board not responding - check wiring / flash PMF firmware");
            view_dispatcher_send_custom_event(app->view_dispatcher, PmfEventScanError);
            continue;
        }

        furi_stream_buffer_reset(app->rx_stream);

        /* 1. PING: prove the board is there and speaking our protocol. */
        with_view_model(
            app->scan_view,
            PmfScanModel* model,
            {
                model->waiting_ping = true;
                model->aps_found = 0;
                model->start_tick = furi_get_tick();
            },
            true);
        pmf_uart_tx(app, "PING\n");
        if(!pmf_wait_for_pong(app, PMF_PING_TIMEOUT_MS)) {
            snprintf(
                app->error_text,
                sizeof(app->error_text),
                "Board not responding - check wiring / flash PMF firmware");
            view_dispatcher_send_custom_event(app->view_dispatcher, PmfEventScanError);
            continue;
        }

        /* 2. SCAN: collect AP lines until DONE, abort, or deadline. */
        with_view_model(
            app->scan_view,
            PmfScanModel* model,
            {
                model->waiting_ping = false;
                model->start_tick = furi_get_tick();
            },
            true);
        pmf_uart_tx(app, "SCAN 15\n");
        uint32_t deadline =
            furi_get_tick() + (uint32_t)(PMF_SCAN_SECONDS + PMF_SCAN_GRACE_MS / 1000) * 1000;
        while(!app->scan_abort && app->worker_cmd != PmfWorkerExit &&
              (int32_t)(furi_get_tick() - deadline) < 0) {
            if(pmf_uart_read_line(app, line, sizeof(line), 100)) {
                if(strncmp(line, "AP|", 3) == 0) {
                    if(app->ap_count < PMF_MAX_APS) {
                        if(pmf_parse_ap_line(line, &app->aps[app->ap_count])) {
                            app->ap_count++;
                        }
                    }
                    /* Past 64 APs the firmware sends no more lines;
                     * extra lines are dropped, not a finding. */
                } else if(strncmp(line, "DONE", 4) == 0) {
                    break;
                }
                /* "STOPPED" / "ERR ..." / anything else: ignore. */
            }
            /* Refresh elapsed time + AP count on the scan screen. */
            with_view_model(
                app->scan_view,
                PmfScanModel* model,
                { model->aps_found = app->ap_count; },
                true);
        }

        if(app->scan_abort) {
            pmf_uart_tx(app, "STOP\n");
            furi_delay_ms(100);
        }

        /* Strongest APs first; count the clean ones for the footer. */
        if(app->ap_count > 1) {
            /* Small table (<=64): simple insertion sort, no qsort
             * dependency surprises on-device. */
            for(uint8_t i = 1; i < app->ap_count; i++) {
                PmfAp tmp = app->aps[i];
                uint8_t j = i;
                while(j > 0 && app->aps[j - 1].rssi < tmp.rssi) {
                    app->aps[j] = app->aps[j - 1];
                    j--;
                }
                app->aps[j] = tmp;
            }
        }
        app->clean_count = 0;
        for(uint8_t i = 0; i < app->ap_count; i++) {
            if(pmf_is_clean(&app->aps[i])) app->clean_count++;
        }

        view_dispatcher_send_custom_event(app->view_dispatcher, PmfEventScanDone);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Scan view (custom View: progress + elapsed + APs found)             */
/* ------------------------------------------------------------------ */

static void pmf_scan_draw(Canvas* canvas, void* context) {
    PmfScanModel* model = context;
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 12, "Scanning...");
    canvas_set_font(canvas, FontSecondary);
    if(model->waiting_ping) {
        canvas_draw_str(canvas, 2, 26, "Contacting board...");
    } else {
        uint32_t elapsed = (furi_get_tick() - model->start_tick) / 1000;
        char buf[40];
        snprintf(buf, sizeof(buf), "Listening, 2.4 GHz");
        canvas_draw_str(canvas, 2, 26, buf);
        snprintf(buf, sizeof(buf), "Elapsed: %lu s / %d s", (unsigned long)elapsed, PMF_SCAN_SECONDS);
        canvas_draw_str(canvas, 2, 38, buf);
    }
    char buf[32];
    snprintf(buf, sizeof(buf), "APs found: %d", model->aps_found);
    canvas_draw_str(canvas, 2, 50, buf);
    /* Progress bar (only once the scan itself is running). */
    if(!model->waiting_ping) {
        uint32_t elapsed = (furi_get_tick() - model->start_tick) / 1000;
        if(elapsed > PMF_SCAN_SECONDS) elapsed = PMF_SCAN_SECONDS;
        canvas_draw_frame(canvas, 2, 54, 124, 7);
        uint8_t fill = (uint8_t)(elapsed * 122 / PMF_SCAN_SECONDS);
        if(fill > 0) canvas_draw_box(canvas, 3, 55, fill, 5);
    }
    canvas_draw_str(canvas, 2, 63, "Back: cancel scan");
}

static bool pmf_scan_input(InputEvent* event, void* context) {
    PmfAuditApp* app = context;
    if(event->type == InputTypeShort && event->key == InputKeyBack) {
        /* Abort: the worker sends STOP and finishes up. */
        app->scan_abort = true;
        return true;
    }
    return false;
}

static uint32_t pmf_scan_previous(void* context) {
    (void)context;
    return PmfViewMainMenu;
}

/* ------------------------------------------------------------------ */
/* Results view (custom View: grouped findings list + All APs)         */
/* ------------------------------------------------------------------ */

static void pmf_results_rebuild(PmfAuditApp* app, uint8_t mode) {
    app->row_count = 0;
    app->exploitable_count = 0;
    app->protect_count = 0;

    if(mode == PmfResultsModeFindings) {
        for(uint8_t i = 0; i < app->ap_count; i++) {
            if(app->aps[i].exploitable_count > 0) app->exploitable_count++;
            else if(app->aps[i].finding_count > 0)
                app->protect_count++;
        }
        if(app->exploitable_count > 0) {
            app->rows[app->row_count++] =
                (PmfRow){.kind = PmfRowHeaderExploitable, .ap_index = 0};
            for(uint8_t i = 0; i < app->ap_count; i++) {
                if(app->aps[i].exploitable_count > 0) {
                    app->rows[app->row_count++] = (PmfRow){.kind = PmfRowAp, .ap_index = i};
                }
            }
        }
        if(app->protect_count > 0) {
            app->rows[app->row_count++] =
                (PmfRow){.kind = PmfRowHeaderProtect, .ap_index = 0};
            for(uint8_t i = 0; i < app->ap_count; i++) {
                if(app->aps[i].exploitable_count == 0 && app->aps[i].finding_count > 0) {
                    app->rows[app->row_count++] = (PmfRow){.kind = PmfRowAp, .ap_index = i};
                }
            }
        }
        app->rows[app->row_count++] = (PmfRow){.kind = PmfRowAllAps, .ap_index = 0};
    } else {
        app->rows[app->row_count++] = (PmfRow){.kind = PmfRowHeaderAll, .ap_index = 0};
        for(uint8_t i = 0; i < app->ap_count; i++) {
            app->rows[app->row_count++] = (PmfRow){.kind = PmfRowAp, .ap_index = i};
        }
    }
}

static bool pmf_row_selectable(const PmfRow* row) {
    return row->kind == PmfRowAp || row->kind == PmfRowAllAps;
}

static void pmf_results_move_selection(PmfAuditApp* app, int8_t direction) {
    with_view_model(
        app->results_view,
        PmfResultsModel* model,
        {
            int16_t next = model->selected;
            for(uint8_t step = 0; step < app->row_count; step++) {
                next += direction;
                if(next < 0 || next >= app->row_count) break;
                if(pmf_row_selectable(&app->rows[next])) {
                    model->selected = next;
                    break;
                }
            }
            /* Keep the selection on screen (4 visible rows). */
            if(model->selected < model->scroll) model->scroll = model->selected;
            if(model->selected > model->scroll + 3) model->scroll = model->selected - 3;
            if(model->scroll < 0) model->scroll = 0;
        },
        true);
}

/* Draw `str` left-aligned, truncated to max_width pixels. */
static void pmf_draw_truncated(Canvas* canvas, uint8_t x, uint8_t y, const char* str, uint8_t max_width) {
    char buf[40];
    size_t len = strlen(str);
    if(len >= sizeof(buf)) len = sizeof(buf) - 1;
    memcpy(buf, str, len);
    buf[len] = '\0';
    while(len > 0 && canvas_string_width(canvas, buf) > max_width) {
        buf[--len] = '\0';
    }
    canvas_draw_str(canvas, x, y, buf);
}

static void pmf_results_draw(Canvas* canvas, void* context) {
    PmfResultsModel* model = context;
    PmfAuditApp* app = model->app;
    canvas_clear(canvas);

    const uint8_t row_h = 13;
    const uint8_t visible_rows = 4;
    for(uint8_t v = 0; v < visible_rows; v++) {
        int16_t idx = model->scroll + v;
        if(idx >= app->row_count) break;
        PmfRow* row = &app->rows[idx];
        uint8_t y = v * row_h;
        bool selected = (idx == model->selected);

        if(row->kind == PmfRowHeaderExploitable || row->kind == PmfRowHeaderProtect ||
           row->kind == PmfRowHeaderAll) {
            canvas_set_color(canvas, ColorBlack);
            canvas_draw_box(canvas, 0, y, 128, row_h - 1);
            canvas_set_color(canvas, ColorWhite);
            canvas_set_font(canvas, FontPrimary);
            char header[32];
            if(row->kind == PmfRowHeaderExploitable) {
                snprintf(header, sizeof(header), "EXPLOITABLE (%d)", app->exploitable_count);
            } else if(row->kind == PmfRowHeaderProtect) {
                snprintf(header, sizeof(header), "PROTECT BETTER (%d)", app->protect_count);
            } else {
                snprintf(header, sizeof(header), "ALL APs (%d)", app->ap_count);
            }
            canvas_draw_str(canvas, 2, y + 10, header);
            canvas_set_color(canvas, ColorBlack);
            continue;
        }

        if(selected) {
            canvas_set_color(canvas, ColorBlack);
            canvas_draw_box(canvas, 0, y, 128, row_h - 1);
            canvas_set_color(canvas, ColorWhite);
        } else {
            canvas_set_color(canvas, ColorBlack);
        }
        canvas_set_font(canvas, FontSecondary);
        if(row->kind == PmfRowAllAps) {
            char buf[32];
            snprintf(buf, sizeof(buf), "All APs (%d)  >", app->ap_count);
            canvas_draw_str(canvas, 2, y + 10, buf);
        } else {
            /* AP row: SSID left, short finding label (findings mode)
             * or encryption (all-APs mode) right-aligned. */
            const PmfAp* ap = &app->aps[row->ap_index];
            const char* right =
                (model->mode == PmfResultsModeAll) ? pmf_enc_to_str(ap->enc)
                                                   : ap->findings[0].label;
            uint16_t right_w = canvas_string_width(canvas, right);
            canvas_draw_str(canvas, 126 - right_w, y + 10, right);
            uint8_t max_left = 126 - (uint8_t)right_w - 6;
            if(max_left > 2) {
                pmf_draw_truncated(
                    canvas, 2, y + 10, pmf_ap_display_name(ap), max_left);
            }
        }
        canvas_set_color(canvas, ColorBlack);
    }

    /* Footer: "N APs scanned, M clean". */
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_line(canvas, 0, 52, 127, 52);
    canvas_set_font(canvas, FontSecondary);
    char footer[40];
    snprintf(
        footer,
        sizeof(footer),
        "%d APs scanned, %d clean",
        app->ap_count,
        app->clean_count);
    canvas_draw_str(canvas, 2, 63, footer);
}

/* ------------------------------------------------------------------ */
/* Detail / About / error text (TextBox)                               */
/* ------------------------------------------------------------------ */

static void pmf_show_info(PmfAuditApp* app, const char* text, PmfView return_view) {
    app->info_return_view = return_view;
    text_box_reset(app->text_box);
    text_box_set_text(app->text_box, text);
    text_box_set_focus(app->text_box, TextBoxFocusStart);
    view_dispatcher_switch_to_view(app->view_dispatcher, PmfViewInfo);
}

static void pmf_build_detail_text(PmfAuditApp* app, uint8_t ap_index) {
    const PmfAp* ap = &app->aps[ap_index];
    size_t pos = 0;
    char* dst = app->info_text;
    dst[0] = '\0';

    pmf_append_wrapped(dst, sizeof(app->info_text), &pos, pmf_ap_display_name(ap), 20);
    if(ap->hidden) {
        pmf_text_append(dst, sizeof(app->info_text), &pos, "(hidden SSID)\n");
    }
    pmf_text_append(dst, sizeof(app->info_text), &pos, "BSSID:\n");
    pmf_text_append(dst, sizeof(app->info_text), &pos, ap->bssid);
    pmf_text_append(dst, sizeof(app->info_text), &pos, "\n");
    char buf[48];
    snprintf(buf, sizeof(buf), "Channel: %d\n", ap->channel);
    pmf_text_append(dst, sizeof(app->info_text), &pos, buf);
    snprintf(buf, sizeof(buf), "Signal: %d dBm\n", ap->rssi);
    pmf_text_append(dst, sizeof(app->info_text), &pos, buf);
    snprintf(buf, sizeof(buf), "Enc: %s\n", pmf_enc_to_str(ap->enc));
    pmf_text_append(dst, sizeof(app->info_text), &pos, buf);
    snprintf(buf, sizeof(buf), "PMF capable: %s\n", ap->mfpc ? "yes" : "no");
    pmf_text_append(dst, sizeof(app->info_text), &pos, buf);
    snprintf(buf, sizeof(buf), "PMF required: %s\n", ap->mfpr ? "yes" : "no");
    pmf_text_append(dst, sizeof(app->info_text), &pos, buf);
    snprintf(buf, sizeof(buf), "Deauth-immune: %s\n", ap->mfpr ? "YES" : "NO");
    pmf_text_append(dst, sizeof(app->info_text), &pos, buf);
    snprintf(buf, sizeof(buf), "BIP: %s\n", ap->bip ? "yes" : "no");
    pmf_text_append(dst, sizeof(app->info_text), &pos, buf);
    snprintf(buf, sizeof(buf), "WPS: %s\n", ap->wps ? "on" : "off");
    pmf_text_append(dst, sizeof(app->info_text), &pos, buf);
    snprintf(buf, sizeof(buf), "Clients seen: %d\n", ap->clients);
    pmf_text_append(dst, sizeof(app->info_text), &pos, buf);

    pmf_text_append(dst, sizeof(app->info_text), &pos, "\nFindings:\n");
    if(ap->finding_count == 0) {
        pmf_text_append(dst, sizeof(app->info_text), &pos, "None - looks clean.\n");
        if(ap->mfpr) {
            pmf_text_append(
                dst, sizeof(app->info_text), &pos, "PMF Required: clients\ncan't be deauthed off.\n");
        }
    } else {
        for(uint8_t i = 0; i < ap->finding_count; i++) {
            pmf_text_append(dst, sizeof(app->info_text), &pos, "- ");
            pmf_append_wrapped(
                dst, sizeof(app->info_text), &pos, ap->findings[i].label, 18);
            pmf_text_append(dst, sizeof(app->info_text), &pos, "  ");
            pmf_append_wrapped(dst, sizeof(app->info_text), &pos, ap->findings[i].fix, 20);
        }
    }
}

static const char* pmf_about_text =
    "Boot Sniffer 2.4\n"
    "\n"
    "Scans nearby 2.4 GHz\n"
    "WiFi networks and\n"
    "shows which ones are\n"
    "immune to deauth\n"
    "attacks (PMF\n"
    "Required).\n"
    "\n"
    "Audit your own\n"
    "networks only.\n"
    "Detection only - this\n"
    "app never transmits\n"
    "or attacks anything.\n"
    "\n"
    "Needs the WiFi\n"
    "Devboard flashed with\n"
    "the Boot Sniffer 2.4\n"
    "firmware. 2.4 GHz\n"
    "only - 5 GHz networks\n"
    "are invisible.\n"
    "\n"
    "UNTESTED on real\n"
    "hardware: the board\n"
    "has not arrived yet.\n";

/* ------------------------------------------------------------------ */
/* Results view callbacks (need the app pointer: the view context     */
/* is the app, the model holds selection/scroll/mode)                  */
/* ------------------------------------------------------------------ */

static void pmf_results_enter(void* context) {
    PmfAuditApp* app = context;
    with_view_model(
        app->results_view,
        PmfResultsModel* model,
        {
            model->mode = PmfResultsModeFindings;
            pmf_results_rebuild(app, PmfResultsModeFindings);
            /* First selectable row. */
            model->selected = 0;
            for(uint8_t i = 0; i < app->row_count; i++) {
                if(pmf_row_selectable(&app->rows[i])) {
                    model->selected = i;
                    break;
                }
            }
            model->scroll = 0;
        },
        true);
}

static bool pmf_results_input(InputEvent* event, void* context) {
    PmfAuditApp* app = context;
    if(event->type == InputTypeShort || event->type == InputTypeRepeat) {
        if(event->key == InputKeyUp) {
            pmf_results_move_selection(app, -1);
            return true;
        }
        if(event->key == InputKeyDown) {
            pmf_results_move_selection(app, 1);
            return true;
        }
    }
    if(event->type == InputTypeShort && event->key == InputKeyOk) {
        PmfResultsModel* model = view_get_model(app->results_view);
        int16_t selected = model->selected;
        view_commit_model(app->results_view, false);
        if(selected < 0 || selected >= app->row_count) return true;
        PmfRow* row = &app->rows[selected];
        if(row->kind == PmfRowAllAps) {
            with_view_model(
                app->results_view,
                PmfResultsModel* m,
                {
                    m->mode = PmfResultsModeAll;
                    pmf_results_rebuild(app, PmfResultsModeAll);
                    m->selected = 1; /* first AP row, after the header */
                    m->scroll = 0;
                },
                true);
            return true;
        }
        if(row->kind == PmfRowAp) {
            pmf_build_detail_text(app, row->ap_index);
            pmf_show_info(app, app->info_text, PmfViewResults);
            return true;
        }
        return true;
    }
    if(event->type == InputTypeShort && event->key == InputKeyBack) {
        PmfResultsModel* model = view_get_model(app->results_view);
        uint8_t mode = model->mode;
        view_commit_model(app->results_view, false);
        if(mode == PmfResultsModeAll) {
            /* Back from All APs returns to the grouped results. */
            with_view_model(
                app->results_view,
                PmfResultsModel* m,
                {
                    m->mode = PmfResultsModeFindings;
                    pmf_results_rebuild(app, PmfResultsModeFindings);
                    m->selected = 0;
                    m->scroll = 0;
                },
                true);
            return true;
        }
        /* Findings mode: let the previous callback take us to menu. */
        return false;
    }
    return false;
}

static uint32_t pmf_results_previous(void* context) {
    (void)context;
    return PmfViewMainMenu;
}

static uint32_t pmf_info_previous(void* context) {
    PmfAuditApp* app = context;
    return app->info_return_view;
}

/* ------------------------------------------------------------------ */
/* Main menu + dispatcher callbacks                                    */
/* ------------------------------------------------------------------ */

static void pmf_submenu_callback(void* context, uint32_t index) {
    PmfAuditApp* app = context;
    if(index == 0) {
        /* Scan. */
        app->scan_abort = false;
        app->ap_count = 0;
        view_dispatcher_switch_to_view(app->view_dispatcher, PmfViewScan);
        app->worker_cmd = PmfWorkerStartScan;
    } else if(index == 1) {
        pmf_show_info(app, pmf_about_text, PmfViewMainMenu);
    }
}

static bool pmf_custom_event_callback(void* context, uint32_t event) {
    PmfAuditApp* app = context;
    if(event == PmfEventScanDone) {
        if(app->ap_count == 0) {
            snprintf(
                app->info_text,
                sizeof(app->info_text),
                "No networks found.\n"
                "\n"
                "Try again closer to\n"
                "an access point.\n"
                "\n"
                "Note: 5 GHz networks\n"
                "are invisible - this\n"
                "tool is 2.4 GHz only.\n");
            pmf_show_info(app, app->info_text, PmfViewMainMenu);
        } else {
            view_dispatcher_switch_to_view(app->view_dispatcher, PmfViewResults);
        }
        return true;
    }
    if(event == PmfEventScanError) {
        snprintf(
            app->info_text,
            sizeof(app->info_text),
            "%s\n"
            "\n"
            "Check the devboard is\n"
            "plugged in, powered,\n"
            "and flashed with the\n"
            "Boot Sniffer 2.4 firmware\n"
            "(not Marauder).\n",
            app->error_text);
        pmf_show_info(app, app->info_text, PmfViewMainMenu);
        return true;
    }
    return false;
}

static bool pmf_navigation_callback(void* context) {
    /* Reached only from the main menu (every other view handles
     * Back itself): exit the app. */
    (void)context;
    return true;
}

/* ------------------------------------------------------------------ */
/* App alloc / free / entry point                                      */
/* ------------------------------------------------------------------ */

static PmfAuditApp* pmf_audit_app_alloc(void) {
    PmfAuditApp* app = malloc(sizeof(PmfAuditApp));
    memset(app, 0, sizeof(PmfAuditApp));
    app->worker_cmd = PmfWorkerIdle;
    app->info_return_view = PmfViewMainMenu;

    app->gui = furi_record_open(RECORD_GUI);
    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_custom_event_callback(app->view_dispatcher, pmf_custom_event_callback);
    view_dispatcher_set_navigation_event_callback(app->view_dispatcher, pmf_navigation_callback);
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);

    /* Main menu. */
    app->submenu = submenu_alloc();
    submenu_add_item(app->submenu, "Scan", 0, pmf_submenu_callback, app);
    submenu_add_item(app->submenu, "About", 1, pmf_submenu_callback, app);
    submenu_set_header(app->submenu, "Boot Sniffer 2.4");
    view_dispatcher_add_view(
        app->view_dispatcher, PmfViewMainMenu, submenu_get_view(app->submenu));

    /* Scan view. */
    app->scan_view = view_alloc();
    view_allocate_model(app->scan_view, ViewModelTypeLocking, sizeof(PmfScanModel));
    view_set_context(app->scan_view, app);
    view_set_draw_callback(app->scan_view, pmf_scan_draw);
    view_set_input_callback(app->scan_view, pmf_scan_input);
    view_set_previous_callback(app->scan_view, pmf_scan_previous);
    view_dispatcher_add_view(app->view_dispatcher, PmfViewScan, app->scan_view);

    /* Results view. */
    app->results_view = view_alloc();
    view_allocate_model(app->results_view, ViewModelTypeLocking, sizeof(PmfResultsModel));
    with_view_model(
        app->results_view, PmfResultsModel* model, { model->app = app; }, false);
    view_set_context(app->results_view, app);
    view_set_draw_callback(app->results_view, pmf_results_draw);
    view_set_input_callback(app->results_view, pmf_results_input);
    view_set_previous_callback(app->results_view, pmf_results_previous);
    view_set_enter_callback(app->results_view, pmf_results_enter);
    view_dispatcher_add_view(app->view_dispatcher, PmfViewResults, app->results_view);

    /* Info / detail / about / error text box. */
    app->text_box = text_box_alloc();
    text_box_set_font(app->text_box, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box), pmf_info_previous);
    view_dispatcher_add_view(
        app->view_dispatcher, PmfViewInfo, text_box_get_view(app->text_box));

    /* UART + worker thread. */
    app->uart_ok = pmf_uart_init(app);
    if(!app->uart_ok) {
        FURI_LOG_W(TAG, "UART init failed - scans will report board-not-responding");
    }
    app->worker_thread = furi_thread_alloc();
    furi_thread_set_name(app->worker_thread, "PmfAuditWorker");
    furi_thread_set_stack_size(app->worker_thread, 2048);
    furi_thread_set_callback(app->worker_thread, pmf_worker_thread);
    furi_thread_set_context(app->worker_thread, app);
    furi_thread_start(app->worker_thread);

    return app;
}

static void pmf_audit_app_free(PmfAuditApp* app) {
    app->worker_cmd = PmfWorkerExit;
    furi_thread_join(app->worker_thread);
    furi_thread_free(app->worker_thread);

    pmf_uart_deinit(app);

    view_dispatcher_remove_view(app->view_dispatcher, PmfViewMainMenu);
    view_dispatcher_remove_view(app->view_dispatcher, PmfViewScan);
    view_dispatcher_remove_view(app->view_dispatcher, PmfViewResults);
    view_dispatcher_remove_view(app->view_dispatcher, PmfViewInfo);
    submenu_free(app->submenu);
    view_free(app->scan_view);
    view_free(app->results_view);
    text_box_free(app->text_box);
    view_dispatcher_free(app->view_dispatcher);
    furi_record_close(RECORD_GUI);
    free(app);
}

int32_t pmf_audit_app(void* p) {
    (void)p;
    PmfAuditApp* app = pmf_audit_app_alloc();
    view_dispatcher_switch_to_view(app->view_dispatcher, PmfViewMainMenu);
    view_dispatcher_run(app->view_dispatcher);
    pmf_audit_app_free(app);
    return 0;
}

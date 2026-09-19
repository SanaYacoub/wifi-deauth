/*
 * ESP8266 Deauth / Disassociation Detector
 * -----------------------------------------
 * PURPOSE:
 *   Passively listens to 802.11 management frames in promiscuous mode
 *   and flags Deauthentication (subtype 0x0C) and Disassociation
 *   (subtype 0x0A) frames — the two frame types used in deauth attacks.
 *
 *   This does NOT transmit anything. It only receives and inspects
 *   frames already present in the air, which is why it's safe to run
 *   on any network (yours or otherwise) without needing authorization
 *   to "test" anyone else's infrastructure.
 *
 * HOW IT WORKS:
 *   1. Puts the WiFi radio into promiscuous (monitor) mode.
 *   2. Hops across channels 1-13 so it isn't blind to APs on other channels.
 *   3. A callback fires for every packet the radio hears.
 *   4. We parse the 802.11 MAC header to check frame type/subtype.
 *   5. Deauth/disassoc frames get logged (source MAC, channel, timestamp)
 *      and counted. A burst of these in a short window = likely attack.
 *   6. A small built-in web dashboard shows live stats and the event log.
 *
 * FRAME FORMAT BACKGROUND:
 *   Byte 0 of the 802.11 header = Frame Control (subfield: type + subtype).
 *   Type 00 = Management frame.
 *   Subtype 1100 (0x0C) = Deauthentication
 *   Subtype 1010 (0x0A) = Disassociation
 *   These frames are UNAUTHENTICATED under WPA2 — anyone can forge them,
 *   which is exactly the weakness this tool helps you notice being abused.
 */



#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>

extern "C" {
#include "user_interface.h"
}

// ---------- Config ----------
#define MAX_LOG 30
#define CHANNEL_DWELL_MS 400
#define ALERT_WINDOW_MS 10000
#define ALERT_THRESHOLD 6   // # de deauth/disassoc frames in window to call it an "attack"

ESP8266WebServer server(80);

struct Event {
  unsigned long time;
  uint8_t channel;
  uint8_t srcMac[6];
  uint8_t bssid[6];
  bool isDisassoc; // false = deauth, true = disassoc
};

Event eventLog[MAX_LOG];
int logCount = 0;
int logHead = 0;

unsigned long totalDeauth = 0;
unsigned long totalDisassoc = 0;
unsigned long recentCount = 0;
unsigned long windowStart = 0;
bool attackActive = false;

uint8_t currentChannel = 1;
unsigned long lastHop = 0;

String macToStr(const uint8_t* m) {
  char buf[18];
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
  return String(buf);
}

void logEvent(uint8_t channel, const uint8_t* src, const uint8_t* bssid, bool disassoc) {
  Event &e = eventLog[logHead];
  e.time = millis();
  e.channel = channel;
  memcpy(e.srcMac, src, 6);
  memcpy(e.bssid, bssid, 6);
  e.isDisassoc = disassoc;

  logHead = (logHead + 1) % MAX_LOG;
  if (logCount < MAX_LOG) logCount++;

  if (disassoc) totalDisassoc++; else totalDeauth++;

  // sliding window for "attack in progress" detection
  unsigned long now = millis();
  if (now - windowStart > ALERT_WINDOW_MS) {
    windowStart = now;
    recentCount = 0;
  }
  recentCount++;
  attackActive = (recentCount >= ALERT_THRESHOLD);

  Serial.printf("[%s] ch=%d src=%s bssid=%s\n",
                disassoc ? "DISASSOC" : "DEAUTH",
                channel, macToStr(src).c_str(), macToStr(bssid).c_str());
}

// Promiscuous mode callback — adaptation de la signature pour l'ESP8266 SDK
void promiscuousCallback(uint8_t *buf, uint16_t len) {
  // L'ESP8266 entoure les trames de gestion avec un en-tête RX status (12 octets)
  if (len < 12 + 24) return; // trop court pour être une vraie trame de gestion

  uint8_t *frame = buf + 12; // saut de l'en-tête RX
  uint8_t frameControl0 = frame[0];
  uint8_t type = (frameControl0 & 0x0C) >> 2;
  uint8_t subtype = (frameControl0 & 0xF0) >> 4;

  // Filtre : Uniquement les trames de gestion (type == 0)
  if (type != 0) return;

  bool isDeauth = (subtype == 0x0C);
  bool isDisassoc = (subtype == 0x0A);
  if (!isDeauth && !isDisassoc) return;

  // Entête 802.11: addr1 (dest) @4, addr2 (src) @10, addr3 (bssid) @16
  uint8_t *src = frame + 10;
  uint8_t *bssid = frame + 16;

  logEvent(currentChannel, src, bssid, isDisassoc);
}

void hopChannel() {
  if (millis() - lastHop >= CHANNEL_DWELL_MS) {
    currentChannel++;
    if (currentChannel > 13) currentChannel = 1;
    wifi_set_channel(currentChannel);
    lastHop = millis();
  }
}

// ---------- Web dashboard ----------
String buildPage() {
  String html = "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>";
  html += "<meta http-equiv='refresh' content='3'>";
  html += "<style>body{font-family:sans-serif;background:#111;color:#eee;padding:1em;}";
  html += "h1{color:#0af;} .ok{color:#4f4;} .bad{color:#f44;font-weight:bold;}";
  html += "table{width:100%;border-collapse:collapse;margin-top:1em;}";
  html += "td,th{border:1px solid #444;padding:4px 8px;text-align:left;font-size:14px;}</style></head><body>";
  html += "<h1>WiFi Deauth Detector</h1>";
  html += "<p>Status: " + String(attackActive ? "<span class='bad'>POSSIBLE ATTACK IN PROGRESS</span>" : "<span class='ok'>Normal</span>") + "</p>";
  html += "<p>Current channel: " + String(currentChannel) + "</p>";
  html += "<p>Total deauth frames: " + String(totalDeauth) + "<br>";
  html += "Total disassoc frames: " + String(totalDisassoc) + "</p>";
  html += "<p>Frames in last " + String(ALERT_WINDOW_MS / 1000) + "s window: " + String(recentCount) + " (alert threshold: " + String(ALERT_THRESHOLD) + ")</p>";

  html += "<h3>Recent events</h3><table><tr><th>Time (s ago)</th><th>Type</th><th>Channel</th><th>Source MAC</th><th>Target BSSID</th></tr>";
  int shown = 0;
  int idx = (logHead - 1 + MAX_LOG) % MAX_LOG;
  for (int i = 0; i < logCount && shown < MAX_LOG; i++) {
    Event &e = eventLog[idx];
    html += "<tr><td>" + String((millis() - e.time) / 1000) + "</td><td>" +
            (e.isDisassoc ? "Disassoc" : "Deauth") + "</td><td>" + String(e.channel) +
            "</td><td>" + macToStr(e.srcMac) + "</td><td>" + macToStr(e.bssid) + "</td></tr>";
    idx = (idx - 1 + MAX_LOG) % MAX_LOG;
    shown++;
  }
  html += "</table></body></html>";
  return html;
}

void handleRoot() {
  server.send(200, "text/html", buildPage());
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("\nStarting Deauth Detector...");

  // 1. Initialiser le mode AP + STA
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP("DeauthDetector", "detector123");
  
  Serial.print("Dashboard AP IP: ");
  Serial.println(WiFi.softAPIP());

  server.on("/", handleRoot);
  server.begin();

  // 2. CORRECTION: Garder le mode STATIONAP pour maintenir l'AP visible
  wifi_set_opmode(STATIONAP_MODE);
  wifi_set_channel(currentChannel);
  
  // 3. Activer le mode promiscuous
  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(promiscuousCallback);
  wifi_promiscuous_enable(1);

  windowStart = millis();
}

void loop() {
  server.handleClient();
  hopChannel();

  // Reset sliding window / attack flag if quiet
  if (millis() - windowStart > ALERT_WINDOW_MS) {
    windowStart = millis();
    recentCount = 0;
    attackActive = false;
  }
}
# ESP8266 Wi-Fi Attack Demonstration

This Arduino sketch demonstrates two common Wi-Fi security attack techniques using an ESP8266, intended for controlled laboratory and educational environments.

## Attacks Demonstrated
## Deauthentication / Disassociation

The sketch can transmit Wi-Fi deauthentication and disassociation management frames to a selected access point.

The purpose is to demonstrate how these frames can be abused to disconnect devices from a Wi-Fi network and to study the resulting wireless traffic.

## Evil Twin

The sketch can create a fake access point using the SSID of a selected network.

It also provides a captive-portal-style web page that simulates a router or firmware update page. In a controlled experiment, this demonstrates how an attacker could attempt to trick users into interacting with a fraudulent access point and submitting Wi-Fi credentials.

# ESP8266 Deauth / Disassociation Detector

A passive WiFi security monitor for the ESP8266. It listens to 802.11
management frames in promiscuous (monitor) mode and flags **Deauthentication**
(subtype `0x0C`) and **Disassociation** (subtype `0x0A`) frames — the two
frame types abused in deauth attacks to forcibly disconnect clients from a
network.

This tool is **receive-only**. It never transmits deauth/disassoc frames or
any other injected packets — it only inspects traffic already present in the
air. That makes it safe to run on any network without needing authorization
to test someone else's infrastructure, since it performs no active attack of
its own.

## How it works

1. Puts the WiFi radio into promiscuous mode via the ESP8266 SDK.
2. Hops sequentially across channels 1–13 (configurable dwell time) so it
   isn't blind to access points on other channels.
3. A callback fires for every packet the radio hears.
4. The 802.11 MAC header is parsed to check the frame type/subtype.
5. Deauth/disassoc frames are logged (source MAC, target BSSID, channel,
   timestamp) and counted.
6. A sliding time window counts recent events; if the count crosses a
   threshold, the tool flags a likely attack in progress.
7. A built-in web dashboard (served from the ESP8266 itself) shows live
   stats and a scrolling event log.

### Why this works

Under WPA2, deauthentication and disassociation frames are **unauthenticated
management frames** — any device can forge them with a spoofed source
address. This is a well-known protocol weakness (addressed only in WPA3 with
Protected Management Frames). This tool doesn't fix that weakness, but it
gives you visibility into when it's being exploited nearby.

## Hardware

- Any ESP8266-based board (NodeMCU, Wemos D1 Mini, etc.)
- No additional peripherals required

## Setup

1. Install the [Arduino core for ESP8266](https://github.com/esp8266/Arduino)
   in the Arduino IDE (or use PlatformIO).
2. Open the `.ino` file and flash it to your board.
3. On boot, the device creates its own WiFi access point.
4. Connect to that AP with your phone or laptop, then browse to the
   device's AP IP address to view the dashboard.

## Dashboard

The dashboard auto-refreshes every few seconds and shows:

- Current status (`Normal` / `POSSIBLE ATTACK IN PROGRESS`)
- Current scanning channel
- Total deauth and disassociation frame counts
- Frame count in the current alert window vs. the alert threshold
- A table of the most recent events (time, type, channel, source MAC,
  target BSSID)

## Configuration

Tunable constants at the top of the sketch:

| Constant | Description | Default |
|---|---|---|
| `MAX_LOG` | Number of events kept in the rolling log | 30 |
| `CHANNEL_DWELL_MS` | Time spent on each channel before hopping | 400 ms |
| `ALERT_WINDOW_MS` | Sliding window used for attack detection | 10000 ms |
| `ALERT_THRESHOLD` | Deauth/disassoc frames within the window to flag an attack | 6 |

## Limitations

- Channel hopping means brief attacks on a channel the device isn't
  currently monitoring can be missed; reduce `CHANNEL_DWELL_MS` for tighter
  coverage at the cost of more missed frames per channel.
- Detection is **statistical** (frame count in a time window), not
  attribution — it tells you an attack pattern is present, not definitively
  who's responsible, since source MACs in these frames can be spoofed.
- Single-radio ESP8266 hardware can't monitor and hop channels with the
  same precision as a dedicated WiFi analysis rig (e.g. a laptop with an
  monitor-mode-capable adapter).

## Disclaimer

This project was tested for educational and cybersecurity research purposes in a controlled environment.

Only use these techniques on networks and devices that you own or have explicit permission to test. Unauthorized use may disrupt networks or compromise credentials.


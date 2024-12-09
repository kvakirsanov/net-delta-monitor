# NetDeltaMonitor

**NetDeltaMonitor** is a comprehensive network reconnaissance and port scanning tool designed with a focus on security and continuous monitoring. It periodically scans specified subnets, identifies active hosts, enumerates open ports and running services, and highlights any changes in the network over time. By integrating with MQTT and optionally sending Telegram notifications, NetDeltaMonitor helps security teams maintain visibility and respond quickly to newly discovered services or unexpected changes.

## Key Features

- **Continuous Network Monitoring:**
  NetDeltaMonitor runs scanning cycles at a configurable interval, ensuring that any newly active hosts or altered services are promptly detected.

- **Efficient Host Discovery:**
  Uses `nmap -sn` to quickly identify active hosts on your network subnets, enabling you to track new or returning devices.

- **Comprehensive Service Enumeration:**
  Performs a full port scan (`1-65535`) with `nmap -sV` on discovered hosts, providing detailed information on open ports, identified services, and their versions.

- **Change Detection and Auditing:**
  Compares current scan results against previous states to detect:
  - New hosts added to the network
  - Hosts that disappeared since the last scan
  - Ports that have opened or closed on known hosts

  This historical comparison supports security auditing, incident response, and continuous compliance monitoring.

- **MQTT Integration (Optional):**
  Publishes scan results, detected changes, and events to an MQTT broker, facilitating seamless integration with SIEMs, dashboards, and automated alerting systems.

- **Telegram Notifications (Optional):**
  Sends concise summaries of network changes to Telegram, keeping your security team informed of significant events even when away from the console.

- **Historical Archives:**
  Each scan iteration is stored in a timestamped directory. A `latest` symlink provides quick access to the most recent results. Over time, this archive offers valuable historical context for assessing trends or investigating past incidents.

## Running with Docker Compose

Adjust and run the provided `docker-compose.yaml`. Ensure that:
- The `scanner` directory contains `scanner.py` and related code.
- The `results` directory is accessible for storing scan results.
- If `USE_MQTT` is enabled, a reachable MQTT broker (e.g., Mosquitto) is running.
- Configure Telegram credentials if you want push notifications.

### Example `docker-compose.yaml`

```yaml
version: '3.8'
services:
  port_scanner:
    build: .
    container_name: port_scanner
    volumes:
      - ./scanner:/scanner
      - /var/log/docker-internal-network-scan/:/scanner/results
      - /etc/timezone:/etc/timezone:ro
      - /etc/localtime:/etc/localtime:ro
    environment:
      - INTERVAL=60
      - SUBNETS_FILE=subnets.json
      - USE_MQTT=false
      - MQTT_BROKER=mosquitto
      - MQTT_PORT=1883
      - MQTT_TOPIC_PREFIX=network-scanner
      - TELEGRAM_BOT_TOKEN=
      - TELEGRAM_CHAT_ID=
    networks:
      - default
    restart: always

networks:
  default:
    driver: bridge
```

### Building and Running

1. Build and run:
   ```bash
   docker-compose build
   docker-compose up -d
   ```

3. NetDeltaMonitor will:
   - Periodically scan the configured subnets as listed in `scanner/subnets.json`.
   - Publish scan events to MQTT (if enabled).
   - Send security-relevant notifications to Telegram (if credentials are set).
   - Store comprehensive results and historical archives in the `results` directory.

## Environment Variables

- **`SUBNETS_FILE`** (default: `subnets.json`): Path to the JSON file listing the subnets to scan.
- **`INTERVAL`** (default: `60`): Interval (in seconds) between scan cycles.
- **`USE_MQTT`** (default: `false`): Set to `true` to enable MQTT integration.
- **`MQTT_BROKER`** (default: `mosquitto`): Hostname or IP of the MQTT broker.
- **`MQTT_PORT`** (default: `1883`): MQTT broker port.
- **`MQTT_TOPIC_PREFIX`** (default: `port_scanner`): Prefix for published MQTT topics.
- **`TELEGRAM_BOT_TOKEN`** (default: empty): Telegram Bot token for notifications.
- **`TELEGRAM_CHAT_ID`** (default: empty): Telegram Chat ID for receiving notifications.

## File and Directory Structure

- **`scanner/`**: Contains `scanner.py` and related scripts.
- **`results/`**: Each scan iteration creates a timestamped directory holding:
  - `network.json`: Current network state.
  - `results.json`: Scan metadata, discovered hosts, and detected changes.
  - Nmap output files (`.nmap`, `.xml`, `.gnmap`) for each host.

  The `results/latest` symlink points to the newest scan data.

## MQTT Topics

- **`<MQTT_TOPIC_PREFIX>/hosts/live`**: Lists active hosts detected during the latest scan.
- **`<MQTT_TOPIC_PREFIX>/scan/start_host` and `finish_host`**: Indicates the start and completion of a detailed host scan.
- **`<MQTT_TOPIC_PREFIX>/scan/network_change`**: Reports changes in network state, such as new or missing hosts and changed ports.
- **`<MQTT_TOPIC_PREFIX>/app/started` and `app/restarted`**: Lifecycle events signaling when the scanning process starts or a new cycle begins.
- **`<MQTT_TOPIC_PREFIX>/telegram/send_message`**: Payloads corresponding to Telegram notifications.

## Telegram Notifications

If configured, Telegram messages provide:
- Start and end times for scans
- Scan duration
- Newly discovered or missing hosts
- Ports that opened or closed since the last scan

This ensures that critical security-related events are communicated to your team promptly.

## Prerequisites

- **Nmap**: Installed inside the container for host and service discovery.
- **Python Packages**: `paho-mqtt`, `requests`, `pyyaml` are installed for MQTT and Telegram integrations.

## Contributing

Contributions and improvements are welcome. Please open an issue or submit a pull request.

## License

NetDeltaMonitor is released under the MIT License.


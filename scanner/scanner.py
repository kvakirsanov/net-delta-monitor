import os
import re
import json
import shutil
import time
import subprocess
import requests
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict, Any

import paho.mqtt.client as mqtt

# --- Configuration ---
SUBNETS_FILE = os.getenv("SUBNETS_FILE", "subnets.json")
INTERVAL = int(os.getenv("INTERVAL", 60))
USE_MQTT = os.getenv("USE_MQTT", "false").lower() == "true"
MQTT_BROKER = os.getenv("MQTT_BROKER", "mosquitto")
MQTT_PORT = int(os.getenv("MQTT_PORT", 1883))
MQTT_TOPIC_PREFIX = os.getenv("MQTT_TOPIC_PREFIX", "network-scanner")

BASE_DIR = "./results"
NETWORK_STATE_FILENAME = "network.json"
RESULTS_FILENAME = "results.json"

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

mqtt_client = mqtt.Client() if USE_MQTT else None


# --- Utilities ---
def log(message: str) -> None:
    """Logs a message with a timestamp."""
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: {message}")


def run_command(command: List[str]) -> subprocess.CompletedProcess:
    """
    Executes a specified command in a subprocess and returns the result.
    Logs an error if the command fails.
    """
    log(f"Executing command: {' '.join(command)}")
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        log(f"Command error: {result.stderr}")
    return result


def load_subnets(file_path: str) -> List[str]:
    """
    Loads a list of subnets from a JSON file.
    
    Args:
        file_path (str): Path to the file containing subnets.

    Returns:
        List[str]: List of subnets.
    """
    with open(file_path, "r") as f:
        return json.load(f)


def connect_mqtt() -> None:
    """Connects to the MQTT broker and logs the successful connection."""
    if mqtt_client:
        mqtt_client.connect(MQTT_BROKER, MQTT_PORT, 60)
        log("Connected to MQTT broker.")


def publish_mqtt(topic: str, message: Dict[str, Any]) -> None:
    """
    Publishes a message to a specified MQTT topic.

    Args:
        topic (str): MQTT topic.
        message (Dict[str, Any]): Message to send.
    """
    if mqtt_client:
        mqtt_client.publish(topic, json.dumps(message))
    log(f"Published to {topic}: {json.dumps(message, indent=4, ensure_ascii=False)}")


def quick_scan(subnet: str) -> List[Dict[str, str]]:
    """
    Performs a quick subnet scan (ICMP ping sweep) to identify active hosts and retrieve their MAC addresses and vendors.

    Args:
        subnet (str): Subnet to scan, e.g., '192.168.0.0/24'.

    Returns:
        List[Dict[str, str]]: List of active hosts with their IP, MAC addresses, and vendors.
    """
    command = ["nmap", "-sn", subnet]
    result = run_command(command)

    live_hosts = []
    current_ip = None  # To keep track of the current IP address in the scan

    for line in result.stdout.splitlines():

        # Parse IP address from the normal report format
        if "Nmap scan report for" in line:
            # Check if the line contains both hostname and IP in parentheses
            ip_match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
            if ip_match:
                current_ip = ip_match.group(1).strip()
            else:
                # Otherwise, extract the last part of the line as the IP
                current_ip = line.split(" ")[-1].strip()

            live_hosts.append({"ip": current_ip, "mac": "unknown", "vendor": "unknown"})  # Add host with placeholders

        # Parse MAC address and vendor
        elif "MAC Address" in line and current_ip:
            mac_match = re.search(r"MAC Address: ([0-9A-F:]+) \((.+)\)", line)
            if mac_match:
                mac_address = mac_match.group(1).strip()
                vendor = mac_match.group(2).strip()

                # Update the last added host's MAC and vendor
                for host in live_hosts:
                    if host["ip"] == current_ip:
                        host["mac"] = mac_address
                        host["vendor"] = vendor
                        break

    # Ensure MAC address is updated for the scanning host (if it's detected)
    for host in live_hosts:
        if host["ip"] == current_ip and host["mac"] == "unknown":
            for line in result.stdout.splitlines():
                if "MAC Address" in line:
                    mac_match = re.search(r"MAC Address: ([0-9A-F:]+) \((.+)\)", line)
                    if mac_match:
                        host["mac"] = mac_match.group(1).strip()
                        host["vendor"] = mac_match.group(2).strip()
                        break
    data = {
       'scanned_at': current_time(),
       'live_hosts': live_hosts
    }

    publish_mqtt(f"{MQTT_TOPIC_PREFIX}/hosts/live", data)
    log(f"Quick scan of {subnet} found {len(live_hosts)} active hosts.")

    live_hosts_ips = [host["ip"] for host in live_hosts if "ip" in host]
    return live_hosts_ips


def current_time() -> int:
    """Returns the current time as a UNIX timestamp."""
    return int(datetime.now().strftime("%s"))


def full_scan(live_hosts: List[str], output_dir: str) -> List[Dict[str, Any]]:
    """
    Performs a full scan of active hosts (all ports, service detection).
    
    Args:
        live_hosts (List[str]): List of active host IPs.
        output_dir (str): Directory for saving results.

    Returns:
        List[Dict[str, Any]]: Results as a list of dictionaries.
    """
    results = []
    ports = "1-65535"
    for ip in live_hosts:
        log(f"Starting full scan for host {ip}.")
        started_at = current_time()

        publish_mqtt(f"{MQTT_TOPIC_PREFIX}/scan/start_host", {"ip": ip, "started_at": started_at})

        output_base = os.path.join(output_dir, ip)
        command = ["nmap", "-sV", "-p", ports, "-T4", "--open", "-oA", output_base, ip]
        run_command(command)

        json_results = nmap_xml_to_json(f"{output_base}.xml")
        json_results["ip"] = ip
        json_results["started_at"] = started_at
        json_results["finished_at"] = current_time()

        publish_mqtt(f"{MQTT_TOPIC_PREFIX}/scan/finish_host", json_results)
        parsed = parse_nmap_results(f"{output_base}.xml")
        results.append(parsed)

    return results


def parse_nmap_results(file_path: str) -> Dict[str, Any]:
    """
    Parses Nmap's XML output to extract host and open port information.

    Args:
        file_path (str): Path to the XML file with scan results.

    Returns:
        Dict[str, Any]: Dictionary with host info and list of open ports.
    """
    tree = ET.parse(file_path)
    root = tree.getroot()

    host_info = {"ip": None, "ports": []}

    # Extract IP
    for address in root.findall(".//address"):
        if address.get("addrtype") == "ipv4":
            host_info["ip"] = address.get("addr")

    # Extract port information
    for port in root.findall(".//port"):
        service = port.find("service")
        port_info = {
            "port": port.get("portid"),
            "state": port.find("state").get("state"),
            "banner": service.get("name", "unknown") if service else "unknown",
            "product": service.get("product", "unknown") if service else "unknown",
            "version": service.get("version", "unknown") if service else "unknown",
        }
        host_info["ports"].append(port_info)

    return host_info


def nmap_xml_to_json(xml_file_path: str) -> Dict[str, Any]:
    """
    Converts Nmap scan results from XML format to a JSON-compatible dictionary.

    Args:
        xml_file_path (str): Path to the Nmap XML results file.

    Returns:
        dict: Dictionary with host and service data.
    """
    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot()
        host_info = {"ip": None, "ports": []}

        # Extract IP address
        for address in root.findall(".//address"):
            if address.get("addrtype") == "ipv4":
                host_info["ip"] = address.get("addr")

        # Extract port data
        for port in root.findall(".//port"):
            port_info = {
                "port": port.get("portid"),
                "protocol": port.get("protocol"),
                "state": port.find("state").get("state"),
                "reason": port.find("state").get("reason", "unknown"),
                "service": {}
            }

            service = port.find("service")
            if service is not None:
                port_info["service"] = {
                    "name": service.get("name", "unknown"),
                    "product": service.get("product", "unknown"),
                    "version": service.get("version", "unknown"),
                    "extrainfo": service.get("extrainfo", "unknown")
                }

            host_info["ports"].append(port_info)

        return host_info

    except ET.ParseError as e:
        raise ValueError(f"XML parsing error: {e}")
    except Exception as e:
        raise ValueError(f"Could not convert XML to JSON: {e}")


# --- State management ---
def load_previous_results(base_dir: str) -> List[Dict[str, Any]]:
    """
    Loads previous scan results from a file.
    
    Args:
        base_dir (str): Directory containing results.

    Returns:
        List[Dict[str, Any]]: Previous scan results.
    """
    latest_path = os.path.join(base_dir, "latest", NETWORK_STATE_FILENAME)
    if os.path.exists(latest_path):
        with open(latest_path, "r") as f:
            return json.load(f)
    return []


def update_latest_link(base_dir: str, output_dir: str) -> None:
    """
    Updates the symbolic link 'latest' to point to the new results directory.
    
    Args:
        base_dir (str): Base results directory.
        output_dir (str): New directory with the latest results.
    """
    latest = os.path.join(base_dir, "latest")
    if os.path.islink(latest):
        os.unlink(latest)
    os.symlink(os.path.basename(output_dir), latest)
    log(f"'latest' symbolic link updated to {output_dir}")


# --- Comparing results ---
def compare_scan_results(current_results: List[Dict[str, Any]], previous_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compares current and previous scan results to determine changes:
    - Added hosts
    - Removed hosts
    - Added ports
    - Removed ports

    Args:
        current_results (List[Dict[str, Any]]): Current scan results.
        previous_results (List[Dict[str, Any]]): Previous scan results.

    Returns:
        dict: Dictionary with network changes.
    """
    changes = {
        "added_hosts": [],
        "removed_hosts": [],
        "added_ports": [],
        "removed_ports": []
    }

    # Convert results to dictionaries for easier comparison
    current_dict = {host["ip"]: set((p["port"], p["banner"]) for p in host["ports"]) for host in current_results}
    previous_dict = {host["ip"]: set((p["port"], p["banner"]) for p in host["ports"]) for host in previous_results}

    # Determine new and removed hosts
    added_hosts = set(current_dict.keys()) - set(previous_dict.keys())
    removed_hosts = set(previous_dict.keys()) - set(current_dict.keys())

    changes["added_hosts"] = list(added_hosts)
    changes["removed_hosts"] = list(removed_hosts)

    # Changes in ports for hosts that remain
    for ip in set(current_dict.keys()).intersection(set(previous_dict.keys())):
        added_ports = current_dict[ip] - previous_dict[ip]
        removed_ports = previous_dict[ip] - current_dict[ip]

        for port, banner in added_ports:
            changes["added_ports"].append({"ip": ip, "port": port, "banner": banner})

        for port, banner in removed_ports:
            changes["removed_ports"].append({"ip": ip, "port": port, "banner": banner})

    # Add ports for newly added hosts
    for ip in added_hosts:
        for port, banner in current_dict[ip]:
            changes["added_ports"].append({"ip": ip, "port": port, "banner": banner})

    return filter_empty_changes(changes)


def publish_changes_if_any(changes: Dict[str, Any], started_at: datetime, finished_at: datetime) -> None:
    """
    If there are network changes, publishes them to MQTT and sends a Telegram notification.
    
    Args:
        changes (dict): Network changes.
        started_at (datetime): Start time of the scan.
        finished_at (datetime): Finish time of the scan.
    """
    if changes:
        publish_mqtt(f"{MQTT_TOPIC_PREFIX}/scan/network_change", changes)
        log(f"Network changes detected: {json.dumps(changes, indent=4, ensure_ascii=False)}")

        telegram_message = format_telegram_message(changes, started_at, finished_at)
        send_telegram_message(telegram_message)
    else:
        log("No network changes detected.")


def send_telegram_message(message: str) -> None:
    """
    Sends a message to a Telegram chat using the Telegram Bot API.
    
    Args:
        message (str): Message to send.
    """

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log("Telegram bot token or chat ID not provided. Skipping Telegram message.")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }

    publish_mqtt(f"{MQTT_TOPIC_PREFIX}/telegram/send_message", payload)

    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            log("Message sent to Telegram.")
        else:
            log(f"Failed to send message to Telegram: {response.status_code} {response.text}")
    except Exception as e:
        log(f"Error sending message to Telegram: {e}")


import socket

def format_telegram_message(changes, started_at, finished_at):
    messages = []

    messages.append("*Scan started:*\n" + started_at.strftime('%Y-%m-%d %H:%M:%S'))
    messages.append("*Scan finished:*\n" + finished_at.strftime('%Y-%m-%d %H:%M:%S'))

    delta = int(finished_at.strftime("%s")) - int(started_at.strftime("%s"))
    messages.append("*Scan duration:*\n" + format_duration(delta))

    # Сортировка списков IP
    if "added_hosts" in changes and changes["added_hosts"]:
        sorted_added_hosts = sorted(changes["added_hosts"], key=lambda ip: socket.inet_aton(ip))
        messages.append("*New hosts:*\n" + "\n".join(sorted_added_hosts))

    if "removed_hosts" in changes and changes["removed_hosts"]:
        sorted_removed_hosts = sorted(changes["removed_hosts"], key=lambda ip: socket.inet_aton(ip))
        messages.append("*Removed hosts:*\n" + "\n".join(sorted_removed_hosts))

    # Сортировка списка портов: сначала по IP, затем по номеру порта
    def port_sort_key(port_info):
        return (socket.inet_aton(port_info["ip"]), int(port_info["port"]))

    if "added_ports" in changes and changes["added_ports"]:
        sorted_added_ports = sorted(changes["added_ports"], key=port_sort_key)
        messages.append("*New ports:*\n" + "\n".join(
            f"{p['ip']}:{p['port']} ({p['banner']})" for p in sorted_added_ports
        ))

    if "removed_ports" in changes and changes["removed_ports"]:
        sorted_removed_ports = sorted(changes["removed_ports"], key=port_sort_key)
        messages.append("*Closed ports:*\n" + "\n".join(
            f"{p['ip']}:{p['port']} ({p['banner']})" for p in sorted_removed_ports
        ))

    return "\n\n".join(messages)


def filter_empty_changes(changes: Dict[str, Any]) -> Dict[str, Any]:
    """
    Filters out empty lists of changes and returns only non-empty entries.
    
    Args:
        changes (dict): Dictionary of changes.

    Returns:
        dict: Filtered dictionary of changes.
    """
    return {key: value for key, value in changes.items() if value}


def format_duration(seconds: int) -> str:
    """
    Formats the scanning duration in a human-readable format.

    Args:
        seconds (int): Duration in seconds.

    Returns:
        str: Formatted time string.
    """
    if seconds < 60:
        return f"{seconds} seconds" if seconds != 1 else "1 second"

    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes} minutes {seconds} seconds" if seconds else f"{minutes} minutes"

    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        if seconds:
            return f"{hours} hours {minutes} minutes {seconds} seconds"
        return f"{hours} hours {minutes} minutes"

    days, hours = divmod(hours, 24)
    if seconds:
        return f"{days} days {hours} hours {minutes} minutes {seconds} seconds"
    return f"{days} days {hours} hours {minutes} minutes"


# --- Main process ---
def main() -> None:
    """
    Main entry point. Initializes MQTT (if needed), loads previous results,
    then in a loop, performs subnet scans, compares results, sends notifications,
    and periodically repeats the process.
    """
    if USE_MQTT:
        connect_mqtt()

    previous_results = load_previous_results(BASE_DIR)
    os.makedirs(BASE_DIR, exist_ok=True)

    log(f"Previous network state: {json.dumps(previous_results, indent=4, ensure_ascii=False)}")
    publish_mqtt(f"{MQTT_TOPIC_PREFIX}/app/started", {"started_at": current_time()})

    while True:
        started_at = datetime.now()
        output_dir = os.path.join(BASE_DIR, started_at.strftime("%Y-%m-%d_%H-%M-%S"))
        os.makedirs(output_dir, exist_ok=True)

        subnets = load_subnets(SUBNETS_FILE)
        current_results = []
        live_hosts = []

        for subnet in subnets:
            hosts = quick_scan(subnet)
            live_hosts.extend(hosts)
            current_results.extend(full_scan(hosts, output_dir))

        finished_at = datetime.now()

        # Compare results
        changes = compare_scan_results(current_results, previous_results)
        publish_changes_if_any(changes, started_at, finished_at)

        # Save current state
        previous_results = current_results
        with open(os.path.join(output_dir, NETWORK_STATE_FILENAME), "w") as f:
            json.dump(current_results, f, indent=4, ensure_ascii=False)

        update_latest_link(BASE_DIR, output_dir)

        # Save additional scan results
        with open(f"{output_dir}/{RESULTS_FILENAME}", "w") as file:
            json.dump({
                "started_at": int(started_at.strftime("%s")),
                "finished_at": int(finished_at.strftime("%s")),
                "live_hosts": live_hosts,
                "network_changes": changes
            }, file, indent=4, ensure_ascii=False)

        log(f"Scan completed. Next scan in {INTERVAL} seconds.\n\n")
        time.sleep(INTERVAL)
        publish_mqtt(f"{MQTT_TOPIC_PREFIX}/app/restarted", {"restarted_at": current_time()})


if __name__ == "__main__":
    main()

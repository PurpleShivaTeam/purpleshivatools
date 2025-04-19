#!/usr/bin/env python3 
# ARP Scan

import argparse
from scapy.all import ARP, Ether, srp
import sys
import signal
import time
import threading
import os
import xml.etree.ElementTree as ET
from datetime import datetime
import ipaddress
import json
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from concurrent.futures import ThreadPoolExecutor

# ANSI color codes
RED = "\033[38;2;255;0;0m"
GREEN = "\033[38;2;0;255;0m"
RESET = "\033[0m"
BOLD = "\033[1m"

# Security recommendations base list
RECOMMENDATIONS = [
    {
        "id": 1,
        "title": "Dynamic ARP Inspection (DAI)",
        "severity": "High",
        "description": (
            "Validates ARP packets on untrusted ports using a default rate limit "
            "of 15 packets per second (pps), and intercepts, logs, and drops invalid ARPs."
        ),
        "metrics": {
            "rate_limit_pps": 15,
            "detection_success_rate": "100%"
        },
        "sources": [
            "Cisco: default 15 pps rate on untrusted ports",
            "Academic research: 100% spoofing detection success in simulation"
        ]
    },
    {
        "id": 2,
        "title": "DHCP Snooping",
        "severity": "Medium",
        "description": (
            "Maintains a DHCP binding table to filter and discard messages from unauthorized "
            "DHCP servers, acting as a 'firewall' between clients and rogue servers."
        ),
        "metrics": {
            "binding_database_size": "number of registered clients",
            "unauthorized_dhcp_drop_rate": "depends on network configuration"
        },
        "sources": [
            "Wikipedia: DHCP Snooping overview",
            "ManageEngine: protection against rogue DHCP servers"
        ]
    },
    {
        "id": 3,
        "title": "Port Security",
        "severity": "Medium",
        "description": (
            "Restricts MAC addresses per port, blocking unknown devices and defining "
            "violation actions (shutdown, restrict, or protect)."
        ),
        "metrics": {
            "max_mac_per_port": 1,
            "unauthorized_device_block_rate": "depends on configuration"
        },
        "sources": [
            "ServerMania: blocking unknown devices by MAC address",
            "Cisco Community: recommended port security configuration"
        ]
    },
    {
        "id": 4,
        "title": "VLAN Segmentation",
        "severity": "Low",
        "description": (
            "Segments the network into isolated broadcast domains, reducing "
            "attack surface and unnecessary traffic."
        ),
        "metrics": {
            "attack_surface_reduction": "up to 90%",
            "broadcast_domain_size_reduction": "proportional to number of VLANs"
        },
        "sources": [
            "Wikipedia: network segmentation benefits",
            "Academic study: microsegmentation reduces exposure by 60–90%"
        ]
    }
]


stopTimer = False
timerThread = None
stdoutLock = threading.Lock()
progressLine = ""

LOG_DIR = "/var/log/purpleshivatoolslog"
os.makedirs(LOG_DIR, exist_ok=True)

# Ensure running as root for ARP packet operations
if os.geteuid() != 0:
    print(f"{RED}Error: This script must be run as root.{RESET}")
    sys.exit(1)

# Timer thread for progress display
def UpdateTimer(startTime):
    global stopTimer
    while not stopTimer:
        elapsed = time.time() - startTime
        elapsedFormatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))
        with stdoutLock:
            sys.stdout.write(f"\r{progressLine} | Duration: {BOLD}{elapsedFormatted}{RESET}")
            sys.stdout.flush()
        time.sleep(1)
    with stdoutLock:
        sys.stdout.write("\n")
        sys.stdout.flush()

# Send ARP request to a single IP and return list of devices found
def scan_ip(ip):
    arp = ARP(pdst=str(ip))
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=1, verbose=False)[0]
    return [{'ip': rcv.psrc, 'mac': rcv.hwsrc} for snd, rcv in result] if result else []

# Main ARP scan respecting the provided CIDR mask
def ArpScan(ipRange):
    global stopTimer, timerThread, progressLine
    try:
        network = ipaddress.ip_network(ipRange, strict=False)
        hosts = list(network.hosts())
    except ValueError:
        print(f"{RED}Invalid IP range format. Use something like 192.168.1.0/24{RESET}")
        return []

    print(f"\nInitializing ARP scan on the IP range {ipRange}")
    devices = []
    totalIps = len(hosts)
    startTime = time.time()

    progressLine = f"Progress: {BOLD}0.00%{RESET} | IP: {BOLD}---{RESET} | Devices Found: {BOLD}0{RESET}"
    stopTimer = False
    timerThread = threading.Thread(target=UpdateTimer, args=(startTime,))
    timerThread.start()

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_ip, ip): ip for ip in hosts}
        for count, future in enumerate(futures, start=1):
            found = future.result()
            if found:
                devices.extend(found)
            ip = futures[future]
            progress = (count / totalIps) * 100
            deviceCount = len(devices)
            progressLine = (
                f"Progress: {BOLD}{progress:.2f}%{RESET} | IP: {BOLD}{ip}{RESET} | Devices Found: {BOLD}{deviceCount}{RESET}"
            )
            with stdoutLock:
                sys.stdout.write(f"\r{progressLine}")
                sys.stdout.flush()

    stopTimer = True
    timerThread.join()
    print()
    return devices

# Detect duplicate MACs indicating possible ARP spoofing
def detect_arp_spoofing(devices):
    seen = {}
    for dev in devices:
        mac = dev['mac']
        ip = dev['ip']
        if mac in seen:
            print(f"{RED}[!] Possible ARP spoofing: MAC {mac} seen for IPs {seen[mac]} and {ip}{RESET}")
        else:
            seen[mac] = ip

# Print found devices in colored output and run spoofing detection
def PrintDevices(devices):
    print("\nFound devices:")
    print("IP\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
        print(f"{GREEN}{device['ip']}{RESET}\t{device['mac']}")
    detect_arp_spoofing(devices)

# Write XML log
def write_xml_log(filepath, devices):
    root = ET.Element("ARPScanLog")
    summary = ET.SubElement(root, "Summary")
    ET.SubElement(summary, "TotalHostsFound").text = str(len(devices))
    ET.SubElement(summary, "ScanStatus").text = "Success"
    hosts = ET.SubElement(root, "Hosts")
    for dev in devices:
        host = ET.SubElement(hosts, "Host")
        ET.SubElement(host, "IP").text = dev['ip']
        ET.SubElement(host, "MAC").text = dev['mac']
    recs = ET.SubElement(root, "SecurityRecommendations")
    for rec in RECOMMENDATIONS:
        ET.SubElement(recs, "Recommendation").text = rec
    ET.SubElement(recs, "Recommendation").text = f"Monitor and validate hosts: {[d['ip'] for d in devices]}"
    tree = ET.ElementTree(root)
    tree.write(filepath, encoding="utf-8", xml_declaration=True)
    print(f"\n{BOLD}XML log written to:{RESET} {filepath}")

# Write JSON log
def write_json_log(filepath, devices):
    data = {
        "TotalHostsFound": len(devices),
        "Hosts": devices,
        "SecurityRecommendations": RECOMMENDATIONS + [f"Monitor and validate hosts: {[d['ip'] for d in devices]}"]
    }
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"\n{BOLD}JSON log written to:{RESET} {filepath}")

# Write PDF log using ReportLab
def write_pdf_log(filepath, devices):
    c = canvas.Canvas(filepath, pagesize=letter)
    txt = c.beginText(40, 750)
    txt.setFont("Helvetica-Bold", 14)
    txt.textLine("ARP Scan Report")
    txt.setFont("Helvetica", 11)
    txt.textLine(f"Date: {datetime.now().isoformat()}")
    txt.textLine(f"Total Hosts Found: {len(devices)}")
    txt.textLine("")
    txt.textLine("Hosts:")
    for dev in devices:
        txt.textLine(f" - {dev['ip']}  {dev['mac']}")
    txt.textLine("")
    txt.textLine("Recommendations:")
    for rec in RECOMMENDATIONS:
        txt.textLine(f" - {rec}")
    txt.textLine(f" - Monitor and validate hosts: {[d['ip'] for d in devices]}")
    c.drawText(txt)
    c.showPage()
    c.save()
    print(f"\n{BOLD}PDF log written to:{RESET} {filepath}")

# Unified log writer based on single format
def WriteLogs(devices, fmt):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    if fmt == 'xml':
        path = os.path.join(LOG_DIR, f"arpscanlog_{timestamp}.xml")
        write_xml_log(path, devices)
    elif fmt == 'json':
        path = os.path.join(LOG_DIR, f"arpscanlog_{timestamp}.json")
        write_json_log(path, devices)
    elif fmt == 'pdf':
        path = os.path.join(LOG_DIR, f"arpscanlog_{timestamp}.pdf")
        write_pdf_log(path, devices)

# Interactive menu
def menu():
    ipRange = input(f"\n{RED}IP range (e.g. 192.168.1.0/24):{RESET} ")
    devices = ArpScan(ipRange)
    PrintDevices(devices)

    format_choice = input("Save report as (xml/json/pdf): ").strip().lower()
    if format_choice in ('xml', 'json', 'pdf'):
        WriteLogs(devices, format_choice)
    else:
        print(f"{RED}Invalid format selected. No log was saved.{RESET}")

# Command-line interface
def terminal():
    parser = argparse.ArgumentParser(
        description="ARP Scan Tool", formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-i", "--ip_range", required=True, help="IP range (e.g. 192.168.1.0/24)")
    parser.add_argument("-f", "--format", choices=['xml', 'json', 'pdf'], help="Log format to save report")
    args = parser.parse_args()

    devices = ArpScan(args.ip_range)
    PrintDevices(devices)
    if args.format:
        WriteLogs(devices, args.format)

# Signal handler to exit cleanly
def signalHandler(sig, frame):
    print(f"\n{RED}Stopping ARP Scan...{RESET}")
    sys.exit(0)

# Entry point
if __name__ == "__main__":
    signal.signal(signal.SIGINT, signalHandler)
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

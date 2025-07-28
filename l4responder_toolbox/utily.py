from kubernetes import client, config,watch
from time import sleep
import os
from itertools import cycle
import logging
import tempfile
import subprocess

def run_nft(cmd: str):
    full_cmd = f"nft {cmd}"
    result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        logging.error(f"nft command failed: {full_cmd}\n{result.stderr}")
    else:
        logging.debug(f"Ran: {full_cmd}")



def run_iptables(cmd: str):
    full_cmd = f"iptables {cmd}"
    result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        logging.error(f"iptables command failed: {full_cmd}\n{result.stderr}")
    else:
        logging.debug(f"Ran: {full_cmd}")

def cleanup():
    logging.info("Flushing and deleting CYBORG chain")
    run_nft("flush chain ip nat CYBORG || true")
    run_nft("delete chain ip nat CYBORG || true")
    run_nft("delete rule ip nat PREROUTING handle $(nft list chain ip nat PREROUTING | grep 'jump CYBORG' | awk '{print $1}') || true")

def init_table():
    logging.info("Initializing nftables NAT table and CYBORG chain...")
    # Create CYBORG chain if it doesn’t exist
    run_nft("add chain ip nat CYBORG { type nat hook prerouting priority 0 \; } || true")

    # Insert jump from PREROUTING to CYBORG if not already present
    check_cmd = "nft list chain ip nat PREROUTING | grep 'jump CYBORG'"
    result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)

    if result.returncode != 0 or not result.stdout.strip():
        run_nft("add rule ip nat PREROUTING jump CYBORG")
        logging.info("Added jump from PREROUTING to CYBORG chain.")
    else:
        logging.debug("Jump from PREROUTING to CYBORG already exists.")

def ensure_masquerade():
    check_cmd = "nft list chain ip nat POSTROUTING | grep masquerade"
    result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
    if not result.stdout.strip():
        run_nft("add rule ip nat POSTROUTING masquerade")
        logging.info("Added MASQUERADE rule to POSTROUTING.")
    else:
        logging.debug("MASQUERADE rule already exists.")

def add_forward(chain_name: str,ip: str, from_port: str, to_port: str, to_ip: str):
    logging.info(f"Adding nftables rule: {ip}:{from_port} -> {to_ip}:{to_port}")
    run_nft(f"add rule ip nat {chain_name} ip daddr {ip} tcp  dport {from_port} dnat to {to_ip}:{to_port}")
    ensure_masquerade()

def remove_forward(chain_name: str, ip: str, from_port: str, to_port: str, to_ip: str):
    logging.info(f"Removing nftables rule for {ip}:{from_port} -> {to_ip}:{to_port}")

    list_cmd = f"nft list chain ip nat {chain_name}"
    result = subprocess.run(list_cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        logging.error(f"Failed to list nftables rules for chain {chain_name}")
        return

    lines = result.stdout.splitlines()
    for line in lines:
        # Match rule line including source IP CIDR (ip saddr <ip>)
        if (f"tcp dport {from_port}" in line and 
            f"ip daddr {ip}" in line and
            f"dnat to {to_ip}:{to_port}" in line):
            handle_match = re.search(r"handle (\d+)", line)
            if handle_match:
                handle = handle_match.group(1)
                run_nft(f"delete rule ip nat {chain_name} handle {handle}")
                logging.info(f"Removed rule with handle {handle}")
                return

    logging.warning("No matching nftables DNAT rule found to delete.")
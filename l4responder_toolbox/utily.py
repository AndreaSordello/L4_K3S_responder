from kubernetes import client, config,watch
from time import sleep
import os
from itertools import cycle
import logging
import tempfile
import subprocess
import re
def run_nft(cmd: str):
    full_cmd = f"nft {cmd}"
    result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        logging.error(f"nft command failed: {full_cmd}\n{result.stderr}")
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

def add_forward(chain_name: str,ip: str, from_port: str, to_port: str, to_ip: str, pod_name: str ):
    logging.info(f"[{pod_name}] Adding nftables rule: {ip}:{from_port} -> {to_ip}:{to_port}")
    run_nft(f"add rule ip nat {chain_name} ip daddr {ip} tcp  dport {from_port} dnat to {to_ip}:{to_port} comment {pod_name}")
    ensure_masquerade()



def remove_forward(chain_name: str, pod_name: str):
    logging.info(f"Removing nftables rule(s) for POD [{pod_name}]")

    list_cmd = f"nft -a list chain ip nat {chain_name}"  # -a shows handle
    result = subprocess.run(list_cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        logging.error(f"Failed to list nftables rules for chain {chain_name}")
        return

    lines = result.stdout.splitlines()
    found = False
    for line in lines:
        # Check if the line contains the pod_name in the comment
        # nft rule comments look like: comment "pod_name"
        if f'{pod_name}' in line:
            #logging.debug(f"DEBUG line: {line}")
            handle_match = re.search(r"handle (\d+)", line)
            if handle_match:
                handle = handle_match.group(1)
                #logging.debug(f"DEBUG handle: {handle}")
                run_nft(f"delete rule ip nat {chain_name} handle {handle}")
                logging.info(f"Removed rule with handle {handle} for pod {pod_name}")
                found = True
                # If you want to delete all matching rules, do not return here

    if not found:
        logging.warning(f"No matching nftables DNAT rule found for pod [{pod_name}].")
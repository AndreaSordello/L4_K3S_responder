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
    logging.info("Cleaning up CYBORG chain (if exists)")
    
    # Check if chain exists first
    check_result = subprocess.run("nft list chain ip nat CYBORG", shell=True, capture_output=True, text=True)
    
    if check_result.returncode == 0:
        logging.debug("CYBORG chain exists, cleaning up...")
        
        # Remove ALL jump rules to CYBORG from PREROUTING
        list_cmd = "nft -a list chain ip nat PREROUTING"
        result = subprocess.run(list_cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            lines = result.stdout.splitlines()
            handles_to_remove = []
            
            # Collect all handles that jump to CYBORG
            for line in lines:
                if 'jump CYBORG' in line:
                    handle_match = re.search(r"handle (\d+)", line)
                    if handle_match:
                        handles_to_remove.append(handle_match.group(1))
            
            # Remove all the jump rules
            for handle in handles_to_remove:
                run_nft(f"delete rule ip nat PREROUTING handle {handle}")
                logging.debug(f"Removed PREROUTING jump rule with handle {handle}")
        
        # Flush the chain (don't delete it, as we discussed)
        run_nft("flush chain ip nat CYBORG")
        logging.info(f"CYBORG chain cleanup completed - removed {len(handles_to_remove)} jump rules")
    else:
        logging.debug("CYBORG chain doesn't exist, skipping cleanup")

def init_table():
    logging.info("Initializing nftables NAT table and CYBORG chain...")
    
    # Create CYBORG chain if it doesn't exist
    chain_check = subprocess.run("nft list chain ip nat CYBORG", shell=True, capture_output=True, text=True)
    if chain_check.returncode != 0:
        run_nft("add chain ip nat CYBORG")
        logging.debug("Created CYBORG chain")
    else:
        logging.debug("CYBORG chain already exists")
    
    # Check if jump rule already exists
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
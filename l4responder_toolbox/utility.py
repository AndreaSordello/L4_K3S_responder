import logging
import subprocess
import re
import shlex

# Validate that a string is a safe Kubernetes resource name (alphanumeric, dashes, dots)
_SAFE_K8S_NAME = re.compile(r'^[a-z0-9][a-z0-9.\-]{0,252}$')
_SAFE_CHAIN_NAME = re.compile(r'^[A-Za-z0-9_]+$')
_SAFE_IP = re.compile(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$')
_SAFE_PORT = re.compile(r'^[0-9]+(-[0-9]+)?$')


def _validate_chain_name(name: str) -> str:
    if not _SAFE_CHAIN_NAME.match(name):
        raise ValueError(f"Invalid chain name: {name}")
    return name


def _validate_ip(ip: str) -> str:
    if not _SAFE_IP.match(ip):
        raise ValueError(f"Invalid IP address: {ip}")
    return ip


def _validate_port(port: str) -> str:
    if not _SAFE_PORT.match(port):
        raise ValueError(f"Invalid port: {port}")
    return port


def _validate_pod_name(name: str) -> str:
    if not _SAFE_K8S_NAME.match(name):
        raise ValueError(f"Invalid pod name: {name}")
    return name


def run_nft(cmd: str):
    cmd_list = ["nft"] + shlex.split(cmd)
    result = subprocess.run(cmd_list, capture_output=True, text=True)
    if result.returncode != 0:
        logging.error(f"nft command failed: {cmd_list}\n{result.stderr}")
    else:
        logging.debug(f"Ran: {cmd_list}")


def cleanup():
    logging.info("Cleaning up CYBORG chain (if exists)")

    # Check if chain exists first
    check_result = subprocess.run(
        ["nft", "list", "chain", "ip", "nat", "CYBORG"],
        capture_output=True, text=True
    )

    if check_result.returncode == 0:
        logging.debug("CYBORG chain exists, cleaning up...")

        # Remove ALL jump rules to CYBORG from PREROUTING
        result = subprocess.run(
            ["nft", "-a", "list", "chain", "ip", "nat", "PREROUTING"],
            capture_output=True, text=True
        )
        handles_to_remove = []
        if result.returncode == 0:
            lines = result.stdout.splitlines()

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

        # Flush the chain
        run_nft("flush chain ip nat CYBORG")
        logging.info(f"CYBORG chain cleanup completed - removed {len(handles_to_remove)} jump rules")
    else:
        logging.debug("CYBORG chain doesn't exist, skipping cleanup")


def init_table():
    logging.info("Initializing nftables NAT table and CYBORG chain...")

    # Create CYBORG chain if it doesn't exist
    chain_check = subprocess.run(
        ["nft", "list", "chain", "ip", "nat", "CYBORG"],
        capture_output=True, text=True
    )
    if chain_check.returncode != 0:
        run_nft("add chain ip nat CYBORG")
        logging.debug("Created CYBORG chain")
    else:
        logging.debug("CYBORG chain already exists")

    # Check if jump rule already exists
    result = subprocess.run(
        ["nft", "list", "chain", "ip", "nat", "PREROUTING"],
        capture_output=True, text=True
    )
    if result.returncode != 0 or 'jump CYBORG' not in result.stdout:
        run_nft("add rule ip nat PREROUTING jump CYBORG")
        logging.info("Added jump from PREROUTING to CYBORG chain.")
    else:
        logging.debug("Jump from PREROUTING to CYBORG already exists.")


def ensure_masquerade():
    result = subprocess.run(
        ["nft", "list", "chain", "ip", "nat", "POSTROUTING"],
        capture_output=True, text=True
    )
    if result.returncode != 0 or 'masquerade' not in result.stdout:
        run_nft("add rule ip nat POSTROUTING masquerade")
        logging.info("Added MASQUERADE rule to POSTROUTING.")
    else:
        logging.debug("MASQUERADE rule already exists.")


def add_forward(chain_name: str, ip: str, from_port: str, to_port: str, to_ip: str, pod_name: str):
    chain_name = _validate_chain_name(chain_name)
    ip = _validate_ip(ip)
    from_port = _validate_port(from_port)
    to_port = _validate_port(to_port)
    to_ip = _validate_ip(to_ip)
    pod_name = _validate_pod_name(pod_name)

    logging.info(f"[{pod_name}] Adding nftables rule: {ip}:{from_port} -> {to_ip}:{to_port}")
    run_nft(
        f'add rule ip nat {chain_name} ip daddr {ip} tcp dport {from_port} '
        f'dnat to {to_ip}:{to_port} comment "{pod_name}"'
    )
    ensure_masquerade()


def remove_forward(chain_name: str, pod_name: str):
    chain_name = _validate_chain_name(chain_name)
    pod_name = _validate_pod_name(pod_name)

    logging.info(f"Removing nftables rule(s) for POD [{pod_name}]")

    result = subprocess.run(
        ["nft", "-a", "list", "chain", "ip", "nat", chain_name],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        logging.error(f"Failed to list nftables rules for chain {chain_name}")
        return

    lines = result.stdout.splitlines()
    found = False
    for line in lines:
        if pod_name in line:
            handle_match = re.search(r"handle (\d+)", line)
            if handle_match:
                handle = handle_match.group(1)
                run_nft(f"delete rule ip nat {chain_name} handle {handle}")
                logging.info(f"Removed rule with handle {handle} for pod {pod_name}")
                found = True

    if not found:
        logging.warning(f"No matching nftables DNAT rule found for pod [{pod_name}].")

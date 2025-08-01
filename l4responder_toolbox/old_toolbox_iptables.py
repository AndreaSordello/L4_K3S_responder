from kubernetes import client, config,watch
from time import sleep
import os
from itertools import cycle
import logging
import tempfile
import subprocess

# Set up colored logging output
class ColorFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[94m',    # Blue
        'INFO': '\033[92m',     # Green
        'WARNING': '\033[93m',  # Yellow
        'ERROR': '\033[91m',    # Red
        'CRITICAL': '\033[95m', # Magenta
    }
    RESET = '\033[0m'

    def format(self, record):
        color = self.COLORS.get(record.levelname, self.RESET)
        message = super().format(record)
        return f"{color}{message}{self.RESET}"




handler = logging.StreamHandler()
formatter = ColorFormatter('[%(levelname)s] %(asctime)s - %(message)s', "%Y-%m-%d %H:%M:%S")
handler.setFormatter(formatter)
logging.basicConfig(level=logging.DEBUG, handlers=[handler])





def run_iptables(cmd: str):
    full_cmd = f"iptables {cmd}"
    result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        logging.error(f"iptables command failed: {full_cmd}\n{result.stderr}")
    else:
        logging.debug(f"Ran: {full_cmd}")


def cleanup():
    logging.info("Flushing and deleting CYBORG chain")
    run_iptables("-t nat -F CYBORG || true")
    run_iptables("-t nat -D PREROUTING -j CYBORG || true")
    run_iptables("-t nat -X CYBORG || true")
        
def init_table():
    logging.info("Initializing iptables NAT table and CYBORG chain...")
    # Create CYBORG chain if it doesn’t exist
    run_iptables("-t nat -N CYBORG || true")

    # Insert jump from PREROUTING to CYBORG if not already present
    check_jump = subprocess.run(
        "iptables -t nat -C PREROUTING -j CYBORG",
        shell=True, capture_output=True, text=True
    )

    if check_jump.returncode != 0:
        run_iptables("-t nat -A PREROUTING -j CYBORG")
        logging.info("Added jump from PREROUTING to CYBORG chain.")
    else:
        logging.debug("Jump from PREROUTING to CYBORG already exists.")



def add_forward(chain_name: str, from_port: str, to_port: str, to_ip: str):
    logging.info(f"Adding iptables rule: {from_port} -> {to_ip}:{to_port}")

    # DNAT rule
    run_iptables(f"-t nat -A {chain_name} -p tcp --dport {from_port} -j DNAT --to-destination {to_ip}:{to_port}")

    # Check for MASQUERADE rule in POSTROUTING
    check_cmd = "iptables -t nat -S POSTROUTING | grep MASQUERADE"
    result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
    if not result.stdout:
        run_iptables("-t nat -A POSTROUTING -j MASQUERADE")
        logging.info("Added MASQUERADE rule to POSTROUTING.")
    else:
        logging.debug("MASQUERADE rule already exists.")

def remove_forward(chain_name: str, from_port: str, to_port: str, to_ip: str):
    logging.info(f"Removing iptables rule for {from_port} -> {to_ip}:{to_port}")

    # List rules in the chain
    list_cmd = f"iptables -t nat -S {chain_name}"
    result = subprocess.run(list_cmd, shell=True, capture_output=True, text=True)

    if result.returncode != 0:
        logging.error(f"Failed to list iptables rules for chain {chain_name}")
        return

    lines = result.stdout.splitlines()
    removed = False

    for line in lines:
        if (f"--dport {from_port}" in line or f"--dport {from_port.split(':')[0]}" in line) and \
           f"--to-destination {to_ip}:{to_port}" in line:
            delete_cmd = line.replace("-A", "-t nat -D", 1)
            run_iptables(delete_cmd)
            logging.info(f"Removed matching rule: {delete_cmd}")
            removed = True
            break

    if not removed:
        logging.warning("No matching iptables DNAT rule found to delete.")



node_name = os.getenv("NODE_NAME")
KUBECONFIG = os.getenv("KUBECONFIG")
CONTAINER_PORT = os.getenv("CONTAINER_PORT")
# Extract all port ranges
port_ranges = []
i = 0
while True:
    port_range = os.getenv(f"PORT_RANGE_{i}")
    if port_range is None:
        break
    start, end = map(int, port_range.split('-'))
    port_ranges.append((start, end))
    i += 1
logging.info("Port Ranges: %s", port_ranges)

if KUBECONFIG == None and node_name == None:
    node_name ="poli-master-00" 

    with open("../development/kubeconfig.yaml", "r") as f:
        KUBECONFIG = f.read()
    logging.info(f"I am running LOCALLY on node: {node_name} with kubeconfig: {KUBECONFIG}")
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmpfile:
        tmpfile.write(KUBECONFIG)
        tmpfile.flush()
        tmp_kubeconfig_path = tmpfile.name

        # Now load config from the temp file
    config.load_kube_config(config_file=tmp_kubeconfig_path)

else:
    config.load_incluster_config()
    logging.info(f"I am running on node: {node_name} with kubeconfig 'incluster_config'")

logging.info(f"Node name: {node_name}")
logging.info(f"Kubeconfig: {KUBECONFIG}")

cleanup()
init_table() 


v1 = client.CoreV1Api()
w = watch.Watch()

def handle_pod_event(event):
        pod = event['object']
        event_type = event['type']
        node_name = pod.spec.node_name
        pod_name = pod.metadata.name
        
        
        if pod.metadata.name == "l4-server" and event_type == "ADDED":
            logging.debug(f"[{event_type}] Pod '{pod_name}' scheduled on node {node_name} in namespace '{pod.metadata.namespace}'")

            while pod.status.pod_ip == None:
                pod = v1.read_namespaced_pod(name=pod.metadata.name,namespace=pod.metadata.namespace)
                logging.debug(f"---[{pod.metadata.name}] Waiting for pod to get an IP address...")
                sleep(2)

            IP_pod_dict[pod.metadata.name] = pod.status.pod_ip
            logging.info(F"---[{pod.metadata.name}] Modifying iptables rules to redirect traffic to  pod IP {pod.status.pod_ip}...")

            for start, end in port_ranges:
                from_port = f"{start}:{end}"
                add_forward("CYBORG", from_port, CONTAINER_PORT, pod.status.pod_ip)

        if pod.metadata.name == "l4-server" and event_type == "DELETED":
            logging.info(f"---[{pod.metadata.name}]Modifying iptables rules to STOP traffic to pod IP {IP_pod_dict[pod.metadata.name]}...")
            for start, end in port_ranges:
                from_port = f"{start}:{end}"
                remove_forward("CYBORG", from_port, CONTAINER_PORT, IP_pod_dict[pod.metadata.name])
            IP_pod_dict.pop(pod.metadata.name, None)




IP_pod_dict = {}


pod_stream = w.stream(v1.list_pod_for_all_namespaces, timeout_seconds=0)
svc_stream = w.stream(v1.list_service_for_all_namespaces, timeout_seconds=0)
config_stream = w.stream(v1.list_config_map_for_all_namespaces, timeout_seconds=0)


streams = [("pod", pod_stream)]  #In the future you can add more streams like ("svc", svc_stream) or ("config", config_stream)
stream_cycle = cycle(streams)

while True:
    stream_type, stream = next(stream_cycle)
    try:
        event = next(stream)
    except StopIteration:
        continue
    except Exception as e:
        
        logging.error(f"Error reading from {stream_type} stream: {e}")
        continue

    

    if stream_type == "pod":
        
        handle_pod_event(event)
    '''
    elif stream_type == "config":
        config_map = event['object']
        event_type = event['type']
        config_name = config_map.metadata.name
        config_namespace = config_map.metadata.namespace

        logging.debug(f"[{event_type}] ConfigMap '{config_name}' in namespace '{config_namespace}'")
        # You can add logic here to handle config map events as needed
    elif stream_type == "svc":
        svc = event['object']
        event_type = event['type']
        svc_name = svc.metadata.name
        svc_namespace = svc.metadata.namespace

        logging.debug(f"[{event_type}] Service '{svc_name}' in namespace '{svc_namespace}'")
    '''
    sleep(1)  # Sleep to avoid overwhelming the output


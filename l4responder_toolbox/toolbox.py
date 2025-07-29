from kubernetes import client, config,watch
from time import sleep
import os
from itertools import cycle
import logging
import tempfile
import subprocess

from utily import run_nft, run_iptables, cleanup, init_table, ensure_masquerade, add_forward, remove_forward




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

# Extract all ip 
ip_list = []
i = 0
while True:
    ip = os.getenv(f"IP_RANGE_{i}")
    if ip is None:
        break
    ip_list.append((ip))
    i += 1
logging.info("ip list: %s", ip_list)



if KUBECONFIG == None and node_name == None:
    #MANUAL MODE
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
    #DEVELOPMENT/PRODUCTION MODE
    config.load_incluster_config()
    logging.info(f"I am running on node: {node_name} with kubeconfig 'incluster_config'")

logging.info(f"Node name: {node_name}")
logging.info(f"Kubeconfig: {KUBECONFIG}")
logging.info(f"Container port: {CONTAINER_PORT}")
logging.info("L4 Server App Name: %s", os.getenv("L4_SERVER_APP_NAME"))


# Initialize the NAT table and CYBORG chain
cleanup()
init_table() 

#Listen to cluster events

v1 = client.CoreV1Api()
w = watch.Watch()
pod_stream = w.stream(v1.list_pod_for_all_namespaces, timeout_seconds=0)
#svc_stream = w.stream(v1.list_service_for_all_namespaces, timeout_seconds=0)
#config_stream = w.stream(v1.list_config_map_for_all_namespaces, timeout_seconds=0)
streams = [("pod", pod_stream)]  
stream_cycle = cycle(streams)




def handle_pod_event(event):
        pod = event['object']
        event_type = event['type']
        node_name = pod.spec.node_name
        pod_name = pod.metadata.name
        
        if  pod.metadata.labels.get("app") == os.getenv("L4_SERVER_APP_NAME") and pod.metadata.labels.get("l4responderserver.io/node") == os.getenv("NODE_NAME") and event_type == "ADDED":
            logging.debug(f"[{event_type}] Pod '{pod_name}' scheduled on node {node_name} in namespace '{pod.metadata.namespace}'")

            while pod.status.pod_ip == None:
                pod = v1.read_namespaced_pod(name=pod.metadata.name,namespace=pod.metadata.namespace)
                logging.debug(f"---[{pod.metadata.name}] Waiting for pod to get an IP address...")
                sleep(2)
            logging.info(F"---[{pod.metadata.name}] Modifying iptables rules to redirect traffic to  pod IP {pod.status.pod_ip}...")

            for ip in ip_list:
                for start, end in port_ranges:
                    from_ports = f"{start}-{end}"
                    add_forward("CYBORG",ip, from_ports, CONTAINER_PORT, pod.status.pod_ip,pod.metadata.name)

        if pod.metadata.labels.get("app") == os.getenv("L4_SERVER_APP_NAME") and pod.metadata.labels.get("l4responderserver.io/node") == os.getenv("NODE_NAME") and event_type == "DELETED":
            logging.info(f"---[{pod.metadata.name}]Modifying iptables rules to STOP traffic...")
            remove_forward("CYBORG",pod.metadata.name)


while True: # Continuously listen for events
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

# for each event involving a pod, we will handle it with this function
# we are interested in pod events like ADDED and DELETED on l4-server pod

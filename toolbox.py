from kubernetes import client, config,watch
import iptc
from time import sleep
import os
from itertools import cycle
import logging

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

def cleanup():
    nat_table = iptc.Table(iptc.Table.NAT)
    nat_table.autocommit = True
    chain_names = [chain.name for chain in nat_table.chains]

    if "CYBORG" in chain_names:
        logging.info("Cleaning up CYBORG related rules...")
        # Remove the CYBORG chain and any associated rules
        nat_table = iptc.Table(iptc.Table.NAT)
        nat_table.autocommit = True
        nat_table.refresh()
        prerouting = iptc.Chain(nat_table, "PREROUTING")
        for rule in prerouting.rules:
            if rule.target.name == "CYBORG":
                prerouting.delete_rule(rule)
                logging.debug("Removed jump from PREROUTING to CYBORG.")
        cyborg_chain = iptc.Chain(nat_table, "CYBORG")
        if cyborg_chain:
            cyborg_chain.flush()
            nat_table.delete_chain(cyborg_chain)
            logging.debug("CYBORG chain removed.")

        # Optionally, you can also remove the jump from PREROUTING to CYBORG
        
def init_table():
    nat_table = iptc.Table(iptc.Table.NAT)
    nat_table.create_chain("CYBORG")
    nat_table.autocommit = True


    # Step 5: Re-insert jump from PREROUTING to CYBORG
    prerouting = iptc.Chain(nat_table, "PREROUTING")
    rule = iptc.Rule()
    rule.target = iptc.Target(rule, "CYBORG")
    prerouting.insert_rule(rule)

    logging.info("[Re-]Created CYBORG chain and linked it to NAT-PREROUTING")
def add_forward(chain_name: str, from_port: str, to_port: str, to_ip: str):
    nat_table = iptc.Table(iptc.Table.NAT)
    nat_table.autocommit = True
    nat_table.refresh()

    # Add DNAT rule in the specified chain (e.g. PREROUTING or your custom chain)
    chain = iptc.Chain(nat_table, chain_name)

    rule = iptc.Rule()
    rule.protocol = "tcp"

    match = rule.create_match("tcp")
    match.dport = from_port

    target = rule.create_target("DNAT")
    target.to_destination = f"{to_ip}:{to_port}"

    chain.append_rule(rule)

    # Add MASQUERADE rule in POSTROUTING chain (if not already present)
    postrouting = iptc.Chain(nat_table, "POSTROUTING")

    # Check if a masquerade rule for this to_ip is already present
    exists = False
    for r in postrouting.rules:
        if r.target.name == "MASQUERADE":
            # Optionally check matches here (e.g. interface or source IP)
            exists = True
            break

    if not exists:
        masquerade_rule = iptc.Rule()
        # You can add specific matches here if needed (e.g. outgoing interface)
        masquerade_rule.target = iptc.Target(masquerade_rule, "MASQUERADE")
        postrouting.insert_rule(masquerade_rule)
def remove_forward(chain_name: str, from_port: str, to_port: str, to_ip: str):
    nat_table = iptc.Table(iptc.Table.NAT)
    nat_table.autocommit = True
    nat_table.refresh()

    # Remove DNAT rule from specified chain
    chain = iptc.Chain(nat_table, chain_name)
    for rule in chain.rules:
            for match in rule.matches:
                if match.name == "tcp" and rule.target.name == "DNAT" and rule.target.to_destination == f"{to_ip}:{to_port}":
                    chain.delete_rule(rule)
                    break



node_name = os.getenv("NODE_NAME")
KUBECONFIG = os.getenv("KUBECONFIG")

if KUBECONFIG == None and node_name == None:
    node_name ="poli-master-00" 
    KUBECONFIG = "/etc/rancher/k3s/k3s.yaml"
    logging.info(f"I am running LOCALY on node: {node_name} with kubeconfig: {KUBECONFIG}")
else:
    logging.info(f"I am running on node: {node_name} with kubeconfig: {KUBECONFIG}")
    logging.info(f"Running in the cluster,{os.getenv('NODE_NAME')}-{KUBECONFIG}.")

cleanup()
init_table() 


config.load_kube_config(config_file=KUBECONFIG)
v1 = client.CoreV1Api()
w = watch.Watch()

def handle_pod_event(event):
        pod = event['object']
        event_type = event['type']
        node_name = pod.spec.node_name
        pod_name = pod.metadata.name

        if node_name == "poli-master-00":
            
            logging.debug(f"[{event_type}] Pod '{pod_name}' scheduled on node {node_name} in namespace '{pod.metadata.namespace}'")
            #print(pod.metadata)

        if pod.metadata.name == "l4-responder" and event_type == "ADDED":

            while pod.status.pod_ip == None:
                pod = v1.read_namespaced_pod(name=pod.metadata.name,namespace=pod.metadata.namespace)
                logging.debug(f"---[{pod.metadata.name}] Waiting for pod to get an IP address...")
                sleep(2)

            IP_pod_dict[pod.metadata.name] = pod.status.pod_ip
            logging.info(F"---[{pod.metadata.name}] Modifying iptables rules to redirect traffic to  pod IP {pod.status.pod_ip}...")
            add_forward("CYBORG", "40000:41000", "10000", pod.status.pod_ip)

        if pod.metadata.name == "l4-responder" and event_type == "DELETED":
            logging.info(f"---[{pod.metadata.name}]Modifying iptables rules to STOP traffic to pod IP {IP_pod_dict[pod.metadata.name]}...")
            remove_forward("CYBORG", "40000:41000", "10000", IP_pod_dict[pod.metadata.name])
            IP_pod_dict.pop(pod.metadata.name, None)




IP_pod_dict = {}


pod_stream = w.stream(v1.list_pod_for_all_namespaces, timeout_seconds=0)
svc_stream = w.stream(v1.list_service_for_all_namespaces, timeout_seconds=0)
config_stream = w.stream(v1.list_config_map_for_all_namespaces, timeout_seconds=0)


streams = [("pod", pod_stream), ("svc", svc_stream),("config", config_stream)]
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
        # You can add logic here to handle service events as needed

    sleep(1)  # Sleep to avoid overwhelming the output


from kubernetes import client, config
import iptc
import threading
from time import sleep
import os
from kubernetes import client, config, watch


nat_table = iptc.Table(iptc.Table.NAT)
nat_table.autocommit = True
nat_table.refresh()




node_name = os.getenv("NODE_NAME")
#node_name ="poli-master-00"
print(f"🏠 I am running on node: {node_name}")
nat_table = iptc.Table(iptc.Table.NAT)
nat_table.autocommit = True


chain_names = [chain.name for chain in nat_table.chains]

if "CYBORG" in chain_names:
    print("🔁 CYBORG chain already exists, flushing and deleting it...")

    # Step 1: Remove any rules in PREROUTING that jump to CYBORG
    prerouting = iptc.Chain(nat_table, "PREROUTING")
    for rule in prerouting.rules:
        if rule.target.name == "CYBORG":
            prerouting.delete_rule(rule)
            print("🧹 Removed jump from PREROUTING to CYBORG")

    # Step 2: Flush the CYBORG chain
    cyborg = iptc.Chain(nat_table, "CYBORG")
    cyborg.flush()

    # Step 3: Delete the CYBORG chain
    nat_table.delete_chain(cyborg)
    print("❌ CYBORG chain deleted")

# Step 4: Create CYBORG again
nat_table.create_chain("CYBORG")

# Step 5: Re-insert jump from PREROUTING to CYBORG
prerouting = iptc.Chain(nat_table, "PREROUTING")
rule = iptc.Rule()
rule.target = iptc.Target(rule, "CYBORG")
prerouting.insert_rule(rule)

print("✅ Re-created CYBORG chain and linked it to PREROUTING")



config.load_kube_config()


v1 = client.CoreV1Api()
w = watch.Watch()

print(f"🔍 Listening for pods scheduled on node {node_name}...")


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

IP_pod_dict = {}



for event in w.stream(v1.list_pod_for_all_namespaces, timeout_seconds=0) :
    pod = event['object']
    event_type = event['type']
    node_name = pod.spec.node_name
    pod_name = pod.metadata.name

    if node_name == "poli-master-00":
        print(f"[{event_type}] Pod '{pod_name}' scheduled on node {node_name} in namespace '{pod.metadata.namespace}'")
        #print(pod.metadata)

    if pod.metadata.name == "l4-responder" and event_type == "ADDED":

        while pod.status.pod_ip == None:
            pod = v1.read_namespaced_pod(name=pod.metadata.name,namespace=pod.metadata.namespace)
            print(f"---[{pod.metadata.name}] Waiting for pod to get an IP address...")
            sleep(2)

        IP_pod_dict[pod.metadata.name] = pod.status.pod_ip
        print(F"---[{pod.metadata.name}] Modifying iptables rules to redirect traffic to  pod IP {pod.status.pod_ip}...")
        add_forward("CYBORG", "40000:41000", "10000", pod.status.pod_ip)


    if pod.metadata.name == "l4-responder" and event_type == "DELETED":
        print(f"---[{pod.metadata.name}]Modifying iptables rules to STOP traffic to pod IP {IP_pod_dict[pod.metadata.name]}...")
        remove_forward("CYBORG", "40000:41000", "10000", IP_pod_dict[pod.metadata.name])
        IP_pod_dict.pop(pod.metadata.name, None)

    sleep(1)  # Sleep to avoid overwhelming the output





def watch_pods():
    config.load_kube_config()
    v1 = client.CoreV1Api()
    w = watch.Watch()
    for event in w.stream(v1.list_pod_for_all_namespaces, timeout_seconds=0):
        print("Pod event:", event['type'], event['object'].metadata.name)


def watch_configmaps():
    config.load_kube_config()
    v1 = client.CoreV1Api()
    w = watch.Watch()
    for event in w.stream(v1.list_config_map_for_all_namespaces, timeout_seconds=0):
        print("ConfigMap event:", event['type'], event['object'].metadata.name)


if __name__ == "__main__":
    t1 = threading.Thread(target=watch_pods)
    t2 = threading.Thread(target=watch_configmaps)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
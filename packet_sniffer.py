from scapy.all import sniff, IP, TCP, UDP
from database import SessionLocal
from models import Packet

# Store ports contacted by each source IP
port_tracker = {}

def process_packet(packet):

    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = packet[IP].proto

    src_port = 0
    dst_port = 0

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    print("=" * 60)
    print(f"Source IP        : {src_ip}")
    print(f"Destination IP   : {dst_ip}")
    print(f"Protocol         : {protocol}")
    print(f"Source Port      : {src_port}")
    print(f"Destination Port : {dst_port}")

    # -------- IDS Rules --------

    alert = "Normal"
    attack_type = "None"

    if src_ip not in port_tracker:
        port_tracker[src_ip] = set()

    port_tracker[src_ip].add(dst_port)

    # Port Scan Detection
    if len(port_tracker[src_ip]) >= 10:
        alert = "Suspicious"
        attack_type = "Port Scan"

    elif protocol == 1:
        alert = "ICMP"

    elif dst_port in [22, 23, 3389]:
        alert = "Suspicious"
        attack_type = "Sensitive Port"

    db = SessionLocal()

    new_packet = Packet(
        source_ip=src_ip,
        destination_ip=dst_ip,
        protocol=str(protocol),
        source_port=src_port,
        destination_port=dst_port,
        alert=alert,
        attack_type=attack_type
    )

    db.add(new_packet)
    db.commit()
    db.close()


def start_sniffer():
    print("=" * 60)
    print("        NetSentinel AI Packet Sniffer")
    print("=" * 60)
    print("Listening for packets...\n")

    sniff(prn=process_packet, store=False)


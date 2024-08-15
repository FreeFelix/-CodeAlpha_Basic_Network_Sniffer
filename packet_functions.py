from scapy.all import sniff, wrpcap

# List to store captured packets
packets = []

def packet_callback(packet):
    """Handle and display captured packet details."""
    packets.append(packet)

    if packet.haslayer('Ether'):
        eth_layer = packet.getlayer('Ether')
        print(f"Ethernet Layer - Source MAC: {eth_layer.src}, Destination MAC: {eth_layer.dst}")

        if packet.haslayer('IP'):
            ip_layer = packet.getlayer('IP')
            print(f"IP Layer - Source: {ip_layer.src}, Destination: {ip_layer.dst}")

            if packet.haslayer('TCP'):
                tcp_layer = packet.getlayer('TCP')
                print(f"TCP Layer - Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")

            elif packet.haslayer('UDP'):
                udp_layer = packet.getlayer('UDP')
                print(f"UDP Layer - Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}")

            if packet.haslayer('DNS'):
                dns_layer = packet.getlayer('DNS')
                print(f"DNS Layer - Transaction ID: {dns_layer.id}")

            if packet.haslayer('ARP'):
                arp_layer = packet.getlayer('ARP')
                print(f"ARP Layer - Source IP: {arp_layer.psrc}, Target IP: {arp_layer.pdst}")

    print("-" * 40)

def packet_capture(selected_interface):
    """Start capturing packets on the selected interface."""
    try:
        print("Starting packet capture. Press Ctrl+C to stop.")
        sniff(iface=selected_interface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\nStopping packet capture.")
        wrpcap('captured_packets.pcap', packets)
        print(f"Captured packets saved to 'captured_packets.pcap'.")


from scapy.all import sniff, wrpcap, get_if_list, get_if_hwaddr

# List to store captured packets
packets = []

def packet_callback(packet):
    # Store the packet
    packets.append(packet)

    # Check if the packet has an Ethernet layer
    if packet.haslayer('Ether'):
        eth_layer = packet.getlayer('Ether')
        print(f"Ethernet Layer - Source MAC: {eth_layer.src}, Destination MAC: {eth_layer.dst}")

        # Check if the packet has an IP layer
        if packet.haslayer('IP'):
            ip_layer = packet.getlayer('IP')
            print(f"IP Layer - Source: {ip_layer.src}, Destination: {ip_layer.dst}")

            # Check if the packet has a TCP layer
            if packet.haslayer('TCP'):
                tcp_layer = packet.getlayer('TCP')
                print(f"TCP Layer - Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")

            # Check if the packet has a UDP layer
            elif packet.haslayer('UDP'):
                udp_layer = packet.getlayer('UDP')
                print(f"UDP Layer - Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}")

            # Check if the packet has a DNS layer
            if packet.haslayer('DNS'):
                dns_layer = packet.getlayer('DNS')
                print(f"DNS Layer - Transaction ID: {dns_layer.id}")

            # Check if the packet has an ARP layer
            if packet.haslayer('ARP'):
                arp_layer = packet.getlayer('ARP')
                print(f"ARP Layer - Source IP: {arp_layer.psrc}, Target IP: {arp_layer.pdst}")

    # Print a line to separate packets
    print("-" * 40)

def scan_interfaces():
    """Scan and display available network interfaces."""
    interfaces = get_if_list()
    print("Available network interfaces:")
    for idx, iface in enumerate(interfaces):
        mac_address = get_if_hwaddr(iface)
        print(f"{idx + 1}: {iface} (MAC: {mac_address})")
    
    return interfaces

def main():
    # Scan and display interfaces
    interfaces = scan_interfaces()
    
    # Ask the user to select an interface
    while True:
        try:
            choice = int(input("Select the interface to capture on (1, 2, ...): ")) - 1
            if 0 <= choice < len(interfaces):
                selected_interface = interfaces[choice]
                print(f"Selected interface: {selected_interface}")
                break
            else:
                print("Invalid choice. Please select a valid interface.")
        except ValueError:
            print("Please enter a number corresponding to the interface.")

    try:
        # Capture packets on the selected interface
        print("Starting packet capture. Press Ctrl+C to stop.")
        sniff(iface=selected_interface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        # Save captured packets to a file
        print("\nStopping packet capture.")
        wrpcap('captured_packets.pcap', packets)
        print(f"Captured packets saved to 'captured_packets.pcap'.")

if __name__ == "__main__":
    main()

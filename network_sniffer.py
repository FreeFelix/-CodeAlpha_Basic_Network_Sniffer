from scapy.all import sniff, wrpcap, get_if_list, get_if_hwaddr, IP, TCP, sr

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

def scan_interfaces():
    """Scan and display available network interfaces."""
    interfaces = get_if_list()
    print("Available network interfaces:")
    for idx, iface in enumerate(interfaces):
        mac_address = get_if_hwaddr(iface)
        print(f"{idx + 1}: {iface} (MAC: {mac_address})")
    
    return interfaces

def packet_interaction():
    """Send and receive packets with user input for destination."""
    dst = input("Enter the destination URL or IP: ").strip()
    print(f"Sending and receiving packets to {dst}...")

    ans, unans = sr(IP(dst=dst, ttl=(1,6))/TCP())
    print(f"Received {len(ans)} packets, got {len(ans)} answers, remaining {len(unans)} packets")
    ans.make_table(lambda s, r: (s.dst, s.ttl, r.src))

def packet_capture(selected_interface):
    """Start capturing packets on the selected interface."""
    try:
        print("Starting packet capture. Press Ctrl+C to stop.")
        sniff(iface=selected_interface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\nStopping packet capture.")
        wrpcap('captured_packets.pcap', packets)
        print(f"Captured packets saved to 'captured_packets.pcap'.")

def main():
    # Display menu options
    while True:
        print("\nSelect an option:")
        print("1. Scan and display available network interfaces")
        print("2. Start packet capture on a selected interface")
        print("3. Send and receive packets to a specified destination")
        print("4. Exit")

        choice = input("Enter your choice (1-4): ").strip()

        if choice == '1':
            interfaces = scan_interfaces()
        elif choice == '2':
            interfaces = scan_interfaces()
            if interfaces:
                while True:
                    try:
                        iface_choice = int(input("Select the interface to capture on (1, 2, ...): ")) - 1
                        if 0 <= iface_choice < len(interfaces):
                            selected_interface = interfaces[iface_choice]
                            print(f"Selected interface: {selected_interface}")
                            packet_capture(selected_interface)
                            break
                        else:
                            print("Invalid choice. Please select a valid interface.")
                    except ValueError:
                        print("Please enter a number corresponding to the interface.")
        elif choice == '3':
            packet_interaction()
        elif choice == '4':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()

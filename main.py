from packet_functions import packet_capture
from geoip_functions import set_geoip_db
from traceroute_functions import perform_traceroute, perform_traceroute_map

def scan_interfaces():
    """Scan and display available network interfaces."""
    from scapy.all import get_if_list, get_if_hwaddr
    interfaces = get_if_list()
    print("Available network interfaces:")
    for idx, iface in enumerate(interfaces):
        mac_address = get_if_hwaddr(iface)
        print(f"{idx + 1}: {iface} (MAC: {mac_address})")
    
    return interfaces

def packet_interaction():
    """Send and receive packets with user input for destination."""
    from scapy.all import sr, IP, TCP
    
    dst = input("Enter the destination URL or IP: ").strip()
    print(f"Sending and receiving packets to {dst}...")

    ans, unans = sr(IP(dst=dst, ttl=(1,6))/TCP())
    print(f"Received {len(ans)} packets, got {len(ans)} answers, remaining {len(unans)} packets")
    ans.make_table(lambda s, r: (s.dst, s.ttl, r.src))

def main():
    """Main function to run the network tool."""
    while True:
        print("\nSelect an option:")
        print("1. Scan and display available network interfaces")
        print("2. Start packet capture on a selected interface")
        print("3. Send and receive packets to a specified destination")
        print("4. Perform a traceroute to specified destinations")
        print("5. Perform a traceroute and display results on a map")
        print("6. Set GeoIP database path")
        print("7. Exit")

        choice = input("Enter your choice (1-7): ").strip()

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
            destinations = input("Enter destinations for traceroute (comma-separated): ").split(',')
            perform_traceroute([d.strip() for d in destinations])
        elif choice == '5':
            destinations = input("Enter destinations for traceroute map (comma-separated): ").split(',')
            perform_traceroute_map([d.strip() for d in destinations])
        elif choice == '6':
            geoip_path = input("Enter the path to the GeoIP database: ").strip()
            set_geoip_db(geoip_path)
        elif choice == '7':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()


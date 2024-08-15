from scapy.all import traceroute, traceroute_map

def perform_traceroute(destinations):
    """Perform a traceroute to the specified destinations."""
    a, unans = traceroute(destinations, verbose=0)
    print("Traceroute results:")
    a.show()

def perform_traceroute_map(destinations):
    """Perform a traceroute and display results on a map."""
    traceroute_map(destinations)


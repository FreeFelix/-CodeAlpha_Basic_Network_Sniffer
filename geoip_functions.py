from scapy.all import conf

def set_geoip_db(path):
    """Set the GeoIP database path."""
    conf.geoip_city = path
    print(f"GeoIP database set to {path}")


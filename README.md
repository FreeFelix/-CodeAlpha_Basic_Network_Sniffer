# CodeAlpha_Basic_Network_Sniffer
Build a network sniffer in Python that captures and analyzes network traffic.

Network Traffic Analysis Tool
This tool provides various functionalities for analyzing network traffic, including packet capture, interface scanning, packet interaction, and advanced features like GeoIP data integration and traceroute visualization.

Features
Scan and Display Available Network Interfaces
Start Packet Capture on a Selected Interface
Send and Receive Packets to a Specified Destination
Run Advanced Features (GeoIP, Traceroute, Multiple Interfaces)
Exit
Requirements
Python 3.x
Scapy
GeoIP Library (Optional for GeoIP features)
GeoLite2-City.mmdb file (for GeoIP features)
Installation
Clone the Repository:

Fig1

Install the Dependencies:

Fig2

Setup GeoIP (Optional):

Download the GeoLite2-City.mmdb file from the MaxMind website.
Update the path in advanced_features.py to point to the GeoLite2-City.mmdb file

Fig3

Usage
Run the main.py script to start the tool:

Fig4 

Menu Options
1. Scan and Display Available Network Interfaces
This option scans and lists all available network interfaces on your machine.

Example:

Fig5

2. Start Packet Capture on a Selected Interface
This option allows you to start capturing network packets on a selected interface.

Example:

Fig6

3. Send and Receive Packets to a Specified Destination
This option sends packets to a specified destination and receives responses. The destination can be an IP address or a URL.

Example:

Fig7

4. Run Advanced Features (GeoIP, Traceroute, Multiple Interfaces)
This option provides advanced features including GeoIP-based packet capture, traceroute visualization, and sniffing on multiple interfaces.

Example:

Fig8

5. Exit
This option exits the program.

Contributing
If you want to contribute to this project, feel free to fork the repository and submit a pull request with your changes.

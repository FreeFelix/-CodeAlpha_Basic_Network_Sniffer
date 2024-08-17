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

<img width="383" alt="fg1" src="https://github.com/user-attachments/assets/feae8d44-e60b-4a9e-81a9-af72d6de86dc">

Then make shell scripts an executable file using chmod u+x <file_name>

<img width="400" alt="image" src="https://github.com/user-attachments/assets/91493f6b-a572-4ecf-978e-5d38881af2d6">

And run it to install dependencies, ./<file_name>


Install the Dependencies:

<img width="383" alt="fig2" src="https://github.com/user-attachments/assets/4d9cbbc1-27c2-4cda-9c19-19fb2190e8dc">

Setup GeoIP (Optional):

Download the GeoLite2-City.mmdb file from the MaxMind website.
Update the path in advanced_features.py to point to the GeoLite2-City.mmdb file

<img width="401" alt="3" src="https://github.com/user-attachments/assets/0ab19bb9-b559-4882-a13a-2eb9d1146a8c">

Usage
Run the main.py script to start the tool:

<img width="401" alt="4" src="https://github.com/user-attachments/assets/b9b564af-ce03-4ae6-865a-80f64276993b">

Menu Options
1. Scan and Display Available Network Interfaces
This option scans and lists all available network interfaces on your machine.

Example:

<img width="401" alt="5" src="https://github.com/user-attachments/assets/24656de0-abd9-4fba-8094-25ef9bd28909">

2. Start Packet Capture on a Selected Interface
This option allows you to start capturing network packets on a selected interface.

Example:

<img width="400" alt="6" src="https://github.com/user-attachments/assets/b31e47a0-8be4-4bac-b236-ff37721e7df8">

3. Send and Receive Packets to a Specified Destination
This option sends packets to a specified destination and receives responses. The destination can be an IP address or a URL.

Example:

<img width="401" alt="7" src="https://github.com/user-attachments/assets/b3edc896-fdae-4647-8dbd-d05cb2b1073b">


4. Run Advanced Features (GeoIP, Traceroute, Multiple Interfaces)
This option provides advanced features including GeoIP-based packet capture, traceroute visualization, and sniffing on multiple interfaces.

5. Exit
This option exits the program.

Contributing
If you want to contribute to this project, feel free to fork the repository and submit a pull request with your changes.

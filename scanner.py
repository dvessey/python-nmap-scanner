import nmap
import json

scanner = nmap.PortScanner()

# Target IP or hostname
target = input("Enter IP address or host name:")

# Nmap flags
# -sS = TCP SYN scan (default scan)
# -sU = UDP scan [SLOW!]
# -O = OS detection
# -p- = Scan all ports (1-65535) [SLOW!]
#flags = "-sS -sU -O -p-"
flags = "-sS -O -p-"

# Run the scan
scanner.scan(target, arguments=flags)

total_devices = 0

inventory = {}

# Print the results of the scan
for host in scanner.all_hosts():
    total_devices += 1
    print("Host: ", host)
    print("State: ", scanner[host].state())
   
    inventory[host] = {'hostname': 'Not Found', 'state': scanner[host].state(), 'ports': {} }

    if 'osmatch' in scanner[host]:
        for  osmatch in scanner[host]['osmatch']:
            print("Host Operating System: {}".format(osmatch['name']))
           
            if 'osclass' in osmatch:
                for osclass in osmatch['osclass']:
                    print("Operating System Type: {}".format(osclass['type']))
                    print("Operating System Vendor: {}".format(osclass['vendor']))
                    print("Operating System Family: {}".format(osclass['osfamily']))
                    print("Operating System Generation: {}".format(osclass['osgen']))
                    print("Operating System Detection Accuracy: {}".format(osclass['accuracy']))
            
    for proto in scanner[host].all_protocols():
        print("Protocol: ", proto)
        inventory[host] = {'hostname': osmatch['name'], 'state': scanner[host].state(), 'type': osclass['type'], 
                           'protocol': proto, 'ports': {} }
        ports = scanner[host][proto].keys()
        for port in ports:
            print("Port: ", port, "State: ", scanner[host][proto][port]['state'])
            inventory[host]['ports'][port] = scanner[host][proto][port]['state']

print("Total Devices Scanned: ", total_devices)

print(inventory)

json_data = json.dumps(inventory, indent=4)

with open("hosts.json", "w") as outfile:
    outfile.write(json_data)
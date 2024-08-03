import nmap

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
    inventory["host {}".format(total_devices)] = host
    if 'osmatch' in scanner[host]:
        for  osmatch in scanner[host]['osmatch']:
            print("Host Operating System: {0}".format(osmatch['name']))
            inventory['host {} name'.format(total_devices)] = osmatch['name']
            
            if 'osclass' in osmatch:
                for osclass in osmatch['osclass']:
                    print("Operating System Type: {0}".format(osclass['type']))
                    print("Operating System Vendor: {0}".format(osclass['vendor']))
                    print("Operating System Family: {0}".format(osclass['osfamily']))
                    print("Operating System Generation: {0}".format(osclass['osgen']))
                    print("Operating System Detection Accuracy: {0}".format(osclass['accuracy']))
                    inventory["host {} type".format(total_devices)] = osclass['type']
                    inventory["host {} vendor".format(total_devices)] = osclass['vendor']
                    inventory["host {} osfamily".format(total_devices)] = osclass['osfamily']
                    inventory["host {} osgen".format(total_devices)] = osclass['osgen']
                    inventory["host {} accuracy".format(total_devices)] = osclass['accuracy']


    print("State: ", scanner[host].state())
    inventory["host {} state".format(total_devices)] = scanner[host].state()
 
    for proto in scanner[host].all_protocols():
        print("Protocol: ", proto)
        inventory["host {} protocol {}".format(total_devices, proto)] = proto
        ports = scanner[host][proto].keys()
        for port in ports:
            print("Port: ", port, "State: ", scanner[host][proto][port]['state'])
            inventory["host {} port {}".format(total_devices, port)] = port
            inventory["host {} port state {}".format(total_devices, port)] =  scanner[host][proto][port]['state']

print("Total Devices Scanned: ", total_devices)

print(inventory)

""" SAMPLE OUTPUT
{'host 1': '192.168.69.1', 'host 1 name': 'FreeBSD 11.2-RELEASE', 'host 1 type': 'general purpose', 'host 1 vendor': 'FreeBSD', 'host 1 osfamily': 'FreeBSD', 'host 1 osgen': '11.X', 'host 1 accuracy': '100', 
'host 1 state': 'up', 'host 1 protocol': 'tcp', 'host 1 port 22': 22, 'host 1 port state 22': 'open', 'host 1 port 53': 53, 'host 1 port state 53': 'open', 'host 1 port 80': 80, 'host 1 port state 80': 'open', 
'host 1 port 443': 443, 'host 1 port state 443': 'open', 

'host 2': '192.168.69.2', 'host 2 state': 'up', 

'host 3': '192.168.69.3', 'host 3 name': 'ZyXEL ZyWALL 2 Plus firewall', 'host 3 type': 'firewall', 'host 3 vendor': 'ZyXEL', 'host 3 osfamily': 'ZyNOS', 'host 3 osgen': None, 'host 3 accuracy': '88', 
'host 3 state': 'up', 'host 3 protocol': 'tcp', 'host 3 port 80': 80, 'host 3 port state 80': 'open', 

'host 4': '192.168.69.4', 'host 4 name': 'Microsoft Windows 10 1607', 'host 4 type': 'general purpose', 'host 4 vendor': 'Microsoft', 'host 4 osfamily': 'Windows', 'host 4 osgen': '10', 'host 4 accuracy': '100', 
'host 4 state': 'up', 'host 4 protocol': 'tcp', 'host 4 port 135': 135, 'host 4 port state 135': 'open', 'host 4 port 137': 137, 'host 4 port state 137': 'filtered', 
'host 4 port 139': 139, 'host 4 port state 139': 'open', 'host 4 port 445': 445, 'host 4 port state 445': 'open', 'host 4 port 1042': 1042, 'host 4 port state 1042': 'open', 
'host 4 port 1043': 1043, 'host 4 port state 1043': 'open', 'host 4 port 5040': 5040, 'host 4 port state 5040': 'open', 'host 4 port 5357': 5357, 'host 4 port state 5357': 'open', 
'host 4 port 5426': 5426, 'host 4 port state 5426': 'open', 'host 4 port 7680': 7680, 'host 4 port state 7680': 'open', 'host 4 port 9012': 9012, 'host 4 port state 9012': 'open', 
'host 4 port 9013': 9013, 'host 4 port state 9013': 'open', 'host 4 port 49664': 49664, 'host 4 port state 49664': 'open', 'host 4 port 49665': 49665, 'host 4 port state 49665': 'open', 
'host 4 port 49666': 49666, 'host 4 port state 49666': 'open', 'host 4 port 49667': 49667, 'host 4 port state 49667': 'open', 'host 4 port 49671': 49671, 'host 4 port state 49671': 'open', 
'host 4 port 49672': 49672, 'host 4 port state 49672': 'open', 'host 4 port 54235': 54235, 'host 4 port state 54235': 'open', 

'host 5': '192.168.69.69', 'host 5 name': 'Linux 4.15 - 5.6', 'host 5 type': 'general purpose', 'host 5 vendor': 'Linux', 'host 5 osfamily': 'Linux', 'host 5 osgen': '5.X', 'host 5 accuracy': '100', 
'host 5 state': 'up', 'host 5 protocol': 'tcp', 'host 5 port 22': 22, 'host 5 port state 22': 'open', 'host 5 port 514': 514, 'host 5 port state 514': 'open', 

'host 6': '192.168.69.8', 'host 6 state': 'up'}
"""
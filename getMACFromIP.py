import sys
from datetime import datetime
try:
    interface = raw_input("[*] Enter Desired Interface: ") #get interface to scan
    ips = raw_input("[*] Enter range of ips to scan for: ")
except KeyboardInterrupt:
    print "\n[*] User requested shutdown"
    print "[*] Quitting..."
    sys.exit(1)

print "\n[*] Scanning..."
start_time = datetime.now()

from scapy.layers.inet import *
from scapy.config import *
import scapy.route

conf.verb = 0 #actually start scanning
ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ips), timeout=2, iface=interface, inter=0.1)

print "MAC - IP\n"
for snd, rcv in ans:
    print rcv.sprintf(r"%Ether.src% - %ARP.psrc%")
stop_time = datetime.now()
total_time = stop_time - start_time
print "\n[*] Scan complete!"
print ("[*] Scan duration: %s" %(total_time))


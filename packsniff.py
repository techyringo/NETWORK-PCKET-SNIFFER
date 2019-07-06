import socket, sys
from struct import *
import time
import json

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error:
    print('Socket could not be created. Error Code : ')
    sys.exit()
print('"Source",'+  '"Destination",'+ '"Protocol"')
# receive a packet
jsonFile = open('test.json','w')
try:
    obj = {'links' : []}
    objHash = []
    while True:

        packet = s.recvfrom(65565)
        #packet string from tuple
        packet = packet[0]

        #parse ethernet header
        eth_length = 14

        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH' , eth_header)
        eth_protocol = socket.ntohs(eth[2])
        
        #Parse IP packets, IP Protocol number = 8
        if eth_protocol == 8 :
            ip_header = packet[eth_length:20+eth_length]

            iph = unpack('!BBHHHBBH4s4s' , ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF

            iph_length = ihl * 4

            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])
            addHash = str(s_addr) + str(d_addr)
            if addHash not in objHash:
                objHash.append(addHash)
                if len(obj['links']) < 10:
                    print('here')
                    obj['links'].append({'source' : str(s_addr),'target' : str(d_addr),'type': 'licensing'})
                else:
                    print('there')
                    obj['links'].pop(0)
                    jsonFile = open('test.json','w')
                    json.dump(obj, jsonFile, ensure_ascii=True, indent=2)
                    jsonFile.close()

            #TCP protocol
            if protocol == 6 :
                t = iph_length + eth_length
                tcp_header = packet[t:t+20]

                #now unpack them :)
                tcph = unpack('!HHLLBBHHH' , tcp_header)

                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4


                h_size = eth_length + iph_length + tcph_length * 4
                data_size = len(packet) - h_size

                #get data from the packet
                data = packet[h_size:]


            #ICMP Packets
            elif protocol == 1 :
                u = iph_length + eth_length
                icmph_length = 4
                icmp_header = packet[u:u+4]

                #now unpack them :)
                icmph = unpack('!BBH' , icmp_header)

                icmp_type = icmph[0]
                code = icmph[1]
                checksum = icmph[2]

                h_size = eth_length + iph_length + icmph_length
                data_size = len(packet) - h_size

                #get data from the packet
                data = packet[h_size:]

            #UDP packets
            elif protocol == 17 :
                u = iph_length + eth_length
                udph_length = 8
                udp_header = packet[u:u+8]

                #now unpack them :)
                udph = unpack('!HHHH' , udp_header)

                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                checksum = udph[3]

                h_size = eth_length + iph_length + udph_length
                data_size = len(packet) - h_size

                #get data from the packet
                data = packet[h_size:]

            print('"'+str(s_addr)+'",'+'"'+str(d_addr)+'",'+'"'+str(protocol)+'"')
               
except KeyboardInterrupt:
    print("Use Again")
    exit(0)
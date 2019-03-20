import socket
import struct

def parsing_ethernet_header(data):
    ethernet_header = struct.unpack("!6c6c2s" , data)
    ether_src = convert_ethernet_address(ethernet_header[0:6])
    ether_dest = convert_ethernet_address(ethernet_header[6:12])
    ip_header = "0x"+ethernet_header[12].hex()

    print("======ethernet header======")
    print("src_mac_address:", ether_src)
    print("dest_mac_address:", ether_dest)
    print("ip_version",ip_header)

def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append(i.hex())
    ethernet_addr = ":".join(ethernet_addr)
    return ethernet_addr

def parsing_ip_header(data):
    ip_header = struct.unpack("!1s1s2s2s2s1s1s2s4s4s", data) 
    ip_version =int(ip_header[0].hex(), 16)>>4
    ip_Length =int(ip_header[0].hex(), 16)&15  	
    ip_differentiated_service_codepoint = int(ip_header[1].hex(),16)>>4
    ip_explicit_congest_notification = int(ip_header[1].hex(),16)&15
    total_length = int(ip_header[2].hex(), 16)
    identification = int(ip_header[3].hex(), 16)
    flags = ip_header[4].hex()
    reserved_bit = int(ip_header[4].hex(), 16)
    not_fragments = int(ip_header[4].hex(), 16)
    fragments = int(ip_header[4].hex(), 16)
    fragments_offset =(ip_header[4].hex(), 16)
    Time_to_live = int(ip_header[5].hex(), 16)
    protocol = int(ip_header[6].hex(), 16)
    header_checksum = ip_header[7].hex()
    source_ip_addreses =convert_ethernet_address(ip_header[26:30])
    dest_ip_address = convert_ethernet_address(ip_header[30:34])
   
    print("======ip_header======")
    print("ip_header :", ip_version)
    print("ip_Length :", ip_Length)
    print("ip_differentiated_service_codepoint :", ip_differentiated_service_codepoint)
#    print("explicit_congestion_service_codepoint :", explicit_congestion_service_codepoint)
    print("total_length :", total_length)
    print("identification :", identification)
    print("flags :", flags)
    print(">>>reserved_bit :", reserved_bit)
    print(">>>not_fragments :", not_fragments)	
    print(">>>fragments :" , fragments)
    print(">>>fragments_offset :", fragments_offset)
    print("Time to live :", Time_to_live)
    print("protocol :", protocol)
    print("header checksum :", header_checksum)
    print("source_ip_addreses :", source_ip_addreses)
    print("dest_ip_address :", dest_ip_address)

def parsing_udp_header(data):
 udp_header = struct.unpack("!2s2s2s2s", data)
 print("=====udp header=====")
 print("source_port :", int(udp_header[0].hex(), 16))
 print("destination_port :", int(udp_header[1].hex(), 16))
 print("length :", int(udp_header[2].hex(), 16))
 print("checksum :", int(udp_header[3].hex(), 16))

recv_socket = socket.socket(socket.AF_PACKET,socket.SOCK_RAW, socket.ntohs(0x800))
    
while True:
    data = recv_socket.recvfrom(20000)
    parsing_ethernet_header(data[0][0:14])
    parsing_ip_header(data[0][14:34])
    parsing_udp_header(data[0][34:42])	
    
    break
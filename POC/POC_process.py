from scapy.all import*
import sys
from threading import Thread
import os

if len(sys.argv) > 1:
    print(sys.argv)
    ip_src = sys.argv[1]
    mac_src = sys.argv[2]
    router_ip = sys.argv[3]
else:
    print("no args")
arp_table = [] # list of tuples (ip,mac)

def send_recieve():
    """
    sniffing packets and sending packets required
    """
    sniff_thread = Thread(target=sniff_packet)
    sniff_thread.daemon = True
    sniff_thread.start()

    while 1:
        # the loop that runs the process, it sniffs and answer according to the packet
        if os.path.exists("req.txt"):
            f = open("req.txt","r+")
            file = f.readlines()
            for line in file:
                if ip_src+":" in line:
                    file.remove(line)
                    pack= line.split(":")[1].split("|")
                    if "SENDTCP" in pack:
                        send_TCP(pack[1], pack[2])
                    elif "SENDPING" in pack:
                        send_PING(pack[1])
                    elif "EXIT__" in pack:
                        f.seek(0)
                        for lin in file:
                            f.write(lin)
                        f.close()
                        print(f"goodbye {ip_src}, and thanks for the fish!")
                        sys.exit()
            f.seek(0)
            for lin in file:
                f.write(lin)
            f.close()
        #packet = sniff(count=1,filter=f"dst host {ip_src}")
        #packet_type = packet.summary().split(" ")[4]

def sniff_packet():
    """

    :return:
    """
    while 1:
        packet = sniff(count=1,filter=f"dst host {ip_src}")
        print(packet.summary())
        packet_type = packet.summary().split(" ")[4]
        if packet_type == "TCP":
            print((packet.load).decode())



def send_TCP(dst_ip,payload):
    """
    sending TCP msg with given payload.
    :param dst_ip: the dst ip to send to
    :param payload: the given payload
    """
    packet = Ether(src=mac_src)/IP(src=ip_src,dst=dst_ip)/TCP()/payload
    send(packet)

def send_PING(dst_ip):
    """
    send ping msg.
    :param dst_ip: the dst ip to send to
    """
    packet = Ether(src=mac_src)/IP(src=ip_src,dst= dst_ip)/ICMP()
    print(sr1(packet).summary() + "\n got it!")

send_recieve()
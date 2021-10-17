from scapy.all import*
import sys

if len(sys.argv) > 1:
    print(sys.argv)
    ip_src = sys.argv[1]
    mac_src = sys.argv[2]
    router_ip = sys.argv[3]
else:
    print("no args")

def sniff_ip():
    """
    sniffing packets and sending packets required
    """
    while 1:
        # the loop that runs the process, it sniffs and answer acording to the packet
        packet = sniff(count=1,filter=f"dst host {ip_src}")
        packet_type = packet.summary().split(" ")[4]
        if packet_type == "TCP":

            data = (packet.load).decode()
            print(data)
            if data == "EXIT_PR":
                sys.exit()
            if "SENDTCP" in data:
                data = data.split("|")
                send_TCP(data[1],data[2],data[3])

        elif packet_type == "ICMP":
            # send ping
            send_PING(packet.src,packet.getlayer(IP).src)


def send_TCP(dst_mac, dst_ip,payload):
    """
    sending TCP msg with given payload.
    :param dst_mac: the dst mac to send to
    :param dst_ip: the dst ip to send to
    :param payload: the given payload
    """
    packet = Ether(src=mac_src, dst=dst_mac)/IP(src=ip_src,dst=dst_ip)/TCP()/payload
    send(packet)

def send_PING(dst_mac,dst_ip):
    """
    send ping msg.
    :param dst_mac: the dst mac to send to
    :param dst_ip: the dst ip to send to
    """
    packet = Ether(src=mac_src,dst=dst_mac)/IP(src=ip_src,dst= dst_ip)/ICMP()
    send(packet)

sniff_ip()

import pydivert
import scapy.all as sc
from socket import socket, AF_INET, SOCK_STREAM
import json
import subprocess
from threading import Thread
import os
from multiprocessing import Process
import random
import sys
# vars for communication with host
msg = ""
PORT = 55555
HOST = "172.16.8.181"
ADDR = (HOST, PORT)

# vars for communicaition inside the LAN

process_manager = {}
router_ip = "10.0.0.1"

computers = {}  # {ip:mac}

router_table = {}  # {ip:(mask,interface)}


def arp_request(mac):
    """
    send arp request for ip with mac
    :return: 
    """
    global router_table


def run_command(cmd):
    """
    execute command line in the cmd and return it's output
    :param cmd:a string command line to execute in the cmd
    :return: byte array contains the output in the cmd
    """
    return subprocess.Popen(cmd,
                            shell=False,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE).communicate()


def run_process_event(dir):
    """
    runs process thread.
    :param dir:
    :return:
    """
    print("bay")
    os.system(dir)  # subprocess
    print("s")


def create_new_process(msg):
    """
    create new process
    :param msg: the command from server
    """
    global computers, process_manager
    ip = msg.split("_")[1]
    mac = msg.split("_")[2]
    computers.update({ip: mac})
    dir = fr"python C:\Users\u101040.DESHALIT\Desktop\POC\POC_process.py {ip} {mac} {router_ip}"

    process_manager[ip] = Thread(target=run_process_event, args=(dir,))
    process_manager[ip].demone = True
    process_manager[ip].start()
    print("f")


def modify_rout(msg):
    """
    modify routing table of an router.
    :param msg:
    """
    global router_table
    router_table.update(
        {msg.split("_")[1].split(",")[0]: (int(msg.split("_")[1].split(",")[1]), msg.split("_")[1].split(",")[2])})


def delete_process(msg):
    """
    create new process
    :param msg: the command from server
    """
    global computers, process_manager
    ip = msg.split("_")[1]
    computers.pop(ip)
    f = open("req.text", "a")
    f.write(f"{ip}:EXIT__")  # src dst payload
    f.close()


def check_rout(dst):
    """

    :param dst:
    :return:
    """
    global router_table
    for ip, tup in router_table:
        if ip.split(".")[0] == dst.split(".")[0] and ip.split(".")[1] == dst.split(".")[1]:
            return tup[1]


def send_tcp(msg):
    """
    send tcp packet from one of the processes
    :param msg: command from the server.
    """
    data = msg.split("_")
    f = open("req.txt", "a")
    f.write(f"{data[1]}:SENDTCP|{data[2]}|{data[3]}\n")  # src dst payload
    f.close()
    # sc.send(sc.Ether(dst=computers[data[1]][1]) / sc.IP(
    #    dst=computers[data[1]][0]) / sc.TCP() / f"SENDTCP|{computers[data[2]]}|{computers[data[2]]}|{data[3]}")
    packet = sc.sniff(count=1, filter=f"src host {data[1]} and tcp")
    print(packet[0].summary())
    #data = (packet[0].load).decode()
    #print(check_rout(data[2]))
    sc.send(
        sc.IP(dst=router_table[data[2]][1]) / sc.TCP() / f"TCP|{packet[0][sc.IP].src}|{packet[0][sc.IP].dst}|{(packet[0].load).decode()}")


def send_ping(msg):
    """
    send ping packet from one of the processes.
    :param msg: command from the server.
    """
    data = msg.split("_")
    f = open("req.text", "a")
    f.write(f"{data[1]}:SENDPING|{data[2]}\n")
    f.close()
    packet = sc.sniff(count=1, filter=f"src host {data[1]} and ICMP")
    print(packet)
    sc.send(
        sc.IP(dst=check_rout(data[1])) / sc.TCP() / f"ICMP|{packet[0][sc.IP].src}|{packet[0][sc.IP].dst}")


def sniff_packet():
    """

    :return:
    """
    while 1:
        packet = sc.sniff(count=1, filter=f"dst host {sc.get_if_addr(sc.conf.iface)}")
        try:

            packet = packet[0].load.decode().split("|")
        except Exception as e:
            continue
        else:
            packet_type = packet[0]
            if packet_type == "TCP":
                sc.send(sc.IP(src=packet[1], dst=packet[2], ttl=127) / sc.TCP() / packet[3])
            elif packet_type == "ICMP":
                sc.send(sc.IP(src=packet[1], dst=packet[2], ttl=127) / sc.ICMP())




def receive():
    global msg
    """Handles receiving of messages."""
    sniff_tread = Thread(target=sniff_packet)
    sniff_tread.daemon = True
    sniff_tread.start()
    while True:
        # receiving messages
        try:
            msg = client_socket.recv(1024).decode("utf8")
            print(msg)

            if "new" in msg:
                print("hello")
                create_new_process(msg)

            if "del" in msg:
                delete_process(msg)

            if "tcp" in msg:
                send_tcp(msg)

            if "ping" in msg:
                send_ping(msg)

            if "routadd" in msg:
                modify_rout(msg)





        except OSError:
            # Possibly client has left the chat
            client_socket.close()


# def catch_packets(filter):
# with pyd.WinDivert(filter) as w:
# for packet in w:
# w.send(packet)


client_socket = socket(AF_INET, SOCK_STREAM)

while 1:
    # makes sure that client waits for connection
    try:
        client_socket.connect(ADDR)
        print(msg)
        print("true")
        break
    except (ConnectionRefusedError, TimeoutError):
        continue

receive()

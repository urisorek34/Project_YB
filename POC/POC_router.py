import pydivert as pyd
import scapy.all as sc
from socket import socket, AF_INET, SOCK_STREAM
import json
import subprocess
from threading import Thread

# vars for communication with host
msg = ""
PORT = 55555
HOST = "127.0.0.1"
ADDR = (HOST, PORT)

# vars for communicaition inside the LAN
computers = {}  # name:(ip,mac)
router_ip = sc.get_if_addr(sc.conf.iface)  # Get computer's ip
available_ip = ["10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9",
                "10.0.0.10"]  # dhcp
available_mac = ["98-CD-5D-A4-3F-86", "55-A9-88-92-4E-91", "73-AB-1E-8A-B6-9B", "4D-43-62-23-80-76",
                 "9E-B7-16-F5-15-1D", "81-6B-00-82-58-BC", "23-AE-FE-B2-FE-20", "4F-CD-29-B2-3B-3F",
                 "E2-09-65-93-AA-DE", "8C-E7-00-B8-42-B0"] # macs address


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


def create_new_process(msg):
    """
    create new process
    :param msg: the command from server
    """
    global computers, available_ip
    name = msg.split("_")[1]
    computers.update({name: (available_ip.pop(0), available_mac.pop(0))})
    print("bay")
    run_command(
        fr"cd C:\Users\admin\Documents\Uri\Project_YB\POC>python POC_process.py {computers[name][0]} {computers[name][1]} {router_ip}")
    print("s")


def delete_process(msg):
    """
    create new process
    :param msg: the command from server
    """
    global computers, available_ip
    name = msg.split("_")[1]
    sc.send(sc.Ether(dst=computers[name][1]) / IP(dst=computers[name][1]) / TCP() / "EXIT_PR")
    available_ip.append(computers[name][0])
    available_mac.append(computers[name][1])
    computers.pop(name)
    sc.send(sc.Ether(m))

def send_tcp(msg):
    """
    
    :param msg: 
    :return: 
    """
    global computers
    data = msg.split("_")
    
    sc.send(sc.Ether(dst=computers[data[1]][1])/sc.IP(dst=computers[data[1]][0])/sc.TCP()/f"SENDTCP|{computers[data[2]][1]}|{computers[data[2]][0]}|{data[3]}")


def receive():
    global msg
    """Handles receiving of messages."""
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



        except OSError:
            # Possibly client has left the chat
            client_socket.close()


#def catch_packets(filter):
    #with pyd.WinDivert(filter) as w:
        #for packet in w:
            #w.send(packet)


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

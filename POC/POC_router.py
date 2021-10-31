import pydivert as pyd
import scapy.all as sc
from socket import socket, AF_INET, SOCK_STREAM
import json
import subprocess
from threading import Thread
import os
from multiprocessing import Process
import random

# vars for communication with host
msg = ""
PORT = 55555
HOST = "127.0.0.1"
ADDR = (HOST, PORT)

# vars for communicaition inside the LAN

process_manager = {}
router_ip = "10.0.0.1"

computers = {}  # {ip:mac}


router_table = [] #(ip,mask)


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
    global computers,process_manager
    ip = msg.split("_")[1]
    mac = msg.split("_")[2]
    computers.update({ip:mac})
    dir = fr"python C:\Users\admin\Documents\Uri\Project_YB\POC\POC_process.py {ip} {mac} {router_ip}"

    process_manager[ip] = Thread(target=run_process_event,args=(dir, ))
    process_manager[ip].demone = True
    process_manager[ip].start()
    print("f")



def modify_rout(msg):
    """
    modify routing table of an router.
    :param msg:
    """
    global router_table
    router_table.append((msg.split("_")[1].split(",")[0],int(msg.split("_")[1].split(",")[1])))


def delete_process(msg):
    """
    create new process
    :param msg: the command from server
    """
    global computers, process_manager
    ip = msg.split("_")[1]
    computers.pop(ip)
    process_manager[ip].terminate()


def send_tcp(msg):
    """
    
    :param msg: 
    :return: 
    """
    global computers
    data = msg.split("_")

    sc.send(sc.Ether(dst=computers[data[1]][1]) / sc.IP(
        dst=computers[data[1]][0]) / sc.TCP() / f"SENDTCP|{computers[data[2]][1]}|{computers[data[2]][0]}|{data[3]}")
    packet = sniff(count=1, filter=f"src host {computers[data[2]][1]}")
    data = (packet.load).decode()


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

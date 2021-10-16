import pydivert as pyd
import scapy.all as sc
from socket import socket, AF_INET, SOCK_STREAM
import json
from threading import Thread

# vars for communication with host
msg = ""
PORT = 55555
HOST = "127.0.0.1"
ADDR = (HOST, PORT)


# vars for communicaition inside the LAN
computers = {}
router_ip = sc.get_if_addr(sc.conf.iface)  # Get computer's ip
available_ip = ["10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9",
                "10.0.0.10"]






def create_new_process(msg):
    """

    :param msg:
    :return:
    """
    global computers,available_ip
    name = msg.split("_")[1]
    computers.update({name:available_ip.pop(0)})


def delete_process(msg):
    """

    :param msg:
    :return:
    """
    global computers, available_ip
    name = msg.split("_")[1]
    available_ip.append(computers[name])
    computers.pop(name)





def receive():
    global msg
    """Handles receiving of messages."""
    while True:
        # receiving messages
        try:
            msg = client_socket.recv(1024).decode("utf8")

            if "new" in msg:
                create_new_process(msg)

            if "del" in msg:
                delete_process(msg)



        except OSError:  # Possibly client has left the chat.
            client_socket.close()


def catch_packets(filter):
    with pyd.WinDivert(filter) as w:
        for packet in w:
            w.send(packet)


client_socket = socket(AF_INET, SOCK_STREAM)

while 1:
    # makes sure that client waits for connection
    try:
        client_socket.connect(ADDR)
        print(msg)
        break
    except (ConnectionRefusedError, TimeoutError):
        continue

receive_thread = Thread(target=receive)
receive_thread.daemon = True  # stop execution of thread when code is stopped (when mainloop is closed by destroy())
receive_thread.start()

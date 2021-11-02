import socket
import json
from select import select
from threading import Thread
import random

computers_connected = {}  # addr:sock
sub_comp = {}  # addr:[ips]
myHost = ""
myPort = 55555
portsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create socketTCP
command = ""
comm_addr = ""
available_ip = ["10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9",
                "10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14", "10.0.0.16"]  # dhcp

available_ip1 = ["192.168.0.2", "192.168.0.3", "192.168.0.4", "192.168.0.5", "192.168.0.6", "192.168.0.7",
                 "192.168.0.8", "192.168.0.9", "192.168.0.10", "192.168.0.11", "192.168.0.12", "192.168.0.13",
                 "192.168.0.14", "192.168.0.16"]  # dhcp
available_ip_comp = {}  # {router address :available ip}
routing_tables = {}  # address:[(ip,subnet mask)]
check = True


def mac_generator():
    """

    :return:
    """
    mac = ""
    for i in range(6):
        hx = hex(random.randint(0, 256))[2:]
        if len(hx) == 1:
            hx = "0" + hx
        mac += hx + "-"

    return mac[:-1]


def input_user():
    """
    temporary. gets commands from user and sand to the relevant computers the command.
    runs in other thread.
    :return:
    """
    global command, comm_addr, sub_comp
    while 1:
        # gets input of ip addr and command you want to execute on the LAN/computer
        print(f"ip option's: {computers_connected.keys()}")
        comm_addr = input("ip of the router/computer --> ")
        if comm_addr in computers_connected.keys():
            print(
                "command options --> new ,del (process ip), comp, rout, done,tcp (src,dst,msg),ping (src,dst), routadd (ip,subnetmask), seerout")
            command = input("the command you want to sand --> ")

            if command not in ["new", "del", "comp", "rout", "done", "tcp", "ping", "routadd"]:
                print("Wrong command :(")
                command = ""

            if command == "new":
                # new computer
                addr = available_ip_comp[comm_addr].pop(0)
                command = f"new_{addr}_{mac_generator()}"
                sub_comp[comm_addr].append(addr)

            if command == "del":
                # delete computer
                print(f"delete options ---> {sub_comp[comm_addr]}")
                ip_proc = input("ip of the process --> ")
                while ip_proc not in sub_comp[comm_addr]:
                    ip_proc = input("ip doesn't exist, try again --> ")
                command = f"del_{ip_proc}"
                available_ip_comp[comm_addr].append(ip_proc)
                sub_comp[comm_addr].remove(ip_proc)

            if command == "comp":
                # show all the computers in all the networks
                count = 0
                for sub in sub_comp:
                    print(f"{sub} --> {len(sub_comp[sub])}")
                    count += len(sub_comp[sub])
                    print(f"Total of {count} computers")

            if command == "rout":
                # show all the routers in all the networks
                count = len(computers_connected)
                for comp in computers_connected:
                    print(comp)
                    print(f"Total of {count} routers")

            if command == "ping":
                # ping msg
                print(f"src options : {sub_comp[comm_addr]}")
                src = input("source (ip) --> ")
                while src not in sub_comp[comm_addr]:
                    src = input("ip doesn't exist, try again --> ")
                # print dst options
                print(f"destination options:")
                [print(sub_comp[ip]) for ip in sub_comp]

                dst = input("destination (ip) --> ")
                for ip, ips in sub_comp.items():
                    if dst not in ips and dst in sub_comp.keys():
                        command = f"ping_{src}_{dst}"
                        break
                if command == "ping":
                    print("not right destination")

            if command == "tcp":
                # tcp msg
                print(f"src options : {sub_comp[comm_addr]}")
                src = input("source (ip) --> ")
                while src not in sub_comp[comm_addr]:
                    src = input("ip doesn't exist, try again --> ")
                # print dst options
                print(f"destination options:")
                [print(sub_comp[ip]) for ip in sub_comp]

                dst = input("destination (ip) --> ")
                #for ip, ips in sub_comp.items():
                #    if dst not in ips and dst in sub_comp.keys():
                #        msg = input("data --> ")
                #        command = f"tcp_{src}_{dst}_{msg}"
                #        break
                #if command == "tcp":
                #    print("not right destination")
                msg = input("data --> ")
                command = f"tcp_{src}_{dst}_{msg}"

            if command == "routadd":
                # add line in the routing table
                print(f"route options : {computers_connected.keys()}")
                add = input("enter 'destination,subnet mask,interface' --> ")
                routing_tables[comm_addr].append((add.split(",")[0], add.split(",")[1], add.split(",")[2]))
                command = f"routadd_{add}"

            if command == "seerout":
                print(routing_tables)

            computers_connected[comm_addr].send(command.encode())  # sends the relevant command


        else:
            print("Wrong address :(")
            comm_addr = ""


def find_key_by_value(dct, value):
    """

    :param dct: dictionary
    :param value: value that you want to find inside dct
    :return: the key of the value
    """
    for key, val in dct.items():
        if val == value:
            return key


def sock():
    """
    the main function, handles all the sockets.
    :return: True to get out.
    """
    # Create Sockets
    global command, comm_addr, computers_connected, check
    mainsocks, readsocks, writesocks = [], [], []

    portsock.bind((myHost, myPort))
    portsock.listen(5)  # no more than 5 outstanding requests
    mainsocks.append(portsock)
    END = False  # the END flag

    readsocks += mainsocks
    while True:

        # creates a new folders for the pictures if not exist
        readables, writeables, exceptions = select(readsocks, readsocks, [],
                                                   0)  # select --> only readables and writeables

        for sockobj in readables:
            if sockobj in mainsocks:
                # accept new clients to the server
                newsock, address = sockobj.accept()
                computers_connected.update({address[0]: newsock})
                if check:
                    available_ip_comp.update({address[0]: available_ip})
                    check = False
                else:
                    available_ip_comp.update({address[0]: available_ip1})
                    check = True

                sub_comp.update({address[0]: []})
                routing_tables[address[0]] = []
                newsock.send(f"Hello {address} welcome to Uri's Packet Tracer!".encode())
                readsocks.append(newsock)

            else:
                try:
                    data = sockobj.recv(1024)

                except ConnectionAbortedError:
                    continue
                except ConnectionResetError:
                    # a client left
                    print("server state: Sad :(\nReason: because client left :(")
                    sockobj.close()
                    # delete the computer from the list

                    addre_sub = find_key_by_value(computers_connected, sockobj)
                    computers_connected.pop(addre_sub)
                    sub_comp.pop(addre_sub)
                    readsocks.remove(sockobj)
                    continue

                if command != "" and computers_connected[comm_addr] == sockobj:
                    # commands for the computers
                    sockobj.send(command.encode())


                else:
                    for socket in writeables:
                        # broadcasts (echo) all the messages to everyone.
                        socket.send(data)


input_thread = Thread(target=input_user)
input_thread.daemon = True  # stop execution of thread when code is stopped (when mainloop is closed by destroy())
input_thread.start()

sock()

portsock.close()  # close the server socket

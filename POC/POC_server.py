import socket
import json
from select import select
from threading import Thread

computers_connected = {}  # addr:sock
sub_comp = {}  # addr:name
myHost = ""
myPort = 55555
portsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create socketTCP
command = ""
comm_addr = ""


def input_user():
    """
    temporary. gets commands from user and sand to the relevant computers the command.
    runs in other thread.
    :return:
    """
    global command, comm_addr, sub_comp
    while 1:
        # gets input of ip addr and command you want to execute on the LAN/computer
        print(f"name of ip option's: {computers_connected.keys()}")
        comm_addr = input("ip of the router/computer --> ")
        if comm_addr in computers_connected.keys():
            print(
                "command options --> new (process name),del (process name), comp, rout, done,tcp (src,dst,msg),ping (src,dst), routmodify (ip,subnetmask)")
            command = input("the command you want to sand --> ")

            if command not in ["new", "del", "comp", "rout", "done", "tcp", "ping", "routmodify"]:
                print("Wrong command :(")
                command = ""

            if command == "new":
                # new computer
                name = input("name of the process --> ")
                while name in sub_comp[comm_addr]:
                    name = input("Name already exist, try again --> ")
                command = f"new_{name}"
                sub_comp[comm_addr].append(name)

            if command == "del":
                # delete computer
                name = input("name of the process --> ")
                while name not in sub_comp[comm_addr]:
                    name = input("Name doesn't exist, try again --> ")
                command = f"del_{name}"
                sub_comp[comm_addr].remove(name)

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

            if command == "tcp":
                # tcp msg
                print(f"src options : {sub_comp[comm_addr]}")
                src = input("source (name) --> ")
                while src not in sub_comp[comm_addr]:
                    src = input("Name doesn't exist, try again --> ")
                # print dst options
                print(f"destination options:")
                [print(sub_comp[ip]) for ip in sub_comp]
            
                dst = input("destination (name) --> ")
                for ip, name in sub_comp.items():
                    if name != dst and dst in sub_comp.keys():
                        msg = input("data --> ")
                        command = f"tcp_{src}_{dst}_{msg}"
                        break
                if command == "tcp":
                    print("not right destination")
                
            
            if command == "routmodify":
                print(f"route options : {computers_connected.keys()}")
                add = input("enter 'ip,subnet mask'")
                command = f"routmodify_[{add}]"

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
    global command, comm_addr, computers_connected
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
                print(computers_connected)
                sub_comp.update({address[0]: []})
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

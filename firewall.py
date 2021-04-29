import socket, select, json, time, os, queue as Queue
import firewall_utils as utils
from cipher import Cipher
#from colorama import Fore, Style
from getpass import getpass

class Firewall:
    def __init__(self, int_interface, ext_interface, rule_file, password):
        self.password = password
        self.rule_file = rule_file
        self.cipher = Cipher(password)
        self.int_interface = int_interface
        self.ext_interface = ext_interface
        self.int_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.ext_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.lp_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        
        try:
            self.int_socket.setblocking(0)
            self.ext_socket.setblocking(0)
            self.lp_socket.setblocking(0)
            self.int_socket.bind((self.int_interface, 0))
            self.ext_socket.bind((self.ext_interface, 0))
            self.lp_socket.bind(('lo',5430))
            self.sockets = [self.int_socket, self.ext_socket, self.lp_socket]
            self.output_queues = {
                self.int_socket : Queue.Queue(),
                self.ext_socket : Queue.Queue()
            }
            self.output_list = []
            self.int_rules, self.ext_rules, _, _ = utils.load_rules(self.rule_file)       
            self.start_firewall()

        except Exception as e:
            self.int_socket.close()
            self.ext_socket.close()
            self.lp_socket.close()
            print("")
            print("Exception occurred! ", e)
            print("Aborting!")

    def start_firewall(self):
        while True:
            try:
                readable, writable, exceptional = select.select(self.sockets, self.output_list, self.sockets)
                for s in readable:
                    raw_packet = s.recv(2048)
                    recv_time = time.time()
                    if s is self.lp_socket:
                        if utils.is_admin_packet(raw_packet): 
                            rule_payload = utils.get_rule_payload(raw_packet)
                            if rule_payload != "" and ("RULE_FILE:" in rule_payload):
                                self.rule_file = rule_payload[10:]
                                self.load_rules(self.rule_file)
                    elif s is self.int_socket:
                        packet_details = utils.get_packet_details(raw_packet)
                        if utils.verify_packet(packet_details, self.int_rules):
                            self.output_queues[self.ext_socket].put(raw_packet)
                            if self.ext_socket not in self.output_list:
                                self.output_list.append(self.ext_socket)
                        else: 
                            print("Packet dropped.")
                            print(packet_details)
                    else:
                        packet_details = utils.get_packet_details(raw_packet)
                        if utils.verify_packet(packet_details, self.ext_rules):
                            self.output_queues[self.int_socket].put(raw_packet)
                            if self.int_socket not in self.output_list:
                                self.output_list.append(self.int_socket)
                        else: 
                            print("Packet dropped.")
                            print(packet_details)
                for s in writable:
                    try:
                        next_msg = self.output_queues[s].get_nowait()
                    except Queue.Empty:
                        self.output_list.remove(s)
                    else:
                        s.send(next_msg)
                for s in exceptional:
                    current_interface = self.int_interface
                    if s is self.ext_socket:
                        current_interface = self.ext_interface
                    print("An exception occurred in the interface,",current_interface)
                    break
            except KeyboardInterrupt:       
                print("")
                abort_conf = input("Keyboard interrupt! Abort firewall? [Y/N]: ")
                if abort_conf == "Y":
                    abort_pswd = getpass(prompt="Please enter the firewall authentication password: ")
                    if abort_pswd == self.password:
                        self.int_socket.close()
                        self.ext_socket.close()
                        self.lp_socket.close()
                        print("Password match! Aborting!")
                        break
                    else:
                        print("Invalid password! cancelling abort!")
                        pass
                else:
                    pass

    
    


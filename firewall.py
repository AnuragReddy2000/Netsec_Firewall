import socket, select, json, time, queue as Queue
import firewall_utils as utils
from cipher import Cipher
from colorama import Fore, Style

class Firewall:
    def __init__(self, int_iterface, ext_interface, password):
        self.password = password
        self.cipher = Cipher(password)
        self.int_interface = int_interface
        self.ext_interface = ext_interface
        self.int_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.ext_socket= socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.int_socket.bind((self.int_interface, 0))
        self.ext_socket.bind((self.ext_interface, 0))
        self.sockets = [self.int_socket, self.ext_socket]
        self.output_queues = {
            self.int_socket : Queue.Queue(),
            self.ext_socket : Queue.Queue()
        }
        self.output_list = []
        self.load_rules()
        self.start_firewall()

    def start_firewall(self):
        while True:
            readable, writable, exceptional = select.select(self.sockets, self.output_list, self.sockets)
            for s in readable:
                raw_packet = s.recv(2048)
                recv_time = time.time()
                if s is self.int_socket:
                    if self.is_admin_packet(raw_packet): 
                        rule_payload = self.get_rule_payload(raw_packet)
                        if rule_payload != "":
                            # reload rules
                    else:
                        packet_details = utils.get_packet_details(raw_packet)
                        if utils.verify_packet(packet_details, self.int_rules):
                            self.output_queues[self.ext_socket].put(raw_packet)
                            if self.ext_socket not in self.output_list:
                                self.output_list.append(self.ext_socket)
                        else: 
                            # drop packet
                else:
                    packet_details = utils.get_packet_details(raw_packet)
                    if utils.verify_packet(packet_details, self.ext_rules):
                        self.output_queues[self.int_socket].put(raw_packet)
                        if self.int_socket not in self.output_list:
                            self.output_list.append(self.int_socket)
                    else: 
                        # drop packet
            for s in writable:
                try:
                    next_msg = self.message_queues[s].get_nowait()
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

    def is_admin_packet(self, packet):
        packet_data = packet.decode('UTF-8')
        if packet_data[:12] == 'UPDATE_RULES':
            return True
        else:
            return False
    
    def get_rule_payload(self, packet):
        packet_data = packet.decode('UTF-8')[12:]
        return self.cipher.decrypt(packet_data)

    def load_rules(self):
        with open('rules.json', 'r', os.O_NONBLOCK) as rules_file:
            rules_data = json.load(rules_file)
            self.int_rules = rules_data['outgoing']
            self.ext_rules = rules_data['incoming']


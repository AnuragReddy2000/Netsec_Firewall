import socket, select, queue as Queue
import firewall_utils as utils

class Firewall:
    def __init__(self, int_iterface, ext_interface, password):
        self.password = password
        self.int_interface = int_interface
        self.ext_interface = ext_interface
        self.int_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.ext_socket= socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.int_socket.bind((self.int_interface, 0))
        self.ext_socket.bind((self.ext_interface, 0))
        self.sockets = [self.int_socket, self.ext_socket]
        self.output_queues = {}
        self.output_queues[self.int_socket] = Queue.Queue()
        self.output_queues[self.ext_socket] = Queue.Queue()
        self.output_list = []
        self.start_firewall()

    def start_firewall(self):
        while True:
            readable, writable, exceptional = select.select(self.sockets, self.output_list, self.sockets)
            for s in readable:
                raw_packet = s.recv(2048)
                if s is self.int_socket:
                    if utils.is_admin_packet(raw_packet): 
                        # handle new rule
                    else:
                        packet_details = utils.get_packet_details(raw_packet)
                        if True: # firewall check on the packet
                            self.output_queues[self.ext_socket].put(raw_packet)
                            if self.ext_socket not in self.output_list:
                                self.output_list.append(self.ext_socket)
                        else: 
                            # drop packet
                else:
                    packet_details = utils.get_packet_details(raw_packet)
                    if True: # firewall check on the packet
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
                # handle exception sockets


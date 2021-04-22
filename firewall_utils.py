import protocols

def get_packet_details(packet):
    packet_details = {}
    protocol_queue = ['Ethernet']
    start_index: int = 0
    for protocol in protocol_queue:
        protocol_class = getattr(protocols, protocol)
        end_index: int = start_index + protocol_class.header_len
        current_protocol = protocol_class(packet[start_index:end_index])
        packet_details = current_protocol.fill_details(packet_details)
        setattr(self, protocol.lower(), current_protocol)
        if current_protocol.encapsulated_proto is None:
            break
        protocol_queue.append(current_protocol.encapsulated_proto)
        start_index = end_index
    return packet_details

def verify_packet(packet_details, rules):
    for rule in rules:

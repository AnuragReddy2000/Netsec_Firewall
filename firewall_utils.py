import protocols

ETH_PROTO = "eth_proto"
NET_PROTO = "net_proto"
TSP_PROTO = "tsp_proto"
SRC_IP = "src_ip"
DST_IP = "dst_ip"
SRC_PORT = "src_port"
DST_PORT = "dst_port"
SRC_MAC = "src_mac"

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

def is_admin_packet(self, packet):
    packet_data = packet.decode('UTF-8')
    if packet_data[:12] == 'UPDATE_RULES':
        return True
    else:
        return False

def get_rule_payload(cipher, packet):
    packet_data = packet.decode('UTF-8')[12:]
    return cipher.decrypt(packet_data)

def verify_packet(packet_details, rules):
    for rule in rules:
        match_count = 0
        if rule[ETH_PROTO] == "any" or rule[ETH_PROTO] == packet_details[ETH_PROTO]:
            match_count += 1
        if rule[NET_PROTO] == "any" or rule[NET_PROTO] == packet_details[NET_PROTO]:
            match_count += 1
        if rule[TSP_PROTO] == "any" or rule[TSP_PROTO] == packet_details[TSP_PROTO]:
            match_count += 1
        if  rule[SRC_IP] == "any" or # chaeck for subnet masks:
            match_count += 1
        if  rule[DST_IP] == "any" or # chaeck for subnet masks:
            match_count += 1
        if  rule[SRC_PORT] == "any" or check_port(packet_details[SRC_PORT], rule[SRC_PORT]):
            match_count += 1
        if  rule[DST_PORT] == "any" or check_port(packet_details[DST_PORT], rule[DST_PORT]):
            match_count += 1
        if  rule[SRC_MAC] == "any" or rule[SRC_MAC] == packet_details[SRC_MAC]:
            match_count += 1
        if match_count == 8:
            return False
    return True

def check_port(port, port_range):
    range_values = port_range.split("-")
    return int(port) >= int(range_values[0]) and int(port) <= int(range_values[1])


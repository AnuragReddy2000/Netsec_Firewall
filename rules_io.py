import firewall_utils as utils, json

class Rules:
    def __init__(self, file_path):
        self.file_path = file_path
        self.int_rules, self.ext_rules = utils.load_rules(file_path)
        self.eth_filters = ["ETH", "ARP", "any"]
        self.net_filters = ["IPv4", "IPv6", "ICMP", "any"]
        self.tsp_filters = ["TCP", "UDP", "any"]

    def commit_changes(self):
        with open(self.file_path, 'w', os.O_NONBLOCK) as rule_file:
            json.dump({"incoming": self.ext_rules, "outgoing": self.int_rules}, rule_file)
            print("Sucessfully committed changes to the rule file, ",self.file_path)
            rule_file.close()

    def input_rule(self):
        rule_eth = input("Enter Link Layer protocol filter for the rule [ETH/ARP/any]: ")
        while rule_eth not in self.eth_filters:
            rule_eth = input("Invalid Link Layer protocol filter! Please try again [ETH/ARP/any]:")
        rule_net = input("Enter Network Layer protocol filter for the rule [IPv4/IPv6/ICMP/any]: ")
        while rule_net not in self.net_filters:
            rule_net = input("Invalid Network Layer filter! Please try again [IPv4/IPv6/ICMP/any]:")
        rule_tsp = input("Enter Transport Layer protocol filter for the rule [TCP/UDP/any]: ")
        while rule_tsp not in self.tsp_filters:
            rule_tsp = input("Invalid Transport Layer protocol filter! Please try again [TCP/UDP/any]:")
        rule_src_ip = input("Enter source ip address (or subnet mask) filter: [eg. 10.0.0.1 or 10.0.0.1/24]")
        while self.check_ip(rule_src_ip):
            rule_src_ip = input("Invalid ip address (or subnet mask)! Please try again: ")
        rule_dst_ip = input("Enter destination ip address (or subnet mask) filter: [eg. 10.0.0.1 or 10.0.0.1/24]")
        while self.check_ip(rule_dst_ip):
            rule_dst_ip = input("Invalid ip address (or subnet mask)! Please try again: ")
        rule_src_port = input("Enter source port (or port range) filter: [eg. 50 or 45-53] ")
        while self.check_port(rule_src_port):
            rule_src_port = input("Invalid port (or port range)! Please try again:")
        rule_dst_port = input("Enter destination port (or port range) filter: [eg. 50 or 45-53] ")
        while self.check_port(rule_dst_port):
            rule_dst_port = input("Invalid port (or port range)! Please try again:")
        rule_src_mac = input("Enter source MAC filter: ")
        new_rule = {
            utils.ETH_PROTO : rule_eth,
            utils.NET_PROTO : rule_net,
            utils.TSP_PROTO : rule_tsp,
            utils.SRC_IP : rule_src_ip,
            utils.DST_IP : rule_dst_ip,
            utils.SRC_PORT : rule_src_port,
            utils.DST_PORT : rule_dst_port,
            utils.SRC_MAC : rule_src_mac
        }
        return new_rule

    def add(self):
        new_rule = self.input_rule()
        rule_set = input("Add the rule to incoming rules or outgoing rules? [i/e]: ")
        while rule_set != "i" and rule_set != "e":
            rule_set = input("Invalid response! Please try again: ")
        if rule_set == "e":
            new_rule["index"] = len(self.ext_rules) + 1
            self.ext_rules.append(new_rule)
        else:
            new_rule["index"] = len(self.int_rules) + 1
            self.int_rules.append(new_rule)
        self.commit_changes()

    def edit_rule(self, rule_set, index):
        if rule_set == "e":
            rules = self.ext_rules
        else:
            rules = self.int_rules
        if index > len(rules):
            print("Invalid index! Please try again!")
        else:
            self.print_rule(rules[index-1])
            print("")
            new_rule = self.input_rule()
            print("")
            confirmation = input("Confirm update to the above rule? [Y/N]: ")
            if confirmation == "Y":
                rules[index-1] = new_rule
                if rule_set == "e":
                    self.ext_rules = rules
                else:
                    self.int_rules = rules
                self.commit_changes()
            else:
                print("Updation cancelled!")

    def check_ip(self, ip):
        if "/" in ip:
            [ip, mask] = ip.split("/")
            if not mask.isnumeric() or int(mask) > 32:
                return False
        if ip.count(".") != 3:
            return False
        ip_components = ip.split(".")
        for component in ip_components:
            if not component.isnumeric() or int(component) > 255:
                return False 
        return True
    
    def check_port(self, port):
        if "-" in port:
            [start_port, stop_port] = port.split("-")
            if not start_port.isnumeric() or not stop_port.isnumeric():
                return False
        else:
            return port.isnumeric()
        return True

    def print_rule(self, rule):
        print("INDEX: ",rule["index"]+1)
        print("LINK LAYER: ", rule[utils.ETH_PROTO], ", NETWORK LAYER: ", rule[utils.NET_PROTO], ", TRANSPORT LAYER: ", rule[utils.TSP_PROTO],", SRC MAC: ",rule[utils.SRC_MAC])
        print("SRC IP: "rule[utils.SRC_IP],", DST IP: ",rule[utils.DST_IP], ", SRC PORT: ",rule[utils.SRC_PORT], ", DST PORT: ",rule[utils.DST_PORT])

    def show_rules(self, rule_set=None, index=None):
        if rule_set == None:
            print("-"*10,"INCOMING PACKETS (EXTERNAL NETWORK) RULES","-"*10)
            print("="*50)
            for rule in self.ext_rules:
                self.print_rule(rule)
                print("-"*50)
            print("")
            print("-"*10,"OUTGOING PACKETS (INTERNAL NETWORK) RULES","-"*10)
            print("="*50)
            for rule in self.int_rules:
                self.print_rule(rule)
                print("-"*50)
            print("="*50)
        else:
            if rule_set == 'e':
                if index == None:
                    print("-"*10,"INCOMING PACKETS (EXTERNAL NETWORK) RULES","-"*10)
                    print("="*50)
                    for rule in self.ext_rules:
                        self.print_rule(rule)
                        print("-"*50)
                else:
                    if index > len(self.ext_rules):
                        print("Invalid index! Please Try again!")
                    else:
                        print("-"*10,"INCOMING PACKETS (EXTERNAL NETWORK) RULE INDEX: ",index,"-"*10)
                        print("="*50)
                        self.print_rule(self.ext_rules[index])
                        print("="*50)
            else:
                if index == None:
                    print("-"*10,"OUTGOING PACKETS (INTERNAL NETWORK) RULES","-"*10)
                    print("="*50)
                    for rule in self.int_rules:
                        self.print_rule(rule)
                        print("-"*50)
                else:
                    if index > len(self.int_rules):
                        print("Invalid index! Please Try again!")
                    else:
                        print("-"*10,"OUTGOING PACKETS (INTERNAL NETWORK) RULE INDEX: ",index,"-"*10)
                        print("="*50)
                        self.print_rule(self.int_rules[index-1])
                        print("="*50)

    def delete_rule(self, rule_set, index):
        if rule_set == "e":
            rules = self.ext_rules
        else:
            rules = self.int_rules
        if index > len(rules):
            print("Invalid index! Please try again!")
        else:
            self.print_rule(rules[index-1])
            print("")
            confirmation = input("Confirm delete the above rule? [Y/N]: ")
            if confirmation == Y:
                rules.remove(rules[index-1])
                if rule_set == "e":
                    self.ext_rules = rules
                else:
                    self.int_rules = rules
                self.commit_changes()
            else:
                print("Deletion cancelled!")

                

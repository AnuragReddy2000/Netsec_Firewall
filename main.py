#!/usr/bin/env python3

from rules_io import Rules
from firewall import Firewall
from getpass import getpass
from cipher import Cipher
import socket, os, sys, json

def main():
    arg_len = len(sys.argv)
    if arg_len < 2:
        print_usage()
    else:
        if sys.argv[1] == "run":
            if arg_len != 8:
                print_usage()
            else:
                int_inf = sys.argv[3]
                ext_inf = sys.argv[5]
                file_path = sys.argv[7]
                print("")
                password = getpass(prompt="Please enter an authentication password. This password must be provided whenever rule changes need to be applied: ")
                pswd_conf = getpass(prompt="Re-enter the same password for confirmation: ")
                while password != pswd_conf:
                    pswd_conf = getpass(prompt="Passwords not matching! Re-enter the password for confirmation: ")
                print("")
                Firewall(int_inf, ext_inf, file_path, password)
        elif sys.argv[1] == "rules":
            if arg_len < 5 or sys.argv[2] != "-f":
                print_usage()
            else:
                file_path = sys.argv[3]
                if sys.argv[4] == "-create":
                    create_new(file_path)
                else:
                    io = Rules(file_path)
                    if sys.argv[4] == "-add":
                        io.add()
                    elif sys.argv[4] == "-apply":
                        password = getpass(prompt="Please enter the firewall authentication password: ")
                        apply_rules(file_path, password)
                    elif sys.argv[4] == "-update":
                        if arg_len != 8:
                            print_usage()
                        else:
                            rule_set = sys.argv[5]
                            rule_index = int(sys.argv[7])
                            io.edit_rule(rule_set, rule_index)
                    elif sys.argv[4] == "-delete":
                        if arg_len != 8:
                            print_usage()
                        else:
                            rule_set = sys.argv[5]
                            rule_index = int(sys.argv[7])
                            io.delete_rule(rule_set, rule_index)
                    elif sys.argv[4] == "-show":
                        rule_set = None
                        rule_index = None
                        if arg_len == 6:
                            rule_set = sys.argv[5]
                        if arg_len == 8:
                            rule_set = sys.argv[5]
                            rule_index = sys.argv[7]
                        io.show_rules(rule_set, rule_index)
                    elif sys.argv[4] == "-show_stats":
                        rule_set = None
                        rule_index = None
                        if arg_len == 6:
                            rule_set = sys.argv[5]
                        if arg_len == 8:
                            rule_set = sys.argv[5]
                            rule_index = sys.argv[7]
                       
        else:
            print_usage()



def print_usage():
    print("")
    print("""
usage:  run -i [internal network interface] -e [external network interface] -f [path to rules]

        rules -f [path to rules] -create

        rules -f [path to rules] -add

        rules -f [path to rules] -update -[i/e] -r [rule_index]

        rules -f [path to rules] -delete -[i/e] -r [rule_index]

        rules -f [path to rules] -apply

        rules -f [path to rules] -show <optional [-i/e] -r [rule_index]>

        rules -f [path to rules] -show_stats <optional [-i/e] -r [rule_index]>""")
    print("")

def create_new(file_path):
    print("")
    with open(file_path, 'w', os.O_NONBLOCK) as rule_file:
        json.dump({
            "incoming": [], 
            "outgoing": [],
            "incoming_last_index": 0,
            "outgoing_last_index": 0,
        }, rule_file)
        rule_file.close()
    print("Sucessfully created an empty rule file")

def apply_rules(file_path, password):
    try:
        lp_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        lp_socket.connect(("127.0.0.1",5430))
        encrypted_msg = Cipher(password).encrypt("RULE_FILE:"+file_path)
        final_msg = "UPDATE_RULES"+encrypted_msg
        lp_socket.sendall(final_msg.encode('UTf-8'))
        lp_socket.close()
    except:
        lp_socket.close()

def show_statistics(file_path):
    pass
 
main()
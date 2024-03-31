#!/usr/bin/env python
import scapy.all as scapy
import optparse
def g_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", dest="ip", help=" Ip ni mac qidirishish")
    (option, arguments) = parser.parse_args()
    if not option.ip:
        parser.error("ip ni kiriting yoki -- halp niyozing!")
        print(option)

    return option
def scan(ip):
    arp_re = scapy.ARP(pdst=ip)
    broat = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_re_broat = broat / arp_re
    answerad_list = scapy.srp(arp_re_broat, timeout=1, verbose=False)[0]
    cla_list = []

    for element in answerad_list:
        cla_r = {"Ip": element[1].psrc, "Mac": element[1].hwsrc}
        cla_list.append(cla_r)

    return cla_list
def print_list(print_resolt):
    print(
        "-----------------------------------------------------\n\tIp\t\t\tMac address\n------------------------------------------------------------")
    for clent in print_resolt:
        print("   ",clent["Ip"] + "\t\t\t" + clent["Mac"])
option = g_arguments()
scan_resolt = scan(option.ip)
print_list(scan_resolt)
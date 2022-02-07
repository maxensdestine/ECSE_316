"""
Created on Sat Feb 05 14:51:17 2022
 @author: Maxens Destine
"""
import argparse
import socket


def parse_arguments():

    # Instantiate the parser

    parser = argparse.ArgumentParser(description="Optional app description")

    parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout: How long to wait, in seconds, \
        before retransmitting an unanswered query. Default value: 5")

    parser.add_argument("-r", "--maxrepeat", type=int, default=3, help="Max retries: The maximum number of \
        times to retransmit an unanswered query before giving up. Default value: 3")

    parser.add_argument("-p", "--port", type=int, default=53, help="Port: The UDP port number of the DNS \
        server. Default value: 53")

    group = parser.add_mutually_exclusive_group()

    group.add_argument("-mx", action="store_true", help="Indicate whether to send a MX \
        (mail server) or NS (name server) query. At most one of these can be given, \
            and if neither is given then the client should send a type A \
            (IP address) query")

    group.add_argument("-ns", action="store_true", help="Indicate whether to send a MX \
        (mail server) or NS (name server) query. At most one of these can be given, \
        and if neither is given then the client should send a type A \
            (IP address) query")

    parser.add_argument("server", help="Server: the IPv4 address of the DNS server, \
        in a.b.c.d.format")

    parser.add_argument("name", help="Name: The domain name to query for")


    print("Client sending request for")
    args = parser.parse_args()
    print(args.name + " Server: " + args.server)

    if args.ns:
        reqType = "NS"
    elif args.mx:
        reqType="MX"
    else:
        reqType="A"

    print("Request type: " + reqType)


parse_arguments()





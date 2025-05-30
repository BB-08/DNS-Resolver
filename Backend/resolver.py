#!/usr/bin/env python3

import socket
import sys
import struct
import secrets
import re
import threading


def build_dns_query(hostname):
    transaction_id = secrets.token_bytes(2)

    request = transaction_id + b'\0\0\0\1\0\0\0\0\0\0'
    for label in hostname.rstrip('.').split('.'):
        assert len(label) < 64, hostname
        request += int.to_bytes(len(label), length=1, byteorder='big')
        request += label.encode()
    request += b'\0'  # terminates with the zero length octet for the null label of the root.
    request += int.to_bytes(1, length=2, byteorder='big')  # QTYPE
    request += b'\0\1'  # QCLASS = 1
    return request


def send_dns_query(query_data, dns_resolver, dns_port, timeout=5):
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        sock.sendto(query_data, (dns_resolver, dns_port))
        response_data, server_address = sock.recvfrom(1024)
    except socket.timeout:
        print("Error: DNS query timed out.")
        return None
    finally:
        sock.close()

    return response_data

def parse_dns_response(response_data, query_data):
    len_question_section = len(query_data)
    answer_section = response_data[len_question_section:]  # Skip the header (12 bytes)
    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', response_data[:12])
    offset = len_question_section
    ip_addresses = []

    if ancount == 0:
        for i in range(nscount):
            if response_data[offset] & 0b11000000 == 0b11000000:
                _, _, _, _, rdlength = struct.unpack('!HHHLH', answer_section[:12])
                offset += 12 + rdlength
                answer_section = answer_section[12 + rdlength:]
            else:
                while response_data[offset] != 0:
                    offset = offset + 1
                offset = offset + 1
                answer_section = answer_section[offset:]
                _, _, _, rdlength = struct.unpack('!HHLH', answer_section[offset:offset + 10])
                offset += 10 + rdlength
                answer_section = answer_section[10 + rdlength:]

        for i in range(arcount):
            _, rrtype, _, _, rdlength = struct.unpack('!HHHLH', answer_section[:12])
            if rrtype == 1:
                rdata = answer_section[12:12 + rdlength]
                # IPv4 address is 4 bytes
                if len(rdata) == 4:
                    ip_address = '.'.join(str(byte) for byte in rdata)
                    ip_addresses.append(ip_address)
            answer_section = answer_section[12 + rdlength:]

    else:
        for _ in range(ancount):
            if response_data[offset] & 0b11000000 == 0b11000000:
                _, _, _, _, rdlength = struct.unpack('!HHHLH', response_data[offset:offset + 12])
                rdata = response_data[offset + 12:offset + 12 + rdlength]
                if len(rdata) == 4:
                    ip_address = '.'.join(str(byte) for byte in rdata)
                    ip_addresses.append(ip_address)
                offset += 12 + rdlength
                answer_section = answer_section[12 + rdlength:]

            else:
                while response_data[offset] != 0:
                    offset += 1
                offset += 1
                print(offset)
                answer_section = answer_section[offset:]
                _, _, _, rdlength = struct.unpack('!HHLH', response_data[offset:offset + 10])
                rdata = response_data[offset+10:offset + 10 + rdlength]
                if len(rdata) == 4:
                    ip_address = '.'.join(str(byte) for byte in rdata)
                    ip_addresses.append(ip_address)
                offset += 10 + rdlength
                answer_section = answer_section[10 + rdlength:]


    return ip_addresses

def get_hostname_from_request(dns_query):
    qname_start = 12  # QNAME starts 12 bytes after the beginning of the DNS query
    qname_end = qname_start
    hostname_labels = []

    while True:
        label_length = dns_query[qname_end]
        if label_length == 0:
            break
        label = dns_query[qname_end + 1: qname_end + 1 + label_length].decode()
        hostname_labels.append(label)
        qname_end += 1 + label_length

    # Join the labels to form the complete hostname
    hostname = '.'.join(hostname_labels)
    return hostname

def get_root_dns_resolvers():
    dns_resolvers = []
    dns_resolve = ''
    with open("named.root", "r") as root_file:
        for line in root_file:
            if re.match(r'[A-Z]\.ROOT\-SERVERS\.NET', line):
                record = line.split()
                rtype = record[2]
                if rtype == 'A':
                    dns_resolvers.append(record[3])
    return dns_resolvers

def get_final_response(hostname):
    ancount = 0
    ip_addresses = get_root_dns_resolvers()
    resolver_count = 0
    port = 53
    dns_query = None
    response_data = None

    while True:
        dns_resolver = ip_addresses[resolver_count]
        dns_query = build_dns_query(hostname)
        response_data = send_dns_query(dns_query, dns_resolver, port)
        if response_data:
            # Parse the response
            transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', response_data[:12])
            rcode = flags & 0b00001111
            temp_ip_addresses = parse_dns_response(response_data, dns_query)
            if ancount == 0 and rcode == 0 and len(temp_ip_addresses) != 0:
                resolver_count = 0
                ip_addresses = temp_ip_addresses
                #  rcode == 3  resolver count = 0
            elif (rcode == 3 or len(temp_ip_addresses) == 0) and resolver_count < len(ip_addresses) - 1:
                resolver_count += 1
            else:
                break
        elif response_data == None and resolver_count < len(ip_addresses) - 1:
            resolver_count += 1
        else:
            break



    return response_data


def build_dns_response(dns_query, final_response):

    transaction_id = dns_query[:2]
    dns_response = transaction_id + final_response[2:]

    return dns_response

def handle_request(client_request, client_address):
    hostname = get_hostname_from_request(client_request)
    final_response = get_final_response(hostname)
    if final_response:
        dns_response = build_dns_response(client_request, final_response)
        server_socket.sendto(dns_response, client_address)
    else:
        print(f"No IP addresses found for {hostname}.")

if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            print("Error: invalid arguments")
            print(f"Usage: {sys.argv[0]} server_port")
            sys.exit(0)
        server_port = int(sys.argv[1])
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind(('localhost', server_port))
        print("Resolver started...")
        while True:
            client_request, client_address = server_socket.recvfrom(2048)
            thread = threading.Thread(target=handle_request, args=(client_request, client_address))
            thread.start()
    except KeyboardInterrupt:
         print("\nDNS query canceled by the user.")

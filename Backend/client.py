import sys
import time
import struct
from resolver import build_dns_query, send_dns_query, parse_dns_response
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/resolve', methods=['GET'])
def resolve_api():
    hostname = request.args.get('hostname')
    dns_resolver = request.args.get('resolver', '8.8.8.8')
    dns_port = int(request.args.get('port', 53))
    timeout = int(request.args.get('timeout', 5))

    if not hostname:
        return jsonify({"error": "Missing 'hostname' parameter"}), 400

    query_data = build_dns_query(hostname)
    response_data = send_dns_query(query_data, dns_resolver, dns_port, timeout)

    if not response_data:
        return jsonify({"error": "DNS query failed or timed out"}), 504

    ip_addresses = parse_dns_response(response_data, query_data)
    rcode, aa_flag, tc_flag = extract_flags(response_data)

    return jsonify({
        "hostname": hostname,
        "ip_addresses": ip_addresses,
        "flags": {
            "AA": aa_flag,
            "TC": tc_flag,
            "RCODE": rcode
        }
    })

def parse_arguments(argv):
    if len(argv) == 4:
        dns_resolver, dns_port, hostname = argv[1:]
        timeout = 5
    elif len(argv) == 5:
        dns_resolver, dns_port, hostname, timeout = argv[1:]
    else:
        print(f"Error: Invalid arguments.\nUsage: {argv[0]} resolver_ip resolver_port hostname [timeout]")
        sys.exit(1)
    return dns_resolver, int(dns_port), hostname, int(timeout)

def perform_dns_query(dns_resolver, dns_port, hostname, timeout):
    query_data = build_dns_query(hostname)
    start_time = time.time()
    response_data = send_dns_query(query_data, dns_resolver, dns_port, timeout)
    end_time = time.time()

    # Log response time
    with open(dns_resolver, 'a') as f:
        f.write(f"{end_time - start_time}\n")

    return query_data, response_data

def extract_flags(response_data):
    flags = struct.unpack('!H', response_data[2:4])[0]
    rcode = flags & 0b1111
    aa_flag = bool(flags & (1 << 10))
    tc_flag = bool(flags & (1 << 9))
    return rcode, aa_flag, tc_flag

def print_dns_result(hostname, ip_addresses, aa_flag, tc_flag):
    format_string = "{:<30} {:<15} {:<5} {:>10}"
    print(format_string.format("Hostname", "IP Address", "AA Flag", "TC Flag"))
    for ip in ip_addresses:
        print(format_string.format(hostname, ip, str(aa_flag), str(tc_flag)))

def handle_rcode(rcode, hostname):
    rcode_messages = {
        1: "The name server was unable to interpret the query.",
        2: "The name server was unable to process this query due to a problem with the name server.",
    }
    message = rcode_messages.get(rcode, f"{hostname} not found.")
    print(f"Usage: error: {message}")
    sys.exit(1)

def main():
    try:
        dns_resolver, dns_port, hostname, timeout = parse_arguments(sys.argv)
        query_data, response_data = perform_dns_query(dns_resolver, dns_port, hostname, timeout)

        if response_data:
            rcode, aa_flag, tc_flag = extract_flags(response_data)
            ip_addresses = parse_dns_response(response_data, query_data)

            if ip_addresses and rcode == 0:
                print_dns_result(hostname, ip_addresses, aa_flag, tc_flag)
            else:
                handle_rcode(rcode, hostname)
        else:
            print("No response received from the DNS server.")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\nDNS query canceled by the user.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        main()
    else:
        app.run(debug=True)
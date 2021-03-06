import socket
import requests
import ipaddress

search_term = 'cat'
reverse_proxies = {}


def check_reverse_proxy(domain, ip_address):
    ip_from_domain = socket.gethostbyname(domain)
    if ip_from_domain != ip_address:
        reverse_proxies[domain] = {'ip_from_domain': ip_from_domain, 'underlying_ip': ip_address}
    return ip_from_domain == ip_address


# read list of ASNs from he.net search results and save in list
with open('asns.txt', 'r') as file:
    line = file.readline()
    haystack = []
    while line:
        processed = line.split('\t')[0]
        haystack.append(processed)
        line = file.readline()

ip_list = []

for cidr_entry in haystack:
    try:
        for ip in ipaddress.IPv4Network(cidr_entry):
            print(ip)
            ip_list.append(str(ip))
    # skip IPv6 addresses since the range is too large and most hosts have a IPv4 address too
    except ipaddress.AddressValueError as e:
        continue

results = {}

for ip in ip_list:
    try:
        host = socket.gethostbyaddr(ip)
        check_reverse_proxy(host[0], ip)
        results[ip] = host[0]
        if search_term in host[0]:
            print(search_term + ' found on ' + ip + ' via host ' + host[0])
        else:
            print(host[0] + ', ' + host[2][0])
        print(reverse_proxies)
    # just skip over invalid hosts for now
    except socket.herror as e:
        continue
    except socket.gaierror as e:
        continue

from __future__ import print_function

from .util import get_hostname, get_open_ports, generate_portlist, generate_per_host_portlist

longline = "-" * 80


def print_grepable(ip, hostname, os):
    print ("{0} {1} {2}".format(ip, hostname, os))


def print_host(host, args):
    hostname = get_hostname(host)

    os_matches = host.os_match_probabilities()
    os = ""
    if len(os_matches) > 0:
        os = os_matches[0].name

    line = "-" * 15

    if not args.print_os and not args.print_ports:
        print_grepable(host.address, hostname, os)
    else:
        print ("#{0}".format("=" *79))
        print ("IP:\t\t{0}".format(host.address))
        print ("Hostname:\t{0}".format(hostname))
        print ("OS:\t\t{0}".format(os))
        print ("#{0}".format("-" *79))
        if args.print_ports:
            port_str = ""
            tcpports = get_open_ports(host)
            for (port, protocol, service, banner) in tcpports:
                port_str += "{0} {1} {2} {3}\n".format(port, protocol, service, banner)

            udpports = get_open_ports(host, protocol='udp')
            for (port, protocol, service, banner) in udpports:
                port_str += "{0} {1} {2} {3}\n".format(port, protocol, service, banner)
            print (port_str)

        if args.print_os:
            match_str = ""
            for match in os_matches:
                match_str += "{0} {1}\n".format(match.accuracy, match.name)
            print ("{0} OS-Matches (accuracy, OS-name): {0}".format(line))
            print (match_str)


def print_hosts(hosts, args):
    for host in hosts:
        # print longline
        print_host(host, args)


def print_portlist(hosts=[]):
    tcp_portlist = sorted(generate_portlist(hosts))
    print ("TCP ports: {0}".format(",".join(str(n) for n in tcp_portlist)))
    udp_portlist = sorted(generate_portlist(hosts, 'udp'))
    print ("UDP ports: {0}".format(",".join(str(n) for n in udp_portlist)))
    all_portlist = sorted(set(tcp_portlist) | set(udp_portlist))
    print ("all ports: {0}".format(",".join(str(n) for n in all_portlist)))


def print_per_host_portlist(hosts=[]):
    result = generate_per_host_portlist(hosts)
    for hostinfo in result:
        addr , tcp_ports, udp_ports, all_ports = hostinfo
        tcp_str = ",".join(str(n) for n in tcp_ports)
        udp_str = ",".join(str(n) for n in udp_ports)
        all_str = ",".join(str(n) for n in all_ports)
        print ("{0};tcp;{1}".format(addr, tcp_str))
        print ("{0};udp;{1}".format(addr, udp_str))
        print ("{0};all;{1}".format(addr, all_str))

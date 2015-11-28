#!/usr/bin/env python

import argparse

from libnmap.parser import NmapParser

longline = "-" * 80


def print_grepable(ip, hostname, os):
    print "{0} {1} {2}".format(ip, hostname, os)


def get_open_ports(host, protocol='tcp'):
    ports = []
    for port, proto in host.get_open_ports():
        if host.get_service(port, proto) is not None:
            service = host.get_service(port, proto)
            servicename = service.service
            banner = service.banner
            if protocol == proto:
                ports.append((port, proto, servicename, banner))
    return ports


def print_host(host, args):
    hostname = ""
    for name in host.hostnames:
        if name == "localhost" and hostname != "":
            continue
        hostname = name

    os_matches = host.os_match_probabilities()
    os = ""
    if len(os_matches) > 0:
        os = os_matches[0].name

    line = "-" * 15

    if not args.print_os and not args.print_ports:
        print_grepable(host.address, hostname, os)
    else:
        print "#{0}".format("=" *79)
        print "IP:\t\t{0}".format(host.address)
        print "Hostname:\t{0}".format(hostname)
        print "OS:\t\t{0}".format(os)
        print "#{0}".format("-" *79)
        if args.print_ports:
            port_str = ""
            tcpports = get_open_ports(host)
            for (port, protocol, service, banner) in tcpports:
                port_str += "{0} {1} {2} {3}\n".format(port, protocol, service, banner)

            udpports = get_open_ports(host, protocol='udp')
            for (port, protocol, service, banner) in udpports:
                port_str += "{0} {1} {2} {3}\n".format(port, protocol, service, banner)
            print port_str

        if args.print_os:
            match_str = ""
            for match in os_matches:
                match_str += "{0} {1}\n".format(match.accuracy, match.name)
            print "{0} OS-Matches (accuracy, OS-name): {0}".format(line)
            print match_str


def ports_to_latex(ports, description):
    port_str = "\\textbf{" + description + "} & "

    if len(ports) == 0:
        port_str += " - "
    else:
        port_list = []
        for (port, protocol, service, banner) in ports:
            port_list.append(str(port))
        port_str += ", ".join(port_list)
    port_str += "\\\\"
    return port_str


def host_to_latex(host):
    tcp_ports = get_open_ports(host)
    tcp_str = ports_to_latex(tcp_ports, "TCP")
    udp_ports = get_open_ports(host, protocol='udp')
    udp_str = ports_to_latex(udp_ports, "UDP")

    output = "{0} & {1}\n\t & {2}".format(host.address, tcp_str, udp_str)
    return output


def export_latex(hosts, file):
    results = []
    results.append("\\begin{longtable}{lll}")
    results.append("\\toprule")
    host_str_list = []
    for host in hosts:
        host_str_list.append(host_to_latex(host))
    results.append("\n\\midrule\n".join(host_str_list))
    results.append("\\bottomrule")
    results.append("\\end{longtable}")

    with open(file, 'w') as f:
        f.write("\n".join(results))


def print_hosts(hosts, args):
    for host in hosts:
        # print longline
        print_host(host, args)


def filter_hosts_by_os(hosts, args):
    if args.os_family is None and args.os_gen is None:
        return hosts

    result = []

    for host in hosts:
        os_matches = host.os_match_probabilities()
        found = False
        for match in os_matches:
            for osc in match.osclasses:
                if args.os_family is not None and args.os_gen is not None:
                    # both filters are used, so we have to check if both match
                    if osc.osgen == args.os_gen and osc.osfamily == args.os_family:
                        found = True
                        break
                else:
                    # one filter used
                    if args.os_gen is not None:
                        # only os_gen was specified
                        if osc.osgen == args.os_gen:
                            found = True
                    elif args.os_family is not None:
                        # only os_family was specified
                        if osc.osfamily == args.os_family:
                            found = True
        if found:
            result.append(host)

    return result


def parse_ports(ports):
    portlist = []
    if ports == "" or ports == None:
        return portlist
    for port in ports.split(','):
        if '-' in port:
            portrange = port.split('-')
            for i in range(int(portrange[0]), int(portrange[1]) + 1):
                # append all ports in the portrange to the new portlist
                portlist.append(i)
        else:
            # append single port to portlist
            portlist.append(int(port))
    return portlist

def parse_ips(ips):
    ip_list = []
    if ips == "" or ips == None:
        return ip_list
    for ip in ips.split(','):
        ip_list.append(ip)
    return ip_list


def filter_hosts_by_port(hosts, tcpports=[], udports=[]):
    if len(tcp_ports) == 0 and len(udp_ports) == 0:
        return hosts

    result = []
    for host in hosts:
        for (port, proto) in host.get_open_ports():
            if proto == "tcp":
                if port in tcp_ports:
                    result.append(host)
                    break
            if proto == "udp":
                if port in udp_ports:
                    result.append(host)
                    break
    return result


def filter_hosts_by_ip(hosts, ips):
    result = []
    for host in hosts:
        if host.address in ips:
            result.append(host)
    return result

def list_ips(hosts):
    result = []
    for host in hosts:
        result.append(host.address)
    return result

def export_list(hosts, file):
    with open(file, 'w') as f:
        f.write("\n".join(list_ips(hosts)))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="I am a simple tool to filter nmap scans")
    parser.add_argument("file", metavar="FILE", type=str, nargs=1, help="The nmap XML file")
    parser.add_argument("-g", "--os-gen", required=False, default=None,
                        help="Filter hosts which are running the specified OS Gen")
    parser.add_argument("-f", "--os-family", required=False, default=None,
                        help="Filter hosts which are running this OS family")
    parser.add_argument("-t", "--tcp", required=False, default="",
                        help="Filter hosts which have the specified tcp ports open. Use ',' to separate ports \
                        and '-' for a range of ports")
    parser.add_argument("-r", required=False, default="",
                        help="Filter the given IP")
    parser.add_argument("-u", "--udp", required=False, default="",
                        help="Filter hosts which have the specified udp ports open. Use ',' to separate ports \
                        and '-' for a range of ports")
    parser.add_argument("-p", "--print-ports", required=False, action='store_true', default=False,
                        help="Print the port section")
    parser.add_argument("-o", "--print-os", required=False, action='store_true', default=False,
                        help="Print the OS section")
    parser.add_argument("--export", metavar="FILE", required=False, type=str, default=None,
                        help="Generate LaTeX tables for each host and write them to the specifies file")
    parser.add_argument("--list", required=False, action='store_true', default=False,
                        help="Generate a Target list usable as nmap input")
    parser.add_argument("-d", "--list-delimiter", required=False, default=" ",
                        help="Delimiter used to separate hosts in the list output")
    parser.add_argument("--list-file", metavar="FILE", required=False, type=str, default=None,
                        help="Generate a file with the target instead of print them to stdout")
    args = parser.parse_args()

    report = NmapParser.parse_fromfile(args.file[0])
    tcp_ports = parse_ports(args.tcp)
    udp_ports = parse_ports(args.udp)
    ips = parse_ips(args.r)
    hosts = report.hosts

    if not args.list:
        print "# number of hosts in the report: {0}".format(str(len(report.hosts)))

    if len(ips) > 0:
        hosts = filter_hosts_by_ip(hosts, ips)
    if not args.list:
        print "# number of hosts after IP filter: {0}".format(str(len(hosts)))

    hosts = filter_hosts_by_os(hosts, args)
    if not args.list:
        print "# number of hosts after OS and IP filter: {0}".format(str(len(hosts)))

    hosts = filter_hosts_by_port(hosts, tcp_ports, udp_ports)
    if not args.list:
        print "# number of hosts after OS, IP and port filter: {0}".format(str(len(hosts)))

    if args.list_file is not None:
        export_list(hosts, args.list_file)
        
    if not args.list:
        print_hosts(hosts, args)
    else:
        print args.list_delimiter.join(list_ips(hosts))

    if args.export is not None:
        export_latex(hosts, args.export)

from .util import list_ips, get_open_ports


def export_list(hosts, file):
    with open(file, 'w') as f:
        f.write("\n".join(list_ips(hosts)))


def export_csv(hosts, file):
    result = []
    result.append("{0};{1};{2};{3};{4};".format("IP", "HOSTNAME", "OS", "TCP-PORTS", "UDP-Ports"))
    for host in hosts:
        hostname = ""
        for name in host.hostnames:
            if name == "localhost" and hostname != "":
                continue
            hostname = name

        os_matches = host.os_match_probabilities()
        os = ""
        if len(os_matches) > 0:
            os = os_matches[0].name

        tcp_ports = []
        for (port, protocol, service, banner) in get_open_ports(host, protocol='tcp'):
            tcp_ports.append(str(port))

        tcp_port_str = ",".join(tcp_ports)

        udp_ports = []
        for (port, protocol, service, banner) in get_open_ports(host, protocol='udp'):
            udp_ports.append(str(port))
        udp_port_str = ",".join(udp_ports)

        if len(tcp_ports) > 0 or len(udp_ports) >0:
            result.append("'{0}';{1};{2};{3};{4};".format(host.address, hostname,os, tcp_port_str, udp_port_str))

    with open(file, 'w') as f:
        f.write("\n".join(result))


def _ports_to_latex(ports, description):
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


def _host_to_latex(host):
    tcp_ports = get_open_ports(host)
    tcp_str = _ports_to_latex(tcp_ports, "TCP")
    udp_ports = get_open_ports(host, protocol='udp')
    udp_str = _ports_to_latex(udp_ports, "UDP")

    output = "{0} & {1}\n\t & {2}".format(host.address, tcp_str, udp_str)
    return output


def export_latex(hosts, file):
    results = []
    results.append("\\begin{longtable}{lll}")
    results.append("\\toprule")
    host_str_list = []
    for host in hosts:
        host_str_list.append(_host_to_latex(host))
    results.append("\n\\midrule\n".join(host_str_list))
    results.append("\\bottomrule")
    results.append("\\end{longtable}")

    with open(file, 'w') as f:
        f.write("\n".join(results))


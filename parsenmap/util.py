
def get_open_ports(host, protocol='tcp'):
    """
    This function generates a list of open ports. Each entry is a tuple which contains the port, protocol, servicename
    and a banner string.

    :param host: The NmapHost object
    :type host libnmap.objects.host.NmapHost
    :param protocol: the protocol type. Either 'tcp' (default) or 'udp'
    :type protocol str
    :return: list of tuples
    """
    ports = []
    for port, proto in host.get_open_ports():
        if host.get_service(port, proto) is not None:
            service = host.get_service(port, proto)
            servicename = service.service
            banner = service.banner
            if protocol == proto:
                ports.append((port, proto, servicename, banner))
    return ports


def get_hostname(host):
    """
    This function get the hostname of the given host.

    :param host: The NmapHost object
    :type host: libnmap.objects.host.NmapHost

    :return: hostname
    :rtype: str
    """
    hostname = ""
    for name in host.hostnames:
        if name == "localhost" and hostname != "":
            continue
        hostname = name
    return hostname


def parse_ports(ports):
    """
    This function is used to generate a list of ports from a port specification. You can use ',' to separate ports
    and '-' for a range of ports. (e.g. 20-22,80,443)

    :param ports: A list of ports

    :return: list of ports
    :rtype list of int
    """
    portlist = []
    if ports == "" or ports is None:
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
    """
    This function generates a list of ips from an input string. This input can contain ips seperated by ",".

    :param ips: string with ips seperated with ","

    :return: a list of ips
    :rtype list of strings
    """
    ip_list = []
    if ips == "" or ips is None:
        return ip_list
    for ip in ips.split(','):
        ip_list.append(ip)
    return ip_list


def list_ips(hosts):
    """
    This function generates a list of ips from as list of NmapHost objects.

    :param hosts: list of NmapHost objects
    :return: list of ips
    :rtype list of strings
    """
    result = []
    for host in hosts:
        result.append(host.address)
    return result


def generate_portlist(hosts=[],protocol='tcp'):
    result = set()
    for host in hosts:
        ports = get_open_ports(host, protocol=protocol)
        result |= set([ port for (port, protocol, service, banner) in ports])
    return map( lambda x: int(x), result)


def generate_per_host_portlist(hosts=[]):
    result = []
    for host in hosts:
        tcp_ports = get_open_ports(host, protocol='tcp')
        tcp_portlist = sorted([port for (port, protocol, service, banner) in tcp_ports])
        udp_ports = get_open_ports(host, protocol='udp')
        udp_portlist = sorted([port for (port, protocol, service, banner) in udp_ports])
        all_portlist = sorted(set(tcp_portlist) | set(udp_portlist))
        result.append((host.address, tcp_portlist, udp_portlist, all_portlist))
    return result

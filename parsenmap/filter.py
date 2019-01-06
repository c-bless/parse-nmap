

def filter_hosts_by_os(hosts, os_family= None, os_gen=None):
    """
    This function creates a list of NmapHost objects which matches the given filters. You either can specify an os
    family or a os generation or both. The parameter os_family has to be an exact string like "Windows" or "Linux" and
    the parameter os_gen should be a string like "7", "8" or "2.4.X".

    :param hosts: as list of NmapHost objects
    :type hosts: list of NmapHost objects

    :param os_family: the os family filter string
    :type os_family: str

    :param os_gen: the os generation filter string
    :type os_gen: str

    :return: list of NmapHost objects
    """
    if os_family is None and os_gen is None:
        return hosts

    result = []

    for host in hosts:
        os_matches = host.os_match_probabilities()
        found = False
        for match in os_matches:
            for osc in match.osclasses:
                if os_family is not None and os_gen is not None:
                    # both filters are used, so we have to check if both match
                    if osc.osgen == os_gen and osc.osfamily == os_family:
                        found = True
                        break
                else:
                    # one filter used
                    if os_gen is not None:
                        # only os_gen was specified
                        if osc.osgen == os_gen:
                            found = True
                    elif os_family is not None:
                        # only os_family was specified
                        if osc.osfamily == os_family:
                            found = True
        if found:
            result.append(host)

    return result


def filter_hosts_by_port(hosts, tcp_ports=[], udp_ports=[]):
    """
    Generates a new list of hosts which matches the given port filters. Only hosts with open ports specified either in
    the tcpports or updports list will be present in the new list.

    :param hosts: list of NmapHost objects
    :type list

    :param tcp_ports: list of TCP ports used for filtering
    :type list

    :param udp_ports: list of UDP ports used for filtering

    :return:
    """
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
    """
    Generates a new list of hosts which matches the given IP filter.

    :param hosts:
    :param ips:
    :return:
    """
    result = []
    for host in hosts:
        if host.address in ips:
            result.append(host)
    return result

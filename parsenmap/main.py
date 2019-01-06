#!/usr/bin/env python

# Copyright (C) 2015 Christoph Bless
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

#
# Description:
# Parse-nmap is a tool which parses nmap scan results (only XML) from a file. By using parse-nmap it is possible to
# filter the results by platform or ip or to generate target lists.
#
# This script is available on bitbucket.org see:
#     https://bitbucket.org/cbless/parse-nmap

from __future__ import print_function

import argparse

from libnmap.parser import NmapParser

from .util import parse_ports, parse_ips, list_ips
from .filter import filter_hosts_by_ip, filter_hosts_by_os, filter_hosts_by_port
from .export import export_csv, export_latex, export_list
from .printer import print_per_host_portlist, print_portlist, print_grepable, print_hosts


def parse_nmap():
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
    parser.add_argument("--export-csv", metavar="FILE", required=False, type=str, default=None,
                        help="export all hosts with open ports")
    parser.add_argument("--list", required=False, action='store_true', default=False,
                        help="Generate a Target list usable as nmap input")
    parser.add_argument("-d", "--list-delimiter", required=False, default=" ",
                        help="Delimiter used to separate hosts in the list output")
    parser.add_argument("--list-file", metavar="FILE", required=False, type=str, default=None,
                        help="Generate a file with the target instead of print them to stdout")
    parser.add_argument("-v", "--verbose", required=False, default=False, action="store_true",
                        help="Print verbose information to stdout")
    parser.add_argument("--portlist", required=False, action="store_true", default=False,
                        help="Gernarte a list of open ports.")
    parser.add_argument("--per-host-portlist", required=False, action="store_true", default=False,
                        help="Gernarte a list of open ports per host.")
    args = parser.parse_args()

    report = NmapParser.parse_fromfile(args.file[0])
    tcp_ports = parse_ports(args.tcp)
    udp_ports = parse_ports(args.udp)
    ips = parse_ips(args.r)
    hosts = report.hosts
    hosts = [x for x in hosts if x.is_up()]

    host_count = len(report.hosts)
    if len(ips) > 0:
        hosts = filter_hosts_by_ip(hosts, ips)
    host_count_after_ip_filter = len(hosts)

    hosts = filter_hosts_by_os(hosts, os_family=args.os_family, os_gen=args.os_gen)
    host_count_after_os_filter = len(hosts)

    hosts = filter_hosts_by_port(hosts, tcp_ports, udp_ports)
    host_count_after_port_filter = len(hosts)

    if not args.list and args.verbose:
        print ("# number of hosts in the report: {0}".format(str(host_count)))
        print ("# number of hosts after IP filter: {0}".format(str(host_count_after_ip_filter)))
        print ("# number of hosts after OS and IP filter: {0}".format(str(host_count_after_os_filter)))
        print ("# number of hosts after OS, IP and port filter: {0}".format(str(host_count_after_port_filter)))

    if args.list_file is not None:
        export_list(hosts, args.list_file)

    if args.portlist:
        print_portlist(hosts)
    elif args.per_host_portlist:
        print_per_host_portlist(hosts)
    else:
        # no portlist and no per host portlist
        if not args.list:
            print_hosts(hosts, args)
        else:
            print (args.list_delimiter.join(list_ips(hosts)))

        if args.export is not None:
            export_latex(hosts, args.export)
        if args.export_csv is not None:
            export_csv(hosts, args.export_csv)


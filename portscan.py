#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import datetime
import logging
import os
import re
import socket
import sys
import subprocess


def ip_scanner(to_check):
    failures = []
    for key in to_check.keys():
        print('\nChecking {} IPs'.format(key.upper()))
        print('-' * 25)

        server = to_check[key]
        for ip in server['ip_list']:
            if ip == '255.255.255.0':
                continue

            print('  {}'.format(ip))
            logging.info('Checking {} - {}'.format(key, ip))

            # make sure command will run on both windows and unix systems
            if os.name == 'nt':
                ping_cmd = 'ping -n 1 -w 2000 {} > nul'.format(ip)
            else:
                ping_cmd = 'ping -c 1 {} > /dev/null'.format(ip)
            status_print('    Pinging ', 1)

            if os.system(ping_cmd) != 0:
                status_print(' fail', 2)
                logging.error('{} is not reachable'.format(ip))
                for port in server['ports']:
                    status_print('    Port {} '.format(port), 1)
                    status_print('n/a', 2)
                failures.append(ip)
            else:
                status_print(' pass', 2)
                ports_failed = port_scanner(ip, server['ports'], server['mode'])
                if ports_failed:
                    failures.append(ip)
            print

    return failures


def port_scanner(ip, port_list, mode):
    ports_failed = False

    for port in port_list:
        status_print('    Port {} '.format(port), 1)
        logging.info('Checking port {}'.format(port))
        address = (ip, port)

        try:
            if mode == 'tcp':
                t = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                t.settimeout(2)
                t.connect(address)
                t.close()
            else:
                u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                u.settimeout(2)
                buf = 1024
                payload = '\x1b' + 47 * '\0'

                u.sendto(payload, address)
                msg, address = u.recvfrom(buf)
                u.close()

            status_print(' pass', 2)
            logging.info('Port {}: open'.format(port))

        except socket.error as msg:  # Error routine
            ports_failed = True
            status_print(' fail', 2)
            logging.error('IP {} Port {}: closed'.format(ip, port))
            logging.debug('Port {} error message: {}'.format(port, msg))

    return ports_failed


def status_print(message, mode):
    if mode == 1:
        sys.stdout.write(message.ljust(15, '.'))
        sys.stdout.flush()
    if mode == 2:
        print(message.rjust(10, '.'))


def extract_ip(string):
    return re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", string)


def build_ip_list(base_list):
    p = subprocess.check_output(['getrackinfo', '-v'])
    rack_ips = iter(p.splitlines())
    for line in rack_ips:
        if 'NTP' in line:
            base_list['ntp']['ip_list'] = extract_ip(next(rack_ips))
        elif 'DNS' in line:
            next(rack_ips)
            next(rack_ips)
            base_list['dns']['ip_list'] = extract_ip(next(rack_ips))
        elif 'public' in line:
            base_list['nodes']['ip_list'].extend(extract_ip(line))
        elif 'Remote Ipmi' in line:
            base_list['rmm']['ip_list'].extend(extract_ip(line))

    return base_list


def check_hostnames(host_name, ip):
    test = socket.gethostbyname(host_name)
    if test == ip:
        test = 'PASS'


def check_mtu(ip, port):
    routeinfo = subprocess.check_output(['ip', 'route', 'get', ip])
    dev = re.search('.*dev (\w+) .*', routeinfo).groups()[0]
    mtuinfo = subprocess.check_output(['ip', 'link', 'show', dev])
    mtu = re.search('.*mtu ([0-9]+) .*', mtuinfo).groups()[0]
    print(mtu)
    return int(mtu)


def main():
    any_failed = []
    # init logging for the script
    logging.basicConfig(filename='{}.log'.format(datetime.date.today()),
                        format="[%(levelname)8s] %(message)s",
                        level=logging.DEBUG
                        )

    logging.info('=' * 80)
    logging.info('New Run'.center(80))
    logging.info('=' * 80)

    # Build IPs list from node
    base_list = {
      "nodes": {
        "mode": "tcp",
        "ip_list": [],
        "ports": [9094, 9095, 9096, 9097, 9098, 22, 80, 443, 4443]
      },
      "rmm": {
        "mode": "tcp",
        "ip_list": [],
        "ports": [80, 443, 5123, 7578, 7578,5120,5123]
      },
      "service_clients": {
        "mode": "tcp",
        "ip_list": [],
        "ports": [3218, 9020, 9021, 9022, 9023, 9024, 9025, 9040]
      },
      "dns": {
        "mode": "tcp",
        "ip_list": [],
        "ports": [53]
      },
      "ntp": {
        "mode": "udp",
        "ip_list": [],
        "ports": [123]
      },
      "smtp": {
        "mode": "tcp",
        "ip_list": ["202.238.84.20"],
        "ports": [25]
      },
      "ad": {
        "mode": "tcp",
        "ip_list": ["10.247.134.54"],
        "ports": [389, 636]
      }
    }

    to_check = build_ip_list(base_list)

    # Iterate through the loaded data and check the IPs and ports
    failed_ips = ip_scanner(to_check)
    if failed_ips:
        any_failed.extend(failed_ips)

    if any_failed:
        print('There were issues with the following servers, please check the log for more details:')
        for i in any_failed:
            print('  {}'.format(i))


if __name__ == '__main__':
    main()

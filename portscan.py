#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import datetime
import logging
import os
import re
import socket
import sys
import subprocess
import argparse


class NetworkScanner:
    def __init__(self, args):
        # Verbose mode will provide output for each service. Normal output just provides a pass/fail for each
        # node. Details for each IP:Port combo are always logged regardless of this param
        self.verbose = args['verbose']

        # init logging for the script
        logging.basicConfig(filename='{}.log'.format(datetime.date.today()),
                            format="[%(levelname)8s] %(message)s",
                            level=logging.DEBUG
                            )

        logging.info('=' * 80)
        logging.info('New Run'.center(80))
        logging.info('=' * 80)

    def ip_scanner(self, to_check):
        """
        Pings each of the IPs in sequence and if it gets a response, calls port_scanner() for each port the IP has
        :param to_check: dict of IPs and ports to check
        :return:
        """
        failures = []
        for key in to_check.keys():
            # create iterable of the dict and begin going through it
            if self.verbose:
                self.status_print('Checking {}'.format(key.upper()), 1)
                print('')
                print('-' * 25)

            server = to_check[key]
            for ip in server['ip_list']:
                if ip == '255.255.255.0':
                    continue

                if self.verbose:
                    print('\n  {}'.format(ip))
                logging.info('Checking {} - {}'.format(key, ip))

                if self.verbose:
                    self.status_print('    Ping ', 1)

                # Try up to 3 times to ping before failing in case there is a temporary network issue
                count = 0
                ping_succeeded = False
                while count < 3:
                    count += 1
                    if os.system('ping -c 1 {} > /dev/null'.format(ip)) != 0:
                        pass
                    else:
                        ping_succeeded = True
                        break

                if ping_succeeded:
                    if self.verbose:
                        self.status_print(' pass', 2)
                    mode = 'udp' if key == 'ntp' else 'tcp'
                    ports_failed = self.port_scanner(ip, server['ports'], mode)
                    if ports_failed:
                        failures.append(ip)
                else:
                    if self.verbose:
                        self.status_print(' fail', 2)
                    logging.error('{} is not reachable'.format(ip))
                    for port in server['ports']:
                        if self.verbose:
                            self.status_print('    Port {} '.format(port), 1)
                            self.status_print('n/a', 2)
                    failures.append(ip)

            print
        return failures

    def port_scanner(self, ip, ports, mode):
        ports_failed = []

        for key, port_list in ports.items():
            if self.verbose:
                self.status_print('    {} '.format(key), 1)
            any_failed = False
            for port in port_list:
                logging.info('Checking {} - port {}'.format(key, port))
                address = (ip, port)

                count = 0
                port_open = False
                while count < 3:
                    count += 1
                    try:
                        if 'tcp' in mode:
                            t = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                            t.settimeout(2)
                            t.connect(address)
                            t.close()

                        if 'udp' in mode:
                            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            u.settimeout(2)
                            buf = 1024
                            payload = '\x1b' + 47 * '\0'

                            u.sendto(payload, address)
                            msg, address = u.recvfrom(buf)
                            u.close()

                        port_open = True
                        break
                    except socket.error as msg:
                        logging.debug('Port {} error message: {}'.format(port, msg))

                if not port_open:
                    any_failed = True

            if any_failed:
                ports_failed.append(port)
                if self.verbose:
                    self.status_print(' fail', 2)
                logging.error('IP {} Port {}: closed'.format(ip, port))
            else:
                if self.verbose:
                    self.status_print(' pass', 2)
                logging.info('Port {}: open'.format(port))

        return ports_failed

    @staticmethod
    def status_print(message, mode):
        """
        Funstion to provide some nicer status printing
        :param message: what should be printed
        :param mode: begining of a message (1) or end of a message (2)
        :return:
        """
        if mode == 1:
            sys.stdout.write(message.ljust(15, '.'))
            sys.stdout.flush()
        if mode == 2:
            print(message.rjust(10, '.'))

    @staticmethod
    def extract_ip(string):
        return re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", string)

    def build_ip_list(self, base_list):
        """
        Takes the output from getrackinfo and parses the IPs of the individual nodes from it
        :param base_list: base list to add IPs to
        :return: base_list with IPs added
        """
        p = subprocess.check_output(['getrackinfo', '-v'])
        rack_ips = iter(p.splitlines())
        for line in rack_ips:
            if 'NTP' in line:
                base_list['ntp']['ip_list'] = self.extract_ip(next(rack_ips))
            elif 'DNS' in line:
                next(rack_ips)
                next(rack_ips)
                base_list['dns']['ip_list'] = self.extract_ip(next(rack_ips))
            elif 'public' in line:
                base_list['nodes']['ip_list'].extend(self.extract_ip(line))
            elif 'private Ipmi' in line:
                base_list['rmm']['ip_list'].extend(self.extract_ip(line))

        return base_list

    def check_hostnames(self, host_name, ip):
        test = socket.gethostbyname(host_name)
        if test == ip:
            test = 'PASS'

    def check_mtu(self, ip, port):
        routeinfo = subprocess.check_output(['ip', 'route', 'get', ip])
        dev = re.search('.*dev (\w+) .*', routeinfo).groups()[0]
        mtuinfo = subprocess.check_output(['ip', 'link', 'show', dev])
        mtu = re.search('.*mtu ([0-9]+) .*', mtuinfo).groups()[0]
        print(mtu)
        return int(mtu)

    def main(self):
        any_failed = []
        # Build IPs list from node
        base_list = {
            "nodes": {
                "ip_list": [],
                "ports": {
                    "SSH": [22],
                    "GUI": [80, 443, 4443],
                    "Geo Rep": [9094, 9095, 9096, 9097, 9098],
                    "s3": [9020, 9021, 9026, 9027],
                    "HDFS": [9040],
                    "ATMOS": [9022, 9023],
                    "Swift": [9024, 9025],
                    "CAS": [3218, 9250],
                    "NFS": [111, 2049, 10000]
                }
            },
            "rmm": {
                "ip_list": [],
                "ports": {
                    "RMM UI": [80, 443],
                    "CD": [5120, 5124],
                    "FD": [5123, 5127],
                    "Video": [7578, 7582]
                }
            },
            "dns": {
                "ip_list": [],
                "ports": {'Ports': [53]}
            },
            "ntp": {
                "ip_list": [],
                "ports": {'Ports': [123]}
            }
            # "smtp": {
            #     "ip_list": ["202.238.84.20"],
            #     "ports": {'Ports': [25]}
            # },
            # "ad": {
            #     "ip_list": ["10.247.134.54"],
            #     "ports": {'Ports': [389, 636]}
            # }
        }

        to_check = self.build_ip_list(base_list)

        # Iterate through the loaded data and check the IPs and ports

        failed_ips = self.ip_scanner(to_check)
        if failed_ips:
            any_failed.extend(failed_ips)

        if any_failed:
            print('There were issues with the following servers, please check the log for more details:')
            for i in any_failed:
                print('  {}'.format(i))


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true', default=False)
    return vars(parser.parse_args())


if __name__ == '__main__':
    params = get_args()
    scanner = NetworkScanner(params)
    scanner.main()

#!/usr/bin/python3

import threading
import sys
import math
import ipaddress
import argparse
import netifaces
import ipscanner
import io as _io

class Static:
    ips = []
    ipStats = dict()
    lock = threading.Lock()


class Scanner:
    def __init__(self, ip, interface, methods):
        self.ip = ip
        self.interface = interface
        self.methods = methods
        self.scan()

    def scan(self):
        result = False

        if 'ping' in self.methods and not result:
            result += ipscanner.PingScanner(self.ip, self.interface).scan()
        if 'arping' in self.methods and not result:
            result += ipscanner.ArpingScanner(self.ip, self.interface).scan()
        if 'portscan' in self.methods and not result:
            result += ipscanner.PortscanScanner(self.ip, None).scan()
        if 'fastportscan' in self.methods and not result:
            result += ipscanner.FastportscanScanner(self.ip, None).scan()

        if result:
            Static.ipStats[self.ip] = 'On'
        else:
            Static.ipStats[self.ip] = 'Off'


class MyThread(threading.Thread):
    def __init__(self, thread_id, name, interface, methods):
        threading.Thread.__init__(self)
        self.threadID = thread_id
        self.name = name
        self.interface = interface
        self.methods = methods
        self.kill_received = False

    def run(self):
        while Static.ips and not self.kill_received:
            Static.lock.acquire()
            if len(Static.ips) > 0:
                ip = str(Static.ips[0])
                del Static.ips[0]
                Static.lock.release()
                Scanner(ip, self.interface, self.methods)


class ProgressBar:
    def __init__(self, symbol='*', length=40, maxitems=100):
        self.symbol = symbol
        self.maxitems = maxitems
        self.length = length

    def print(self,progress):
        self._test_progress(progress)

        x = self._get_number_of_symbols(progress)
        proc = self._get_percentage(progress)

        sys.stdout.write('{:4d}/{:4s} |{:{width}}| {:3d}%\r'.format(progress,
                                                                    str(self.maxitems),
                                                                    self.symbol * x,
                                                                    proc,
                                                                    width=self.length))

        if progress == self.maxitems:
            sys.stdout.write("\033[K")

    def _test_progress(self, progress):
        if not (isinstance(progress, float) | isinstance(progress, int)):
            raise ValueError("progress must be a float or int")
        if progress > self.maxitems:
            raise ValueError("progress can't be grater than maxitems")

    def _get_number_of_symbols(self, progress):
        self._test_progress(progress)
        return math.floor((self.length * progress) / self.maxitems)

    def _get_percentage(self, progress):
        self._test_progress(progress)
        return math.floor((progress * 100) / self.maxitems)


class AnalyzePool:
    pool = []
    interface = ''
    on = 0
    off = 0
    scanned = False
    destination = ''
    outputfilename = False
    outputfile = ''
    methods = []

    def __init__(self, threads=5, silentmode=False):
        self.threads = threads
        self.silentmode = silentmode

    def __del__(self):
        if isinstance(self.outputfile, _io.TextIOWrapper):
            self.outputfile.close()

    def set_outputfile(self, filename):
        self.outputfilename = filename
        self.outputfile = open(self.outputfilename, "w")

    def set_methods(self, methods):
        if methods:
            self.methods = methods[0]
        else:
            self.methods = ['ping']

    def generate_ips(self, network: str) -> None:
        Static.ips = list(ipaddress.ip_network(network).hosts())

    def analyze(self):
        on = 0
        off = 0
        for key, val in Static.ipStats.items():
            if val == "On":
                on += 1
            else:
                off += 1
        return on, off

    def set_network(self, network):
        self.destination = str(network)
        self.generate_ips(network)

    def set_ip(self, ip):
        self.destination = str(ipaddress.IPv4Address(ip))
        Static.ips.append(ip)

    def set_interface(self, interface: str):
        self.interface = interface

    def _printSummary(self):
        if not self.silentmode:
            print('{:15s} ==> online={:d} offline={:d}'.format(str(self.destination),
                                                               self.on,
                                                               self.off))

    def write_to_file(self):
        if self.outputfilename:
            helper = lambda val: 1 if val == 'On' else 0
            # json.dump(Static.ipStats, self.outputfile)
            for key, val in Static.ipStats.items():
                self.outputfile.write('{:s};{:d}\n'.format(key, helper(val)))
            return True
        else:
            return False

    def check(self):
        Static.ipStats = {}
        self.pool = []
        ips_size = len(Static.ips)

        self._start_threads()

        if not self.silentmode:
            pb = ProgressBar(maxitems=ips_size, length=80)

        try:
            while Static.ips and not self.silentmode:
                pb.print(ips_size-len(Static.ips))
        except KeyboardInterrupt:
            for t in self.pool:
                t.kill_received = True
            sys.exit(0)

        for t in self.pool:
            t.join()
        else:
            if not self.silentmode:
                pb.print(ips_size - len(Static.ips))

        self.on, self.off = self.analyze()
        self._printSummary()
        self.write_to_file()
        return self.on, self.off, Static.ipStats, self.destination

    def _start_threads(self):
        for i in range(self.threads):
            t = MyThread(i, "thread-" + str(i), self.interface, self.methods)
            t.start()
            self.pool.append(t)


def main():
    # only for check values
    def check_ips(ips):
        for ip in ips:
            ipaddress.IPv4Address(ip)

    def check_networks(networks):
        for network in networks:
            ipaddress.IPv4Network(network)

    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--network',
                        action="append",
                        dest="network",
                        help="Network to scan (format IP/MASK)",
                        default=[])
    parser.add_argument('-m', '--methods', action="append", dest="methods", nargs='+',
                        choices=['ping', 'arping', 'portscan', 'fastportscan'],
                        help="type of scan")
    parser.add_argument('-i', '--ip',
                        action="append",
                        dest="ip",
                        help="IP to scan",
                        default=[])
    parser.add_argument('-I', '--interface', dest='iface', help='interface using to scan')
    parser.add_argument('-t', dest='threads', type=int, default=80, help="number of threads")
    parser.add_argument('-o', '--output', dest='output', help='output file', default=False)
    parser.add_argument('-s', dest='silent_mode', action='store_true', help='Silent mode', default=False)
    parser.set_defaults(silence=False)
    args = parser.parse_args()

    check_ips(args.ip)
    check_networks(args.network)

    analyze = AnalyzePool(threads=args.threads, silentmode=args.silent_mode)
    analyze.set_methods(args.methods)
    analyze.set_outputfile(args.output)

    if not args.iface:
        interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        analyze.set_interface(interface)
    elif args.iface in netifaces.interfaces():
        analyze.set_interface(args.iface)
    else:
        raise ValueError("Unexisting interface")

    for net in args.network:
        analyze.set_network(ipaddress.IPv4Network(net, strict=False))
        analyze.check()

    for ip in args.ip:
        analyze.set_ip(ipaddress.IPv4Address(ip))
        analyze.check()


if __name__ == '__main__':
    try:
        main()
    except ipaddress.AddressValueError as e:
        print(e.__str__())
    except ipaddress.NetmaskValueError as e:
        print(e.__str__())
    except ValueError as e:
        print(e)
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(e.__str__())

#!/usr/bin/python3

import threading
import subprocess
import sys
import math
import ipaddress
import argparse
import netifaces
import ipscanner

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
            ipStats[self.ip] = 'On'
        else:
            ipStats[self.ip] = 'Off'


class myThread(threading.Thread):
    def __init__(self, threadID, name, interface, methods):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.interface = interface
        self.methods = methods
        self.kill_received = False

    def run(self):
        while ips and not self.kill_received:
            lock.acquire()
            if len(ips) > 0:
                ip = str(ips[0])
                del ips[0]
                lock.release()
                Scanner(ip, self.interface, self.methods)



class ProgressBar:
    def __init__(self, symbol='*', length=40, maxitems=100):
        self.symbol = symbol
        self.maxitems = maxitems
        self.length = length

    def print(self,proggress):
        x = self.getNumberOfSymbols(proggress)
        proc = self.getPercentage(proggress)

        sys.stdout.write('{:4d}/{:4s} |{:{width}}| {:3d}%\r'.format(proggress,
                                                                      str(self.maxitems),
                                                                      (self.symbol * x),
                                                                      proc,
                                                                      width=self.length))

        if proggress == self.maxitems:
            sys.stdout.write("\033[K")

    def getNumberOfSymbols(self, proggress):
        return math.floor((self.length * proggress) / self.maxitems)

    def getPercentage(self, proggress):
        return math.floor((proggress * 100) / self.maxitems)


class AnaylyzePool:
    def __init__(self, threads=5, silentmode=False):
        self.threads = threads
        self.silentmode = silentmode
        self.pool = []
        self.interface = ''
        self.on = 0
        self.off = 0
        self.scanned = False
        self.destination = ''
        self.outputFileName = False
        self.outputFile = ''
        self.methods = []

    def __del__(self):
        self.outputFile.close()

    def setOutputFile(self, filename):
        self.outputFileName = filename
        self.outputFile = open(self.outputFileName, "w")

    def setMethods(self, methods):
        if methods:
            self.methods = methods[0]

    def generateIPs(self, network):
        global ips
        ips = list(ipaddress.ip_network(network).hosts())

    def analyze(self, ipStats):
        on = 0
        off = 0
        for key, val in ipStats.items():
            if val == "On":
                on += 1
            else:
                off += 1
        return on, off

    def setNetwork(self, network):
        self.destination = str(network)
        self.generateIPs(network)

    def setIp(self, ip):
        self.destination = str(ip)
        global ips
        ips.append(ip)

    def setInterface(self, interface):
        self.interface = interface

    def _printSummary(self):
        if not self.silentmode:
            print('{:15s} ==> online={:d} offline={:d}'.format(str(self.destination),
                                                           self.on,
                                                           self.off))

    def writeToFile(self, ipStats):
        if self.outputFileName:
            helper = lambda val: 1 if val == 'On' else 0
            for key, val in ipStats.items():
                self.outputFile.write('{:s};{:d}\n'.format(key, helper(val)))

    def check(self):
        global ipStats
        ipStats = {}
        self.pool = []
        ipsSize = len(ips)

        for i in range(self.threads):
            t = myThread(i, "thread-" + str(i), self.interface, self.methods)
            t.start()

            self.pool.append(t)

        if not self.silentmode:
            pb = ProgressBar(maxitems=ipsSize, length=80)

        try:
            while ips and not self.silentmode:
                pb.print(ipsSize-len(ips))
        except KeyboardInterrupt:
            for t in self.pool:
                t.kill_received = True
            sys.exit(0)

        for t in self.pool:
            t.join()
        else:
            if not self.silentmode:
                pb.print(ipsSize - len(ips))

        self.on, self.off = self.analyze(ipStats)

        self._printSummary()
        self.writeToFile(ipStats)
        return self.on, self.off, ipStats, self.destination


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--network', action="append", dest="network", help="Network to scan (format IP/MASK)", default=[])
    parser.add_argument('-m', '--methods', action="append", dest="methods", nargs='+', choices=['ping', 'arping', 'portscan', 'fastportscan'], help="type of scan")
    parser.add_argument('-i', '--ip', action="append", dest="ip", help="IP to scan", default=[])
    parser.add_argument('-I', '--interface', dest='iface', help='interface using to scan')
    parser.add_argument('-t', dest='threads', type=int, default=80, help="number of threads")
    parser.add_argument('-o', '--output', dest='output', help='output file', default=False)
    parser.add_argument('-s', dest='silent_mode', action='store_true', help='Silent mode', default=False)
    parser.set_defaults(silence=False)
    args = parser.parse_args()

    # argdict = vars(args)

    analyze = AnaylyzePool(threads=args.threads, silentmode=args.silent_mode)
    analyze.setMethods(args.methods)
    analyze.setOutputFile(args.output)

    if not args.iface:
        interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        analyze.setInterface(interface)
    elif args.iface in netifaces.interfaces():
        analyze.setInterface(args.iface)
    else:
        try:
            raise ValueError
        except ValueError:
            print("Unexisting interface")
            sys.exit(1)

    for net in args.network:
        try:
            analyze.setNetwork(ipaddress.IPv4Network(net, strict=False))
            analyze.check()
        except ipaddress.AddressValueError:
            print("Invalid network address")

    for ip in args.ip:
        try:
            analyze.setIp(ipaddress.IPv4Address(ip))
            analyze.check()
        except ipaddress.AddressValueError:
            print("Invalid IP address")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)



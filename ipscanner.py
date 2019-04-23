import subprocess
import socket


class AbstractScanner:
    def __init__(self, ip: str, interface: str):
        self.ip = ip
        self.interface = interface

    def scan(self):
        pass


class PingScanner(AbstractScanner):
    def __init__(self, ip, interface):
        super().__init__(ip, interface)

    def scan(self):
        try:
            subprocess.check_output(["ping", "-c", "1", "-W", "1", "-I", self.interface, self.ip],
                                    stderr=subprocess.PIPE)
            return True
        except subprocess.CalledProcessError:
            return False


class ArpingScanner(AbstractScanner):
    def __init__(self, ip, interface):
        super().__init__(ip, interface)

    def scan(self):
        try:
            subprocess.check_output(["arping", "-c", "1", "-w", "1", "-I", self.interface, self.ip],
                                    stderr=subprocess.PIPE)
            return True
        except subprocess.CalledProcessError:
            return False


class PortscanScanner(AbstractScanner):
    def __init__(self, ip, interface):
        super().__init__(ip, interface)

    def scan(self):
        for port in range(1, 10000):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.001)
            result = sock.connect_ex((self.ip, port))
            if result == 0:
                sock.close()
                return True
            sock.close()
        return False


class FastportscanScanner(AbstractScanner):
    def __init__(self, ip, interface):
        super().__init__(ip, interface)

    def scan(self):
        for port in [21, 22, 25, 80, 110, 113, 902, 3306, 8080]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.0001)
            result = sock.connect_ex((self.ip, port))
            if result == 0:
                sock.close()
                return True
            sock.close()
        return False

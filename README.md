# dnsteal

This is a DNS exfiltration tool that uses a custom protocol to transmit arbitrary (compressed and encoded) JSON data over DNS, and can reassemble the data on the other end - even if it arrives in a different order from that which it was sent in. It does not require running or setting up a real DNS server, opting instead for a fake one written in Python, and does not even need to be able to reach the fake server directly, taking advantage of DNS hierarchy.

This is particularly useful in a cloud environment such as AWS, because it means that you can still exfiltrate data under the following conditions:

  * You can't change the targets DNS server to one of your choice,
  * Are not able to make outbound DNS connections
  * Are stuck using an internal resolver.

The counter to this of course is to figure out a way to do DNS filtering in your cloud provider (i.e AWS). This requires a bit of effort because you don't control the internal DNS resolvers.

Other features include:
  * The client supports making DNS requests using custom DNS servers, avoiding having to change the target OS's DNS.
  * Support for exfiltrating multiple files in a batch.
  * Gzip compression to reduce network usage
  * The server supports listening on any port (not just 53) which is useful if you don't have the permission to listen on ports below 1024, and plan on routing / proxying to listen on 53 externally.
  * Documented specification used for data exfiltration, making writing your own client that is plug-and-play with the Python server feasible.

## Requirements

`dnsteal` only requires:

 * Target machine (with Python 3)
 * Server machine (also with Python 3)
 * Domain name that resolves to the server machine.

That's it! It does not require:

* Libraries, packages, package managers
* The setup of a real DNS server
* Root privileges*

\**Root privileges aren't needed on the client, but may be needed on the server depending on what port you run it on.*

### Basic exfiltration example

#### Server
To start the fake DNS server, you can use the following command:

```bash
python dnsteal.py 0.0.0.0 53
```

The port you choose will determine whether or not you need root permissions. You can also use workarounds by routing traffic in `iptables`.

#### Client

Client docs TBD
```
python dnsteal_client.py
```

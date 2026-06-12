import argparse
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, DNS, load_layer, conf, Raw
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.all import TLS, TLSClientHello

load_layer("http")
load_layer("tls")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Network Sniffer")
    parser.add_argument("-i", dest="interface", help="Interface")
    parser.add_argument("-r", dest="tracefile", help="Tracefile")
    parser.add_argument("expression", nargs="?", help="BPF filter expression")
    return parser.parse_args()

def get_packet_info(pkt):
    if not pkt.haslayer(IP):
        return None

    timestamp = datetime.fromtimestamp(float(pkt.time))
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    else:
        return None

    return timestamp, src_ip, src_port, dst_ip, dst_port

def print_output(protocol, metadata, message):
    timestamp, src_ip, src_port, dst_ip, dst_port = metadata
    print(f"{timestamp} {protocol:<4} "
          f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} {message}")

def handle_dns(pkt, metadata):
    dns = pkt[DNS]
    if dns.qr != 0 or dns.qd is None:
        return

    if dns.qd.qtype != 1:
        return

    name = dns.qd.qname.decode(errors="ignore").rstrip(".")
    internal = ""
    if name.endswith((".local", ".corp", ".internal")):
        internal = " INTERNAL"

    print_output("DNS", metadata, f"{name}{internal}")

def handle_http(http_layer, metadata):
    try:
        method = http_layer.Method.decode() if isinstance(http_layer.Method, bytes) else http_layer.Method
        host = http_layer.Host.decode() if isinstance(http_layer.Host, bytes) else http_layer.Host
        path = http_layer.Path.decode() if isinstance(http_layer.Path, bytes) else http_layer.Path
    except:
        return

    message = f"{host} {method} {path}"

    if hasattr(http_layer, "User_Agent") and http_layer.User_Agent:
        ua_raw = http_layer.User_Agent.decode() if isinstance(http_layer.User_Agent, bytes) else http_layer.User_Agent
        if any(x in ua_raw.lower() for x in ["curl", "wget", "python"]):
            message += f" AUTOMATION {ua_raw}"

    print_output("HTTP", metadata, message)

def handle_tls(ch, metadata):
    server_name = "NO SNI"
    exts = getattr(ch, "extensions", getattr(ch, "ext", None))
    
    if exts:
        for ext in exts:
            if getattr(ext, "type", -1) == 0:
                try:
                    server_name = ext.servernames[0].servername.decode(errors="ignore")
                except:
                    pass
                break

    print_output("TLS", metadata, server_name)

def process_packet(pkt):
    metadata = get_packet_info(pkt)
    if not metadata:
        return

    if pkt.haslayer(UDP) and (pkt.haslayer(DNS) or (pkt.haslayer(Raw) and len(pkt[Raw].load) > 10)):
        try_dns = pkt[DNS] if pkt.haslayer(DNS) else DNS(pkt[Raw].load)
        try:
            if try_dns.qr == 0:
                handle_dns(try_dns, metadata)
                return
        except:
            pass

    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        load = bytes(pkt[Raw].load)

        if len(load) >= 5 and load[0] == 0x16 and load[1] == 0x03:
            try:
                forced_tls = TLS(load)
                if forced_tls.haslayer(TLSClientHello):
                    handle_tls(forced_tls[TLSClientHello], metadata)
                    return
            except:
                pass

        elif any(load.startswith(m) for m in [b'GET ', b'POST ', b'PUT ', b'DELETE ']):
            try:
                forced_http = HTTPRequest(load)
                handle_http(forced_http, metadata)
                return
            except:
                pass

    if pkt.haslayer(TLSClientHello):
        handle_tls(pkt[TLSClientHello], metadata)
    elif pkt.haslayer(HTTPRequest):
        handle_http(pkt[HTTPRequest], metadata)

def main():
    conf.verb = 0
    conf.max_list_count = 10000
    args = parse_arguments()

    sniff_kwargs = {
        "prn": process_packet,
        "store": False
    }

    if args.expression:
        sniff_kwargs["filter"] = args.expression

    if args.tracefile:
        sniff_kwargs["offline"] = args.tracefile
    else:
        iface = args.interface if args.interface else "eth0"
        sniff_kwargs["iface"] = iface

    sniff(**sniff_kwargs)

if __name__ == "__main__":
    main()

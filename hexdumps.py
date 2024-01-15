from scapy.all import *

def hex_to_packet(hex_data):
    packet_data = bytes.fromhex(hex_data)
    return Ether(packet_data)

def analyze_packet(packet):
    
    results ={}
    
    results['Packet Length'] = len(packet)

    if ARP in packet:
        arp_layer = packet[ARP]
        results['ARP Operation'] = 'Request' if arp_layer.op == 1 else 'Reply'
        results['Source MAC'] = arp_layer.hwsrc
        results['Source IP'] = arp_layer.psrc
        results['Destination MAC'] = arp_layer.hwdst
        results['Destination IP'] = arp_layer.pdst

    if IP in packet:
        ip_layer = packet[IP]
        results['Source IP'] = ip_layer.src
        results['Destination IP'] = ip_layer.dst
        results['IP TTL'] = ip_layer.ttl
        results['IP Flags'] = ip_layer.flags
        results['IP Fragmentation'] = 'More Fragments' if 'MF' in ip_layer.flags else 'Last Fragment'
        results['IP Fragment Offset'] = ip_layer.frag

        if TCP in packet:
            tcp_layer = packet[TCP]
            results['Source Port'] = tcp_layer.sport
            results['Destination Port'] = tcp_layer.dport
            results['TCP Flags'] = tcp_layer.flags

        elif UDP in packet:
            udp_layer = packet[UDP]
            results['Source Port'] = udp_layer.sport
            results['Destination Port'] = udp_layer.dport

        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            results['ICMP Type'] = icmp_layer.type
            results['ICMP Code'] = icmp_layer.code
            if 'seq' in icmp_layer.fields:
                results['ICMP Sequence Number'] = icmp_layer.seq

    if packet.haslayer(Raw):
        raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
        results['Raw Data'] = raw_data
        if raw_data.startswith('GET') or raw_data.startswith('POST'):
            results['HTTP Method'] = raw_data.split(' ')[0]
            results['HTTP Path'] = raw_data.split(' ')[1]
            for line in raw_data.split('\n'):
                if line.startswith('Host:'):
                    results['HTTP Host'] = line.split(': ')[1].strip()

    return results

dumps = ["3894ed5c20d2cc15312d08840800450000b5af8d400040062a790a0b0c738efabac4ec20005062663cb50049d6c6801801f660e400000101080a6522dbfdbad4a691474554202f20485454502f312e310d0a486f73743a207777772e676f6f676c652e636f6d0d0a557365722d4167656e743a20576765742f312e32312e320d0a4163636570743a202a2f2a0d0a4163636570742d456e636f64696e673a206964656e746974790d0a436f6e6e656374696f6e3a204b6565702d416c6976650d0a0d0a",
"3894ed5c20d2cc15312d08840800450000d04a4640004006591e0a0b0c7340be3f88beb40050e39ead9a1c12ae50801801f6978600000101080ab047fa89cc09e05d474554202f3f757369643d313926757469643d313834323535353335343420485454502f312e310d0a486f73743a207777312e706f726e6f6875622e636f6d0d0a557365722d4167656e743a20576765742f312e32312e320d0a4163636570743a202a2f2a0d0a4163636570742d456e636f64696e673a206964656e746974790d0a436f6e6e656374696f6e3a204b6565702d416c6976650d0a0d0a",
"cc15312d08843894ed5c20d20800450000787e15400040068fe10a0b0c010a0b0c738d59200850bc1a846123daf7801801c9432000000101080a1acc65593fb52941474554202f726f6f74446573632e786d6c20485454502f312e310d0a486f73743a2031302e31312e31322e3131353a383230300d0a4163636570743a202a2f2a0d0a0d0a",
"3894ed5c20d2cc15312d08840800450000542d0e4000400119bb0a0b0c731facbdb60800c33900020003d44b9d6500000000003d040000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
"3894ed5c20d2cc15312d0884080045000047b2c7000040119b550a0b0c730a0b0c01cf08003500332cce5c530100000100000000000108736176656c69666502696e027561000001000100002905c0000000000000",
"ffffffffffff00bd3e08def40806000108000604000100bd3e08def40a0b0c6fffffffffffff0a0b0c01",
"3894ed5c20d2cc15312d088408004500003c0000400040060e330a0b0c730a0b0c0120088d96d259df2c0632fef7a012fe882cb80000020405b40402080a3fbc7c711ad3b7cb01030307"
]

for hex_dump in dumps:
    packet=hex_to_packet(hex_dump)
    analysis_results = analyze_packet(packet)
    print("Analysing packet:" + "\n" + hex_dump + "\n")
    for key, value in analysis_results.items():
        print(f"{key}:{value}")
        
    print("\n")
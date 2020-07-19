/*************************************************************************
*********************** P A R S E R  *******************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            TYPE_TRACKED_UDP: parse_tracked_udp;
            TYPE_TRACK_RESPONSE: parse_track_response;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        meta.srcPort = hdr.tcp.srcPort;
        meta.dstPort = hdr.tcp.dstPort;
        hdr.tcp.setValid();
        hdr.udp.setInvalid();
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        meta.srcPort = hdr.udp.srcPort;
        meta.dstPort = hdr.udp.dstPort;
        hdr.udp.setValid();
        hdr.tcp.setInvalid();
        transition accept;
    } 

    state parse_tracked_udp {
        hdr.ipv4.protocol = hdr.ipv4.protocol - 1;
        meta.tracked_packet_flag = 1;
        packet.extract(hdr.udp);
        meta.srcPort = hdr.udp.srcPort;
        meta.dstPort = hdr.udp.dstPort;
        hdr.udp.setValid();
        hdr.tcp.setInvalid();
        transition accept;
    }

    state parse_track_response {
        packet.extract(hdr.udp);
        meta.srcPort = hdr.udp.srcPort;
        meta.dstPort = hdr.udp.dstPort;
        hdr.udp.setValid();
        hdr.tcp.setInvalid();

        packet.extract(hdr.tracking);
        hdr.tracking.setValid();
        hdr.tracking.hop_num = hdr.tracking.hop_num + 1;
        
        transition accept;
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.tracking);
    }
}


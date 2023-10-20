#include <core.p4>
#include <v1model.p4>

#define PORT_INGRESS 0
#define PORT_FORWARD_NON_DNS 1
#define PORT_FORWARD_DNS 2

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

header gtp_u_header_t {
    bit<3> version;
    bit<1> PT;
    bit<1> reserved;
    bit<1> E;
    bit<1> S;
    bit<1> PN;
    bit<8> messageType;
    bit<16> length;
    bit<32> teid;
}

header gtp_u_ext_psc_t {
    bit<32> headerType;
    bit<8> extLenght;
    bit<8> pduType;
    bit<8> QFI;
    bit<8> nextExtHeader;
    
}


struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
    gtp_u_header_t gtp_u_header;
    gtp_u_ext_psc_t gtp_u_ext_psc;
    ipv4_t inner_ipv4;
    udp_t inner_udp;
}

struct metadata {
}

parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        transition select(standard_metadata.ingress_port) {
            PORT_INGRESS: parse_start;
            default: accept;
        }
    }

    state parse_start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w17: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            2152: parse_gtp_u; // GTP-U port
            default: accept;
        }
    }

    state parse_gtp_u {
        packet.extract(hdr.gtp_u_header);
        transition select(hdr.gtp_u_header.E) {
            1: parse_gtp_u_ext;
            default: parse_inner_ipv4;
        }
    }

    state parse_gtp_u_ext {
        packet.extract(hdr.gtp_u_ext_psc);
        transition parse_inner_ipv4;
    }
    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition select(hdr.inner_ipv4.protocol) {
            8w0d17: parse_inner_udp;
            default: accept;
        }
    }

    state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action set_egress_port(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
 

    apply {
        if (standard_metadata.ingress_port == PORT_FORWARD_NON_DNS) {
            set_egress_port(PORT_INGRESS);
        } else if (standard_metadata.ingress_port == PORT_INGRESS && hdr.gtp_u_header.isValid() && hdr.inner_udp.isValid() && (hdr.inner_udp.dstPort == 53 || hdr.inner_udp.dstPort == 5353)) {
            // Remove GTP and UDP headers

            hdr.ipv4.setInvalid();
            hdr.udp.setInvalid();
            hdr.gtp_u_header.setInvalid();
            hdr.gtp_u_ext_psc.setInvalid(); 

            // Forward to port 2 (DNS)
            set_egress_port(PORT_FORWARD_NON_DNS);
        } else {
            // Forward to port 1 (non-DNS)
            set_egress_port(PORT_FORWARD_NON_DNS);
        }
    }





}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {  }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {

    }
}


control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.gtp_u_header);
        packet.emit(hdr.gtp_u_ext_psc);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.inner_udp);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

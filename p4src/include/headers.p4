/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_RECIRC 4
#define PKT_INSTANCE_TYPE_NORMAL 0

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_TCP = 0x06;
const bit<8> TYPE_UDP = 0x11;
const bit<8> TYPE_TRACKED_UDP = 0x12;
const bit<8> TYPE_TRACK_RESPONSE = 0x13;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<49> swName_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header tracking_t {
    bit<19> enq_qdepth;
    bit<19> deq_qdepth;
    bit<16> hop_num;
    swName_t sw_name;
    bit<1> final_hop;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;
    tracking_t   tracking;
}

struct metadata {
    bit<1> tracked_packet_flag;
    bit<14> ecmp_group_id;
    bit<16> ecmp_hash;
    bit<16> srcPort;
    bit<16> dstPort;
    bit<19> enq_qdepth;
    bit<19> deq_qdepth;
    bit<19> hop_num;
    bit<1> final_hop;
    bit<14> dst_type;
}

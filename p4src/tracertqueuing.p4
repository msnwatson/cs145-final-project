/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/headers.p4"
#include "include/parsers.p4"

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {    
    action drop() {
        mark_to_drop();
    }

    action ecmp_group(bit<14> ecmp_group_id, bit<16> num_nhops){
        hash(meta.ecmp_hash,
	    HashAlgorithm.crc16,
	    (bit<1>)0,
	    { hdr.ipv4.srcAddr,
	      hdr.ipv4.dstAddr,
          meta.srcPort,
          meta.dstPort,
          hdr.ipv4.protocol}, num_nhops);

	    meta.ecmp_group_id = ecmp_group_id;
    }

    action set_nhop(macAddr_t dstAddr, egressSpec_t port) {

        //set the src mac address as the previous dst, this is not correct right?
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;

       //set the destination mac address that we got from the match in the table
        hdr.ethernet.dstAddr = dstAddr;

        //set the output port that we also get from the table
        standard_metadata.egress_spec = port;

        //decrease ttl by 1
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action set_dst_type(bit<14> dst_type) {
        meta.dst_type = dst_type;
    }

    action set_swname(swName_t sw_name) {
        hdr.tracking.sw_name = sw_name;
    }

    table sw_name {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_swname;
        }
        size = 1024;
    }

    table dst_type_table {
        key = {
            standard_metadata.egress_spec: exact;
        }
        actions = {
            set_dst_type;
        }
    }

    table ecmp_group_to_nhop {
        key = {
            meta.ecmp_group_id:    exact;
            meta.ecmp_hash: exact;
        }
        actions = {
            drop;
            set_nhop;
        }
        size = 1024;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_nhop;
            ecmp_group;
            drop;
        }
        size = 1024;
        default_action = drop;
    }

    apply {
        if (standard_metadata.instance_type != 0) {
            hdr.tcp.setInvalid();
            hdr.udp.setValid();
            hdr.tracking.setValid();

            // Swap source and destination
            ip4Addr_t tmp;
            tmp = hdr.ipv4.srcAddr;
            hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
            hdr.ipv4.dstAddr = tmp;

            // Swap source and dest port
            bit<16> tmp2;
            tmp2 = hdr.udp.srcPort;
            hdr.udp.srcPort = hdr.udp.dstPort;
            hdr.udp.dstPort = tmp2;

            // Setting all data and applying table
            sw_name.apply();
            hdr.tracking.enq_qdepth = meta.enq_qdepth;
            hdr.tracking.deq_qdepth = meta.deq_qdepth;
            hdr.tracking.final_hop = meta.final_hop;
            hdr.ipv4.protocol = 19;
        }

        if (hdr.ipv4.isValid()) {
            switch (ipv4_lpm.apply().action_run){
                ecmp_group: {
                    switch(ecmp_group_to_nhop.apply().action_run) {
                        set_nhop: {
                            dst_type_table.apply();
                        }
                    }
                }
                set_nhop: {
                    dst_type_table.apply();
                }
            }
            if (hdr.tracking.isValid() && meta.dst_type == 1) {
                hdr.ipv4.protocol = 18;
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {    
    apply {
        if (meta.tracked_packet_flag == 1 && standard_metadata.instance_type == 0) {
            meta.enq_qdepth = standard_metadata.enq_qdepth;
            meta.deq_qdepth = standard_metadata.deq_qdepth;

            if (meta.dst_type == 1) {
                meta.final_hop = 1;
            }

            hdr.ipv4.protocol = 18;

            clone3(CloneType.E2E, 100, meta);
        }
        if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_EGRESS_CLONE) {
            recirculate(meta);
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
              hdr.ipv4.hdrChecksum,
              HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

struct IpHdr {
    uint8_t v_:4;           // version
    uint8_t hdr_len_:4;     // header_length
    uint8_t tos_val_;

    uint16_t tot_len_;      // total_length
    uint16_t id_val_;       // identification
    
    uint8_t flags_val_:3;
    uint16_t frag_offset_:13;

    uint8_t ttl_val_;
    uint8_t protocol_val_;
    uint16_t checksum_val_;
    
    Ip src_ip_;             // sip
    Ip dest_ip_;            // dip
};

struct IcmpHdr {
    uint8_t type_;
    uint8_t code_;
    uint16_t check_;
    uint16_t id_;
    uint16_t seq_;

};

#pragma pack(push, 1)
struct EthIpPacket final{
        EthHdr eth_;
        IpHdr ip_;
	IcmpHdr icmp_; 
};

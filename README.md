# pcap_analysis
scripts about analyzing network basic characteristics(bandwidth/one-way delay/loss)
- Packet Match between the sender's pcap and the receiver's pcap is based on IPID
- Take care of the TSO/GSO/GRO mechanism: ethtool -K {network surface} tso off gso off gro off

this script is not mature enough currently so any advice is welcome!

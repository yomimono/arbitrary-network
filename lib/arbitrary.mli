open QuickCheck_gen

val arbitrary_ipv4 : Ipaddr.V4.t gen
val arbitrary_ipv6 : Ipaddr.V6.t gen
val arbitrary_ip : Ipaddr.t gen
val arbitrary_port : int gen
val arbitrary_tcp_or_udp : int gen
val arbitrary_mac : Macaddr.t gen

val qc_printer : QuickCheck.testresult -> string

(* TODO: arbitrary_frame, arbitrary_tcp,
   arbitrary_udp, arbitrary_payload .  (arbitrary_http, etc would be nice too) 
   there is the pcap module that mort wrote forever ago, but I think that's at
   extreme prototype stage at best.
*)

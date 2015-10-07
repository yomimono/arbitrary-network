open QuickCheck
open QuickCheck_gen

let arbitrary_port = 
  arbitrary_int >>= fun p -> ret_gen (abs (p mod 65536))

let arbitrary_ipv6 =
  arbitrary_bytesequenceN 16 >>= fun bytes ->
  ret_gen (Ipaddr.V6.of_bytes_exn bytes)

let arbitrary_ipv4 =
  arbitrary_bytesequenceN 4 >>= fun bytes ->
  ret_gen (Ipaddr.V4.of_bytes_exn bytes)

let arbitrary_ip = 
  let byte_switch is_ipv6 =
    match is_ipv6 with
    | true -> arbitrary_ipv6 >>= fun ip -> ret_gen (Ipaddr.V6 ip)
    | false -> arbitrary_ipv4 >>= fun ip -> ret_gen (Ipaddr.V4 ip)
  in
  arbitrary_bool >>= byte_switch

(* protocol really should probably be arbitrary_int, but instead
 * we'll choose randomly between 6 (tcp) and 17 (udp).  (next header in ipv6
  * is 8 bits, same for protocol in ipv4) *)
let arbitrary_tcp_or_udp = 
  arbitrary_bool >>= fun p -> ret_gen (if p then 6 else 17)

let arbitrary_uint16 =
  arbitrary_int >>= fun i -> ret_gen (abs (i mod 65536))

let arbitrary_mac = 
  arbitrary_bytesequenceN 6 >>= fun b -> ret_gen (Macaddr.of_bytes_exn b)

let arbitrary_cstruct n =
  arbitrary_bytesequenceN n >>= fun bytes -> ret_gen (Cstruct.of_string bytes)

let arbitrary_ethernet_header =
  let build_ethernet_header (src, dst, ethertype) =
    let c = Cstruct.create (Wire_structs.sizeof_ethernet) in
    Wire_structs.set_ethernet_src (Macaddr.to_bytes src) 0 c;
    Wire_structs.set_ethernet_dst (Macaddr.to_bytes dst) 0 c;
    Wire_structs.set_ethernet_ethertype c ethertype;
    c
  in
  arbitrary_triple arbitrary_mac arbitrary_mac arbitrary_uint16 >>= 
  fun a -> ret_gen (build_ethernet_header a)

let arbitrary_arp = 
  let sizeof_arpv4 = 28 in (* since we can't easily extract it *)
  let arpify str = 
    let arp = Cstruct.create sizeof_arpv4 in
    Cstruct.blit_from_string str 0 arp 0 sizeof_arpv4;
    Wire_structs.set_ethernet_ethertype arp 0x0806; 
  in
  arbitrary_bytesequenceN sizeof_arpv4 >>= fun r -> ret_gen (arpify r)

let qc_printer = function
  | Success -> "Randomized check passed"
  | Failure n -> Printf.sprintf "Randomized test failure after %d tests" n
  | Exhausted n -> Printf.sprintf "Random test pool exhausted after %d tests" n

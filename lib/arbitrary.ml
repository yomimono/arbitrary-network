open QuickCheck
open QuickCheck_gen

let arbitrary_port = 
  arbitrary_int >>= fun p -> ret_gen (abs (p mod 65536))

let arbitrary_ip = 
  let byte_switch is_ipv6 bytes =
    match is_ipv6 with
    | true -> Ipaddr.V6 (Ipaddr.V6.of_bytes_exn bytes) (* Ipaddr.V6.t = 4x int32 *)
    | false -> Ipaddr.V4 (Ipaddr.V4.of_bytes_raw bytes 12) (* Ipaddr.V4.t = int32 *)
  in
  arbitrary_pair arbitrary_bool (arbitrary_bytesequenceN 16) >>=
  fun (b, i) -> ret_gen (byte_switch b i)

(* protocol really should probably be arbitrary_int, but instead
 * we'll choose randomly between 6 (tcp) and 17 (udp).  (next header in ipv6
  * is 8 bits, same for protocol in ipv4) *)
let arbitrary_tcp_or_udp = 
  arbitrary_bool >>= fun p -> ret_gen (if p then 6 else 17)

let arbitrary_uint16 =
  arbitrary_int >>= fun i -> ret_gen (abs (i mod 65536))

let arbitrary_mac = 
  arbitrary_bytesequenceN 6 >>= fun b -> ret_gen (Macaddr.of_bytes_exn b)

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

use pcap;
use std::io::Cursor;
use std::collections::HashMap;
use byteorder::{ReadBytesExt, BigEndian};
use time::{Timespec};

use std::rc::Rc;
use std::cell::RefCell;
use std::ffi::CString;
use libc::c_void;
use guile_sys::{
    SCM, scm_to_pointer, scm_symbol_to_string, scm_to_locale_string,
    scm_to_uint16, scm_to_uint8, scm_from_pointer,
    scm_pointer_to_bytevector, scm_from_int32, 
    scm_from_utf8_symbol, scm_call_2, scm_object_to_string
};

const ETHERTYPE_IPV4: u16 = 0x0800;

const IPPROTO_ICMP: u8 = 1; 
const IPPROTO_TCP: u8 = 6; 
const IPPROTO_UDP: u8 = 17; 

const ICMP_ECHO_REPLY: u8 = 0; 
const ICMP_DST_UNREACH: u8 = 3; 
const ICMP_ECHO_REQUEST: u8 = 8; 
const ICMP_NET_UNREACH: u8 = 0; 
const ICMP_HOST_UNREACH: u8 = 1; 
const ICMP_PROTO_UNREACH: u8 = 2; 
const ICMP_PORT_UNREACH: u8 = 3; 
const ICMP_FRAG_NEED: u8 = 4; 
const ICMP_SRC_RT_FAIL: u8 = 5; 


#[derive(Debug)]
pub struct PacketInfo {
    pub num: u32,
    pub time: Timespec,
    pub len: u32,
    pub net_src: Option<String>,
    pub net_dst: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub proto: Option<String>,
    pub info: Option<String>,
}

pub struct DissectorTable {
    net_dissectors: HashMap<u16, SCM>,
    transport_dissectors: HashMap<u8, SCM>,
    tcp_dissectors: HashMap<u8, SCM>,
    udp_dissectors: HashMap<u8, SCM>,
}

impl DissectorTable {
    pub fn new() -> Self {
        DissectorTable {
            net_dissectors: HashMap::new(),
            transport_dissectors: HashMap::new(),
            tcp_dissectors: HashMap::new(),
            udp_dissectors: HashMap::new(),
        }
    }

    fn net(&self, type_num: u16) -> Option<&SCM> {
        self.net_dissectors.get(&type_num)
    }

    fn set_net(&mut self, type_num: u16, disct_proc: SCM) {
        self.net_dissectors.insert(type_num, disct_proc);
    }

    fn transport(&self, num: u8) -> Option<&SCM> {
        self.transport_dissectors.get(&num)
    }

    #[allow(dead_code)]
    fn set_transport(&mut self, num: u8, disct_proc: SCM) {
        self.transport_dissectors.insert(num, disct_proc);
    }

    #[allow(dead_code)]
    fn tcp(&self, port_num: u8) -> Option<&SCM> {
        self.tcp_dissectors.get(&port_num)
    }

    fn set_tcp(&mut self, port_num: u8, disct_proc: SCM) {
        self.tcp_dissectors.insert(port_num, disct_proc);
    }

    #[allow(dead_code)]
    fn udp(&self, port_num: u8) -> Option<&SCM> {
        self.udp_dissectors.get(&port_num)
    }

    fn set_udp(&mut self, port_num: u8, disct_proc: SCM) {
        self.udp_dissectors.insert(port_num, disct_proc);
    }
}

pub extern "C" fn set_dissector(tbl: SCM, tbl_type: SCM, num: SCM, prc: SCM) -> SCM{
    unsafe {
        let tbl_ptr = scm_to_pointer(tbl) as *mut DissectorTable;
        let tbl = tbl_ptr.as_mut().unwrap();

        let tbl_type = scm_symbol_to_string(tbl_type);
        let tbl_type: &str = &CString::from_raw(scm_to_locale_string(tbl_type)).into_string().unwrap();
        match tbl_type {
            "net" => {
                let num = scm_to_uint16(num) as u16;
                tbl.set_net(num, prc);
            },
            "tcp" => {
                let num = scm_to_uint8(num) as u8;
                tbl.set_tcp(num, prc);
            },
            "udp" => {
                let num = scm_to_uint8(num) as u8;
                tbl.set_udp(num, prc);
            },
            _ => {
                println!("dissector registration error");
            }
        }
    }
    tbl
}

pub extern "C" fn set_proto(pinfo: SCM, proto: SCM) -> SCM{
    {
        unsafe {
            let pinfo = scm_to_pointer(pinfo) as *mut PacketInfo;
            let pinfo = pinfo.as_mut().unwrap();
            let proto = CString::from_raw(scm_to_locale_string(proto)).into_string().unwrap();
            pinfo.proto = Some(proto);
        }
    }
    pinfo
}

pub extern "C" fn set_info(pinfo: SCM, info: SCM) -> SCM{
    {
        unsafe {
            let pinfo = scm_to_pointer(pinfo) as *mut PacketInfo;
            let pinfo = pinfo.as_mut().unwrap();
            let info = CString::from_raw(scm_to_locale_string(info)).into_string().unwrap();
            pinfo.info = Some(info);
        }
    }
    pinfo
}

fn to_bytevector(bytes: &mut [u8]) -> SCM {
    let v_ptr = bytes.as_mut_ptr() as *mut c_void;
    unsafe {
        let scm_ptr = scm_from_pointer(v_ptr, None);
        let cstr = CString::new("u8").unwrap();
        scm_pointer_to_bytevector(scm_ptr,
                                  scm_from_int32(bytes.len() as i32),
                                  scm_from_int32(0),
                                  scm_from_utf8_symbol(cstr.as_ptr()))
    }
}


fn dissect_tcp(data: &[u8], mut pinfo: PacketInfo) -> (String, PacketInfo) {
    let src_port;
    let dst_port;
    let mut rdr = Cursor::new(&data[0..4]);
    src_port = rdr.read_u16::<BigEndian>().unwrap();
    dst_port = rdr.read_u16::<BigEndian>().unwrap();
    let tcp_val = format!("TCP {} -> {}", src_port, dst_port);

    let tcp_tree = format!("((\"Transmission Control Protocol\" \"Src Port: {}, Dst Port: {}\") \
                            ((\"Source Port\" \"{}\") () \
                             ((\"Destination Port\" \"{}\") () ()))\
                            ())",
                           src_port, dst_port, src_port, dst_port);

    pinfo.info = Some(tcp_val);
    pinfo.src_port = Some(src_port);
    pinfo.dst_port = Some(dst_port);

    (tcp_tree, pinfo)
}

fn dissect_udp(data: &[u8], mut pinfo: PacketInfo) -> (String, PacketInfo) {
    let src_port;
    let dst_port;
    let mut rdr = Cursor::new(&data[0..4]);
    src_port = rdr.read_u16::<BigEndian>().unwrap();
    dst_port = rdr.read_u16::<BigEndian>().unwrap();
    let udp_val = format!("UDP {} -> {}", src_port, dst_port);

    let udp_tree = format!("((\"User Datagram Protocol\" \"Src Port: {}, Dst Port: {}\") \
                            ((\"Source Port\" \"{}\") () \
                             ((\"Destination Port\" \"{}\") () ()))\
                            ())",
                           src_port, dst_port, src_port, dst_port);

    pinfo.info = Some(udp_val);
    pinfo.src_port = Some(src_port);
    pinfo.dst_port = Some(dst_port);

    (udp_tree, pinfo)
}

fn icmp_type_and_code(typ: u8, cod: u8) -> (String, String) {
    match typ {
        ICMP_ECHO_REPLY => (String::from("Echo Reply(0)"), cod.to_string()),
        ICMP_DST_UNREACH => {
            let t = String::from("Destination Unreachable(3)");
            match cod {
                ICMP_NET_UNREACH => (t, String::from("net unreachable(0)")),
                ICMP_HOST_UNREACH => (t, String::from("host unreachable(1)")),
                ICMP_PROTO_UNREACH => (t, String::from("protocol unreachable(2)")),
                ICMP_PORT_UNREACH => (t, String::from("port unreachable(3)")),
                ICMP_FRAG_NEED => (t, String::from("fragmentation needed and DF set(4)")),
                ICMP_SRC_RT_FAIL => (t, String::from("source route failed(5)")),
                _ => (t, String::from("unknown code")),
            }
        },
        ICMP_ECHO_REQUEST => (String::from("Echo Request(8)"), cod.to_string()),
        _ => (String::from("Not implemented yet"), String::from("Sorry")),
    }
}

fn dissect_icmp(data: &[u8], mut pinfo: PacketInfo) -> (String, PacketInfo) {
    let (type_val, code_val) = icmp_type_and_code(data[0], data[1]);
    let icmp_val = format!("ICMP {}, {}", type_val, code_val);

    let icmp_tree = format!("((\"Internet Control Message Protocol\" \"icmp\") \
                            ((\"Type\" \"{}\") () \
                             ((\"Code\" \"{}\") () \
                              ((\"Data\" \"...\") () ())))\
                            ())",
                           type_val, code_val);

    pinfo.info = Some(icmp_val);

    (icmp_tree, pinfo)
}

fn ipaddr_str(bytes: &[u8]) -> String {
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

fn dissect_ip(data: &mut [u8], mut pinfo: PacketInfo, disct_tbl: Rc<RefCell<DissectorTable>>, write_proc: SCM) -> (String, PacketInfo) {
    let ttl_val = data[8];
    let src_val = ipaddr_str(&data[12..16]);
    let dst_val = ipaddr_str(&data[16..20]);
    let ip_val = format!("IP {} -> {}", src_val, dst_val);

    let payload;
    let proto_val = match data[9] {
        IPPROTO_TCP => {
            let (pl, inf) = dissect_tcp(&data[20..], pinfo);
            payload = pl;
            pinfo = inf;
            String::from("TCP")
        },
        IPPROTO_UDP => {
            let (pl, inf) = dissect_udp(&data[20..], pinfo);
            payload = pl;
            pinfo = inf;
            String::from("UDP")
        },
        IPPROTO_ICMP => {
            let (pl, inf) = dissect_icmp(&data[20..], pinfo);
            payload = pl;
            pinfo = inf;
            String::from("ICMP")
        },
        n => {
            if let Some(dsctr) = disct_tbl.borrow().transport(n) {
                unsafe {
                    let pinfo_ptr = scm_from_pointer(&mut pinfo as *mut _ as *mut c_void, None);
                    let res = scm_call_2(*dsctr,
                                         to_bytevector(&mut data[20..]),
                                         pinfo_ptr);
                    let res = scm_to_locale_string(scm_object_to_string(res, write_proc));
                    payload = CString::from_raw(res).into_string().unwrap();
                }
            } else {
                payload = String::from("UNKNODWN");
            }
            n.to_string()
        }
    };

    pinfo.net_src = Some(src_val.clone());
    pinfo.net_dst = Some(dst_val.clone());
    pinfo.proto = Some(proto_val.clone());
    if pinfo.info.is_none() { pinfo.info = Some(ip_val.clone()); }

    let ip_tree = format!("((\"Internet Protocol v4\" \"{}\") \
                            ((\"Time to live\" \"{}\") () \
                             ((\"Protocol\" \"{}\") () \
                              ((\"Source\" \"{}\") () \
                               ((\"Destination\" \"{}\") () ())))) \
                            {})",
                           ip_val, ttl_val, proto_val, src_val, dst_val, payload);
    (ip_tree, pinfo)
}

fn hwaddr_str(bytes: &[u8]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
}

fn dissect_ethernet(data: &mut [u8], mut pinfo: PacketInfo, disct_tbl: Rc<RefCell<DissectorTable>>, write_proc: SCM) -> (String, PacketInfo) {
    let dst_val = hwaddr_str(&data[0..6]);
    let src_val = hwaddr_str(&data[6..12]);
    let eth_val = format!("Ethernet {} -> {}", src_val, dst_val);

    let typ;
    {
        let mut rdr = Cursor::new(&data[12..14]);
        typ = rdr.read_u16::<BigEndian>().unwrap();
    }

    let payload;
    let type_val = match typ {
        ETHERTYPE_IPV4 => {
            let (pl, inf) = dissect_ip(&mut data[14..], pinfo, disct_tbl, write_proc);
            payload = pl;
            pinfo = inf;
            String::from("IPv4")
        },
        n => {
            if let Some(dsctr) = disct_tbl.borrow().net(n) {
                unsafe {
                    let pinfo_ptr = scm_from_pointer(&mut pinfo as *mut _ as *mut c_void, None);
                    let res = scm_call_2(*dsctr,
                                         to_bytevector(&mut data[14..]),
                                         pinfo_ptr);
                    let res = scm_to_locale_string(scm_object_to_string(res, write_proc));
                    payload = CString::from_raw(res).into_string().unwrap();
                }
            } else {
                payload = String::from("UNKNODWN");
            }
            n.to_string()
        },
    };

    if pinfo.net_src.is_none() { pinfo.net_src = Some(src_val.clone()); }
    if pinfo.net_dst.is_none() { pinfo.net_dst = Some(dst_val.clone()); }
    if pinfo.info.is_none() { pinfo.info = Some(eth_val.clone()); }

    let eth_tree = format!("((\"Ethernet\" \"{}\") \
                             ((\"Destination\" \"{}\") () \
                              ((\"Source\" \"{}\") () \
                               ((\"Type\" \"{}\") () ()))) \
                             {})",
                           eth_val, dst_val, src_val, type_val, payload);
    (eth_tree, pinfo)
}

pub fn dissect(n: u32, hdr: pcap::PacketHeader, mut data: Vec<u8>, disct_tbl: Rc<RefCell<DissectorTable>>, write_proc: SCM) -> (String, PacketInfo) {
    let pinfo = PacketInfo {
        num: n,
        time: Timespec::new(hdr.ts.tv_sec, (hdr.ts.tv_usec * 1000) as i32),
        len: hdr.len,
        net_src: None, net_dst: None,
        src_port: None, dst_port: None,
        proto: None, info: None,
    };

    //<node>    := (<key-val> <child> <next>)
    //<key-val> := (<string> <string>)
    //<child>   := <node> | ()
    //<next>    := <node> | ()
    dissect_ethernet(&mut data, pinfo, disct_tbl, write_proc)
}


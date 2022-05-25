use esp_idf_sys::*;

extern crate alloc;
use alloc::borrow::Cow;
use alloc::vec::Vec;

use std::ffi::CStr;
use std::ffi::CString;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use std::time::Duration;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Interface {
    STA,
    AP,
    ETH,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Protocol {
    V4,
    V6,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Type {
    A = MDNS_TYPE_A as _,
    AAAA = MDNS_TYPE_AAAA as _,
    ANY = MDNS_TYPE_ANY as _,
    NSEC = MDNS_TYPE_NSEC as _,
    OPT = MDNS_TYPE_OPT as _,
    PTR = MDNS_TYPE_PTR as _,
    SRV = MDNS_TYPE_SRV as _,
    TXT = MDNS_TYPE_TXT as _,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryResults(Vec<QueryResult>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryResult {
    pub instance_name: Option<String>,
    pub hostname: Option<String>,
    pub port: u16,
    pub txt: Vec<(String, String)>,
    pub addr: Vec<IpAddr>,
    pub interface: Interface,
    pub ip_protocol: Protocol,
}

impl From<mdns_result_t> for QueryResult {
    fn from(result: mdns_result_t) -> Self {
        let instance_name = unsafe { result.instance_name.as_ref() }
            .map(|p| unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string());
        let hostname = unsafe { result.hostname.as_ref() }
            .map(|p| unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string());
        let port = result.port;

        let mut txt = Vec::with_capacity(result.txt_count as usize);
        for i in 0..result.txt_count as _ {
            let p = unsafe { result.txt.offset(i) };
            let key = unsafe { CStr::from_ptr((*p).key) }
                .to_str()
                .unwrap()
                .to_string();
            let value = unsafe { (*p).value.as_ref() }
                .map_or(Default::default(), |p| {
                    unsafe { CStr::from_ptr(p) }.to_str().unwrap()
                })
                .to_string();
            txt.push((key, value));
        }

        let mut addr = Vec::new();
        let mut p = result.addr;
        while !p.is_null() {
            let a = unsafe { (*p).addr };
            let a = match a.type_ as _ {
                ESP_IPADDR_TYPE_V4 => IpAddr::V4(from_esp_ip4_addr_t(unsafe { &a.u_addr.ip4 })),
                ESP_IPADDR_TYPE_V6 => IpAddr::V6(from_esp_ip6_addr_t(unsafe { &a.u_addr.ip6 })),
                _ => panic!(),
            };
            addr.push(a);

            p = unsafe { (*p).next };
        }

        let interface = match result.tcpip_if {
            mdns_if_internal_MDNS_IF_STA => Interface::STA,
            mdns_if_internal_MDNS_IF_AP => Interface::AP,
            mdns_if_internal_MDNS_IF_ETH => Interface::ETH,
            _ => panic!(),
        };

        let ip_protocol = match result.ip_protocol {
            mdns_ip_protocol_t_MDNS_IP_PROTOCOL_V4 => Protocol::V4,
            mdns_ip_protocol_t_MDNS_IP_PROTOCOL_V6 => Protocol::V6,
            _ => panic!(),
        };

        QueryResult {
            instance_name,
            hostname,
            port,
            txt,
            addr,
            interface,
            ip_protocol,
        }
    }
}

impl From<*mut mdns_result_t> for QueryResults {
    fn from(result: *mut mdns_result_t) -> Self {
        let mut query_results = Vec::new();
        let mut p = result;
        while !p.is_null() {
            query_results.push(QueryResult::from(unsafe { *p }));
            p = unsafe { (*p).next };
        }

        unsafe { mdns_query_results_free(unsafe { result }) };

        QueryResults(query_results)
    }
}

fn from_esp_ip4_addr_t(addr: &esp_ip4_addr_t) -> Ipv4Addr {
    Ipv4Addr::from(addr.addr.to_le_bytes())
}

fn from_esp_ip6_addr_t(addr: &esp_ip6_addr_t) -> Ipv6Addr {
    let mut buf = [0u8; 16];
    let mut i = 0;
    for e in addr.addr.iter() {
        for e in e.to_le_bytes().iter() {
            buf[i] = *e;
            i += 1;
        }
    }
    Ipv6Addr::from(buf)
}

pub struct Mdns {}

impl Drop for Mdns {
    fn drop(&mut self) {
        unsafe { mdns_free() };
    }
}

impl Mdns {
    pub fn new() -> Result<Self, EspError> {
        esp!(unsafe { mdns_init() })?;
        Ok(Self {})
    }

    pub fn hostname_set<'a, S>(&mut self, hostname: S) -> Result<(), EspError>
    where
        S: Into<Cow<'a, str>>,
    {
        let hostname = CString::new(hostname.into().as_ref()).unwrap();

        esp!(unsafe { mdns_hostname_set(hostname.as_ptr()) })
    }

    pub fn instance_name_set<'a, S>(&mut self, instance_name: S) -> Result<(), EspError>
    where
        S: Into<Cow<'a, str>>,
    {
        let instance_name = CString::new(instance_name.into().as_ref()).unwrap();

        esp!(unsafe { mdns_instance_name_set(instance_name.as_ptr()) })
    }

    pub fn service_add<'a, S1, S2>(
        &mut self,
        instance_name: Option<&str>,
        service_type: S1,
        proto: S2,
        port: u16,
        txt: &[(&str, &str)],
    ) -> Result<(), EspError>
    where
        S1: Into<Cow<'a, str>>,
        S2: Into<Cow<'a, str>>,
    {
        let instance_name = instance_name.map(|x| CString::new(x.to_string()).unwrap());
        let service_type = CString::new(service_type.into().as_ref()).unwrap();
        let proto = CString::new(proto.into().as_ref()).unwrap();
        let mut txtcstr = Vec::with_capacity(txt.len());
        let mut txtptr = Vec::with_capacity(txt.len());
        for e in txt.iter() {
            let key = CString::new(e.0.as_bytes()).unwrap();
            let value = CString::new(e.1.as_bytes()).unwrap();
            txtptr.push(mdns_txt_item_t {
                key: key.as_ptr(),
                value: value.as_ptr(),
            });
            txtcstr.push((key, value));
        }

        esp!(unsafe {
            mdns_service_add(
                instance_name
                    .as_ref()
                    .map_or(std::ptr::null(), |x| x.as_ptr()),
                service_type.as_ptr(),
                proto.as_ptr(),
                port,
                txtptr.as_mut_ptr(),
                txtptr.len() as _,
            )
        })
    }

    pub fn service_port_set<'a, S1, S2>(
        &mut self,
        service_type: S1,
        proto: S2,
        port: u16,
    ) -> Result<(), EspError>
    where
        S1: Into<Cow<'a, str>>,
        S2: Into<Cow<'a, str>>,
    {
        let service_type = CString::new(service_type.into().as_ref()).unwrap();
        let proto = CString::new(proto.into().as_ref()).unwrap();

        esp!(unsafe { mdns_service_port_set(service_type.as_ptr(), proto.as_ptr(), port) })
    }

    pub fn service_instance_name_set<'a, S1, S2, S3>(
        &mut self,
        service_type: S1,
        proto: S2,
        instance_name: S3,
    ) -> Result<(), EspError>
    where
        S1: Into<Cow<'a, str>>,
        S2: Into<Cow<'a, str>>,
        S3: Into<Cow<'a, str>>,
    {
        let service_type = CString::new(service_type.into().as_ref()).unwrap();
        let proto = CString::new(proto.into().as_ref()).unwrap();
        let instance_name = CString::new(instance_name.into().as_ref()).unwrap();

        esp!(unsafe {
            mdns_service_instance_name_set(
                service_type.as_ptr(),
                proto.as_ptr(),
                instance_name.as_ptr(),
            )
        })
    }

    pub fn service_txt_item_set<'a, S1, S2, S3, S4>(
        &mut self,
        service_type: S1,
        proto: S2,
        key: S3,
        value: S4,
    ) -> Result<(), EspError>
    where
        S1: Into<Cow<'a, str>>,
        S2: Into<Cow<'a, str>>,
        S3: Into<Cow<'a, str>>,
        S4: Into<Cow<'a, str>>,
    {
        let service_type = CString::new(service_type.into().as_ref()).unwrap();
        let proto = CString::new(proto.into().as_ref()).unwrap();
        let key = CString::new(key.into().as_ref()).unwrap();
        let value = CString::new(value.into().as_ref()).unwrap();

        esp!(unsafe {
            mdns_service_txt_item_set(
                service_type.as_ptr(),
                proto.as_ptr(),
                key.as_ptr(),
                value.as_ptr(),
            )
        })
    }

    pub fn service_txt_item_remove<'a, S1, S2, S3>(
        &mut self,
        service_type: S1,
        proto: S2,
        key: S3,
    ) -> Result<(), EspError>
    where
        S1: Into<Cow<'a, str>>,
        S2: Into<Cow<'a, str>>,
        S3: Into<Cow<'a, str>>,
    {
        let service_type = CString::new(service_type.into().as_ref()).unwrap();
        let proto = CString::new(proto.into().as_ref()).unwrap();
        let key = CString::new(key.into().as_ref()).unwrap();

        esp!(unsafe {
            mdns_service_txt_item_remove(service_type.as_ptr(), proto.as_ptr(), key.as_ptr())
        })
    }

    pub fn service_txt_set<'a, S1, S2>(
        &mut self,
        service_type: S1,
        proto: S2,
        txt: &[(&str, &str)],
    ) -> Result<(), EspError>
    where
        S1: Into<Cow<'a, str>>,
        S2: Into<Cow<'a, str>>,
    {
        let service_type = CString::new(service_type.into().as_ref()).unwrap();
        let proto = CString::new(proto.into().as_ref()).unwrap();
        let mut txtcstr = Vec::with_capacity(txt.len());
        let mut txtptr = Vec::with_capacity(txt.len());
        for e in txt.iter() {
            let key = CString::new(e.0.as_bytes()).unwrap();
            let value = CString::new(e.1.as_bytes()).unwrap();
            txtptr.push(mdns_txt_item_t {
                key: key.as_ptr(),
                value: value.as_ptr(),
            });
            txtcstr.push((key, value));
        }

        esp!(unsafe {
            mdns_service_txt_set(
                service_type.as_ptr(),
                proto.as_ptr(),
                txtptr.as_mut_ptr(),
                txtptr.len() as _,
            )
        })
    }

    pub fn service_remove<'a, S1, S2>(
        &mut self,
        service_type: S1,
        proto: S2,
    ) -> Result<(), EspError>
    where
        S1: Into<Cow<'a, str>>,
        S2: Into<Cow<'a, str>>,
    {
        let service_type = CString::new(service_type.into().as_ref()).unwrap();
        let proto = CString::new(proto.into().as_ref()).unwrap();

        esp!(unsafe { mdns_service_remove(service_type.as_ptr(), proto.as_ptr()) })
    }

    pub fn service_remove_all(&mut self) -> Result<(), EspError> {
        esp!(unsafe { mdns_service_remove_all() })
    }

    pub fn query(
        &mut self,
        name: Option<&str>,
        service_type: Option<&str>,
        proto: Option<&str>,
        mdns_type: Type,
        timeout: Duration,
        max_results: usize,
    ) -> Result<QueryResults, EspError> {
        let name = name.map(|x| CString::new(x.to_string()).unwrap());
        let service_type = service_type.map(|x| CString::new(x.to_string()).unwrap());
        let proto = proto.map(|x| CString::new(x.to_string()).unwrap());
        let mut result = std::ptr::null_mut();

        esp!(unsafe {
            mdns_query(
                name.as_ref().map_or(std::ptr::null(), |x| x.as_ptr()),
                service_type
                    .as_ref()
                    .map_or(std::ptr::null(), |x| x.as_ptr()),
                proto.as_ref().map_or(std::ptr::null(), |x| x.as_ptr()),
                mdns_type as _,
                timeout.as_millis() as _,
                max_results as _,
                &mut result,
            )
        })?;
        Ok(QueryResults::from(result))
    }

    pub fn query_a<'a, S>(&mut self, hostname: S, timeout: Duration) -> Result<Ipv4Addr, EspError>
    where
        S: Into<Cow<'a, str>>,
    {
        let hostname = CString::new(hostname.into().as_ref()).unwrap();
        let mut addr: esp_ip4_addr_t = Default::default();

        esp!(unsafe { mdns_query_a(hostname.as_ptr(), timeout.as_millis() as _, &mut addr) })?;

        Ok(from_esp_ip4_addr_t(&addr))
    }

    pub fn query_aaaa<'a, S>(
        &mut self,
        hostname: S,
        timeout: Duration,
    ) -> Result<Ipv6Addr, EspError>
    where
        S: Into<Cow<'a, str>>,
    {
        let hostname = CString::new(hostname.into().as_ref()).unwrap();
        let mut addr: esp_ip6_addr_t = Default::default();

        esp!(unsafe { mdns_query_aaaa(hostname.as_ptr(), timeout.as_millis() as _, &mut addr) })?;

        Ok(from_esp_ip6_addr_t(&addr))
    }

    pub fn query_txt<'a, S1, S2, S3>(
        &mut self,
        instance_name: S1,
        service_type: S2,
        proto: S3,
        timeout: Duration,
    ) -> Result<QueryResults, EspError>
    where
        S1: Into<Cow<'a, str>>,
        S2: Into<Cow<'a, str>>,
        S3: Into<Cow<'a, str>>,
    {
        let instance_name = CString::new(instance_name.into().as_ref()).unwrap();
        let service_type = CString::new(service_type.into().as_ref()).unwrap();
        let proto = CString::new(proto.into().as_ref()).unwrap();
        let mut result = std::ptr::null_mut();

        esp!(unsafe {
            mdns_query_txt(
                instance_name.as_ptr(),
                service_type.as_ptr(),
                proto.as_ptr(),
                timeout.as_millis() as _,
                &mut result,
            )
        })?;
        Ok(QueryResults::from(result))
    }

    pub fn query_srv<'a, S1, S2, S3>(
        &mut self,
        instance_name: S1,
        service_type: S2,
        proto: S3,
        timeout: Duration,
    ) -> Result<QueryResults, EspError>
    where
        S1: Into<Cow<'a, str>>,
        S2: Into<Cow<'a, str>>,
        S3: Into<Cow<'a, str>>,
    {
        let instance_name = CString::new(instance_name.into().as_ref()).unwrap();
        let service_type = CString::new(service_type.into().as_ref()).unwrap();
        let proto = CString::new(proto.into().as_ref()).unwrap();
        let mut result = std::ptr::null_mut();

        esp!(unsafe {
            mdns_query_srv(
                instance_name.as_ptr(),
                service_type.as_ptr(),
                proto.as_ptr(),
                timeout.as_millis() as _,
                &mut result,
            )
        })?;
        Ok(QueryResults::from(result))
    }

    pub fn query_ptr<'a, S1, S2>(
        &mut self,
        service_type: S1,
        proto: S2,
        timeout: Duration,
        max_results: usize,
    ) -> Result<QueryResults, EspError>
    where
        S1: Into<Cow<'a, str>>,
        S2: Into<Cow<'a, str>>,
    {
        let service_type = CString::new(service_type.into().as_ref()).unwrap();
        let proto = CString::new(proto.into().as_ref()).unwrap();
        let mut result = std::ptr::null_mut();

        esp!(unsafe {
            mdns_query_ptr(
                service_type.as_ptr(),
                proto.as_ptr(),
                timeout.as_millis() as _,
                max_results as _,
                &mut result,
            )
        })?;
        Ok(QueryResults::from(result))
    }
}

#![allow(unused_variables)]

use std::{
    ffi::{CStr, CString},
    sync::{Mutex, MutexGuard},
    cell::RefCell,
    pin::Pin,
    convert::TryInto,
};
use core::slice;

use crate::{Error, FilterRules, Result};

pub trait ParserHandler {
    fn read(&mut self, parser: &Parser, buf: &mut [u8]) -> std::io::Result<usize>;
    fn write(&mut self, parser: &Parser, buf: &[u8]) -> std::io::Result<usize>;
    fn hello(&mut self, parser: &Parser, hello: &Hello);
}

pub type Hello = ffi::usb_redir_hello_header;
pub type DeviceConnect = ffi::usb_redir_device_connect_header;
pub type InterfaceInfo = ffi::usb_redir_interface_info_header;
pub type EPInfo = ffi::usb_redir_ep_info_header;
pub type SetConfiguration = ffi::usb_redir_set_configuration_header;
pub type ConfigurationStatus = ffi::usb_redir_configuration_status_header;
pub type SetAltSetting = ffi::usb_redir_set_alt_setting_header;
pub type GetAltSetting = ffi::usb_redir_get_alt_setting_header;
pub type AltSettingStatus = ffi::usb_redir_alt_setting_status_header;
pub type StartIsoStream = ffi::usb_redir_start_iso_stream_header;
pub type StopIsoStream = ffi::usb_redir_stop_iso_stream_header;
pub type IsoStreamStatus = ffi::usb_redir_iso_stream_status_header;
pub type StartInterruptReceiving = ffi::usb_redir_start_interrupt_receiving_header;
pub type StopInterruptReceiving = ffi::usb_redir_stop_interrupt_receiving_header;
pub type InterruptReceivingStatus = ffi::usb_redir_interrupt_receiving_status_header;
pub type AllocBulkStreams = ffi::usb_redir_alloc_bulk_streams_header;
pub type FreeBulkStreams = ffi::usb_redir_free_bulk_streams_header;
pub type BulkStreamsStatus = ffi::usb_redir_bulk_streams_status_header;
pub type StartBulkReceiving = ffi::usb_redir_start_bulk_receiving_header;
pub type StopBulkReceiving = ffi::usb_redir_stop_bulk_receiving_header;
pub type BulkReceivingStatus = ffi::usb_redir_bulk_receiving_status_header;

pub type ControlPacket = ffi::usb_redir_control_packet_header;
pub type BulkPacket = ffi::usb_redir_bulk_packet_header;
pub type IsoPacket = ffi::usb_redir_iso_packet_header;
pub type InterruptPacket = ffi::usb_redir_interrupt_packet_header;
pub type BufferedBulkPacket = ffi::usb_redir_buffered_bulk_packet_header;

pub struct Parser {
    parser: *mut ffi::usbredirparser,
    handler: RefCell<Box<dyn ParserHandler>>,
}

pub struct ParserState {
    buf: *mut u8,
    len: i32,
}

impl Drop for ParserState {
    fn drop(&mut self) {
        unsafe {
            libc::free(self.buf as *mut _);
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum DeviceType {
    Device,
    Host,
}

impl Parser {
    pub fn new<H>(handler: H, devtype: DeviceType) -> Pin<Box<Self>>
        where H: ParserHandler + 'static
    {
        let parser = unsafe { ffi::usbredirparser_create() };
        assert!(!parser.is_null());
        let handler = Box::new(handler);
        unsafe {
            (*parser).log_func = Some(log);
            (*parser).read_func = Some(read);
            (*parser).write_func = Some(write);
            (*parser).device_connect_func = Some(device_connect);
            (*parser).device_disconnect_func = Some(device_disconnect);
            (*parser).reset_func = Some(reset);
            (*parser).interface_info_func = Some(interface_info);
            (*parser).ep_info_func = Some(ep_info);
            (*parser).set_configuration_func = Some(set_configuration);
            (*parser).get_configuration_func = Some(get_configuration);
            (*parser).configuration_status_func = Some(configuration_status);
            (*parser).set_alt_setting_func = Some(set_alt_setting);
            (*parser).get_alt_setting_func = Some(get_alt_setting);
            (*parser).alt_setting_status_func = Some(alt_setting_status);
            (*parser).start_iso_stream_func = Some(start_iso_stream);
            (*parser).stop_iso_stream_func = Some(stop_iso_stream);
            (*parser).iso_stream_status_func = Some(iso_stream_status);
            (*parser).start_interrupt_receiving_func = Some(start_interrupt_receiving);
            (*parser).stop_interrupt_receiving_func = Some(stop_interrupt_receiving);
            (*parser).interrupt_receiving_status_func = Some(interrupt_receiving_status);
            (*parser).alloc_bulk_streams_func = Some(alloc_bulk_streams);
            (*parser).free_bulk_streams_func = Some(free_bulk_streams);
            (*parser).bulk_streams_status_func = Some(bulk_streams_status);
            (*parser).cancel_data_packet_func = Some(cancel_data_packet);
            (*parser).control_packet_func = Some(control_packet);
            (*parser).bulk_packet_func = Some(bulk_packet);
            (*parser).iso_packet_func = Some(iso_packet);
            (*parser).interrupt_packet_func = Some(interrupt_packet);
            (*parser).alloc_lock_func = Some(alloc_lock);
            (*parser).free_lock_func = Some(free_lock);
            (*parser).lock_func = Some(lock);
            (*parser).unlock_func = Some(unlock);
            (*parser).hello_func = Some(hello);
            (*parser).filter_reject_func = Some(filter_reject);
            (*parser).filter_filter_func = Some(filter_filter);
            (*parser).device_disconnect_ack_func = Some(device_disconnect_ack);
            (*parser).start_bulk_receiving_func = Some(start_bulk_receiving);
            (*parser).stop_bulk_receiving_func = Some(stop_bulk_receiving);
            (*parser).bulk_receiving_status_func = Some(bulk_receiving_status);
            (*parser).buffered_bulk_packet_func = Some(buffered_bulk_packet);
        }
        let p = Box::pin(Self { parser, handler: RefCell::new(handler) });
        let priv_ = &*p as *const Parser as *mut _;
        unsafe {
            (*parser).priv_ = priv_
        }

        let flags = if devtype == DeviceType::Host {
            ffi::usbredirparser_fl_usb_host as i32
        } else {
            0
        };
        let version = CString::new("usbredir-rs").unwrap();
        let mut caps: u32 = 0;
        unsafe { ffi::usbredirparser_init(parser, version.as_ptr(), &mut caps as _, 1, flags) }

        p
    }

    pub fn has_cap(&self, cap: u32) -> bool {
        unsafe { ffi::usbredirparser_have_cap(self.parser, cap as _) == 1 }
    }

    pub fn have_peer_caps(&self) -> bool {
        unsafe { ffi::usbredirparser_have_peer_caps(self.parser) == 1 }
    }

    pub fn peer_has_cap(&self, cap: u32) -> bool {
        unsafe { ffi::usbredirparser_peer_has_cap(self.parser, cap as _) == 1 }
    }

    pub fn do_read(&self) -> Result<()> {
        let ret = unsafe { ffi::usbredirparser_do_read(self.parser) };
        match ret {
            0 => Ok(()),
            ffi::usbredirparser_read_io_error => Err(Error::ReadIO),
            ffi::usbredirparser_read_parse_error => Err(Error::ReadParse),
            _ => panic!(),
        }
    }

    pub fn has_data_to_write(&self) -> i32 {
        unsafe { ffi::usbredirparser_has_data_to_write(self.parser) }
    }

    pub fn do_write(&self) -> Result<()> {
        let ret = unsafe { ffi::usbredirparser_do_write(self.parser) };
        match ret {
            0 => Ok(()),
            ffi::usbredirparser_write_io_error => Err(Error::WriteIO),
            _ => panic!(),
        }
    }

    pub fn send_device_connect(&self, device_connect: &DeviceConnect) {
        unsafe {
            ffi::usbredirparser_send_device_connect(
                self.parser,
                device_connect as *const _ as *mut _,
            )
        }
    }

    pub fn send_device_disconnect(&self) {
        unsafe { ffi::usbredirparser_send_device_disconnect(self.parser) }
    }

    pub fn send_reset(&self) {
        unsafe { ffi::usbredirparser_send_reset(self.parser) }
    }

    pub fn send_interface_info(&self, interface_info: &InterfaceInfo) {
        unsafe {
            ffi::usbredirparser_send_interface_info(
                self.parser,
                interface_info as *const _ as *mut _,
            )
        }
    }

    pub fn send_ep_info(&self, ep_info: &EPInfo) {
        unsafe { ffi::usbredirparser_send_ep_info(self.parser, ep_info as *const _ as *mut _) }
    }

    pub fn send_set_configuration(&self, id: u64, set_configuration: &SetConfiguration) {
        unsafe {
            ffi::usbredirparser_send_set_configuration(
                self.parser,
                id,
                set_configuration as *const _ as *mut _,
            )
        }
    }

    pub fn send_get_configuration(&self, id: u64) {
        unsafe { ffi::usbredirparser_send_get_configuration(self.parser, id) }
    }

    pub fn send_configuration_status(&self, id: u64, configuration_status: &ConfigurationStatus) {
        unsafe {
            ffi::usbredirparser_send_configuration_status(
                self.parser,
                id,
                configuration_status as *const _ as *mut _,
            )
        }
    }

    pub fn send_set_alt_setting(&self, id: u64, set_alt_setting: &SetAltSetting) {
        unsafe {
            ffi::usbredirparser_send_set_alt_setting(
                self.parser,
                id,
                set_alt_setting as *const _ as *mut _,
            )
        }
    }

    pub fn send_get_alt_setting(&self, id: u64, get_alt_setting: &GetAltSetting) {
        unsafe {
            ffi::usbredirparser_send_get_alt_setting(
                self.parser,
                id,
                get_alt_setting as *const _ as *mut _,
            )
        }
    }

    pub fn send_alt_setting_status(&self, id: u64, alt_setting_status: &AltSettingStatus) {
        unsafe {
            ffi::usbredirparser_send_alt_setting_status(
                self.parser,
                id,
                alt_setting_status as *const _ as *mut _,
            )
        }
    }

    pub fn send_start_iso_stream(&self, id: u64, start_iso_stream: &StartIsoStream) {
        unsafe {
            ffi::usbredirparser_send_start_iso_stream(
                self.parser,
                id,
                start_iso_stream as *const _ as *mut _,
            )
        }
    }

    pub fn send_stop_iso_stream(&self, id: u64, stop_iso_stream: &StopIsoStream) {
        unsafe {
            ffi::usbredirparser_send_stop_iso_stream(
                self.parser,
                id,
                stop_iso_stream as *const _ as *mut _,
            )
        }
    }

    pub fn send_iso_stream_status(&self, id: u64, iso_stream_status: &IsoStreamStatus) {
        unsafe {
            ffi::usbredirparser_send_iso_stream_status(
                self.parser,
                id,
                iso_stream_status as *const _ as *mut _,
            )
        }
    }

    pub fn send_start_interrupt_receiving(
        &self,
        id: u64,
        start_interrupt_receiving: &StartInterruptReceiving,
    ) {
        unsafe {
            ffi::usbredirparser_send_start_interrupt_receiving(
                self.parser,
                id,
                start_interrupt_receiving as *const _ as *mut _,
            )
        }
    }

    pub fn send_stop_interrupt_receiving(
        &self,
        id: u64,
        stop_interrupt_receiving: &StopInterruptReceiving,
    ) {
        unsafe {
            ffi::usbredirparser_send_stop_interrupt_receiving(
                self.parser,
                id,
                stop_interrupt_receiving as *const _ as *mut _,
            )
        }
    }

    pub fn send_interrupt_receiving_status(
        &self,
        id: u64,
        interrupt_receiving_status: &InterruptReceivingStatus,
    ) {
        unsafe {
            ffi::usbredirparser_send_interrupt_receiving_status(
                self.parser,
                id,
                interrupt_receiving_status as *const _ as *mut _,
            )
        }
    }

    pub fn send_alloc_bulk_stream(&self, id: u64, alloc_bulk_streams: &AllocBulkStreams) {
        unsafe {
            ffi::usbredirparser_send_alloc_bulk_streams(
                self.parser,
                id,
                alloc_bulk_streams as *const _ as *mut _,
            )
        }
    }

    pub fn send_free_bulk_streams(&self, id: u64, free_bulk_streams: &FreeBulkStreams) {
        unsafe {
            ffi::usbredirparser_send_free_bulk_streams(
                self.parser,
                id,
                free_bulk_streams as *const _ as *mut _,
            )
        }
    }

    pub fn send_bulk_streams_status(&self, id: u64, bulk_streams_status: &BulkStreamsStatus) {
        unsafe {
            ffi::usbredirparser_send_bulk_streams_status(
                self.parser,
                id,
                bulk_streams_status as *const _ as *mut _,
            )
        }
    }

    pub fn send_cancel_data_packet(&self, id: u64) {
        unsafe {
            ffi::usbredirparser_send_cancel_data_packet(self.parser, id);
        }
    }

    pub fn send_filter_reject(&self) {
        unsafe {
            ffi::usbredirparser_send_filter_reject(self.parser);
        }
    }

    pub fn send_filter_filter(&self, filter: &FilterRules) {
        unsafe {
            ffi::usbredirparser_send_filter_filter(
                self.parser,
                filter.rules.as_ptr(),
                filter.rules.len() as _,
            );
        }
    }

    pub fn send_start_bulk_receiving(&self, id: u64, start_bulk_receiving: &StartBulkReceiving) {
        unsafe {
            ffi::usbredirparser_send_start_bulk_receiving(
                self.parser,
                id,
                start_bulk_receiving as *const _ as *mut _,
            )
        }
    }

    pub fn send_stop_bulk_receiving(&self, id: u64, stop_bulk_receiving: &StopBulkReceiving) {
        unsafe {
            ffi::usbredirparser_send_stop_bulk_receiving(
                self.parser,
                id,
                stop_bulk_receiving as *const _ as *mut _,
            )
        }
    }

    pub fn send_bulk_receiving_status(&self, id: u64, bulk_receiving_status: &BulkReceivingStatus) {
        unsafe {
            ffi::usbredirparser_send_bulk_receiving_status(
                self.parser,
                id,
                bulk_receiving_status as *const _ as *mut _,
            )
        }
    }

    pub fn send_control_packet(&self, id: u64, control_packet: &ControlPacket, data: &[u8]) {
        let data_ptr = if data.len() > 0 {
            data.as_ptr()
        } else {
            std::ptr::null()
        };
        unsafe {
            ffi::usbredirparser_send_control_packet(
                self.parser,
                id,
                control_packet as *const _ as *mut _,
                data_ptr as *const _ as *mut _,
                data.len() as _,
            )
        }
    }

    pub fn send_bulk_packet(&self, id: u64, bulk_packet: &BulkPacket, data: &[u8]) {
        let data_ptr = if data.len() > 0 {
            data.as_ptr()
        } else {
            std::ptr::null()
        };
        unsafe {
            ffi::usbredirparser_send_bulk_packet(
                self.parser,
                id,
                bulk_packet as *const _ as *mut _,
                data_ptr as *const _ as *mut _,
                data.len() as _,
            )
        }
    }

    pub fn send_iso_packet(&self, id: u64, iso_packet: &IsoPacket, data: &[u8]) {
        let data_ptr = if data.len() > 0 {
            data.as_ptr()
        } else {
            std::ptr::null()
        };
        unsafe {
            ffi::usbredirparser_send_iso_packet(
                self.parser,
                id,
                iso_packet as *const _ as *mut _,
                data_ptr as *const _ as *mut _,
                data.len() as _,
            )
        }
    }

    pub fn send_interrupt_packet(&self, id: u64, interrupt_packet: &InterruptPacket, data: &[u8]) {
        let data_ptr = if data.len() > 0 {
            data.as_ptr()
        } else {
            std::ptr::null()
        };
        unsafe {
            ffi::usbredirparser_send_interrupt_packet(
                self.parser,
                id,
                interrupt_packet as *const _ as *mut _,
                data_ptr as *const _ as *mut _,
                data.len() as _,
            )
        }
    }

    pub fn send_buffered_bulk_packet(
        &self,
        id: u64,
        buffered_packet: &BufferedBulkPacket,
        data: &[u8],
    ) {
        unsafe {
            ffi::usbredirparser_send_buffered_bulk_packet(
                self.parser,
                id,
                buffered_packet as *const _ as *mut _,
                data.as_ptr() as *const _ as *mut _,
                data.len() as _,
            )
        }
    }

    pub fn serialize(&self) -> Result<ParserState> {
        let buf = std::ptr::null_mut();
        let len = 0;
        let ret = unsafe {
            ffi::usbredirparser_serialize(
                self.parser,
                &buf as *const _ as *mut _,
                &len as *const _ as *mut _,
            )
        };
        match ret {
            0 => Ok(ParserState { buf, len }),
            -1 => Err(Error::Failed),
            _ => panic!(),
        }
    }

    pub fn deserialize(&self, state: &ParserState) -> Result<()> {
        let ret = unsafe { ffi::usbredirparser_unserialize(self.parser, state.buf, state.len) };
        match ret {
            0 => Ok(()),
            -1 => Err(Error::Failed),
            _ => panic!(),
        }
    }
}

impl Drop for Parser {
    fn drop(&mut self) {
        unsafe {
            ffi::usbredirparser_destroy(self.parser);
        }
    }
}

extern "C" fn log(
    priv_: *mut ::std::os::raw::c_void,
    level: ::std::os::raw::c_int,
    msg: *const ::std::os::raw::c_char,
) {
    let msg = unsafe {
        CStr::from_ptr(msg).to_str().unwrap()
    };
    let log_level = match level as u32 {
        ffi::usbredirparser_error => log::Level::Error,
        ffi::usbredirparser_warning => log::Level::Warn,
        ffi::usbredirparser_info => log::Level::Info,
        ffi::usbredirparser_debug => log::Level::Debug,
        ffi::usbredirparser_debug_data => log::Level::Trace,
        _ => log::Level::max(),
    };
    log::log!(log_level, "{}", msg);
}

extern "C" fn read(
    priv_: *mut ::std::os::raw::c_void,
    data: *mut u8,
    count: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {
    let (parser, buf) = unsafe {
        let parser = &mut *(priv_ as *mut Parser);
        let buf = slice::from_raw_parts_mut(data, count as _);
        (parser, buf)
    };
    // the parser expects a 0 return value on -EWOULDBLOCK
    match parser.handler.borrow_mut().read(parser, buf) {
        Ok(count) => count.try_into().unwrap(),
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => 0,
        Err(err) => -1,
    }
}

extern "C" fn write(
    priv_: *mut ::std::os::raw::c_void,
    data: *mut u8,
    count: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {
    let (parser, buf) = unsafe {
        let parser = &mut *(priv_ as *mut Parser);
        let buf = slice::from_raw_parts(data, count as _);
        (parser, buf)
    };
    let mut h = parser.handler.borrow_mut();
    match h.write(parser, buf) {
        Ok(count) => count.try_into().unwrap(),
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => 0,
        Err(err) => -1,
    }
}

extern "C" fn device_connect(
    priv_: *mut ::std::os::raw::c_void,
    device_connect: *mut ffi::usb_redir_device_connect_header,
) {
    unimplemented!()
}

extern "C" fn device_disconnect(priv_: *mut ::std::os::raw::c_void) {
    unimplemented!()
}

extern "C" fn reset(priv_: *mut ::std::os::raw::c_void) {
    unimplemented!()
}

extern "C" fn interface_info(
    priv_: *mut ::std::os::raw::c_void,
    interface_info: *mut ffi::usb_redir_interface_info_header,
) {
    unimplemented!()
}

extern "C" fn ep_info(
    priv_: *mut ::std::os::raw::c_void,
    ep_info: *mut ffi::usb_redir_ep_info_header,
) {
    unimplemented!()
}

extern "C" fn set_configuration(
    priv_: *mut ::std::os::raw::c_void,
    id: u64,
    set_configuration: *mut ffi::usb_redir_set_configuration_header,
) {
    unimplemented!()
}

extern "C" fn get_configuration(priv_: *mut ::std::os::raw::c_void, id: u64) {
    unimplemented!()
}

extern "C" fn configuration_status(
    priv_: *mut ::std::os::raw::c_void,
    id: u64,
    configuration_status: *mut ffi::usb_redir_configuration_status_header,
) {
    unimplemented!()
}

extern "C" fn set_alt_setting(
    priv_: *mut ::std::os::raw::c_void,
    id: u64,
    set_alt_setting: *mut ffi::usb_redir_set_alt_setting_header,
) {
    unimplemented!()
}

extern "C" fn get_alt_setting(
    priv_: *mut ::std::os::raw::c_void,
    id: u64,
    get_alt_setting: *mut ffi::usb_redir_get_alt_setting_header,
) {
    unimplemented!()
}
extern "C" fn alt_setting_status(
    priv_: *mut ::std::os::raw::c_void,
    id: u64,
    alt_setting_status: *mut ffi::usb_redir_alt_setting_status_header,
) {
    unimplemented!()
}

extern "C" fn start_iso_stream(
    priv_: *mut ::std::os::raw::c_void,
    id: u64,
    start_iso_stream: *mut ffi::usb_redir_start_iso_stream_header,
) {
    unimplemented!()
}

extern "C" fn stop_iso_stream(
    priv_: *mut ::std::os::raw::c_void,
    id: u64,
    stop_iso_stream: *mut ffi::usb_redir_stop_iso_stream_header,
) {
    unimplemented!()
}
extern "C" fn iso_stream_status(
    priv_: *mut ::std::os::raw::c_void,
    id: u64,
    iso_stream_status: *mut ffi::usb_redir_iso_stream_status_header,
) {
    unimplemented!()
}

extern "C" fn start_interrupt_receiving(
    priv_: *mut ::std::os::raw::c_void,
    id: u64,
    start_interrupt_receiving: *mut ffi::usb_redir_start_interrupt_receiving_header,
) {
    unimplemented!()
}

extern "C" fn stop_interrupt_receiving(
    priv_: *mut ::std::os::raw::c_void,
    id: u64,
    stop_interrupt_receiving: *mut ffi::usb_redir_stop_interrupt_receiving_header,
) {
    unimplemented!()
}

extern "C" fn interrupt_receiving_status(
    priv_: *mut ::std::os::raw::c_void,
    id: u64,
    interrupt_receiving_status: *mut ffi::usb_redir_interrupt_receiving_status_header,
) {
    unimplemented!()
}

extern "C" fn alloc_bulk_streams(
    priv_: *mut ::std::os::raw::c_void,
    id: u64,
    alloc_bulk_streams: *mut ffi::usb_redir_alloc_bulk_streams_header,
) {
    unimplemented!()
}

extern "C" fn free_bulk_streams(
    priv_: *mut ::std::os::raw::c_void,
    id: u64,
    free_bulk_streams: *mut ffi::usb_redir_free_bulk_streams_header,
) {
    unimplemented!()
}

extern "C" fn bulk_streams_status(
    priv_: *mut ::std::os::raw::c_void,
    id: u64,
    bulk_streams_status: *mut ffi::usb_redir_bulk_streams_status_header,
) {
    unimplemented!()
}

extern "C" fn cancel_data_packet(priv_: *mut ::std::os::raw::c_void, id: u64) {
    unimplemented!()
}

extern "C" fn control_packet(
    priv_: *mut ::std::os::raw::c_void,
    id: u64,
    control_header: *mut ffi::usb_redir_control_packet_header,
    data: *mut u8,
    data_len: ::std::os::raw::c_int,
) {
    unimplemented!()
}

extern "C" fn bulk_packet(
    priv_: *mut ::std::os::raw::c_void,
    id: u64,
    bulk_header: *mut ffi::usb_redir_bulk_packet_header,
    data: *mut u8,
    data_len: ::std::os::raw::c_int,
) {
    unimplemented!()
}

extern "C" fn iso_packet(
    priv_: *mut ::std::os::raw::c_void,
    id: u64,
    iso_header: *mut ffi::usb_redir_iso_packet_header,
    data: *mut u8,
    data_len: ::std::os::raw::c_int,
) {
    unimplemented!()
}

extern "C" fn interrupt_packet(
    priv_: *mut ::std::os::raw::c_void,
    id: u64,
    interrupt_header: *mut ffi::usb_redir_interrupt_packet_header,
    data: *mut u8,
    data_len: ::std::os::raw::c_int,
) {
    unimplemented!()
}

extern "C" fn hello(
    priv_: *mut ::std::os::raw::c_void,
    hello: *mut ffi::usb_redir_hello_header,
) {
    let (parser, hello) = unsafe {
        let parser = &mut *(priv_ as *mut Parser);
        let hello = &mut *(hello);
        (parser, hello)
    };
    let mut h = parser.handler.borrow_mut();
    h.hello(&parser, &hello);
}

extern "C" fn filter_reject(priv_: *mut ::std::os::raw::c_void) {
    unimplemented!()
}

extern "C" fn filter_filter(
    priv_: *mut ::std::os::raw::c_void,
    rules: *mut ffi::usbredirfilter_rule,
    rules_count: ::std::os::raw::c_int,
) {
    unimplemented!()
}

extern "C" fn device_disconnect_ack(priv_: *mut ::std::os::raw::c_void) {
    unimplemented!()
}

extern "C" fn start_bulk_receiving(
    priv_: *mut ::std::os::raw::c_void,
    id: u64,
    start_bulk_receiving: *mut ffi::usb_redir_start_bulk_receiving_header,
) {
    unimplemented!()
}

extern "C" fn stop_bulk_receiving(
    priv_: *mut ::std::os::raw::c_void,
    id: u64,
    stop_bulk_receiving: *mut ffi::usb_redir_stop_bulk_receiving_header,
) {
    unimplemented!()
}

extern "C" fn bulk_receiving_status(
    priv_: *mut ::std::os::raw::c_void,
    id: u64,
    bulk_receiving_status: *mut ffi::usb_redir_bulk_receiving_status_header,
) {
    unimplemented!()
}

extern "C" fn buffered_bulk_packet(
    priv_: *mut ::std::os::raw::c_void,
    id: u64,
    buffered_bulk_header: *mut ffi::usb_redir_buffered_bulk_packet_header,
    data: *mut u8,
    data_len: ::std::os::raw::c_int,
) {
    unimplemented!()
}

struct Lock {
    mutex: Mutex<()>,
    guard: Option<MutexGuard<'static, ()>>,
}

pub extern "C" fn alloc_lock() -> *mut ::std::os::raw::c_void {
    let lock = Box::new(Lock {
        mutex: Mutex::new(()),
        guard: None,
    });
    Box::into_raw(lock) as _
}

pub extern "C" fn free_lock(ptr: *mut ::std::os::raw::c_void) {
    let lock: Box<Lock> = unsafe { Box::from_raw(ptr as _) };
    drop(lock);
}

pub extern "C" fn lock(ptr: *mut ::std::os::raw::c_void) {
    let mut lock: Box<Lock> = unsafe { Box::from_raw(ptr as _) };
    let guard = unsafe { std::mem::transmute(lock.mutex.lock().unwrap()) };
    lock.guard = Some(guard);
    std::mem::forget(lock);
}

pub extern "C" fn unlock(ptr: *mut ::std::os::raw::c_void) {
    let mut lock: Box<Lock> = unsafe { Box::from_raw(ptr as _) };
    lock.guard.take();
    std::mem::forget(lock);
}

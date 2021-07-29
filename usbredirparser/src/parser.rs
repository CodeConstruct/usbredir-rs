use std::{ffi::CString, os::unix::net::UnixDatagram, sync::{Mutex, MutexGuard}};

pub trait ParserHandler {
    fn log(&mut self);
}

#[derive(Debug)]
pub struct Parser<H> {
    parser: *mut ffi::usbredirparser,
    handler: Box<H>,
}

impl<H: ParserHandler> Parser<H> {
    pub const FLAG_USB_HOST: u32 = ffi::usbredirparser_fl_usb_host;
    pub const FLAG_WRITE_CBS_OWNS_BUFFER: u32 = ffi::usbredirparser_fl_write_cb_owns_buffer;
    pub const FLAG_NO_HELLO: u32 = ffi::usbredirparser_fl_no_hello;

    pub fn new(handler: H) -> Self {
        let mut parser = unsafe { ffi::usbredirparser_create() };
        assert!(!parser.is_null());
        let handler = Box::new(handler);
        let priv_ = &*handler as *const H as *mut _;
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
            (*parser).priv_ = priv_;
        }

        let flags = 0;
        let version = CString::new("usbredir-rs").unwrap();
        let mut caps: u32 = 0;
        unsafe { ffi::usbredirparser_init(parser, version.as_ptr(), &mut caps as _, 1, flags) }

        Self { parser, handler }
    }
}

impl<H> Drop for Parser<H> {
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
    //unsafe { (*(priv_ as *mut Inner<H>)).handler.log() }
    unimplemented!()
}

extern "C" fn read(
    priv_: *mut ::std::os::raw::c_void,
    data: *mut u8,
    count: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {
    unimplemented!()
}

extern "C" fn write(
    priv_: *mut ::std::os::raw::c_void,
    data: *mut u8,
    count: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {
    unimplemented!()
}

extern "C" fn device_connect(
    priv_: *mut ::std::os::raw::c_void,
    device_connect: *mut ffi::usb_redir_device_connect_header,
) {
    unimplemented!()
}

extern "C" fn device_disconnect(
    priv_: *mut ::std::os::raw::c_void,
) {
    unimplemented!()
}

extern "C" fn reset(
    priv_: *mut ::std::os::raw::c_void,
) {
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
    priv_: *mut ::std::os::raw::c_void, hello: *mut ffi::usb_redir_hello_header
) {
    unimplemented!()
}

extern "C" fn filter_reject(
    priv_: *mut ::std::os::raw::c_void,
) {
    unimplemented!()
}

extern "C" fn filter_filter(
    priv_: *mut ::std::os::raw::c_void,
    rules: *mut ffi::usbredirfilter_rule,
    rules_count: ::std::os::raw::c_int,
) {
    unimplemented!()
}

extern "C" fn device_disconnect_ack(
    priv_: *mut ::std::os::raw::c_void,
) {
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

extern "C" fn alloc_lock() -> *mut ::std::os::raw::c_void {
    let lock = Box::new(Lock {
        mutex: Mutex::new(()),
        guard: None,

    });
    Box::into_raw(lock) as _
}

extern "C" fn free_lock(ptr: *mut ::std::os::raw::c_void) {
    let lock: Box<Lock> = unsafe { Box::from_raw(ptr as _) };
    drop(lock);
}

extern "C" fn lock(ptr: *mut ::std::os::raw::c_void) {
    let mut lock: Box<Lock> = unsafe { Box::from_raw(ptr as _) };
    let guard = unsafe { std::mem::transmute(lock.mutex.lock().unwrap()) };
    lock.guard = Some(guard);
    std::mem::forget(lock);
}

extern "C" fn unlock(ptr: *mut ::std::os::raw::c_void) {
    let mut lock: Box<Lock> = unsafe { Box::from_raw(ptr as _) };
    lock.guard.take();
    std::mem::forget(lock);
}

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

pub use libusb1_sys;
pub use usbredirparser_sys;

pub const usbredirhost_read_io_error: ::std::os::raw::c_int = -1;
pub const usbredirhost_parse_error: ::std::os::raw::c_int = -2;
pub const usbredirhost_device_rejected: ::std::os::raw::c_int = -3;
pub const usbredirhost_device_lost: ::std::os::raw::c_int = -4;

pub const usbredirhost_write_io_error: ::std::os::raw::c_int = -1;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct usbredirhost {
    _unused: [u8; 0],
}
pub type usbredirhost_flush_writes =
    ::std::option::Option<unsafe extern "C" fn(priv_: *mut ::std::os::raw::c_void)>;
pub type usbredirhost_buffered_output_size =
    ::std::option::Option<unsafe extern "C" fn(priv_: *mut ::std::os::raw::c_void) -> u64>;
extern "C" {
    pub fn usbredirhost_open(
        usb_ctx: *mut libusb1_sys::libusb_context,
        usb_dev_handle: *mut libusb1_sys::libusb_device_handle,
        log_func: usbredirparser_sys::usbredirparser_log,
        read_guest_data_func: usbredirparser_sys::usbredirparser_read,
        write_guest_data_func: usbredirparser_sys::usbredirparser_write,
        func_priv: *mut ::std::os::raw::c_void,
        version: *const ::std::os::raw::c_char,
        verbose: ::std::os::raw::c_int,
        flags: ::std::os::raw::c_int,
    ) -> *mut usbredirhost;
}
extern "C" {
    pub fn usbredirhost_open_full(
        usb_ctx: *mut libusb1_sys::libusb_context,
        usb_dev_handle: *mut libusb1_sys::libusb_device_handle,
        log_func: usbredirparser_sys::usbredirparser_log,
        read_guest_data_func: usbredirparser_sys::usbredirparser_read,
        write_guest_data_func: usbredirparser_sys::usbredirparser_write,
        flush_writes_func: usbredirhost_flush_writes,
        alloc_lock_func: usbredirparser_sys::usbredirparser_alloc_lock,
        lock_func: usbredirparser_sys::usbredirparser_lock,
        unlock_func: usbredirparser_sys::usbredirparser_unlock,
        free_lock_func: usbredirparser_sys::usbredirparser_free_lock,
        func_priv: *mut ::std::os::raw::c_void,
        version: *const ::std::os::raw::c_char,
        verbose: ::std::os::raw::c_int,
        flags: ::std::os::raw::c_int,
    ) -> *mut usbredirhost;
}
extern "C" {
    pub fn usbredirhost_close(host: *mut usbredirhost);
}
extern "C" {
    pub fn usbredirhost_set_device(
        host: *mut usbredirhost,
        usb_dev_handle: *mut libusb1_sys::libusb_device_handle,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn usbredirhost_set_buffered_output_size_cb(
        host: *mut usbredirhost,
        buffered_output_size_func: usbredirhost_buffered_output_size,
    );
}
extern "C" {
    pub fn usbredirhost_read_guest_data(host: *mut usbredirhost) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn usbredirhost_has_data_to_write(host: *mut usbredirhost) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn usbredirhost_write_guest_data(host: *mut usbredirhost) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn usbredirhost_free_write_buffer(host: *mut usbredirhost, data: *mut u8);
}
extern "C" {
    pub fn usbredirhost_get_guest_filter(
        host: *mut usbredirhost,
        rules_ret: *mut *const usbredirparser_sys::usbredirfilter_rule,
        rules_count_ret: *mut ::std::os::raw::c_int,
    );
}
extern "C" {
    pub fn usbredirhost_check_device_filter(
        rules: *const usbredirparser_sys::usbredirfilter_rule,
        rules_count: ::std::os::raw::c_int,
        dev: *mut libusb1_sys::libusb_device,
        flags: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}

use core::slice;
use std::{
    convert::TryInto,
    ffi::{CStr, CString},
    ptr::NonNull,
};

pub use ffi;
pub use libusb1_sys;
pub use parser;
pub use rusb;

mod error;
pub use error::*;

use rusb::{DeviceHandle, UsbContext};

pub type LogLevel = parser::LogLevel;

pub trait DeviceHandler {
    fn log(&mut self, level: LogLevel, msg: &str);
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize>;
    fn flush_writes(&mut self);
}

#[derive(Debug)]
struct Inner<C, H> {
    host: Option<NonNull<ffi::usbredirhost>>,
    handler: H,
    context: C,
}

unsafe impl<C, H> Sync for Inner<C, H> {}
unsafe impl<C, H> Send for Inner<C, H> {}

#[derive(Debug)]
pub struct Device<C, H> {
    inner: Box<Inner<C, H>>,
}

impl<C, H> Device<C, H> {
    fn as_raw(&self) -> *mut ffi::usbredirhost {
        self.inner.host.unwrap().as_ptr()
    }
}

impl<C: UsbContext, H: DeviceHandler> Device<C, H> {
    pub fn new(
        context: &C,
        device: Option<DeviceHandle<C>>,
        handler: H,
        verbose: i32,
    ) -> Result<Self> {
        let flags = 0;
        let version = CString::new("usbredir-rs").unwrap();
        let mut inner = Box::new(Inner {
            context: context.clone(),
            host: None,
            handler,
        });
        let host = unsafe {
            ffi::usbredirhost_open_full(
                context.as_raw(),
                device_handle(device),
                Some(log::<C, H>),
                Some(read::<C, H>),
                Some(write::<C, H>),
                Some(flush_writes::<C, H>),
                Some(parser::alloc_lock),
                Some(parser::lock),
                Some(parser::unlock),
                Some(parser::free_lock),
                &*inner as *const _ as *mut _,
                version.as_ptr(),
                verbose,
                flags,
            )
        };
        let host = NonNull::new(host).ok_or(Error::Failed)?;
        inner.host = Some(host);
        Ok(Self { inner })
    }

    pub fn handler(&self) -> &H {
        &self.inner.handler
    }

    pub fn set_device(&self, device: Option<DeviceHandle<C>>) -> Result<()> {
        let ret = unsafe { ffi::usbredirhost_set_device(self.as_raw(), device_handle(device)) };
        match ret as _ {
            parser::ffi::usb_redir_success => Ok(()),
            parser::ffi::usb_redir_cancelled => Err(Error::Cancelled),
            parser::ffi::usb_redir_inval => Err(Error::Invalid),
            parser::ffi::usb_redir_ioerror => Err(Error::IO),
            parser::ffi::usb_redir_stall => Err(Error::Stalled),
            parser::ffi::usb_redir_timeout => Err(Error::Timeout),
            parser::ffi::usb_redir_babble => Err(Error::Babbled),
            _ => Err(Error::Failed),
        }
    }

    pub fn read_peer(&self) -> Result<()> {
        let ret = unsafe { ffi::usbredirhost_read_guest_data(self.as_raw()) };
        match ret {
            0 => Ok(()),
            ffi::usbredirhost_read_io_error => Err(Error::IO),
            ffi::usbredirhost_parse_error => Err(Error::Parse),
            ffi::usbredirhost_device_rejected => Err(Error::DeviceRejected),
            ffi::usbredirhost_device_lost => Err(Error::DeviceLost),
            _ => Err(Error::Failed),
        }
    }

    pub fn has_data_to_write(&self) -> usize {
        let ret = unsafe { ffi::usbredirhost_has_data_to_write(self.as_raw()) };
        ret as _
    }

    pub fn write_peer(&self) -> Result<()> {
        let ret = unsafe { ffi::usbredirhost_write_guest_data(self.as_raw()) };
        match ret {
            0 => Ok(()),
            ffi::usbredirhost_write_io_error => Err(Error::IO),
            _ => Err(Error::Failed),
        }
    }

    pub fn peer_filter(&self) -> Option<parser::FilterRules> {
        let len = 0;
        let ptr: *mut parser::ffi::usbredirfilter_rule = std::ptr::null_mut();
        unsafe {
            ffi::usbredirhost_get_guest_filter(
                self.as_raw(),
                &ptr as *const _ as *mut _,
                &len as *const _ as *mut _,
            )
        };
        if len == 0 {
            assert!(ptr.is_null());
            return None;
        }
        let rules = unsafe {
            let slice = std::slice::from_raw_parts(ptr, len);
            slice.to_vec()
        };
        unsafe { libc::free(ptr as _) }
        Some(parser::FilterRules { rules })
    }

    pub fn check_device_filter(
        filter: &parser::FilterRules,
        device: &rusb::Device<C>,
        flags: i32,
    ) -> parser::Result<()> {
        let dev = device.as_raw();
        let ret = unsafe {
            ffi::usbredirhost_check_device_filter(
                filter.rules.as_ptr(),
                filter.rules.len() as _,
                dev,
                flags,
            )
        };
        parser::FilterRules::return_to_result(ret)
    }
}

extern "C" fn log<C, H: DeviceHandler>(
    priv_: *mut ::std::os::raw::c_void,
    level: ::std::os::raw::c_int,
    msg: *const ::std::os::raw::c_char,
) {
    unsafe {
        let msg = CStr::from_ptr(msg);
        let inner = &mut *(priv_ as *mut Inner<C, H>);
        inner.handler.log(level.into(), msg.to_str().unwrap());
    }
}

extern "C" fn read<C, H: DeviceHandler>(
    priv_: *mut ::std::os::raw::c_void,
    data: *mut u8,
    count: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {
    let ret = unsafe {
        let buf = slice::from_raw_parts_mut(data, count as _);
        let inner = &mut *(priv_ as *mut Inner<C, H>);
        inner.handler.read(buf)
    };
    match ret {
        Ok(count) => count.try_into().unwrap(),
        Err(err) => -err.raw_os_error().unwrap_or(1),
    }
}

extern "C" fn write<C, H: DeviceHandler>(
    priv_: *mut ::std::os::raw::c_void,
    data: *mut u8,
    count: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {
    let ret = unsafe {
        let buf = slice::from_raw_parts(data, count as _);
        let inner = &mut *(priv_ as *mut Inner<C, H>);
        inner.handler.write(buf)
    };
    match ret {
        Ok(count) => count.try_into().unwrap(),
        Err(err) => -err.raw_os_error().unwrap_or(1),
    }
}

extern "C" fn flush_writes<C, H: DeviceHandler>(priv_: *mut ::std::os::raw::c_void) {
    unsafe {
        let inner = &mut *(priv_ as *mut Inner<C, H>);
        inner.handler.flush_writes();
    }
}

fn device_handle<C: UsbContext>(
    device: Option<DeviceHandle<C>>,
) -> *mut libusb1_sys::libusb_device_handle {
    if let Some(device) = device {
        device.into_raw()
    } else {
        std::ptr::null_mut()
    }
}

impl<C, H> Drop for Device<C, H> {
    fn drop(&mut self) {
        unsafe {
            ffi::usbredirhost_close(self.as_raw());
        }
    }
}

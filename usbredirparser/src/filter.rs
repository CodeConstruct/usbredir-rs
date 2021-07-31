use std::ffi::{CStr, CString};
use std::fmt;
use std::str::FromStr;

use crate::{Error, Result};

pub struct Interface {
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
}

#[derive(Debug)]
pub struct FilterRules {
    pub rules: Vec<ffi::usbredirfilter_rule>,
}

impl FilterRules {
    pub const DEFAULT_ALLOW: u32 = ffi::usbredirfilter_fl_default_allow;
    pub const DONT_SKIP_NONBOOT_HID: u32 = ffi::usbredirfilter_fl_dont_skip_non_boot_hid;

    pub fn check(
        &self,
        device_class: u8,
        device_subclass: u8,
        device_protocol: u8,
        interfaces: Vec<Interface>,
        vendor_id: u16,
        product_id: u16,
        device_version_bcd: u16,
        flags: u32,
    ) -> Result<()> {
        let mut interface_class: Vec<_> = interfaces.iter().map(|i| i.class).collect();
        let mut interface_subclass: Vec<_> = interfaces.iter().map(|i| i.subclass).collect();
        let mut interface_protocol: Vec<_> = interfaces.iter().map(|i| i.protocol).collect();
        let interface_count = interfaces.len();
        let ret = unsafe {
            ffi::usbredirfilter_check(
                self.rules.as_ptr(),
                self.rules.len() as _,
                device_class,
                device_subclass,
                device_protocol,
                interface_class.as_mut_ptr(),
                interface_subclass.as_mut_ptr(),
                interface_protocol.as_mut_ptr(),
                interface_count as _,
                vendor_id,
                product_id,
                device_version_bcd,
                flags as _,
            )
        };
        Self::return_to_result(ret)
    }

    pub fn return_to_result(ret: i32) -> Result<()> {
        match -ret {
            0 => Ok(()),
            libc::EINVAL => Err(Error::InvalidParameters),
            libc::EPERM => Err(Error::DeniedByRule),
            libc::ENOENT => Err(Error::NoMatchingRule),
            _ => Err(Error::Failed),
        }
    }

    pub fn verify(&self) -> bool {
        unsafe { ffi::usbredirfilter_verify(self.rules.as_ptr(), self.rules.len() as _) == 0 }
    }
}

impl fmt::Display for FilterRules {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            let rules = self.rules.as_ptr();
            let token_sep = CString::new(",").unwrap();
            let rule_sep = CString::new("|").unwrap();
            let s = ffi::usbredirfilter_rules_to_string(
                rules,
                self.rules.len() as _,
                token_sep.as_ptr(),
                rule_sep.as_ptr(),
            );
            if s.is_null() {
                return Err(fmt::Error);
            }
            let cstr = CStr::from_ptr(s);
            write!(f, "{}", cstr.to_string_lossy())?;
            libc::free(s as _);
            Ok(())
        }
    }
}

impl FromStr for FilterRules {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let cs = CString::new(s).unwrap();
        let token_sep = CString::new(",").unwrap();
        let rule_sep = CString::new("|").unwrap();
        let len = 0;
        let ptr: *mut ffi::usbredirfilter_rule = std::ptr::null_mut();
        let ret = unsafe {
            ffi::usbredirfilter_string_to_rules(
                cs.as_ptr(),
                token_sep.as_ptr(),
                rule_sep.as_ptr(),
                &ptr as *const _ as *mut _,
                &len as *const _ as *mut _,
            )
        };
        if ret < 0 {
            return Err(Error::Failed);
        }
        let rules = unsafe {
            let slice = std::slice::from_raw_parts(ptr, len);
            slice.to_vec()
        };
        unsafe { libc::free(ptr as _) }
        Ok(FilterRules { rules })
    }
}

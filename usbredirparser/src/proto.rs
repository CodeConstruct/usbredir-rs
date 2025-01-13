pub const VERSION: u32 = ffi::USBREDIR_VERSION;

pub const CAP_BULK_STREAMS: u32 = ffi::usb_redir_cap_bulk_streams;
pub const CAP_CONNECT_DEVICE_VERSION: u32 = ffi::usb_redir_cap_connect_device_version;
pub const CAP_FILTER: u32 = ffi::usb_redir_cap_filter;
pub const CAP_DEVICE_DISCONNECT_ACK: u32 = ffi::usb_redir_cap_device_disconnect_ack;
pub const CAP_EF_INFO_MAX_PACKET_SIZE: u32 = ffi::usb_redir_cap_ep_info_max_packet_size;
pub const CAP_64BITS_IDS: u32 = ffi::usb_redir_cap_64bits_ids;
pub const CAP_32BITS_BULK_LENGTH: u32 = ffi::usb_redir_cap_32bits_bulk_length;
pub const CAP_BULK_RECEIVING: u32 = ffi::usb_redir_cap_bulk_receiving;

pub const CAPS_SIZE: u32 = ffi::USB_REDIR_CAPS_SIZE;

pub const SPEED_LOW : u8 = ffi::usb_redir_speed_low as u8;
pub const SPEED_FULL : u8 = ffi::usb_redir_speed_full as u8;
pub const SPEED_HIGH : u8 = ffi::usb_redir_speed_high as u8;
pub const SPEED_SUPER : u8 = ffi::usb_redir_speed_super as u8;

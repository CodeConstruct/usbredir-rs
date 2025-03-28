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

pub const TYPE_CONTROL: u8 = ffi::usb_redir_type_control as u8;
pub const TYPE_ISO: u8 = ffi::usb_redir_type_iso as u8;
pub const TYPE_BULK: u8 = ffi::usb_redir_type_bulk as u8;
pub const TYPE_INTERRUPT: u8 = ffi::usb_redir_type_interrupt as u8;
pub const TYPE_INVALID: u8 = ffi::usb_redir_type_invalid as u8;

pub const STATUS_SUCCESS : u8 = ffi::usb_redir_success as u8;
pub const STATUS_CANCELLED : u8 = ffi::usb_redir_cancelled as u8;
pub const STATUS_INVAL : u8 = ffi::usb_redir_inval as u8;
pub const STATUS_IOERROR : u8 = ffi::usb_redir_ioerror as u8;
pub const STATUS_STALL : u8 = ffi::usb_redir_stall as u8;
pub const STATUS_TIMEOUT : u8 = ffi::usb_redir_timeout as u8;
pub const STATUS_BABBLE : u8 = ffi::usb_redir_babble as u8;

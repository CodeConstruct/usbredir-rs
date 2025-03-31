//! Simple Comminations Device Class / Abstract Control Model serial-over-USB
//! device emulation.
//!
//! This uses the usbredirparser crate to expose the a CDC-ADM device, mainly as
//! an example of the usbredirparser API. We provide some control-message
//! infrastructure for standard USB device enumeration, the CDC descriptors, and
//! some simple CDC control responses. A pair of bulk IN/OUT endpoints provide
//! the data transfer, but we only use the OUT endpoint to receive data.
//!
//! To run:
//!
//!  Start qemu with a usbredir guest on a new pty:
//!
//!      qemu [...] -chardev pty,id=usbredir -device usb-redir,chardev=usbredir
//!
//!  qemu will output the name of the new pty:
//!
//!      char device redirected to /dev/pts/11 (label usbredir)
//!
//!  Start cdc-acm, passing the pty path from above:
//!
//!      cdc-acm /dev/pts/11
//!
//!  From the qemu system, write to the ttyACM device:
//!
//!      echo hello world > /dev/ttyACM0
//!
//!  Serial data will be printed on cdc-acm's stdout.

use anyhow::{Context, Result};
use argh::FromArgs;
use log::{LevelFilter, debug, trace, warn};
use std::{
    io::{Read, Write},
    pin::Pin,
};
use usbredirparser::{
    BulkPacket, ConfigurationStatus, ControlPacket, DeviceConnect, DeviceType, Hello,
    InterruptPacket, Parser, ParserHandler, SetConfiguration, StartInterruptReceiving,
    StopInterruptReceiving,
};

/// Our top-level USB device
struct UsbCdcAcm {
    /// usbredir parser
    parser: Pin<Box<usbredirparser::Parser>>,
    /// usbredir protocol stream
    stream: smol::Async<std::fs::File>,
}

impl UsbCdcAcm {
    /// Create a USB CDC ACM device on the provided device path.
    pub fn new(path: &str) -> Result<Self> {
        let fd = std::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .open(path)
            .context("Can't open tty device")?;

        let handler = UsbCdcAcmHandler {
            stream: fd.try_clone()?,
        };

        let parser = Parser::new(handler, DeviceType::Host);

        Ok(Self {
            parser,
            stream: smol::Async::new(fd)?,
        })
    }

    /// Main async processing loop
    pub async fn process(&self) -> Result<()> {
        loop {
            self.stream.readable().await?;
            self.parser.do_read()?;

            while self.parser.has_data_to_write() != 0 {
                let res = self.parser.do_write();
                match res {
                    Err(e) => {
                        warn!("parser write error");
                        return Err(e.into());
                    }
                    Ok(_) => (),
                }
            }
        }
    }
}

/// usbredirparser handler implementation. This only contains the protocol
/// stream, allowing our read & write implementations.
///
/// The control_packet and bulk_packet handlers do most of the work here;
/// ACM operations are sent as simple control messages (we don't have any
/// line state to get/set, so these are no-ops). Serial data is sent over the
/// bulk endpoint.
struct UsbCdcAcmHandler {
    stream: std::fs::File,
}

impl ParserHandler for UsbCdcAcmHandler {
    fn read(&mut self, _parser: &Parser, buf: &mut [u8]) -> std::io::Result<usize> {
        let res = self.stream.read(buf);
        trace!("read:in:{res:?} {:x?}", buf);
        match res {
            Ok(0) => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "disconnected",
            )),
            r => r,
        }
    }
    fn write(&mut self, _parser: &Parser, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }
    fn hello(&mut self, parser: &Parser, _hello: &Hello) {
        debug!("hello");
        self.send_config(parser);

        let chdr = DeviceConnect {
            speed: usbredirparser::SPEED_HIGH,
            device_class: 0,
            device_subclass: 0,
            device_protocol: 0,
            vendor_id: 0xcc00,
            product_id: 0xcc00,
            device_version_bcd: 0x0,
        };
        parser.send_device_connect(&chdr)
    }

    fn reset(&mut self, _parser: &Parser) {
        debug!("reset");
    }

    fn control_packet(&mut self, parser: &Parser, id: u64, pkt: &ControlPacket, data: &[u8]) {
        debug!("[{id:x}] control packet {pkt:x?}, data: {data:x?}");
        match pkt.request {
            USB_CTRL_GET_DESCRIPTOR => self.control_get_descriptor(parser, id, pkt),
            USB_CDC_CTRL_SET_LINE_CODING | USB_CDC_CTRL_SET_CONTROL_LINE_STATE => {
                let mut resp = ControlPacket { ..*pkt };
                resp.length = 0;
                parser.send_control_packet(id, &resp, &[])
            }
            _ => (),
        }
    }

    fn bulk_packet(&mut self, parser: &Parser, id: u64, pkt: &BulkPacket, data: &[u8]) {
        debug!("[{id:x}] bulk packet {pkt:x?}, data: {data:x?}");
        match pkt.endpoint {
            EP_ADDR_IN => (),
            EP_ADDR_OUT => {
                let _ = std::io::stdout().write(data);
                /* ack */
                let resp = BulkPacket {
                    status: 0,
                    length: 0,
                    length_high: 0,
                    ..*pkt
                };
                parser.send_bulk_packet(id, &resp, &[]);
            }
            _ => {
                warn!("unknown bulk packet for ep {:02x}", pkt.endpoint);
            }
        }
    }

    fn interrupt_packet(&mut self, _parser: &Parser, id: u64, pkt: &InterruptPacket, data: &[u8]) {
        debug!(
            "irq packet ep {:02x} {id} {pkt:x?}, data: {data:x?}",
            pkt.endpoint
        );
    }

    fn start_interrupt_receiving(
        &mut self,
        _parser: &Parser,
        id: u64,
        hdr: &StartInterruptReceiving,
    ) {
        debug!("[{id:x}] start irq {:x}", hdr.endpoint);
    }

    fn stop_interrupt_receiving(
        &mut self,
        _parser: &Parser,
        id: u64,
        hdr: &StopInterruptReceiving,
    ) {
        debug!("[{id:x}] stop irq {:x}", hdr.endpoint);
    }

    fn cancel_data_packet(&mut self, _parser: &Parser, id: u64) {
        debug!("[{id:x}] cancel");
    }

    fn set_configuration(&mut self, parser: &Parser, id: u64, cfg: &SetConfiguration) {
        debug!("[{id:x}] set configuration {}", cfg.configuration);

        let mut cfg_status = ConfigurationStatus {
            configuration: cfg.configuration,
            status: 1,
        };

        if cfg.configuration == 1 {
            self.send_config(parser);
            cfg_status.status = 0;
        }

        parser.send_configuration_status(id, &cfg_status)
    }
}

const USB_CTRL_GET_DESCRIPTOR: u8 = 6;

const USB_CDC_CTRL_SET_LINE_CODING: u8 = 0x20;
const USB_CDC_CTRL_SET_CONTROL_LINE_STATE: u8 = 0x22;

const USB_DESC_TYPE_DEVICE: u8 = 0x01;
const USB_DESC_TYPE_CONFIGURATION: u8 = 0x02;
const USB_DESC_TYPE_STRING: u8 = 0x03;
const USB_DESC_TYPE_INTERFACE: u8 = 0x04;
const USB_DESC_TYPE_ENDPOINT: u8 = 0x05;
const USB_DESC_TYPE_CS_INTERFACE: u8 = 0x24;

// Our endpoint address allocations
const EP_ADDR_INT: u8 = 0x82;
const EP_ADDR_OUT: u8 = 0x01;
const EP_ADDR_IN: u8 = 0x81;

// USB descriptor data for our device, configuration, interfaces, endpoints and
// CDC function. This is defined here explicitly for simplicity, but could also
// be generated programmatically.

#[rustfmt::skip]
const DEV_DESC : [u8; 18] = [
    18, /* bLength */
    USB_DESC_TYPE_DEVICE, /* bDescriptorTYpe */
    0x00, 0x02, /* bcdUSB */
    0x00, /* bDeviceClass: CDC */
    0x00, /* bDeviceSubClass */
    0x00, /* bDeviceProtocol */
    0x40, /* bMaxPacketSize0 */
    0x00, 0x00, /* idVendor */
    0x00, 0x00, /* idProduct */
    0x01, 0x01, /* bcdDevice */
    0x01, /* iManufacturer */
    0x02, /* iProduct */
    0x03, /* iSerialNumber */
    0x01, /* bNumConfigurations */
];

#[rustfmt::skip]
const CONFIG_DESC : [u8; 9] = [
    0x09, /* bLength */
    USB_DESC_TYPE_CONFIGURATION, /* bDescriptorType */
    0x00, 0x00, /* wTotalLength (set during access) */
    0x02, /* bNumInterfaces */
    0x01, /* bConfigurationValue */
    0x00, /* iConfiguration */
    0x80, /* bmAttributes: bus powered */
    0x01, /* bMaxPower: 2ma */
];

#[rustfmt::skip]
const IFACE_CTRL_DESC :  [u8; 9] = [
    0x09, /* bLength */
    USB_DESC_TYPE_INTERFACE, /* bDescriptorType */
    0x00, /* bInterfaceNumber */
    0x00, /* bAlternateSetting */
    0x01, /* bNumEndpoints */
    0x02, /* bInterfaceClass: Communications interface */
    0x02, /* bInterfaceSubClass: Abstract Control Model */
    0x00, /* bInterfaceProtocol */
    0x05, /* iInterface */
];

#[rustfmt::skip]
const CDC_DESC : [u8; 15] = [
    0x05, /* bLength */
    USB_DESC_TYPE_CS_INTERFACE, /* bDescriptorType */
    0x00, /* bDescriptorSubType: CDC header */
    0x14, 0x01, /* bcdCDC */

    0x05, /* bLength */
    USB_DESC_TYPE_CS_INTERFACE, /* bDescriptorType */
    0x06, /* bDescriptorSubType: CDC union */
    0x00, /* bControlInterface */
    0x01, /* bSubordinateInterface0 */
    0x05, /* bLength */

    USB_DESC_TYPE_CS_INTERFACE, /* bDescriptorType */
    0x01, /* bDescriptorSubType: CDC call management */
    0x00, /* bmCapabilities */
    0x01, /* bDataInterface */
];

#[rustfmt::skip]
const EP_CTRL_DESCS : [[u8; 7]; 1] = [
    [
        0x07, /* bLength */
        USB_DESC_TYPE_ENDPOINT, /* bDescriptorType */
        EP_ADDR_INT, /* bEndpointAddress */
        0x03, /* bmAttributes */
        0x00, 0x02, /* wMaxPacketSize: 512 */
        0x0b /* bInterval */
    ],
];

#[rustfmt::skip]
const IFACE_DATA_DESC :  [u8; 9] = [
    0x09, /* bLength */
    USB_DESC_TYPE_INTERFACE, /* bDescriptorType */
    0x01, /* bInterfaceNumber */
    0x00, /* bAlternateSetting */
    0x02, /* bNumEndpoints */
    0x0a, /* bInterfaceClass: CDC data */
    0x00, /* bInterfaceSubClass  */
    0x00, /* bInterfaceProtocol */
    0x06, /* iInterface */
];

#[rustfmt::skip]
const EP_DATA_DESCS : [[u8; 7]; 2] = [
    [
        0x07, /* bLength */
        USB_DESC_TYPE_ENDPOINT, /* bDescriptorType */
        EP_ADDR_IN, /* bEndpointAddress */
        0x02, /* bmAttributes */
        0x00, 0x02, /* wMaxPacketSize: 512 */
        0 /* bInterval */
    ],
    [
        0x07, /* bLength */
        USB_DESC_TYPE_ENDPOINT, /* bDescriptorType */
        EP_ADDR_OUT, /* bEndpointAddress */
        0x02, /* bmAttributes */
        0x00, 0x02, /* wMaxPacketSize */
        0 /* bInterval */
    ],
];

#[rustfmt::skip]
const STRINGS : &[&str] = &[
    "usbredir-rs",
    "Example CDC ACM device",
    "0000",
    "CDC function",
    "CDC ACM interface",
    "CDC data interface",
];

#[rustfmt::skip]
const STRING_LANGS : [u8; 4] = [
    4, /* bLength */
    USB_DESC_TYPE_STRING, /* bDescriptorType */
    0x09, 0x04, /* en */
];

impl UsbCdcAcmHandler {
    /// Helper for USB GET_DESCRIPTOR responses
    fn control_get_descriptor(&mut self, parser: &Parser, id: u64, req: &ControlPacket) {
        let mut resp = ControlPacket { ..*req };
        let (desc_type, desc_idx): (u8, u8) = (
            ((req.value >> 8) & 0xff) as u8,
            ((req.value >> 0) & 0xff) as u8,
        );
        debug!("[{id:x}] desc request for type {desc_type:02x} idx {desc_idx:02x}");
        let mut v = Vec::new();
        let mut data = match desc_type {
            USB_DESC_TYPE_DEVICE => DEV_DESC.as_slice(),
            USB_DESC_TYPE_STRING => {
                let s_idx = desc_idx as usize;
                if s_idx == 0 {
                    STRING_LANGS.as_slice()
                } else if s_idx - 1 < STRINGS.len() {
                    v.extend_from_slice(&[0, USB_DESC_TYPE_STRING]);
                    for b in STRINGS[s_idx - 1].encode_utf16() {
                        v.extend_from_slice(&b.to_le_bytes());
                    }
                    v[0] = (v.len() & 0xff) as u8;
                    v.as_slice()
                } else {
                    &[]
                }
            }
            USB_DESC_TYPE_CONFIGURATION => {
                v.extend_from_slice(&CONFIG_DESC);
                //v.extend_from_slice(&IFACE_ASSOC_DESC);
                v.extend_from_slice(&IFACE_CTRL_DESC);
                v.extend_from_slice(&CDC_DESC);
                v.extend_from_slice(&EP_CTRL_DESCS[0]);
                v.extend_from_slice(&IFACE_DATA_DESC);
                v.extend_from_slice(&EP_DATA_DESCS[0]);
                v.extend_from_slice(&EP_DATA_DESCS[1]);
                /* set total length */
                let len = v.len() as u16;
                v[3] = (len >> 8) as u8 & 0xff;
                v[2] = (len >> 0) as u8 & 0xff;
                v.as_slice()
            }
            _ => {
                warn!("unsupported descriptor {desc_type:02x}");
                &[]
            }
        };
        let req_len = req.length as usize;
        if req_len < data.len() {
            data = &data[..req_len];
        }
        resp.length = data.len() as u16;
        parser.send_control_packet(id, &resp, data)
    }

    /// Helper for usbredir protocol initialisation
    fn send_config(&mut self, parser: &Parser) {
        let mut if_info = usbredirparser::InterfaceInfo {
            interface_count: 0,
            interface: [0; 32],
            interface_class: [0; 32],
            interface_subclass: [0; 32],
            interface_protocol: [0; 32],
        };
        if_info.interface_count = 1;
        if_info.interface[0] = 0;
        if_info.interface_class[0] = 0x0;
        if_info.interface_protocol[0] = 0x0;
        parser.send_interface_info(&if_info);

        let mut ep_info = usbredirparser::EPInfo {
            type_: [usbredirparser::TYPE_INVALID; 32],
            interval: [0; 32],
            interface: [0; 32],
            max_packet_size: [0; 32],
            max_streams: [0; 32],
        };
        /* control */
        ep_info.type_[0] = usbredirparser::TYPE_CONTROL;
        ep_info.max_packet_size[0] = 16;
        ep_info.type_[16] = usbredirparser::TYPE_CONTROL;
        ep_info.max_packet_size[16] = 16;

        /* bulk in/out */
        ep_info.type_[1] = usbredirparser::TYPE_BULK;
        ep_info.max_packet_size[1] = 64;
        ep_info.type_[17] = usbredirparser::TYPE_BULK;
        ep_info.max_packet_size[17] = 64;

        /* interrupt */
        ep_info.type_[18] = usbredirparser::TYPE_INTERRUPT;
        ep_info.max_packet_size[18] = 64;
        ep_info.interval[18] = 1;
        parser.send_ep_info(&ep_info);
    }
}

#[derive(FromArgs)]
/// CDC ACM device over a usbredir socket.
struct Options {
    /// path to usbredir socket
    #[argh(positional)]
    path: String,

    /// verbose mode: print USB interactions on stderr
    #[argh(switch)]
    verbose: bool,
}

fn main() -> Result<()> {
    let opts: Options = argh::from_env();

    let loglevel = if opts.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Warn
    };

    simplelog::TermLogger::init(
        loglevel,
        simplelog::Config::default(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    let acm = UsbCdcAcm::new(&opts.path)?;

    smol::block_on(acm.process())?;

    Ok(())
}

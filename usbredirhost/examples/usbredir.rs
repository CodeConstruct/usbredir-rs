use std::{
    io::{Read, Write},
    os::unix::{
        net::UnixStream,
        prelude::{AsRawFd, FromRawFd, RawFd},
    },
};

use color_eyre::{eyre, Report};
use rusb::{self, UsbContext};
use tracing::debug;
use tracing_subscriber::EnvFilter;
use usbredirhost::{Device, DeviceHandler, LogLevel};

struct Handler {
    stream: UnixStream,
    quit: bool,
}

impl DeviceHandler for Handler {
    fn log(&mut self, level: LogLevel, msg: &str) {
        eprintln!("usbredir-{:?}: {}", level, msg);
    }

    fn flush_writes(&mut self) {}

    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = match fd_poll_readable(self.stream.as_raw_fd(), false) {
            Ok(true) => {
                let read = self.stream.read(buf);
                if let Ok(0) = read {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "disconnected",
                    ))
                } else {
                    read
                }
            }
            Ok(false) => Ok(0),
            Err(e) => Err(e),
        };

        self.quit = read.is_err();
        debug!(?read);
        read
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let write = self.stream.write_all(buf);
        debug!(?write);
        self.quit = write.is_err();
        write?;
        Ok(buf.len())
    }
}

#[derive(Debug)]
enum DeviceArg {
    VidPid(u16, u16),
}

#[derive(Debug)]
enum IOArg {
    Default,
    Fd(RawFd),
}

#[derive(Debug)]
struct Args {
    device: DeviceArg,
    io: IOArg,
}

fn usage() -> ! {
    println!("Usage: usbredir --fd FD VENDORID:PRODUCTID");
    std::process::exit(0);
}

fn parse_args() -> Result<Args, lexopt::Error> {
    use lexopt::prelude::*;

    let mut device = None;
    let mut io = IOArg::Default;
    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Long("fd") => {
                io = IOArg::Fd(parser.value()?.parse()?);
            }
            Value(val) if device.is_none() => {
                device = Some(val.into_string()?);
            }
            Long("help") => {
                usage();
            }
            _ => return Err(arg.unexpected()),
        }
    }

    let device = device.ok_or("missing device argument")?;

    let device = if device.find(':').is_some() {
        let mut iter = device.split(":");
        let vid = iter.next().and_then(|v| u16::from_str_radix(v, 16).ok());
        let pid = iter.next().and_then(|v| u16::from_str_radix(v, 16).ok());
        match (vid, pid) {
            (Some(vid), Some(pid)) => DeviceArg::VidPid(vid, pid),
            _ => usage(),
        }
    } else {
        return Err(lexopt::Error::ParsingFailed {
            value: device,
            error: "Failed to parse device".into(),
        });
    };

    Ok(Args { device, io })
}

fn setup() -> Result<(), Report> {
    if std::env::var("RUST_LIB_BACKTRACE").is_err() {
        std::env::set_var("RUST_LIB_BACKTRACE", "1")
    }
    color_eyre::install()?;

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info")
    }
    tracing_subscriber::fmt::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    Ok(())
}

fn fd_poll_readable(fd: RawFd, wait: bool) -> std::io::Result<bool> {
    let mut fds = [libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }];
    let ret = unsafe { libc::poll(fds.as_mut_ptr(), 1, if wait { -1 } else { 0 }) };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret > 0)
    }
}

fn main() -> Result<(), Report> {
    setup()?;

    let args = parse_args()?;

    let stream = match args.io {
        IOArg::Default => {
            // we could take stdio?
            usage();
        }
        IOArg::Fd(fd) => unsafe { UnixStream::from_raw_fd(fd) },
    };
    let handler = Handler {
        stream: stream.try_clone()?,
        quit: false,
    };

    let ctxt = rusb::Context::new().unwrap();
    let device = match args.device {
        DeviceArg::VidPid(vid, pid) => ctxt.open_device_with_vid_pid(vid, pid),
    };
    let device = device.ok_or(eyre::eyre!("Failed to open device {:?}", args.device))?;
    let device = Device::new(&ctxt, Some(device), handler, LogLevel::None as _)?;

    let c = ctxt.clone();
    std::thread::spawn(move || loop {
        if let Ok(true) = fd_poll_readable(stream.as_raw_fd(), true) {
            c.interrupt_handle_events();
        }
    });

    loop {
        if device.handler().quit {
            break;
        }
        if fd_poll_readable(device.handler().stream.as_raw_fd(), false)? {
            device.read_peer()?;
        }
        if device.has_data_to_write() > 0 {
            device.write_peer()?;
        }
        debug!("next_timeout={:?}", ctxt.next_timeout());
        ctxt.handle_events(None)?;
    }

    Ok(())
}

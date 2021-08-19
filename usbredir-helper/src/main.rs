use std::{
    error::Error,
    fs::{metadata, File},
    os::unix::fs::MetadataExt,
    os::unix::io::{FromRawFd, IntoRawFd},
};

use zbus::{dbus_interface, fdo, zvariant::OwnedFd, Connection, ObjectServer};

const S_IFMT: u32 = 61440;
const S_IFCHR: u32 = 8192;

struct Interface;

#[dbus_interface(name = "org.freedesktop.usbredir1")]
impl Interface {
    /// Open the USB device at the given USB address.
    fn open_bus_dev(&self, bus: u8, dev: u8) -> fdo::Result<OwnedFd> {
        let path = format!("/dev/bus/usb/{:03}/{:03}", bus, dev);

        let metadata =
            metadata(&path).map_err(|e| fdo::Error::Failed(format!("stat() failed: {}", e)))?;
        if metadata.mode() & S_IFMT != S_IFCHR {
            return Err(fdo::Error::Failed("Invalid device".into()));
        }

        // TODO: polkit, would need async Interface

        let fd = File::open(path)
            .map_err(|e| fdo::Error::Failed(format!("Failed to open: {}", e)))?
            .into_raw_fd();
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let connection = Connection::system()?;

    let mut object_server =
        ObjectServer::new(&connection).request_name("org.freedesktop.usbredir1")?;

    object_server.at("/org/freedesktop/usbredir1", Interface)?;

    loop {
        // TODO: quit on timeout
        object_server.try_handle_next()?;
    }
}

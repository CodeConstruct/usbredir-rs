use std::{
    error::Error,
    fs::{metadata, OpenOptions},
    os::unix::fs::MetadataExt,
    os::unix::io::{FromRawFd, IntoRawFd},
    time::Duration,
};

use zbus::{dbus_interface, fdo, zvariant::OwnedFd, Connection, MessageHeader, ObjectServer};
use zbus_polkit::policykit1::{AsyncAuthorityProxy, CheckAuthorizationFlags, Subject};

const S_IFMT: u32 = 61440;
const S_IFCHR: u32 = 8192;

struct Interface {
    polkit: AsyncAuthorityProxy<'static>,
}

impl Interface {
    async fn new(connection: &Connection) -> Result<Self, zbus::Error> {
        Ok(Self {
            polkit: AsyncAuthorityProxy::new(&connection).await?,
        })
    }
}

#[dbus_interface(name = "org.freedesktop.usbredir1")]
impl Interface {
    /// Open the USB device at the given USB address.
    async fn open_bus_dev(
        &self,
        bus: u8,
        dev: u8,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> fdo::Result<OwnedFd> {
        let path = format!("/dev/bus/usb/{:03}/{:03}", bus, dev);

        let metadata =
            metadata(&path).map_err(|e| fdo::Error::Failed(format!("stat() failed: {}", e)))?;
        if metadata.mode() & S_IFMT != S_IFCHR {
            return Err(fdo::Error::Failed("Invalid device".into()));
        }

        let subject = Subject::new_for_message_header(&header)
            .map_err(|e| fdo::Error::Failed(format!("Failed to create polkit Subject: {}", e)))?;
        let mut details = std::collections::HashMap::new();
        details.insert("usbredir.path", path.as_ref());
        let result = self
            .polkit
            .check_authorization(
                &subject,
                "org.freedesktop.usbredir1.open",
                &details,
                CheckAuthorizationFlags::AllowUserInteraction.into(),
                "",
            )
            .await
            .map_err(|e| fdo::Error::Failed(format!("Failed to check authorization: {}", e)))?;

        if !result.is_authorized {
            return Err(fdo::Error::Failed("Check authorization failed!".into()));
        }

        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| fdo::Error::Failed(format!("Failed to open: {}", e)))?
            .into_raw_fd();
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let connection = Connection::system().await?;
    connection.object_server_mut().await.at(
        "/org/freedesktop/usbredir1",
        Interface::new(&connection).await?,
    )?;
    connection.request_name("org.freedesktop.usbredir1").await?;

    loop {
        let listener = connection.monitor_activity();
        if !listener.wait_timeout(Duration::from_secs(10)) {
            break;
        }
    }

    Ok(())
}

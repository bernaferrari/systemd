use zbus::Connection;

pub struct SystemBus {
    connection: Connection,
}

impl SystemBus {
    pub async fn new() -> zbus::Result<Self> {
        // Connect to the system bus
        let connection = zbus::Connection::system().await?;
        Ok(Self { connection })
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

pub struct SessionBus {
    connection: Connection,
}

impl SessionBus {
    pub async fn new() -> zbus::Result<Self> {
        // Connect to the session bus
        let connection = zbus::Connection::session().await?;
        Ok(Self { connection })
    }

    /// Borrows the connected session bus for proxy and object-server setup.
    ///
    /// Keeping the `Connection` inside this wrapper makes its lifetime explicit,
    /// just as it is for [`SystemBus`].
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

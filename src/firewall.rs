use std::net::IpAddr;

/// A firewall trait.
pub trait Firewall: Sync + Send {
    type Error;

    /// Clears the white list.
    fn clear_whitelist(&self) -> Result<(), Self::Error>;

    /// Adds an IP address to the white list.
    fn add_ip(&self, ip: &IpAddr) -> Result<(), Self::Error>;

    /// Checks whether a given IP address to the white list.
    fn check_ip(&self, ip: &IpAddr) -> Result<bool, Self::Error>;
}

use super::firewall::Firewall;
use std::net::IpAddr;
use std::sync::Mutex;
use std::{io, process};

/// Ruling the Shorewall.
#[derive(Debug)]
pub struct Shorewall {
    /// Path to the `shorewall` binary.
    executable_path: String,
    /// Name of the dynamic list.
    list_name: String,
    /// Synchronization mutex.
    sync: Mutex<()>,
}

impl Shorewall {
    /// Constructs a new Shorewall object.
    pub fn new(executable_path: &str, list_name: &str) -> Shorewall {
        Shorewall {
            executable_path: executable_path.into(),
            list_name: list_name.into(),
            sync: Mutex::new(()),
        }
    }
}

quick_error! {
    /// An error that could happen during shorewall commands execution.
    #[derive(Debug)]
    pub enum Error {
        // IO error.
        Io(err: io::Error){
            from()
            cause(err)
        }
        // Shorewall error.
        Failure(code: Option<i32>, error: String){
        }
    }
}

/// A firewall trait.
impl Firewall for Shorewall {
    type Error = Error;

    fn clear_whitelist(&self) -> Result<(), Error> {
        let _lg = self.sync.lock();
        let out = process::Command::new("sh")
            .arg("-c")
            .arg(&format!{
                "{0} show dynamic {1} | awk '/^ / {{print $1}}' | xargs -n1 {0} delete",
                &self.executable_path,
                &self.list_name,
            })
            .output()?;
        output_to_result(out)
    }

    fn add_ip(&self, ip: &IpAddr) -> Result<(), Error> {
        let _lg = self.sync.lock();
        let out = process::Command::new(&self.executable_path)
            .args(&["add", &self.list_name, &ip.to_string()])
            .output()?;
        output_to_result(out)
    }

    fn check_ip(&self, ip: &IpAddr) -> Result<bool, Error> {
        let _lg = self.sync.lock();
        let status = process::Command::new("sh")
            .arg("-c")
            .arg(&format![
                "{} show dynamic {} | grep {}",
                &self.executable_path,
                &self.list_name,
                ip,
            ])
            .stdout(process::Stdio::null())
            .stderr(process::Stdio::null())
            .status()?;
        Ok(status.success())
    }
}

/// Converts a process output to a Result type.
fn output_to_result(output: process::Output) -> Result<(), Error> {
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::Failure(
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).into(),
        ))
    }
}

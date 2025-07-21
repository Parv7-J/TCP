use std::{
    fs::File,
    io::{self, Read},
    os::fd::AsRawFd,
    process::{self, Command, Stdio},
};
use tcp_scratch::{Packet, Protocol};

struct IptablesGuard {
    device_name: String,
}

impl IptablesGuard {
    fn new(device_name: &str) -> io::Result<Self> {
        println!(
            "Adding iptables rule to prevent kernel RST packets on {}...",
            device_name
        );
        let status = Command::new("sudo")
            .args([
                "iptables",
                "-I",
                "INPUT",
                "1",
                "-i",
                device_name,
                "-p",
                "tcp",
                "-j",
                "DROP",
            ])
            .status()?;

        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to add iptables rule",
            ));
        }

        Ok(IptablesGuard {
            device_name: device_name.to_string(),
        })
    }
}

impl Drop for IptablesGuard {
    fn drop(&mut self) {
        println!("\nCleaning up iptables rule for {}...", self.device_name);
        let status = Command::new("sudo")
            .args([
                "iptables",
                "-D",
                "INPUT",
                "-i",
                &self.device_name,
                "-p",
                "tcp",
                "-j",
                "DROP",
            ])
            .status();

        match status {
            Ok(s) if s.success() => println!("Successfully removed iptables rule."),
            _ => eprintln!("Error: Failed to remove iptables rule. Please remove it manually."),
        }
    }
}

fn main() -> io::Result<()> {
    let if_name = "tun0";
    let ip_address = "10.0.0.1/24";

    let if_name_clone = if_name.to_string();
    ctrlc::set_handler(move || {
        println!("\nCtrl+C received. Cleaning up and exiting.");

        // Run the cleanup command to remove the iptables rule.
        let status = Command::new("sudo")
            .args([
                "iptables",
                "-D",
                "INPUT",
                "-i",
                &if_name_clone,
                "-p",
                "tcp",
                "-j",
                "DROP",
            ])
            .status()
            .expect("Failed to run iptables cleanup command.");

        if status.success() {
            println!("Successfully removed iptables rule.");
        } else {
            eprintln!("Error: Failed to remove iptables rule. Please remove it manually.");
        }

        // Exit the process cleanly.
        process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    let mut tun_file = File::options()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;

    let tun_fd = tun_file.as_raw_fd();

    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };

    for (i, ch) in if_name.as_bytes().iter().enumerate() {
        req.ifr_name[i] = *ch as libc::c_char;
    }

    req.ifr_ifru.ifru_flags = libc::IFF_TUN as i16 | libc::IFF_NO_PI as i16;

    let res = unsafe { libc::ioctl(tun_fd, libc::TUNSETIFF as u64, &req) };

    if res < 0 {
        return Err(io::Error::last_os_error());
    }

    println!("TUN interface set succesfully, now configuration begins");

    Command::new("sudo")
        .args([
            "sysctl",
            "-w",
            &format!("net.ipv6.conf.{}.disable_ipv6=1", if_name),
        ])
        .stdout(Stdio::null())
        .status()?;

    Command::new("sudo")
        .args(["ip", "link", "set", "dev", if_name, "up"])
        .status()?;

    Command::new("sudo")
        .args(["ip", "addr", "add", ip_address, "dev", if_name])
        .status()?;

    let _guard = IptablesGuard::new(if_name)?;

    println!("Interface {} configured successfully.", if_name);

    let mut buff = [0u8; 2000];

    loop {
        let n = tun_file.read(&mut buff)?;

        if n == 0 {
            println!("TUN device closed, exiting.");
            break;
        }

        let packet = Packet::parse(&buff[..n])?;

        if let Protocol::TCP = packet.protocol {
            println!("{packet:?}");
        } else {
            println!("Packet is not tcp, it is {}", packet.version);
        }
    }

    Ok(())
}

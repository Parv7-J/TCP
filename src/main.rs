use std::{
    fs::File,
    io::{self, Read},
    os::fd::AsRawFd,
    process::Command,
};

fn main() -> io::Result<()> {
    let device_name = "tun0";

    let mut tun_file = File::options()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;

    let fd = tun_file.as_raw_fd();

    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };

    for (i, byte) in device_name.as_bytes().iter().enumerate() {
        req.ifr_name[i] = *byte as libc::c_char;
    }

    req.ifr_ifru.ifru_flags = libc::IFF_TUN as i16 | libc::IFF_NO_PI as i16;

    let res = unsafe { libc::ioctl(fd, libc::TUNSETIFF as u64, &req) };

    if res < 0 {
        return Err(io::Error::last_os_error());
    }

    println!("TUN device created. Running configuration script...");

    let mut cmd = Command::new("sudo");

    cmd.arg("./configure-tun.sh");

    let status = cmd
        .status()
        .expect("Failed to execute configuration script.");

    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Configuration script failed!",
        ));
    }

    println!("Script finished. Ready to handle packets.");

    let mut buff = [0u8; 1504];

    while let Ok(n) = tun_file.read(&mut buff) {
        println!("{n} bytes were read");
    }

    Ok(())
}

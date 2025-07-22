use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read, Write},
    os::fd::AsRawFd,
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
};

use tcp_scratch::{Connection, Packet, Protocol, RequestType, Segment, State};

static SHUTDOWN_FLAG: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigint(_signal: i32) {
    SHUTDOWN_FLAG.store(true, Ordering::Relaxed);
}

fn main() -> io::Result<()> {
    let mut connections: HashMap<(u32, u16, u32, u16), Connection> = HashMap::new();

    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handle_sigint as libc::size_t;
        if libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) != 0 {
            panic!("Failed to register signal handler.");
        }
    }

    let tunif_name = "tun0";
    let tunif_address = "10.0.0.1/24";

    let mut tun_file = File::options()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;

    let tun_fd = tun_file.as_raw_fd();

    let mut tunif_req: libc::ifreq = unsafe { std::mem::zeroed() };

    for (i, byte) in tunif_name.as_bytes().iter().enumerate() {
        tunif_req.ifr_name[i] = *byte as libc::c_char;
    }

    tunif_req.ifr_ifru.ifru_flags = libc::IFF_NO_PI as i16 | libc::IFF_TUN as i16;

    let tunif_res = unsafe { libc::ioctl(tun_fd, libc::TUNSETIFF as u64, &tunif_req) };

    if tunif_res < 0 {
        return Err(io::Error::last_os_error());
    }

    println!("TUN is established!");

    Command::new("sudo")
        .args([
            "iptables",
            "-I",
            "INPUT",
            "1",
            "-i",
            tunif_name,
            "-p",
            "tcp",
            "--tcp-flags", // This is the new part
            "SYN,RST,ACK,FIN",
            "SYN", // This is the new part
            "-j",
            "DROP",
        ])
        .status()?;

    Command::new("sudo")
        .args([
            "sysctl",
            "-w",
            &format!("net.ipv6.conf.{}.disable_ipv6=1", tunif_name),
        ])
        .stdout(Stdio::null())
        .status()?;

    Command::new("sudo")
        .args(["ip", "link", "set", "dev", tunif_name, "up"])
        .status()?;

    Command::new("sudo")
        .args(["ip", "addr", "add", tunif_address, "dev", { tunif_name }])
        .status()?;

    println!("TUN is configured!");

    let mut buff = [0u8; 2000];

    loop {
        if SHUTDOWN_FLAG.load(Ordering::Relaxed) {
            break;
        }

        let n = match tun_file.read(&mut buff) {
            Ok(0) => {
                println!("EOF reached!");
                break;
            }
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                continue;
            }
            Err(e) => {
                return Err(e);
            }
        };

        let packet = Packet::parse(&buff[..n])?;

        if packet.protocol == Protocol::TCP {
            println!("Hey tcp is here!!!");

            let length_of_ip_header = packet.ihl * 4;
            let length_of_segment = packet.total_length - length_of_ip_header as u16;

            let pseudo_header = [
                (packet.source_address >> 16) as u16,
                (packet.source_address & 0xFFFF) as u16,
                (packet.destination_address >> 16) as u16,
                (packet.destination_address & 0xFFFF) as u16,
                6,
                length_of_segment,
            ];

            let segment = Segment::parse(&buff[length_of_ip_header as usize..n], pseudo_header)?;

            // let segment_header_length = segment.data_offset * 4;

            // let data_size = length_of_segment - segment_header_length as u16;

            let segment_type = Segment::check_flags(segment.flags);

            match segment_type {
                RequestType::SYN => {
                    if let Some(pckt) = hanlde_syn(&packet, &segment, &mut connections) {
                        tun_file.write_all(&pckt)?
                    };
                }
                RequestType::ACK => {
                    hanlde_ack(&packet, &segment);
                }
                RequestType::Unknown(_) => {
                    continue;
                }
            }
        } else {
            println!("Packet is {}", packet.protocol);
        }
    }

    Command::new("sudo")
        .args([
            "iptables",
            "-D", // Use -D for Delete
            "INPUT",
            "-i",
            tunif_name,
            "-p",
            "tcp",
            "--tcp-flags",
            "SYN,RST,ACK,FIN",
            "SYN",
            "-j",
            "DROP",
        ])
        .status()?;

    println!("TUN is cleaned up!");

    Ok(())
}

fn hanlde_syn(
    packet: &Packet,
    segment: &Segment,
    connections: &mut HashMap<(u32, u16, u32, u16), Connection>,
) -> Option<[u8; 40]> {
    let isn = 0;

    let connection = Connection {
        state: State::SynRcvd,
        source_address: packet.source_address,
        source_port: segment.source_port,
        destination_address: packet.destination_address,
        destination_port: segment.destination_port,
        send_next: isn + 1,
        recv_next: segment.sequence_number + 1,
    };

    if connections.contains_key(&(
        connection.source_address,
        connection.source_port,
        connection.destination_address,
        connection.destination_port,
    )) {
        return None;
    }

    let tcp_header = match Segment::build(&connection) {
        Ok(header) => header,
        Err(_) => {
            println!("Checksum calc is not done correctly for segment");
            return None;
        }
    };

    let ip_packet = match Packet::build(tcp_header, &connection) {
        Ok(packet) => packet,
        Err(_) => {
            println!("Checksum calc is not done correctly for packet");
            return None;
        }
    };

    connections.insert(
        (
            connection.source_address,
            connection.source_port,
            connection.destination_address,
            connection.destination_port,
        ),
        connection,
    );

    return Some(ip_packet);
}

fn hanlde_ack(packet: &Packet, segment: &Segment) {
    println!("ACK received");
}

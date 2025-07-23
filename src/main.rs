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

    configure(tunif_name, tunif_address)?;

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

            let segment_type = Segment::check_flags(segment.flags);

            match segment_type {
                RequestType::SYN => {
                    if let Some(pckt) = handle_syn(&packet, &segment, &mut connections) {
                        tun_file.write_all(&pckt)?
                    };
                }
                RequestType::ACK => {
                    if let Some(pckt) = handle_ack(&packet, &segment, &mut connections) {
                        tun_file.write_all(&pckt)?
                    };
                }
                RequestType::PSHACK => {
                    if let Some(pckt) = handle_pshack(&packet, &segment, &mut connections, &buff) {
                        tun_file.write_all(&pckt)?
                    };
                }
                _ => {}
            }
        }
    }

    return cleanup(tunif_name);
}

fn handle_syn(
    packet: &Packet,
    segment: &Segment,
    connections: &mut HashMap<(u32, u16, u32, u16), Connection>,
) -> Option<[u8; 40]> {
    let key = (
        packet.source_address,
        segment.source_port,
        packet.destination_address,
        segment.destination_port,
    );

    if connections.contains_key(&key) {
        return None;
    }

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

    let tcp_header = match Segment::build(&connection, RequestType::SYNACK) {
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

    connections.insert(key, connection);

    return Some(ip_packet);
}

fn handle_ack(
    packet: &Packet,
    segment: &Segment,
    connections: &mut HashMap<(u32, u16, u32, u16), Connection>,
) -> Option<[u8; 40]> {
    let key = (
        packet.source_address,
        segment.source_port,
        packet.destination_address,
        segment.destination_port,
    );

    if let Some(connection) = connections.get_mut(&key) {
        match connection.state {
            State::SynRcvd => {
                if segment.acknowledgement_number == connection.send_next {
                    println!("Connection ESTABLISHED!");
                    connection.state = State::Established;
                } else {
                    println!("Received ACK with wrong number for a connection in SYN_RCVD.");
                }
            }
            State::Established => {
                println!("Established connection is sending an ack");
                //we will send some packet here
            }
            _ => {}
        }
    }
    return None;
}

fn handle_pshack(
    packet: &Packet,
    segment: &Segment,
    connections: &mut HashMap<(u32, u16, u32, u16), Connection>,
    buff: &[u8; 2000],
) -> Option<[u8; 40]> {
    let key = (
        packet.source_address,
        segment.source_port,
        packet.destination_address,
        segment.destination_port,
    );

    if let Some(connection) = connections.get_mut(&key) {
        match connection.state {
            State::Established => {
                if segment.sequence_number == connection.recv_next {
                    let tcp_header_length = segment.data_offset * 4;
                    let total_header_length = (packet.ihl * 4) + tcp_header_length;
                    let data_length = packet.total_length as usize - total_header_length as usize;

                    if data_length > 0 {
                        let payload_start = total_header_length as usize;
                        let payload_end = payload_start + data_length;
                        let payload = &buff[payload_start..payload_end];
                        println!("Received Data: {}", String::from_utf8_lossy(payload));
                    }

                    connection.recv_next += data_length as u32;
                    connection.send_next += 1;

                    let tcp_header = match Segment::build(&connection, RequestType::ACK) {
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

                    return Some(ip_packet);
                }
            }
            _ => {}
        }
    }
    return None;
}

fn configure(name: &'static str, address: &'static str) -> io::Result<()> {
    Command::new("sudo")
        .args([
            "iptables",
            "-I",
            "INPUT",
            "1",
            "-i",
            name,
            "-p",
            "tcp",
            "--tcp-flags",
            "SYN,RST,ACK,FIN",
            "SYN",
            "-j",
            "DROP",
        ])
        .status()?;

    Command::new("sudo")
        .args([
            "sysctl",
            "-w",
            &format!("net.ipv6.conf.{}.disable_ipv6=1", name),
        ])
        .stdout(Stdio::null())
        .status()?;

    Command::new("sudo")
        .args(["ip", "link", "set", "dev", name, "up"])
        .status()?;

    Command::new("sudo")
        .args(["ip", "addr", "add", address, "dev", name])
        .status()?;

    println!("TUN is set up!");

    Ok(())
}

fn cleanup(name: &'static str) -> io::Result<()> {
    Command::new("sudo")
        .args([
            "iptables",
            "-D",
            "INPUT",
            "-i",
            name,
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

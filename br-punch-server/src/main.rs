use {
    etherparse::{InternetSlice, LinkSlice, PacketBuilder, SlicedPacket, TransportSlice},
    pcap::Device,
    rayon::prelude::*,
    std::{
        env,
        net::{Ipv4Addr, UdpSocket},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread,
        time::Duration,
    },
    websocket::{client::ClientBuilder, OwnedMessage},
};

#[derive(Clone, Copy, Debug)]
struct PacketMeta {
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
}

// default server is hardcoded in because people are lazy
const WS_HOST: &'static str = "104.155.180.165:6923";

const FAKE_SRC_PORT: u16 = 3333;
const FAKE_TARGET_IP: &'static str = "172.15.200.200";
const FAKE_TARGET_PORT: u16 = 44444;

fn main() {
    // default server port to first arg
    let server_port = env::args()
        .nth(1)
        .unwrap_or("7777".to_string())
        .parse()
        .unwrap_or(7777u16);

    let ws_host = env::args().nth(2).unwrap_or(WS_HOST.to_string());

    // get the ethernet/ip info from sending garbage packets
    // also get the device that is actually sending packets
    let (device, packet_meta) = if let Some((device_name, template)) = create_template(
        FAKE_SRC_PORT,
        FAKE_TARGET_IP.parse().unwrap(),
        FAKE_TARGET_PORT,
    ) {
        (
            get_device(device_name.clone()).unwrap(),
            get_packet_meta(template.clone()).unwrap(),
        )
    } else {
        panic!("unable to create template packet")
    };

    // create websocket
    let client = ClientBuilder::new(&format!("ws://{}/api/host", ws_host))
        .unwrap()
        .add_protocol("rust-websocket")
        .connect_insecure()
        .unwrap();

    let (mut receiver, mut sender) = client.split().unwrap();

    // packet interface
    let mut iface = device.open().expect("failed to open device");

    // tell the server the server ip
    sender
        .send_message(&OwnedMessage::Text(format!("server_port:{}", server_port)))
        .expect("failed to send server port to middle server");

    for message in receiver.incoming_messages() {
        let message = match message {
            Ok(m) => m,
            Err(e) => {
                println!("Incoming Message Error: {:?}", e);
                sender
                    .send_message(&OwnedMessage::Close(None))
                    .expect("error sending message");
                return;
            }
        };
        match message {
            OwnedMessage::Close(_) => {
                // Got a close message, so send a close message and return
                sender
                    .send_message(&OwnedMessage::Close(None))
                    .expect("error sending close response");
                return;
            }
            OwnedMessage::Ping(data) => {
                sender
                    .send_message(&OwnedMessage::Pong(data))
                    .expect("error sending pong");
            }
            OwnedMessage::Text(msg) => {
                if msg.starts_with("open") {
                    let opts = msg.split(" ").collect::<Vec<_>>();
                    if opts.len() == 3 {
                        // parse args from the message
                        let dst_ip = opts[1].parse().unwrap();
                        let dst_port = opts[2].parse().unwrap();
                        let packet = spoof_packet(packet_meta, server_port, dst_ip, dst_port)
                            .expect("failed to spoof packet");
                        iface.sendpacket(packet).expect("failed to send packet");
                    }
                }
            }
            // Say what we received
            _ => println!("Received message: {:?}", message),
        }
    }
}

// build a template packet
fn create_template(src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) -> Option<(String, Vec<u8>)> {
    let is_active = Arc::new(AtomicBool::new(true));

    // bind client socket to specified ports
    let sock = UdpSocket::bind(format!("0.0.0.0:{}", src_port)).expect("couldn't bind");
    sock.connect(format!("{}:{}", dst_ip, dst_port))
        .expect("couldn't connect");

    // send packets until no longer active
    let is_active_udp = Arc::clone(&is_active);
    thread::spawn(move || {
        while is_active_udp.load(Ordering::SeqCst) {
            sock.send(&[0]).expect("couldn't send");
            thread::sleep(Duration::from_millis(10));
        }
    });

    let capture_len = 500;

    // timer that only runs for one second
    let is_active_timer = is_active.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(capture_len));
        is_active_timer.swap(false, Ordering::Release);
    });

    let mut result: Vec<_> = Device::list()
        .unwrap()
        .par_iter()
        .cloned()
        .map(|device| {
            let is_active_cap = Arc::clone(&is_active);

            let name = device.clone().name;

            let mut cap = pcap::Capture::from_device(device)
                .unwrap()
                .immediate_mode(true)
                .timeout(capture_len as i32)
                .open()
                .unwrap();
            cap.filter("ip proto \\udp").unwrap();

            while is_active_cap.load(Ordering::SeqCst) {
                // capture a packet
                if let Ok(packet) = cap.next() {
                    // parse it
                    if let Ok(value) = SlicedPacket::from_ethernet(&packet) {
                        // ensure it's the packet we sent
                        if let (
                            Some(InternetSlice::Ipv4(internet)),
                            Some(TransportSlice::Udp(transport)),
                        ) = (value.ip, value.transport)
                        {
                            if src_port != transport.source_port()
                                || dst_port != transport.destination_port()
                                || dst_ip != internet.destination_addr()
                            {
                                continue;
                            }
                            // copy the packet - we will be using this one as a template
                            let mut data = vec![0u8; packet.len()];
                            data.copy_from_slice(&packet);
                            return (name, Some(data));
                        }
                    }
                }
            }

            return (name, None);
        })
        .filter_map(|(name, packet)| {
            if let Some(bytes) = packet {
                Some((name, bytes))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    result.pop()
}

// get mac/ip info from a packet
fn get_packet_meta(template: Vec<u8>) -> Option<PacketMeta> {
    if let Ok(value) = SlicedPacket::from_ethernet(&template) {
        match (value.link, value.ip) {
            (Some(LinkSlice::Ethernet2(link)), Some(InternetSlice::Ipv4(internet))) => {
                let mut src_mac = [0; 6];
                src_mac.copy_from_slice(link.source());
                let mut dst_mac = [0; 6];
                dst_mac.copy_from_slice(link.destination());

                Some(PacketMeta {
                    src_mac,
                    dst_mac,
                    src_ip: internet.source_addr(),
                })
            }
            _ => None,
        }
    } else {
        None
    }
}

// modify a template packet to be sent at a different destination from a different source port
fn spoof_packet(
    meta: PacketMeta,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> Option<Vec<u8>> {
    // build the packet with manipulated source and destination
    let builder = PacketBuilder::ethernet2(meta.src_mac, meta.dst_mac)
        .ipv4(meta.src_ip.octets(), dst_ip.octets(), 20)
        .udp(src_port, dst_port);

    // packet buffer
    let mut buf = Vec::with_capacity(builder.size(0));

    // return buffer on success
    match builder.write(&mut buf, &vec![]) {
        Ok(_) => Some(buf),
        _ => None,
    }
}

// get device by name
fn get_device(name: String) -> Option<Device> {
    Device::list().unwrap().into_iter().find(|d| d.name == name)
}

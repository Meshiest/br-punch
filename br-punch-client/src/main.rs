use {
    dirs,
    netstat::{get_sockets_info, AddressFamilyFlags, ProtocolFlags},
    regex::Regex,
    reqwest,
    sha1::Sha1,
    std::{env, fs::File, io::prelude::*},
    sysinfo::{ProcessExt, SystemExt},
};

// default server is hardcoded in because people are lazy
const NOTIFY_HOST: &'static str = "104.155.180.165:6923";

fn main() {
    let notify_host = env::args().nth(1).unwrap_or(NOTIFY_HOST.to_string());

    let target = get_target_server();
    println!("target server: {:?}", target);

    let mut system = sysinfo::System::new();
    system.refresh_all();

    // find brickadia's process
    let brickadia_pid = get_brickadia_pid().expect("Brickadia should be running");

    // find all ports brickadia is using (should be one)
    let active_ports = get_active_ports(brickadia_pid);
    println!("my port: {:?}", active_ports);

    if active_ports.len() == 1 && target.is_some() {
        println!("telling server to let me in");
        notify_server(notify_host, target.unwrap(), active_ports[0]);
    } else {
        println!("I need to be trying to connect to a server!!!");
    }
}

// get brickadia's process
fn get_brickadia_pid() -> Option<u32> {
    // get processes
    let mut system = sysinfo::System::new();
    system.refresh_all();

    // find brickadia's process
    system
        .get_processes()
        .iter()
        .find(|(_pid, proc)| proc.name().contains("Brickadia"))
        .map(|(pid, _)| *pid as u32)
}

// get ports brickadia is actively using
fn get_active_ports(pid: u32) -> Vec<u16> {
    get_sockets_info(AddressFamilyFlags::IPV4, ProtocolFlags::UDP)
        .unwrap()
        .into_iter()
        .filter(|info| {
            info.associated_pids.iter().any(|&p|
                // all open sockets for brickadia's process
                p == pid
                // udp sockets only
                && match info.protocol_socket_info {
                    netstat::ProtocolSocketInfo::Udp(_) => true,
                    _ => false,
                })
        })
        .map(|info| match info.protocol_socket_info {
            netstat::ProtocolSocketInfo::Udp(info) => info.local_port,
            _ => unreachable!(),
        })
        .collect::<Vec<u16>>()
}

// find the ip:port combo from logs
fn get_target_server() -> Option<String> {
    // find the log that indicates brickadia is trying to connect
    let attempt_pattern =
        Regex::new(r"^\[.+?\]\[ *\d+\]LogTemp: Attempting to connect to (.+)\n?$").unwrap();

    // get brickadia log file path
    let localappdata = dirs::cache_dir().expect("not running on windows");
    let log_file_path = localappdata.join("Brickadia\\Saved\\Logs\\Brickadia.log");

    // read the file
    let mut file = File::open(log_file_path).expect("brickadia should be running");
    let mut contents = vec![];
    file.read_to_end(&mut contents).unwrap();
    let data = String::from_utf8(contents).unwrap();

    // find the last line that matches the regex
    data.lines()
        .filter(|line| attempt_pattern.is_match(line))
        .last()
        .map(|line| {
            // extract the IP from the line
            let cap = attempt_pattern.captures(line).unwrap();
            if cap.len() > 1 {
                cap[1].to_string()
            } else {
                unreachable!()
            }
        })
}

// let the server know to punch this port
fn notify_server(server: String, target: String, port: u16) {
    let client = reqwest::blocking::Client::new();
    let res = client
        .post(format!(
            "http://{}/api/join?target={}&port={}",
            server,
            sha1(target),
            port
        ))
        .send();
    if res.is_ok() {
        println!("sent message to punch server")
    } else {
        println!("error sending message to punch server")
    }
}

// generate a sha1 from a string
fn sha1(str: String) -> String {
    let mut hash = Sha1::new();
    hash.update(str.as_bytes());
    hash.digest()
        .bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

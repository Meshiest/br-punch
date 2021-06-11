# Brickadia nat punch tools

Brickadia doesn't have native nat punch capabilities.
These tools address this issue, though clients and servers need to run a program for it to work.

**It is recommended to port forward or wait for official nat punch support rather than use this tool.**

[Download from the releases tab](https://github.com/Meshiest/br-punch/releases). It's not a virus, windows just hasn't seen it before.

Running a server requires [winpcap](https://www.winpcap.org/install/default.htm). Client doesn't require anything extra.

This is not guaranteed to fix your server hosting problems, though it should work 95% of the time.

Closing the application will not break your brickadia server or disconnect anyone.

## br-punch-client

Run this when you are connecting to a server to tell the server to let you in.

### Process

1. Checks for running Brickadia process, finds the UDP port it's listening on.
2. Checks brickadia logs for the server you're trying to connect to.
3. Sends a POST request to br-punch-middle with `sha1(hostip:port)` and client udp port.

That's it.

### Options

* `br-punch-client` - uses default br-punch-middle server
* `br-punch-client 1.2.3.4:3000` - connects to br-punch-middle server at `1.2.3.4:3000`

### Compiling

Rust: `cargo build`

## br-punch-server

Run this while you host to let people people join your server without port forwarding.

Note: The server requires [winpcap](https://www.winpcap.org/install/default.htm) because it provides low level access for manipulating packets. Yes, npcap exists, but the pcap rust library uses winpcap.

### Process

1. Sends some garbage packets with known source and destination to grab information for forging packets and learn which device is used for networking.
2. Connect to br-punch-middle and tell it which port is being used for the server
3. Wait for br-punch-middle to send a client's ip:port combo.
4. Using the packet information, create a fake udp packet pretending to be sourced from brickadia's port with the client's destination.
5. The client should be able to join!

### Options

`br-punch-server [port [middleServerIp]]`

* `br-punch-server` - uses default br-punch-middle server on brickadia server port 7777
* `br-punch-server 7778` - uses default br-punch-middle server on brickadia server port 7778
* `br-punch-server 7779 1.2.3.4:3000` - connects to br-punch-middle server at `1.2.3.4:3000` on brickadia server port 7779

### Compiling

Rust: `cargo build`

## br-punch-middle

Your own middle server if the main one goes down.

### Process

1. A punch-server joins via websocket and specifies brickadia server port. The server is added to a list of available servers.
2. A punch-client makes a POST request and specifies a target hash and brickadia client port.
3. The punch-server is sent the punch-client's information

### Running

`PORT=3000 npm start`

trust proxies with `PROXY=yes PORT=3000 npm start`

specify your own external IP with `EXTERNAL_IP=1.2.3.4 PORT=3000 npm start`

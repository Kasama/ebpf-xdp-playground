use std::io;

use tokio::join;
use tokio::net::UdpSocket;

enum Protocol {
    UDP(u16),
}

#[tokio::main]
async fn main() {
    let wait = vec![
        tokio::spawn(run_server(Protocol::UDP(9874))),
        tokio::spawn(run_server(Protocol::UDP(9875))),
        tokio::spawn(run_server(Protocol::UDP(9876))),
    ];

    for w in wait {
        w.await.expect("server failed").unwrap();
    };
}

async fn run_server(protocol: Protocol) -> io::Result<()> {
    match protocol {
        Protocol::UDP(port) => {
            let bindaddr = format!("127.0.0.1:{}", port);

            let sock = UdpSocket::bind(&bindaddr).await?;
            println!("Listening on {bindaddr}");

            let mut buf = [0; 16];

            loop {
                let (len, addr) = sock.recv_from(&mut buf).await?;
                println!("Port {port}: {len} bytes received from {addr}");
                println!(
                    "port {port}: buffer contents: {}",
                    String::from_utf8_lossy(&buf)
                );
            }
        }
    }
}

use std::env;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::sync::Mutex;

static SEGMENT_BITS: u8 = 0x7F;
static CONTINUE_BIT: u8 = 0x80;

enum ConnectionState {
    WaitingHandshake,
    Status,
    Forward,
    Closed,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listen_addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:25577".to_string());
    let server_addr = env::args()
        .nth(2)
        .unwrap_or_else(|| "0.0.0.0:25565".to_string());

    println!("Listening on: {}", listen_addr);
    println!("Proxying to: {}", server_addr);

    let listener = TcpListener::bind(listen_addr).await?;
    while let Ok((inbound, incoming_addr)) = listener.accept().await {
        tokio::spawn(
            listener_thread(inbound, incoming_addr, server_addr.clone())
        );
    }

    Ok(())
}

async fn listener_thread(inbound: TcpStream, incoming_addr: SocketAddr, server_addr: String) {
    println!("Incoming connection from: {}", incoming_addr);
    let result = transfer(inbound, server_addr).await;

    if let Err(e) = result {
        println!("Error: {}", e);
    }
}

async fn transfer(mut inbound: TcpStream, proxy_addr: String) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut outbound = TcpStream::connect(proxy_addr).await?;

    let (ri, wi) = inbound.split();
    let (ro, wo) = outbound.split();
    let arc_wi = Arc::new(Mutex::new(wi));

    tokio::try_join!(handle_client_to_server(ri, wo, Arc::clone(&arc_wi)), handle_server_to_client(ro, Arc::clone(&arc_wi)))?;

    match outbound.shutdown().await {
        Ok(_) => println!("Shutdown outbound"),
        Err(e) => println!("Error shutting down outbound: {}", e),
    };
    match inbound.shutdown().await {
        Ok(_) => println!("Shutdown inbound"),
        Err(e) => println!("Error shutting down inbound: {}", e),
    };

    Ok(())
}

async fn handle_client_to_server(mut ri: ReadHalf<'_>, mut wo: WriteHalf<'_>, wi: Arc<Mutex<WriteHalf<'_>>>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut state = ConnectionState::WaitingHandshake;
    loop {
        match state {
            ConnectionState::WaitingHandshake => {
                match read_var_int(&mut ri).await { // Packet length - ignored
                    Ok(length) => length,
                    Err(e) => return Err(Box::try_from(e.to_string())?)
                };
                let packet_id = match read_var_int(&mut ri).await {
                    Ok(packet_id) => packet_id,
                    Err(e) => return Err(Box::try_from(e.to_string())?)
                };

                if packet_id != 0x00 {
                    println!("Handshake Invalid packet id: {}", packet_id);
                    return Ok(());
                }

                let protocol_version = match read_var_int(&mut ri).await {
                    Ok(protocol_version) => protocol_version,
                    Err(e) => return Err(Box::try_from(e.to_string())?)
                };
                let server_address = match read_string(&mut ri, 255).await {
                    Ok(server_address) => server_address,
                    Err(e) => return Err(Box::try_from(e.to_string())?)
                };
                let server_port = match read_unsigned_short(&mut ri).await {
                    Ok(server_port) => server_port,
                    Err(e) => return Err(Box::try_from(e.to_string())?)
                };
                let next_state = match read_var_int(&mut ri).await {
                    Ok(next_state) => next_state,
                    Err(e) => return Err(Box::try_from(e.to_string())?)
                };

                println!("Protocol version: {}", protocol_version);
                println!("Server address: {}", server_address);
                println!("Server port: {}", server_port);
                println!("Next state: {}", next_state);

                if next_state == 1 {
                    state = ConnectionState::Status;
                    wo.shutdown().await?;
                    println!("Waiting for status request from client");
                } else if next_state == 2 {
                    let mut bytes = BytesMut::new();
                    write_var_num_to_buf(&mut bytes, 0x00).await; // Packet id
                    write_var_num_to_buf(&mut bytes, protocol_version as isize).await;
                    write_string_to_buf(&mut bytes, server_address).await;
                    write_unsigned_short_to_buf(&mut bytes, server_port).await;
                    write_var_num_to_buf(&mut bytes, next_state as isize).await;

                    write_packet(&mut wo, &bytes).await?;

                    state = ConnectionState::Forward;
                    println!("Allowing unfiltered traffic from client");
                } else {
                    println!("Invalid next state: {}", next_state);
                    return Ok(());
                }
            }
            ConnectionState::Status => {
                let packet_length = match read_var_int(&mut ri).await { // Packet length - ignored
                    Ok(length) => length,
                    Err(e) => return Err(Box::try_from(e.to_string())?)
                };
                println!("Status packet length: {}", packet_length);
                let packet_id = match read_var_int(&mut ri).await {
                    Ok(packet_id) => packet_id,
                    Err(e) => return Err(Box::try_from(e.to_string())?)
                };
                println!("Status packet id: {:#01x}", packet_id);

                if packet_id == 0x00 {
                    let response = r#"{"version":{"name":"1.19.3","protocol":761},"players":{"max":100,"online":0},"description":{"text":"I made a custom rust proxy!!!"}}"#;
                    let mut bytes = BytesMut::new();
                    write_var_num_to_buf(&mut bytes, 0x00).await; // Packet id
                    write_string_to_buf(&mut bytes, response.to_string()).await; // Response

                    let mut wi = wi.lock().await;
                    write_packet(&mut wi, &bytes).await?;
                } else if packet_id == 0x01 {
                    let payload = match read_var_long(&mut ri).await {
                        Ok(payload) => payload,
                        Err(e) => return Err(Box::try_from(e.to_string())?)
                    };

                    println!("Payload {}", payload);
                    println!("Status ping");

                    let mut bytes = BytesMut::new();
                    write_var_num_to_buf(&mut bytes, 0x01).await; // Packet id
                    write_var_num_to_buf(&mut bytes, payload as isize).await; // Payload

                    let mut wi = wi.lock().await;
                    write_packet(&mut wi, &bytes).await?;
                } else {
                    println!("Status invalid packet id: {}", packet_id);
                    return Ok(());
                }
            }
            ConnectionState::Forward => {
                let buf = &mut [0; 1024];
                let n = ri.read(buf).await?;
                if n == 0 {
                    return Ok(());
                }
                wo.write_all(&buf[0..n]).await?;
            }
            ConnectionState::Closed => {
                return Ok(());
            }
        }
    }
}

async fn handle_server_to_client(mut ro: ReadHalf<'_>, wi: Arc<Mutex<WriteHalf<'_>>>) -> Result<(), Box<dyn Error + Send + Sync>> {
    loop {
        let buf = &mut [0; 1024];
        let n = ro.read(buf).await?;
        if n == 0 {
            return Ok(())
        }
        match wi.lock().await.write_all(&buf[..n]).await {
            Ok(_) => (),
            Err(e) => {
                println!("Error writing packet: {}", e);
                return Ok(());
            }
        };
    }
}

async fn read_var_int(stream: &mut ReadHalf<'_>) -> Result<i32, Box<dyn Error>> {
    let mut value = 0;
    let mut position = 0;
    let mut current_byte = 0;

    loop {
        let mut buf = [0; 1];
        stream.read_exact(&mut buf).await?;
        current_byte = buf[0];

        value |= ((current_byte & SEGMENT_BITS) as i32) << position;

        if (current_byte & CONTINUE_BIT) == 0 {
            break;
        }

        position += 7;

        if position >= 32 {
            return Err(Box::try_from("VarInt is too big")?);
        }
    }

    Ok(value)
}

async fn read_var_long(stream: &mut ReadHalf<'_>) -> Result<i64, Box<dyn Error>> {
    let mut value = 0;
    let mut position = 0;
    let mut current_byte = 0;

    loop {
        let mut buf = [0; 1];
        stream.read_exact(&mut buf).await?;
        current_byte = buf[0];

        value |= ((current_byte & SEGMENT_BITS) as i64) << position;

        if (current_byte & CONTINUE_BIT) == 0 {
            break;
        }

        position += 7;

        if position >= 64 {
            return Err(Box::try_from("VarLong is too big")?);
        }
    }

    Ok(value)
}

async fn read_string(stream: &mut ReadHalf<'_>, max_length: i32) -> Result<String, Box<dyn Error>> {
    let length = read_var_int(stream).await?;
    if length == 0 {
        return Ok("".to_string());
    }
    if length > max_length {
        return Err("String too big".into());
    }
    let mut buf = vec![0; length as usize];
    stream.read_exact(&mut buf).await?;
    Ok(String::from_utf8(buf)?)
}

async fn read_unsigned_short(stream: &mut ReadHalf<'_>) -> Result<u16, Box<dyn Error>> {
    let mut buf = [0; 2];
    stream.read_exact(&mut buf).await?;
    Ok(u16::from_be_bytes(buf))
}

async fn write_string_to_buf(buf: &mut BytesMut, value: String) {
    write_var_num_to_buf(buf, value.len() as isize).await;
    buf.put(value.as_bytes());
}

async fn write_var_num_to_buf(buf: &mut BytesMut, mut value: isize) {
    loop {
        let mut temp = (value & (SEGMENT_BITS as isize)) as u8;
        value >>= 7;
        if value != 0 {
            temp |= CONTINUE_BIT;
        }
        buf.put_u8(temp);
        if value == 0 {
            break;
        }
    }
}

async fn write_unsigned_short_to_buf(buf: &mut BytesMut, value: u16) {
    buf.put_u16(value);
}

async fn write_packet(stream: &mut WriteHalf<'_>, buf: &BytesMut) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut length_buf = BytesMut::with_capacity(5);
    write_var_num_to_buf(&mut length_buf, buf.len() as isize).await;
    stream.write_all(&length_buf).await?;
    stream.write_all(buf).await?;
    Ok(())
}

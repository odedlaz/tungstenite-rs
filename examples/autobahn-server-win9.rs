//! Lever arm for the Autobahn tester-memory experiment: identical to
//! `autobahn-server` except that our compression window is capped at 9 bits.
//!
//! Autobahn already offers `server_max_window_bits=9` on 54 of the 216
//! compression cases and we already agree it; this arm moves the other 162 from
//! 15 to 9, so the measurement covers the whole group rather than a quarter of
//! it. On the 126 cases whose offer omits the parameter our response now demands
//! it, which RFC 7692 §7.1.2.1 permits without a companion client-MUST-support
//! -- if wstest rejects it the handshake fails loudly and the arm is void, not
//! quietly cheaper.
//!
//! Measured null: wstest accepted all 126, and peak, onset and abort rate all
//! matched the 15-bit default. The window is not a mitigation.

use std::{
    net::{TcpListener, TcpStream},
    thread::spawn,
};

use log::*;
use tungstenite::{
    accept_with_config,
    handshake::HandshakeRole,
    protocol::{Role, WebSocketConfig},
    Error, HandshakeError, Message, Result,
};

fn must_not_block<Role: HandshakeRole>(err: HandshakeError<Role>) -> Error {
    match err {
        HandshakeError::Interrupted(_) => panic!("Bug: blocking socket would block"),
        HandshakeError::Failure(f) => f,
    }
}

fn handle_client(stream: TcpStream) -> Result<()> {
    // Enabling is all the server owes: the accept path answers the client's offers.
    let mut socket = accept_with_config(
        stream,
        Some(WebSocketConfig::default().enable_deflate().deflate_max_window_bits(Role::Server, 9)),
    )
    .map_err(must_not_block)?;
    info!("Running test");
    loop {
        match socket.read()? {
            msg @ Message::Text(_) | msg @ Message::Binary(_) => {
                socket.send(msg)?;
            }
            Message::Ping(_) | Message::Pong(_) | Message::Close(_) | Message::Frame(_) => {}
        }
    }
}

fn main() {
    env_logger::init();

    let server = TcpListener::bind("127.0.0.1:9002").unwrap();

    for stream in server.incoming() {
        spawn(move || match stream {
            Ok(stream) => {
                if let Err(err) = handle_client(stream) {
                    match err {
                        Error::ConnectionClosed | Error::Protocol(_) | Error::Utf8(_) => (),
                        e => error!("test: {e}"),
                    }
                }
            }
            Err(e) => error!("Error accepting stream: {e}"),
        });
    }
}

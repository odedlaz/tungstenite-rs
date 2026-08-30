//! The Autobahn server suite with permessage-deflate negotiated.
//!
//! A sibling of `autobahn-server` rather than a flag on it: the feature-off example is the
//! object the unchanged three-toolchain job measures, and keeping it byte-identical is worth
//! more here than sharing the echo loop.

use std::{
    net::{TcpListener, TcpStream},
    thread::spawn,
};

use log::*;
use tungstenite::{
    accept_with_config, handshake::HandshakeRole, protocol::WebSocketConfig, Error, HandshakeError,
    Message, Result,
};

fn must_not_block<Role: HandshakeRole>(err: HandshakeError<Role>) -> Error {
    match err {
        HandshakeError::Interrupted(_) => panic!("Bug: blocking socket would block"),
        HandshakeError::Failure(f) => f,
    }
}

fn handle_client(stream: TcpStream) -> Result<()> {
    let config = WebSocketConfig::default().enable_deflate();
    let mut socket = accept_with_config(stream, Some(config)).map_err(must_not_block)?;
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

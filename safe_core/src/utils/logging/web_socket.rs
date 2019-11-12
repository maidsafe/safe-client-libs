// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use std::borrow::Borrow;
use std::collections::VecDeque;
use std::convert::From;
use std::io;
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use url::Url;
use ws::{self, CloseCode, Handler, Handshake, Message, Request};

/// Try to reconnect at most once every `RECONNECT_PERIOD` seconds.
#[cfg(not(test))]
const RECONNECT_PERIOD: u64 = 10;
#[cfg(test)]
const RECONNECT_PERIOD: u64 = 0;

/// Maximum number of messages to hold until we start dropping some.
/// 500,000 messages at 100B each is approx 50MB.
const MAX_BUFFERED_MESSAGES: usize = 500_000;

/// HTTP header name to use in web socket handshake request.
/// The session ID is agreed upon by the server and all loggers to prevent spam.
const SESSION_ID_HEADER: &str = "SessionId";

pub struct WebSocket {
    url: String,
    session_id: Option<String>,
    socket: ws::Result<(ws::Sender, JoinHandle<()>)>,
    last_reconnect: Instant,
    message_buffer: VecDeque<Message>,
}

impl WebSocket {
    pub fn new<U: Borrow<str>>(url_borrow: U, session_id: Option<String>) -> Self {
        let url = url_borrow.borrow().to_owned();
        // Set `last_reconnect` in the past to allow an instant reconnect if the initial
        // connection fails.
        let last_reconnect = Instant::now() - Duration::from_secs(RECONNECT_PERIOD);
        let socket = Self::connect(url.clone(), session_id.clone());

        WebSocket {
            url,
            session_id,
            socket,
            last_reconnect,
            message_buffer: VecDeque::new(),
        }
    }

    pub fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.queue_message(Message::Binary(buf.to_owned()));

        while let Some(msg) = self.message_buffer.pop_front() {
            let to_send = msg.clone();

            if self
                .get_sender()
                .and_then(|sender| sender.send(to_send))
                .is_err()
            {
                // If sending fails, requeue the message and try to reconnect (note: this blocks!).
                self.message_buffer.push_front(msg);

                let now = Instant::now();

                if now - self.last_reconnect >= Duration::from_secs(RECONNECT_PERIOD) {
                    self.last_reconnect = now;
                    self.socket = Self::connect(self.url.clone(), self.session_id.clone());
                }

                if self.socket.is_err() {
                    break;
                }
            }
        }

        Ok(())
    }

    fn get_sender(&self) -> ws::Result<&ws::Sender> {
        self.socket
            .as_ref()
            .map(|&(ref sender, _)| sender)
            .map_err(|_| ws::Error::new(ws::ErrorKind::Internal, "No web socket thread running"))
    }

    /// Try to queue a message. If the buffer is full the message is dropped.
    fn queue_message(&mut self, msg: Message) {
        if self.message_buffer.len() < MAX_BUFFERED_MESSAGES {
            self.message_buffer.push_back(msg);
        }
    }

    /// Start a thread to run the websocket event loop.
    ///
    /// This will *block* until either an error occurs or the WS handshake succeeds.
    pub fn connect(
        url: String,
        mut session_id: Option<String>,
    ) -> ws::Result<(ws::Sender, JoinHandle<()>)> {
        let (tx, rx) = mpsc::channel();

        let joiner = thread::Builder::new()
            .name(String::from("WebSocketLogger"))
            .spawn(move || {
                struct Client<'a> {
                    ws_tx: ws::Sender,
                    tx: &'a Sender<ws::Result<ws::Sender>>,
                    session_id: Option<String>,
                }

                impl<'a> Client<'a> {
                    fn new(
                        ws_tx: ws::Sender,
                        tx: &'a Sender<ws::Result<ws::Sender>>,
                        session_id: Option<String>,
                    ) -> Self {
                        Client {
                            ws_tx,
                            tx,
                            session_id,
                        }
                    }
                }

                impl<'a> Handler for Client<'a> {
                    // Include a "SessionId: <session-id>" header in our handshake request.
                    fn build_request(&mut self, url: &Url) -> ws::Result<Request> {
                        let mut req = Request::from_url(url)?;
                        if let Some(ref session_id) = self.session_id {
                            req.headers_mut()
                                .push((SESSION_ID_HEADER.into(), session_id.clone().into()));
                        }
                        Ok(req)
                    }

                    fn on_open(&mut self, _: Handshake) -> ws::Result<()> {
                        if self.tx.send(Ok(self.ws_tx.clone())).is_err() {
                            Err(ws::Error {
                                kind: ws::ErrorKind::Internal,
                                details: From::from("Channel error - Could not send ws_tx."),
                            })
                        } else {
                            Ok(())
                        }
                    }

                    fn on_error(&mut self, _: ws::Error) {
                        // Ignore errors (to prevent `ws` from logging them).
                    }
                }

                // Block indefinitely on the websocket's event loop.
                if let Err(e) = ws::connect(url, |ws_tx| Client::new(ws_tx, &tx, session_id.take()))
                {
                    // Or, if an error occurs while connecting, notify the constructor above.
                    let _ = tx.send(Err(e));
                }
            })?;

        match rx.recv() {
            Ok(Ok(ws_tx)) => Ok((ws_tx, joiner)),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(ws::Error::new(
                ws::ErrorKind::Internal,
                format!("WebSocket Logger Error: {:?}", e),
            )),
        }
    }
}

impl Drop for WebSocket {
    fn drop(&mut self) {
        let _ = self
            .get_sender()
            .and_then(|sender| sender.close(CloseCode::Normal));
    }
}

/// Check that a handshake request has the correct session ID value.
pub fn validate_request(req: &Request, expected_id: Option<&str>) -> ws::Result<ws::Response> {
    match (expected_id, req.header(SESSION_ID_HEADER)) {
        (Some(exp), Some(obs)) if &obs[..] == exp.as_bytes() => ws::Response::from_request(req),
        (None, _) => ws::Response::from_request(req),
        _ => Err(ws::Error::new(ws::ErrorKind::Internal, "Invalid SessionId")),
    }
}

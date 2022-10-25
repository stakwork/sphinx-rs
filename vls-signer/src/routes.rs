use rocket::response::stream::{Event, EventStream};
use rocket::tokio::select;
use rocket::tokio::sync::{
    broadcast::{self, error::RecvError},
    mpsc, oneshot,
};
use rocket::*;
use sphinx_signer::sphinx_glyph::{error::Error as ParserError, topics};

pub type Result<T> = std::result::Result<T, Error>;

/// Responses are received on the oneshot sender
#[derive(Debug)]
pub struct ChannelRequest {
    pub topic: String,
    pub message: Vec<u8>,
    pub reply_tx: oneshot::Sender<ChannelReply>,
}
impl ChannelRequest {
    pub fn new(topic: &str, message: Vec<u8>) -> (Self, oneshot::Receiver<ChannelReply>) {
        let (reply_tx, reply_rx) = oneshot::channel();
        let cr = ChannelRequest {
            topic: topic.to_string(),
            message,
            reply_tx,
        };
        (cr, reply_rx)
    }
}

// mpsc reply
#[derive(Debug)]
pub struct ChannelReply {
    pub reply: Vec<u8>,
}

#[post("/control?<msg>")]
pub async fn control(sender: &State<mpsc::Sender<ChannelRequest>>, msg: &str) -> Result<String> {
    let message = hex::decode(msg)?;
    // FIXME validate?
    if message.len() < 65 {
        return Err(Error::Fail);
    }
    let (request, reply_rx) = ChannelRequest::new(topics::CONTROL, message);
    // send to ESP
    let _ = sender.send(request).await.map_err(|_| Error::Fail)?;
    // wait for reply
    let reply = reply_rx.await.map_err(|_| Error::Fail)?;
    Ok(hex::encode(reply.reply).to_string())
}

#[get("/errors")]
async fn errors(error_tx: &State<broadcast::Sender<Vec<u8>>>, mut end: Shutdown) -> EventStream![] {
    let mut rx = error_tx.subscribe();
    EventStream! {
        loop {
            let msg = select! {
                msg = rx.recv() => match msg {
                    Ok(msg) => ParserError::from_slice(&msg[..]),
                    Err(RecvError::Closed) => break,
                    Err(RecvError::Lagged(_)) => continue,
                },
                _ = &mut end => break,
            };

            yield Event::json(&msg);
        }
    }
}

pub fn launch_rocket(
    tx: mpsc::Sender<ChannelRequest>,
    error_tx: broadcast::Sender<Vec<u8>>,
) -> Rocket<Build> {
    let config = Config {
        // address: V4(Ipv4Addr::UNSPECIFIED),
        // port: settings.http_port,
        ..Config::debug_default()
    };
    rocket::build()
        .configure(config)
        .mount("/api/", routes![control, errors])
        .manage(tx)
        .manage(error_tx)
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed")]
    Fail,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("hex error: {0}")]
    Hex(#[from] hex::FromHexError),
}

use rocket::http::Status;
use rocket::response::{self, Responder};
impl<'r, 'o: 'r> Responder<'r, 'o> for Error {
    fn respond_to(self, req: &'r rocket::Request<'_>) -> response::Result<'o> {
        // log `self` to your favored error tracker, e.g.
        // sentry::capture_error(&self);
        match self {
            // in our simplistic example, we're happy to respond with the default 500 responder in all cases
            _ => Status::InternalServerError.respond_to(req),
        }
    }
}

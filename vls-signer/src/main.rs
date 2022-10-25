mod signer;

use crate::env::check_env;
use crate::logs::{get_log_tx, LogChans, LOGS};
use fairing::{Fairing, Info, Kind};
use fs::{relative, FileServer};
use response::stream::{Event, EventStream};
use rocket::serde::json::json;
use rocket::*;
use std::sync::Arc;
use tokio::sync::{broadcast::error::RecvError, mpsc, oneshot, Mutex};

pub type Result<T> = std::result::Result<T, Error>;


/// Responses are received on the oneshot sender
#[derive(Debug)]
pub struct CmdRequest {
    pub tag: String,
    pub message: String,
    pub reply_tx: oneshot::Sender<String>,
}
impl CmdRequest {
    pub fn new(tag: &str, message: &str) -> (Self, oneshot::Receiver<String>) {
        let (reply_tx, reply_rx) = oneshot::channel();
        let cr = CmdRequest {
            tag: tag.to_string(),
            message: message.to_string(),
            reply_tx,
        };
        (cr, reply_rx)
    }
}

#[get("/cmd?<tag>&<txt>")]
pub async fn cmd(sender: &State<mpsc::Sender<CmdRequest>>, tag: &str, txt: &str) -> Result<String> {
    let (request, reply_rx) = CmdRequest::new(tag, &txt);
    let _ = sender.send(request).await.map_err(|_| Error::Fail)?;
    let reply = reply_rx.await.map_err(|_| Error::Fail)?;
    Ok(reply)
}


#[get("/logs?<tag>")]
async fn logs(tag: &str) -> Result<String> {
    let lgs = LOGS.lock().await;
    let ret = lgs.get(tag).unwrap_or(&Vec::new()).clone();
    Ok(json!(ret).to_string())
}

#[get("/logstream?<tag>")]
async fn logstream(
    log_txs: &State<Arc<Mutex<LogChans>>>,
    mut end: Shutdown,
    tag: &str,
) -> EventStream![] {
    let log_tx = get_log_tx(tag, log_txs).await;
    let mut rx = log_tx.subscribe();
    EventStream! {
        loop {
            let msg = tokio::select! {
                msg = rx.recv() => match msg {
                    Ok(lo) => lo,
                    Err(RecvError::Closed) => break,
                    Err(RecvError::Lagged(_)) => continue,
                },
                _ = &mut end => break,
            };

            yield Event::json(&msg);
        }
    }
}


// {tag: [log]}
pub type LogStore = HashMap<String, Vec<String>>;

pub static LOGS: Lazy<Mutex<LogStore>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub type LogChans = HashMap<String, broadcast::Sender<String>>;

pub async fn launch_rocket(
    tx: mpsc::Sender<CmdRequest>,
    log_txs: Arc<Mutex<LogChans>>,
) -> Result<Rocket<Ignite>> {
    Ok(rocket::build()
        .mount("/", FileServer::from(relative!("app/public")))
        .mount("/api/", routes![cmd, logstream, logs])
        .manage(tx)
        .manage(log_txs)
        .launch()
        .await?)
}
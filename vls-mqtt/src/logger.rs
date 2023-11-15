use log::*;
use rocket::tokio::{self, sync::broadcast};
use std::io::Write;
use std::{env, fs};

const DEFAULT_ERROR_LOG_PATH: &str = "error.log";

pub fn log_errors(mut error_rx: broadcast::Receiver<Vec<u8>>) {
    // collect errors
    tokio::spawn(async move {
        let err_log_path = env::var("ERROR_LOG_PATH").unwrap_or(DEFAULT_ERROR_LOG_PATH.to_string());
        if let Ok(mut file) = fs::OpenOptions::new()
            .create(true) // create if doesn't exist
            .append(true)
            .open(err_log_path)
        {
            while let Ok(err_msg) = error_rx.recv().await {
                let mut log = format!("[{}]: ", chrono::Utc::now())
                    .as_bytes()
                    .to_vec();
                log.extend_from_slice(&err_msg);
                log.extend_from_slice(b"\n");
                if let Err(e) = file.write_all(&log) {
                    log::warn!("failed to write error to log {:?}", e);
                }
            }
        } else {
            log::warn!("FAILED TO OPEN ERROR LOG FILE");
        }
    });
}

struct MyLogger {
    filter: LevelFilter,
    tx: Option<broadcast::Sender<Vec<u8>>>,
}

impl Log for MyLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.filter
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let lg = format!("{} {} {}", record.level(), record.target(), record.args());
            if let Some(tx) = &self.tx {
                let _ = tx.send(lg.as_bytes().to_vec());
            } else {
                println!("{}", &lg);
            }
        }
    }

    fn flush(&self) {}
}

pub fn setup_logs(error_tx: broadcast::Sender<Vec<u8>>) {
    // let (log_tx, mut log_rx) = broadcast::channel::<Vec<u8>>(1000);
    // tokio::spawn(async move {
    //     while let Ok(log_msg) = log_rx.recv().await {
    //         println!("{}", String::from_utf8_lossy(&log_msg));
    //     }
    // });
    let elog1: Box<dyn Log> = Box::new(MyLogger {
        filter: LevelFilter::Debug,
        // tx: Some(log_tx),
        tx: None,
    });
    let elog2: Box<dyn Log> = Box::new(MyLogger {
        filter: LevelFilter::Error,
        tx: Some(error_tx),
    });
    fern::Dispatch::new()
        .level(LevelFilter::Debug)
        // .level_for("lightning_signer", LevelFilter::Info)
        .level_for("rocket", LevelFilter::Info)
        .level_for("rumqttc", LevelFilter::Warn)
        // .level_for("sphinx_signer", LevelFilter::Info)
        .chain(elog1) // Chaining two logs
        .chain(elog2)
        .apply()
        .expect("log config");
    debug!("debug");
    info!("info");
    info!(target: "lightning_signer", "info policy");
    warn!(target: "lightning_signer", "warn policy");
    warn!("warn");
}

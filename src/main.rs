#[macro_use]
extern crate log;
extern crate base64;
extern crate log4rs;
extern crate notify;
extern crate openssl;
extern crate openssl_probe;

use notify::{DebouncedEvent, RecommendedWatcher, RecursiveMode, Watcher};
use openssl::{cms::CmsContentInfo, error::ErrorStack, pkey::{PKey, Private}, x509::X509};
use std::ffi::OsStr;
use std::ops::Deref;
use std::panic;
use std::sync::mpsc::channel;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::io::{self, prelude::*};
use std::time::Duration;

const LOGGING_SETTINGS_FILE: &str = "config/log4rs.yaml";
const PRIVATE_KEY_PATH: &str = "config/private.key";
const CERTIFICATE_PATH: &str = "config/cert.pem";
const INBOX_PATH: &str = "inbox";
const DECRYPTED_PATH: &str = "decrypted";
const SMIME_HEADER: &str = "MIME-Version: 1.0\nContent-Disposition: attachment; filename=\"smime.p7m\"\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\nContent-Transfer-Encoding: base64\n\n";

fn decrypt_message(
    private_key: &PKey<Private>,
    certificate: &X509,
    message: &CmsContentInfo,
) -> Result<Vec<u8>, ErrorStack> {
    message.decrypt(private_key, certificate)
}

// Parse S/MIME message to CMS_ContentInfo struct.
fn parse_message(message: &[u8]) -> Result<CmsContentInfo, ErrorStack> {
    CmsContentInfo::smime_read_cms(message)
}

// Split string by substring length to vector of the substrings.
fn sub_strings(string: &str, sub_len: usize) -> Vec<&str> {
    let mut subs = Vec::with_capacity(string.len() / sub_len);
    let mut iter = string.chars();
    let mut pos = 0;

    while pos < string.len() {
        let mut len = 0;
        for ch in iter.by_ref().take(sub_len) {
            len += ch.len_utf8();
        }
        subs.push(&string[pos..pos + len]);
        pos += len;
    }
    subs
}

// Convert binary (DER) S/MIME data to PEM enveloped-data format.
fn to_smime(message: &[u8]) -> Result<Vec<u8>, ()> {
    // Width of the base64 encoded line.
    let pem_width: usize = 64;
    // Encode binary data to base64.
    let base64_message = base64::encode_config(message, base64::STANDARD);
    // Join smime header and base64-encoded data to final message.
    let enveloped_data =
        SMIME_HEADER.to_owned() + &sub_strings(&base64_message, pem_width).join("\n");
    debug!("Enveloped data:\n{}", enveloped_data);
    // Return enveloped-data as vector of bytes.
    Ok(enveloped_data.as_bytes().to_vec())
}

fn get_message(path: &PathBuf) -> Result<Vec<u8>, io::Error> {
    // Check whether message file exist at all.
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Message file not found",
        ));
    }

    // Check whether path is a regular file.
    let metadata = fs::metadata(path)?;
    let file_type = metadata.file_type();

    if !file_type.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Message should be a regular file",
        ));
    }

    // Try to open and read message.
    let mut message_file = File::open(path)?;
    let mut message = Vec::new();
    message_file.read_to_end(&mut message)?;

    // Convert DER binary data to PEM enveloped-data format.
    // It is required as smime_read_cms function requires this format as input.
    message = to_smime(&message).unwrap();
    Ok(message)
}

fn save_message(decrypted_message: &[u8], filename: &Option<&OsStr>) -> io::Result<()> {
    match filename {
        Some(filename) => {
            let decrypted_file_path = Path::new(DECRYPTED_PATH)
                .canonicalize()
                .unwrap()
                .join(filename);
            info!("Saving decrypted message to file {:?}", decrypted_file_path);
            let mut decrypted_file = File::create(decrypted_file_path)?;
            decrypted_file.write_all(decrypted_message)?;
            Ok(())
        }
        None => {
            error!("");
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Filename for decrypted message not specified",
            ))
        }
    }
}

fn handle_message(
    path: &PathBuf,
    private_key: &PKey<Private>,
    certificate: &X509,
) -> Result<(), io::Error> {
    // Get message from a file by a path.
    match get_message(path) {
        Err(e) => Err(e),
        Ok(message) => {
            debug!("Got message from {:?}", path);
            //debug!("Message: {:?}", message);
            match parse_message(&message) {
                Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
                Ok(cms_content_info) => {
                    info!("Message {:?} successfully parsed.", path);
                    match decrypt_message(&private_key, &certificate, &cms_content_info) {
                        Err(e) => Err(io::Error::new(io::ErrorKind::Other, e.to_string())),
                        Ok(decrypted_message) => {
                            info!("Message {:?} successfully decrypted.", path);
                            //debug!(
                            //    "Decrypted message:\n{}",
                            //    std::str::from_utf8(&decrypted_message).unwrap()
                            //);
                            match save_message(&decrypted_message, &path.as_path().file_name()) {
                                Err(e) => Err(e),
                                Ok(_) => Ok(()),
                            }
                        }
                    }
                }
            }
        }
    }
}

fn watch(private_key: &PKey<Private>, certificate: &X509) -> notify::Result<()> {
    // Create a channel to receive the events.
    let (tx, rx) = channel();

    // Automatically select the best implementation for your platform.
    // You can also access each implementation directly e.g. INotifyWatcher.
    let mut watcher: RecommendedWatcher = Watcher::new(tx, Duration::from_secs(3))?;

    // Add a path to be watched. Only files and directories at that path will be monitored for changes.
    // No recursive monitoring.
    watcher.watch(INBOX_PATH, RecursiveMode::NonRecursive)?;

    // This is a simple loop, but you may want to use more complex logic here,
    // for example to handle I/O.
    loop {
        match rx.recv() {
            Ok(event) => {
                //info!("Event received {:?}", event),
                match event {
                    DebouncedEvent::Create(path) | DebouncedEvent::Write(path) => {
                        info!("New message received: {:?}", path);

                        match handle_message(&path, &private_key, &certificate) {
                            Ok(_) => info!("Message {:?} handled", path),
                            Err(e) => error!("Message handling error: {}", e),
                        }
                    }
                    _ => (),
                }
            }
            Err(e) => error!("inbox watch error: {:?}", e),
        }
    }
}

// Load from file and return private key.
// Supports only PEM private keys for now.
fn load_private_key() -> PKey<Private> {
    let mut private_key_file = File::open(PRIVATE_KEY_PATH).expect("Can't open private key file");
    let mut private_key = Vec::new();
    private_key_file
        .read_to_end(&mut private_key)
        .expect("Can't read private key from file");

    PKey::private_key_from_pem(&private_key).expect("Can't parse private key")
}

fn load_certificate() -> X509 {
    let mut certificate_file = File::open(CERTIFICATE_PATH).expect("Can't open certificate file");
    let mut certificate = Vec::new();
    certificate_file
        .read_to_end(&mut certificate)
        .expect("Can't read certificate from file");

    X509::from_pem(&certificate).expect("Can't parse certificate")
}

fn init() {
    // Initialize logging.
    log4rs::init_file(LOGGING_SETTINGS_FILE, Default::default()).unwrap();

    info!("Find SSL certificate locations on the system for OpenSSL...");
    openssl_probe::init_ssl_cert_env_vars();

    // Setup panic logging.
    panic::set_hook(Box::new(|panic_info| {
        let (filename, line) = panic_info
            .location()
            .map(|loc| (loc.file(), loc.line()))
            .unwrap_or(("<unknown>", 0));

        let cause = panic_info
            .payload()
            .downcast_ref::<String>()
            .map(String::deref);

        let cause = cause.unwrap_or_else(|| {
            panic_info
                .payload()
                .downcast_ref::<&str>()
                .cloned()
                .unwrap_or("<cause unknown>")
        });

        error!("A panic occurred at {}:{}: {}", filename, line, cause);
    }));
}

fn main() {
    init();

    info!("Loading private key from {}", PRIVATE_KEY_PATH);
    let private_key: PKey<Private> = load_private_key();

    info!("Loading certificate from {}", CERTIFICATE_PATH);
    let certificate: X509 = load_certificate();

    info!("Start watching inbox folder for new messages...");
    if let Err(e) = watch(&private_key, &certificate) {
        error!("error: {:?}", e)
    }
}

// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Logging utilities

use log4rs::append::Append;
use log4rs::encode::pattern::PatternEncoder;
use log4rs::encode::Encode;
use log4rs::file::{Deserialize, Deserializers};
use serde_value::Value;
use std::error::Error;
use regex::Regex;
use log4rs::encode::writer::simple::SimpleWriter;
use std::fmt::{self, Display, Formatter};
use std::fs::{OpenOptions, File};
use std::{io, env};
use std::path::{Path, PathBuf};
use log::{Record, LevelFilter};
//use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config, Logger, Root};
use std::sync::mpsc::{self, Sender};
use std::sync::{Once, Mutex};
use std::thread::Builder;
use std::collections::BTreeMap;
use log4rs::encode::json::JsonEncoder;
use std::io::{Stdout, Write};

static INITIALISE_LOGGER: Once = Once::new();
static DEFAULT_LOG_LEVEL_FILTER: LevelFilter = LevelFilter::Warn;

enum AsyncEvent {
    Log(Vec<u8>),
    Terminate,
}

#[derive(Debug)]
pub struct AsyncAppender {
    encoder: Box<dyn Encode>,
    tx: Mutex<Sender<AsyncEvent>>,
}

impl AsyncAppender {
    fn new<W: 'static + SyncWrite + Send>(mut writer: W, encoder: Box<dyn Encode>) -> Self {
        let (tx, rx) = mpsc::channel::<AsyncEvent>();

        let _joiner = Builder::new()
            .name(String::from("AsyncLog"))
            .spawn(move || {
            let re = unwrap!(Regex::new(r"#FS#?.*[/\\#]([^#]+)#FE#"));

            for event in rx.iter() {
                match event {
                    AsyncEvent::Log(mut msg) => {
                        if let Ok(mut str_msg) = String::from_utf8(msg) {
                            let str_msg_cloned = str_msg.clone();
                            if let Some(file_name_capture) = re.captures(&str_msg_cloned) {
                                if let Some(file_name) = file_name_capture.get(1) {
                                    str_msg = re.replace(&str_msg[..], file_name.as_str()).into();
                                }
                            }

                            msg = str_msg.into_bytes();
                            let _ = writer.sync_write(&msg);
                        }
                    }
                    AsyncEvent::Terminate => break,
                }
            }
        });

        AsyncAppender {
            encoder,
            tx: Mutex::new(tx),
        }
    }
}

impl Append for AsyncAppender {
    fn append(&self, record: &Record) -> Result<(), Box<dyn Error + Sync + Send>> {
        let mut msg = Vec::new();
        self.encoder.encode(&mut SimpleWriter(&mut msg), record)?;
        unwrap!(self.tx.lock()).send(AsyncEvent::Log(msg))?;
        Ok(())
    }

    fn flush(&self) {
        unimplemented!()
    }
}

impl Drop for AsyncAppender {
    fn drop(&mut self) {
        let _ = unwrap!(self.tx.lock()).send(AsyncEvent::Terminate);
    }
}


pub struct AsyncConsoleAppender;

impl AsyncConsoleAppender {
    pub fn builder() -> AsyncConsoleAppenderBuilder {
        AsyncConsoleAppenderBuilder {
            encoder: Box::new(PatternEncoder::default()),
        }
    }
}

pub struct AsyncConsoleAppenderBuilder {
    encoder: Box<dyn Encode>,
}

impl AsyncConsoleAppenderBuilder {
    pub fn encoder(self, encoder: Box<dyn Encode>) -> Self {
        AsyncConsoleAppenderBuilder { encoder }
    }

    pub fn build(self) -> AsyncAppender {
        AsyncAppender::new(io::stdout(), self.encoder)
    }
}

pub struct AsyncFileAppender;

impl AsyncFileAppender {
    pub fn builder<P: AsRef<Path>>(path: P) -> AsyncFileAppenderBuilder {
        AsyncFileAppenderBuilder {
            path: path.as_ref().to_path_buf(),
            encoder: Box::new(PatternEncoder::default()),
            append: true,
            timestamp: false,
        }
    }
}

pub struct AsyncFileAppenderBuilder {
    path: PathBuf,
    encoder: Box<dyn Encode>,
    append: bool,
    timestamp: bool,
}

impl AsyncFileAppenderBuilder {
    pub fn encoder(self, encoder: Box<dyn Encode>) -> Self {
        AsyncFileAppenderBuilder {
            path: self.path,
            encoder,
            append: self.append,
            timestamp: self.timestamp,
        }
    }

    pub fn append(self, append: bool) -> Self {
        AsyncFileAppenderBuilder {
            path: self.path,
            encoder: self.encoder,
            append,
            timestamp: self.timestamp,
        }
    }

    pub fn timestamp(self, timestamp: bool) -> Self {
        AsyncFileAppenderBuilder {
            path: self.path,
            encoder: self.encoder,
            append: self.append,
            timestamp,
        }
    }

    pub fn build(self) -> io::Result<AsyncAppender> {
        let file = if self.append {
            OpenOptions::new()
                .write(true)
                .append(true)
                .create(true)
                .open(self.path)?
        } else {
            OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(self.path)?
        };

        Ok(AsyncAppender::new(file, self.encoder))
    }
}

pub struct AsyncConsoleAppenderCreator;

impl Deserialize for AsyncConsoleAppenderCreator {
    type Trait = dyn Append;
    type Config = Value;

    fn deserialize(
        &self,
        config: Value,
        _deserializers: &Deserializers,
    ) -> Result<Box<dyn Append>, Box<dyn Error + Sync + Send>> {
        let mut map = match config {
            Value::Map(map) => map,
            _ => return Err(Box::new(ConfigError("config must be a map".to_owned()))),
        };

        let pattern = parse_pattern(&mut map, false)?;
        Ok(Box::new(
            AsyncConsoleAppender::builder().encoder(pattern).build(),
        ))
    }
}

/// Takes an optional parameter for an output file name override.
pub struct AsyncFileAppenderCreator(pub Option<String>);

impl Deserialize for AsyncFileAppenderCreator {
    type Trait = dyn Append;
    type Config = Value;

    fn deserialize(
        &self,
        config: Value,
        _deserializers: &Deserializers,
    ) -> Result<Box<dyn Append>, Box<dyn Error + Sync + Send>> {

        let mut map = match config {
            Value::Map(map) => map,
            _ => return Err(Box::new(ConfigError("config must be a map".to_owned()))),
        };

        let op_file = if let Some(op_file_name_override) = self.0.clone() {
            op_file_name_override
        } else {
            match map.remove(&Value::String("output_file_name".to_owned())) {
                Some(Value::String(op_file)) => op_file,
                Some(_) => {
                    return Err(Box::new(ConfigError(
                        "`output_file_name` must be a string".to_owned(),
                    )));
                }
                None => {
                    return Err(Box::new(ConfigError(
                        "`output_file_name` is required".to_owned(),
                    )));
                }
            }
        };

//        let timestamp = match map.remove(&Value::String("file_timestamp".to_owned())) {
//            Some(Value::Bool(t)) => t,
//            Some(_) => {
//                return Err(Box::new(ConfigError(
//                    "`file_timestamp` must be a boolean".to_owned(),
//                )));
//            }
//            None => false,
//        };
//
//        if timestamp {
//            let path = Path::new(&op_file).to_owned();
//            let mut path_owned = path.to_owned();
//            path.file_stem()
//                .and_then(|s| s.to_str())
//                .and_then(|stem| {
//                    UNIX_EPOCH
//                        .elapsed()
//                        .map_err(|e| println!("Could not get timestamp: {:?}", e))
//                        .ok()
//                        .map(|dur| (dur, stem))
//                })
//                .and_then(|elt| {
//                    path.extension()
//                        .and_then(|ex| ex.to_str())
//                        .map(|ex| (elt, ex))
//                })
//                .map_or_else(
//                    || println!("Could not set timestamped file!"),
//                    |((dur, stem), ext)| {
//                        path_owned.set_file_name(format!("{}-{}.{}", stem, dur.as_secs(), ext))
//                    },
//                );

//            path_owned.file_name().and_then(|f| f.to_str()).map_or_else(
//                || println!("Could not extract modified file name from path"),
//                |f| op_file = ,
//            );
//        }

//        let op_path = match std::fs::File::open(op_file) {
//            Ok(fh) => fh.
//            Err(e) => {
//                return Err(Box::new(ConfigError(format!(
//                    "Could not establish log file path: \
//                     {:?}",
//                    e
//                ))));
//            }
//        };

        let append = match map.remove(&Value::String("append".to_owned())) {
            Some(Value::Bool(append)) => append,
            Some(_) => return Err(Box::new(ConfigError("`append` must be a bool".to_owned()))),
            None => false,
        };

        let pattern = parse_pattern(&mut map, false)?;
        let appender = AsyncFileAppender::builder(op_file)
            .encoder(pattern)
            .append(append)
            .build()?;

        Ok(Box::new(appender))
    }
}

#[derive(Debug)]
struct ConfigError(String);

impl Error for ConfigError {
    fn description(&self) -> &str {
        &self.0
    }
}

impl Display for ConfigError {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        fmt.write_str(&self.0)
    }
}

trait SyncWrite {
    fn sync_write(&mut self, buf: &[u8]) -> io::Result<()>;
}

impl SyncWrite for Stdout {
    fn sync_write(&mut self, buf: &[u8]) -> io::Result<()> {
        let mut out = self.lock();
        out.write_all(buf)?;
        out.flush()
    }
}

impl SyncWrite for File {
    fn sync_write(&mut self, buf: &[u8]) -> io::Result<()> {
        self.write_all(buf)?;
        self.flush()
    }
}

#[derive(Debug)]
struct ParseLoggerError;

impl Display for ParseLoggerError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "ParseLoggerError")
    }
}

impl From<()> for ParseLoggerError {
    fn from(_: ()) -> Self {
        ParseLoggerError
    }
}

fn parse_loggers_from_env() -> Result<(LevelFilter, Vec<Logger>), ParseLoggerError> {
    if let Ok(var) = env::var("RUST_LOG") {
        parse_loggers(&var)
    } else {
        Ok((DEFAULT_LOG_LEVEL_FILTER, Vec::new()))
    }
}

fn parse_loggers(input: &str) -> Result<(LevelFilter, Vec<Logger>), ParseLoggerError> {
    use std::collections::VecDeque;

    let mut loggers = Vec::new();
    let mut grouped_modules = VecDeque::new();
    let mut default_level = DEFAULT_LOG_LEVEL_FILTER;

    for sub_input in input.split(',').map(str::trim).filter(|d| !d.is_empty()) {
        let mut parts = sub_input.trim().split('=');
        match (parts.next(), parts.next()) {
            (Some(module_name), Some(level)) => {
                let level_filter = level.parse().map_err(|_|())?;
                while let Some(module) = grouped_modules.pop_front() {
                    loggers.push(Logger::builder().build(module, level_filter));
                }
                loggers.push(Logger::builder().build(module_name.to_owned(), level_filter));
            }
            (Some(module), None) => {
                if let Ok(level_filter) = module.parse::<LevelFilter>() {
                    default_level = level_filter;
                } else {
                    grouped_modules.push_back(module.to_owned());
                }
            }
            _ => return Err(ParseLoggerError),
        }
    }

    while let Some(module) = grouped_modules.pop_front() {
        loggers.push(Logger::builder().build(module, default_level));
    }

    Ok((default_level, loggers))
}


fn parse_pattern(
    map: &mut BTreeMap<Value, Value>,
    is_websocket: bool,
) -> Result<Box<dyn Encode>, Box<dyn Error + Sync + Send>> {
    match map.remove(&Value::String("pattern".to_owned())) {
        Some(Value::String(pattern)) => Ok(Box::new(PatternEncoder::new(&pattern))),
        Some(_) => Err(Box::new(ConfigError(
            "`pattern` must be a string".to_owned(),
        ))),
        None => {
            if is_websocket {
                Ok(Box::new(JsonEncoder::new()))
            } else {
                Ok(Box::new(PatternEncoder::default()))
            }
        }
    }
}

/// Initialises the `env_logger` for output to stdout.
///
/// For further details, see the [module docs](index.html).
pub fn init(show_thread_name: bool) -> Result<(), String> {
    init_once_guard(|| init_impl(show_thread_name, false, None))
}

/// Initialises the `env_logger` for output to stdout and takes
/// an output file name that will override the log configuration.
///
/// For further details, see the [module docs](index.html).
pub fn init_with_output_file<S>(
    show_thread_name: bool,
    output_file_name_override: S,
) -> Result<(), String>
    where
        S: Into<String>,
{
    init_once_guard(|| init_impl(show_thread_name, true, Some(output_file_name_override.into())))
}

pub fn init_impl(
    show_thread_name: bool,
    with_output_file: bool,
    output_file_name_override: Option<String>,
) -> Result<(), String>
{
    let pattern = if show_thread_name {
        "{l} {d(%H:%M:%S.%f)} {T} [{M} #FS#{f}#FE#:{L}] {m}{n}"
    } else {
        "{l} {d(%H:%M:%S.%f)} [{M} #FS#{f}#FE#:{L}] {m}{n}"
    };

    if with_output_file {
        let file_name = if let Some(name) = output_file_name_override.clone() {
            name
        } else {
            "Client.log".to_string()
        };
//        let logfile = FileAppender::builder()
//            .encoder(Box::new(PatternEncoder::new(pattern)))
//            .build(Path::new(&file_name)).map_err(|e|format!("{}",e))?;
//        let config = Config::builder()
//            .appender(Appender::builder().build("logfile", Box::new(logfile)))
//            .build(Root::builder()
//                .appender("logfile")
//                .build(LevelFilter::Trace)).map_err(|e|format!("{}",e))?;
        let mut deserializers = Deserializers::default();
        deserializers.insert("async_console", AsyncConsoleAppenderCreator);
        deserializers.insert(
            "async_file",
            AsyncFileAppenderCreator(output_file_name_override),
        );
        log4rs::init_file(Path::new(&file_name), deserializers)
            .map_err(|e| format!("{}", e))
            .map(|_| ())
    } else {
        let console_appender = AsyncConsoleAppender::builder()
            .encoder(Box::new(PatternEncoder::new(pattern)))
            .build();
        let console_appender =
            Appender::builder().build("async_console".to_owned(), Box::new(console_appender));

        let (default_level, loggers) = unwrap!(
            parse_loggers_from_env(),
            "failed to parse RUST_LOG env variable"
        );

        let root = Root::builder()
            .appender("async_console".to_owned())
            .build(default_level);
        let config = Config::builder()
            .appender(console_appender)
            .loggers(loggers)
            .build(root)
            .map_err(|e| format!("{}", e))?;

        log4rs::init_config(config)
            .map_err(|e| format!("{}", e))
            .map(|_| ())
    }
}

fn init_once_guard<F: FnOnce() -> Result<(), String>>(init_fn: F) -> Result<(), String> {
    let mut result = Err("Logger already initialised".to_owned());
    INITIALISE_LOGGER.call_once(|| {
        result = init_fn();
    });
    result
}
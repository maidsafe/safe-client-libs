// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! These functions can initialise logging for output to stdout only, or to a file and stdout.  For
//! more fine-grained control, create a file called `log.toml` in the root directory of the project,
//! or in the same directory where the executable is.  See
//! [log4rs docs](http://sfackler.github.io/log4rs/doc/v0.3.3/log4rs/index.html) for details about
//! the format and structure of this file.
//!
//! An example of a log message is:
//!
//! ```
//! # fn main() { /*
//! WARN 19:33:49.245434200 <main> [example::my_mod main.rs:10] Warning level message.
//! ^           ^             ^              ^         ^                  ^
//! |       timestamp         |           module       |               message
//! |                         |                        |
//! |                    thread name           file and line no.
//! |
//! level (ERROR, WARN, INFO, DEBUG, or TRACE)
//! # */}
//! ```
//!
//! Logging of the thread name is enabled or disabled via the `show_thread_name` parameter.  If
//! enabled, and the thread executing the log statement is unnamed, the thread name is shown as
//! `<unnamed>`.
//!
//! The functions can safely be called multiple times concurrently.
//!
//! #Examples
//!
//! ```
//! #[macro_use]
//! extern crate log;
//! #[macro_use]
//! extern crate unwrap;
//! use std::thread;
//! use safe_core::utils::logging;
//!
//! mod my_mod {
//!     pub fn show_warning() {
//!         warn!("A warning");
//!     }
//! }
//!
//! fn main() {
//!     unwrap!(logging::init(true));
//!
//!     my_mod::show_warning();
//!
//!     let unnamed = thread::spawn(move || info!("Message in unnamed thread"));
//!     let _ = unnamed.join();
//!
//!     let _named = unwrap!(thread::Builder::new()
//!                             .name(String::from("Worker"))
//!                             .spawn(|| error!("Message in named thread")));
//!
//!     // WARN 16:10:44.989712300 <main> [example::my_mod main.rs:10] A warning
//!     // INFO 16:10:44.990716600 <unnamed> [example main.rs:19] Message in unnamed thread
//!     // ERROR 16:10:44.991221900 Worker [example main.rs:22] Message in named thread
//! }
//! ```
//!
//! Environment variable `RUST_LOG` can be set and fine-tuned to get various modules logging to
//! different levels. E.g. `RUST_LOG=mod0,mod1=debug,mod2,mod3` will have `mod0` & `mod1` logging at
//! `Debug` and more severe levels while `mod2` & `mod3` logging at default (currently `Warn`) and
//! more severe levels. `RUST_LOG=trace,mod0=error,mod1` is going to change the default log level to
//! `Trace` and more severe. Thus `mod0` will log at `Error` level and `mod1` at `Trace` and more
//! severe ones.

pub use self::async_log::MSG_TERMINATOR;
pub use self::web_socket::validate_request as validate_web_socket_request;

mod async_log;
mod web_socket;

use self::async_log::{
    AsyncConsoleAppender, AsyncConsoleAppenderCreator, AsyncFileAppender, AsyncFileAppenderCreator,
    AsyncServerAppender, AsyncServerAppenderCreator, AsyncWebSockAppender,
    AsyncWebSockAppenderCreator,
};
use crate::config_dir;
use log::LevelFilter;
use log4rs;
use log4rs::config::{Appender, Config, Logger, Root};
use log4rs::encode::json::JsonEncoder;
use log4rs::encode::pattern::PatternEncoder;
use log4rs::file::Deserializers;
use std::borrow::Borrow;
use std::env;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::File;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::sync::Once;

static INITIALISE_LOGGER: Once = Once::new();
static CONFIG_FILE: &str = "log.toml";
static DEFAULT_LOG_LEVEL_FILTER: LevelFilter = LevelFilter::Warn;

/// Initialises the `env_logger` for output to stdout.
///
/// For further details, see the [module docs](index.html).
pub fn init(show_thread_name: bool) -> Result<(), String> {
    init_once_guard(|| init_impl(show_thread_name, None))
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
    init_once_guard(|| init_impl(show_thread_name, Some(output_file_name_override.into())))
}

fn init_impl(show_thread_name: bool, op_file_name_override: Option<String>) -> Result<(), String> {
    let path = config_dir()
        .map_err(|e| e.description().to_string())?
        .join(CONFIG_FILE);
    let log_config_path = match File::open(&path) {
        Ok(_file) => {
            trace!("Reading: {}", path.display());
            Some(path)
        }
        Err(_) => {
            trace!("Not available: {}", path.display());
            None
        }
    };
    if let Some(config_path) = log_config_path {
        let mut deserializers = Deserializers::default();
        deserializers.insert("async_console", AsyncConsoleAppenderCreator);
        deserializers.insert(
            "async_file",
            AsyncFileAppenderCreator(op_file_name_override),
        );
        deserializers.insert("async_server", AsyncServerAppenderCreator);
        deserializers.insert("async_web_socket", AsyncWebSockAppenderCreator);

        log4rs::init_file(config_path, deserializers).map_err(|e| format!("{}", e))
    } else {
        let console_appender = AsyncConsoleAppender::builder()
            .encoder(Box::new(make_pattern(show_thread_name)))
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

/// Initialises the `env_logger` for output to a file and optionally to the console asynchronously.
///
/// For further details, see the [module docs](index.html).
pub fn init_to_file<P: AsRef<Path>>(
    show_thread_name: bool,
    file_path: P,
    log_to_console: bool,
) -> Result<(), String> {
    let mut result = Err("Logger already initialised".to_owned());

    INITIALISE_LOGGER.call_once(|| {
        let (default_level, loggers) = match parse_loggers_from_env() {
            Ok((level, loggers)) => (level, loggers),
            Err(error) => {
                result = Err(format!("{}", error));
                return;
            }
        };

        let mut root = Root::builder().appender("file".to_owned());

        if log_to_console {
            root = root.appender("console".to_owned());
        }

        let root = root.build(default_level);

        let mut config = Config::builder().loggers(loggers);

        let file_appender = AsyncFileAppender::builder(file_path)
            .encoder(Box::new(make_pattern(show_thread_name)))
            .append(false)
            .build();
        let file_appender = match file_appender {
            Ok(appender) => appender,
            Err(error) => {
                result = Err(format!("{}", error));
                return;
            }
        };
        let file_appender = Appender::builder().build("file".to_owned(), Box::new(file_appender));

        config = config.appender(file_appender);

        if log_to_console {
            let console_appender = AsyncConsoleAppender::builder()
                .encoder(Box::new(make_pattern(show_thread_name)))
                .build();
            let console_appender =
                Appender::builder().build("console".to_owned(), Box::new(console_appender));

            config = config.appender(console_appender);
        }

        let config = match config.build(root).map_err(|e| format!("{}", e)) {
            Ok(config) => config,
            Err(e) => {
                result = Err(e);
                return;
            }
        };
        result = log4rs::init_config(config)
            .map_err(|e| format!("{}", e))
            .map(|_| ())
    });

    result
}

/// Initialises the `env_logger` for output to a server and optionally to the console
/// asynchronously.
///
/// For further details, see the [module docs](index.html).
pub fn init_to_server<A: ToSocketAddrs>(
    server_addr: A,
    show_thread_name: bool,
    log_to_console: bool,
) -> Result<(), String> {
    init_once_guard(|| {
        let (default_level, loggers) = match parse_loggers_from_env() {
            Ok((level, loggers)) => (level, loggers),
            Err(error) => {
                return Err(format!("{}", error));
            }
        };

        let mut root = Root::builder().appender("server".to_owned());

        if log_to_console {
            root = root.appender("console".to_owned());
        }

        let root = root.build(default_level);

        let mut config = Config::builder().loggers(loggers);

        let server_appender = AsyncServerAppender::builder(server_addr)
            .encoder(Box::new(make_pattern(show_thread_name)))
            .build()
            .map_err(|e| format!("{}", e))?;

        let server_appender =
            Appender::builder().build("server".to_owned(), Box::new(server_appender));

        config = config.appender(server_appender);

        if log_to_console {
            let console_appender = AsyncConsoleAppender::builder()
                .encoder(Box::new(make_pattern(show_thread_name)))
                .build();
            let console_appender =
                Appender::builder().build("console".to_owned(), Box::new(console_appender));

            config = config.appender(console_appender);
        }

        let config = config.build(root).map_err(|e| format!("{}", e))?;

        log4rs::init_config(config)
            .map_err(|e| format!("{}", e))
            .map(|_| ())
    })
}

/// Initialises the `env_logger` for output to a web socket and optionally to the console
/// asynchronously. The log which goes to the web-socket will be both verbose and in JSON as
/// filters should be present in web-servers to manipulate the output/view.
///
/// For further details, see the [module docs](index.html).
pub fn init_to_web_socket<U: Borrow<str>>(
    server_url: U,
    session_id: Option<String>,
    show_thread_name_in_console: bool,
    log_to_console: bool,
) -> Result<(), String> {
    init_once_guard(|| {
        let (default_level, loggers) = match parse_loggers_from_env() {
            Ok((level, loggers)) => (level, loggers),
            Err(error) => {
                return Err(format!("{}", error));
            }
        };

        let mut root = Root::builder().appender("server".to_owned());

        if log_to_console {
            root = root.appender("console".to_owned());
        }

        let root = root.build(default_level);

        let mut config = Config::builder().loggers(loggers);

        let server_appender = AsyncWebSockAppender::builder(server_url)
            .encoder(Box::new(JsonEncoder::new()))
            .session_id(session_id)
            .build()
            .map_err(|e| format!("{}", e))?;

        let server_appender =
            Appender::builder().build("server".to_owned(), Box::new(server_appender));

        config = config.appender(server_appender);

        if log_to_console {
            let console_appender = AsyncConsoleAppender::builder()
                .encoder(Box::new(make_pattern(show_thread_name_in_console)))
                .build();
            let console_appender =
                Appender::builder().build("console".to_owned(), Box::new(console_appender));

            config = config.appender(console_appender);
        }

        let config = config.build(root).map_err(|e| format!("{}", e))?;
        log4rs::init_config(config)
            .map_err(|e| format!("{}", e))
            .map(|_| ())
    })
}

fn make_pattern(show_thread_name: bool) -> PatternEncoder {
    let pattern = if show_thread_name {
        "{l} {d(%H:%M:%S.%f)} {T} [{M} #FS#{f}#FE#:{L}] {m}{n}"
    } else {
        "{l} {d(%H:%M:%S.%f)} [{M} #FS#{f}#FE#:{L}] {m}{n}"
    };

    PatternEncoder::new(pattern)
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
                let level_filter = level.parse().map_err(|_| ParseLoggerError)?;
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

fn init_once_guard<F: FnOnce() -> Result<(), String>>(init_fn: F) -> Result<(), String> {
    let mut result = Err("Logger already initialised".to_owned());
    INITIALISE_LOGGER.call_once(|| {
        result = init_fn();
    });
    result
}

#[cfg(test)]
mod tests {
    use super::parse_loggers;
    use log::LevelFilter;

    #[test]
    fn test_parse_loggers_empty() {
        let (level, loggers) = unwrap!(parse_loggers(""));
        assert_eq!(level, LevelFilter::Warn);
        assert!(loggers.is_empty());
    }

    #[test]
    fn test_parse_loggers_warn() {
        let (level, loggers) = unwrap!(parse_loggers("foo"));
        assert_eq!(level, LevelFilter::Warn);
        assert_eq!(loggers.len(), 1);
        assert_eq!(loggers[0].name(), "foo");
        assert_eq!(loggers[0].level(), LevelFilter::Warn);
    }

    #[test]
    fn test_parse_loggers_info() {
        let (level, loggers) = unwrap!(parse_loggers("info"));
        assert_eq!(level, LevelFilter::Info);
        assert!(loggers.is_empty());
    }

    #[test]
    fn test_parse_loggers_composed_warn() {
        let (level, loggers) = unwrap!(parse_loggers("foo::bar=warn"));
        assert_eq!(level, LevelFilter::Warn);
        assert_eq!(loggers.len(), 1);
        assert_eq!(loggers[0].name(), "foo::bar");
        assert_eq!(loggers[0].level(), LevelFilter::Warn);
    }

    #[test]
    fn test_parse_loggers_all_levels() {
        let (level, loggers) = unwrap!(parse_loggers("foo::bar=error,baz=debug,qux"));
        assert_eq!(level, LevelFilter::Warn);
        assert_eq!(loggers.len(), 3);

        assert_eq!(loggers[0].name(), "foo::bar");
        assert_eq!(loggers[0].level(), LevelFilter::Error);

        assert_eq!(loggers[1].name(), "baz");
        assert_eq!(loggers[1].level(), LevelFilter::Debug);

        assert_eq!(loggers[2].name(), "qux");
        assert_eq!(loggers[2].level(), LevelFilter::Warn);
    }

    #[test]
    fn test_parse_loggers_debug_and_info() {
        let (level, loggers) = unwrap!(parse_loggers("info,foo::bar,baz=debug,a0,a1, a2 , a3"));
        assert_eq!(level, LevelFilter::Info);
        assert_eq!(loggers.len(), 6);

        assert_eq!(loggers[0].name(), "foo::bar");
        assert_eq!(loggers[0].level(), LevelFilter::Debug);

        assert_eq!(loggers[1].name(), "baz");
        assert_eq!(loggers[1].level(), LevelFilter::Debug);

        assert_eq!(loggers[2].name(), "a0");
        assert_eq!(loggers[2].level(), LevelFilter::Info);

        assert_eq!(loggers[3].name(), "a1");
        assert_eq!(loggers[3].level(), LevelFilter::Info);

        assert_eq!(loggers[4].name(), "a2");
        assert_eq!(loggers[4].level(), LevelFilter::Info);

        assert_eq!(loggers[5].name(), "a3");
        assert_eq!(loggers[5].level(), LevelFilter::Info);
    }
}

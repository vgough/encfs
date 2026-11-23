//! Send CLI tracing events to the macOS unified log.

use crate::idle_lock::TRANSITION_EVENT;
use std::ffi::{CString, c_char};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::fmt::format::{DefaultFields, FormatFields, Writer};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

// Keep the discriminants in sync with encfs_log_category in console_log.c.
#[repr(C)]
enum LogCategory {
    Diagnostics = 0,
    IdleLock = 1,
}

unsafe extern "C" {
    fn encfs_console_log(message: *const c_char, category: LogCategory, error: bool);
}

pub(crate) fn layer<S: Subscriber + for<'span> LookupSpan<'span>>() -> impl Layer<S> {
    ConsoleLog.with_filter(filter_fn(|metadata| {
        metadata.is_event()
            && (*metadata.level() <= Level::WARN || metadata.name() == TRANSITION_EVENT)
    }))
}

struct ConsoleLog;

impl<S: Subscriber> Layer<S> for ConsoleLog {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let metadata = event.metadata();
        let category = if metadata.name() == TRANSITION_EVENT {
            LogCategory::IdleLock
        } else {
            LogCategory::Diagnostics
        };
        let mut message = match category {
            LogCategory::Diagnostics => format!("{} {}: ", metadata.level(), metadata.target()),
            LogCategory::IdleLock => String::new(),
        };
        if DefaultFields::new()
            .format_fields(Writer::new(&mut message), event)
            .is_err()
        {
            return;
        }
        if message.contains('\0') {
            message = message.replace('\0', "\\0");
        }
        if let Ok(message) = CString::new(message) {
            // SAFETY: The shim reads the NUL-terminated string during the call.
            unsafe {
                encfs_console_log(
                    message.as_ptr(),
                    category,
                    *metadata.level() == Level::ERROR,
                );
            }
        }
    }
}

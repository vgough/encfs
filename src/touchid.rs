//! Touch ID authentication through Apple's LocalAuthentication framework.

use crate::idle_lock::Authenticator;
use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};
use std::sync::mpsc;
use std::time::Duration;

const POLICY: LAPolicy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;

/// Longest a FUSE request waits on the prompt. macFUSE treats a daemon that
/// does not answer within its `daemon_timeout` (60 s by default) as hung, so
/// give up and dismiss the dialog before that.
const PROMPT_TIMEOUT: Duration = Duration::from_secs(45);

/// Prompts for Touch ID with a fixed reason string, shown in the system
/// dialog as "<process> is trying to <reason>."
pub struct TouchId {
    reason: String,
}

impl TouchId {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl Authenticator for TouchId {
    fn authenticate(&self) -> Result<(), String> {
        // A fresh context per prompt, so an earlier success is never reused.
        // canEvaluatePolicy reports a missing or unenrolled sensor up front.
        // SAFETY: LAContext may be created and used from any thread.
        let context = unsafe { LAContext::new() };
        unsafe { context.canEvaluatePolicy_error(POLICY) }.map_err(|e| describe(&e))?;

        let (tx, rx) = mpsc::sync_channel(1);
        let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
            let result = if success.as_bool() {
                Ok(())
            } else {
                // SAFETY: on failure LocalAuthentication passes a valid
                // NSError (or nil) that lives for the duration of the call.
                Err(unsafe { error.as_ref() }
                    .map(describe)
                    .unwrap_or_else(|| "authentication failed".to_string()))
            };
            let _ = tx.send(result);
        });
        let reason = NSString::from_str(&self.reason);
        // SAFETY: the reply block is retained by the framework until it runs,
        // and runs on a private queue, so blocking here cannot deadlock it.
        unsafe { context.evaluatePolicy_localizedReason_reply(POLICY, &reason, &reply) };

        match rx.recv_timeout(PROMPT_TIMEOUT) {
            Ok(result) => result,
            Err(_) => {
                // Dismiss the dialog; the reply then fires with a cancel error
                // that nobody is waiting for.
                unsafe { context.invalidate() };
                Err("timed out waiting for Touch ID".to_string())
            }
        }
    }
}

fn describe(error: &NSError) -> String {
    error.localizedDescription().to_string()
}

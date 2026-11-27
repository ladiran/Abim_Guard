//! Keeps track of when the malware signatures (known-bad SHA-256 hashes)
//! were last updated, and when to remind the user.
//!
//! MalwareBazaar's "recent" export covers the last 48 hours, so updating at
//! least every two days means no new sample is missed. After that, the app
//! shows a banner, and (if switched on) a tray pop-up at most once a day.

use crate::config::AppPaths;
use chrono::{DateTime, Duration, Local};
use serde::{Deserialize, Serialize};

/// Signatures count as out of date this long after the last update.
pub const STALE_AFTER_HOURS: i64 = 48;
/// The tray reminder repeats at most this often.
pub const POPUP_EVERY_HOURS: i64 = 24;

const FILE: &str = "signature_state.json";

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct State {
    /// When this copy of the app first ran (the clock starts here until the
    /// first update, so a new user is not nagged on day one).
    pub first_seen: Option<DateTime<Local>>,
    /// Last successful download or import of a hash list.
    pub last_update: Option<DateTime<Local>>,
    /// How many new fingerprints that update added.
    pub last_added: usize,
    /// Last time the tray reminder was shown.
    pub last_popup: Option<DateTime<Local>>,
}

impl State {
    pub fn load(paths: &AppPaths) -> Self {
        let mut s: State = std::fs::read_to_string(paths.root.join(FILE))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        if s.first_seen.is_none() {
            s.first_seen = Some(Local::now());
            s.save(paths);
        }
        s
    }

    pub fn save(&self, paths: &AppPaths) {
        if let Ok(t) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(paths.root.join(FILE), t);
        }
    }

    fn since(&self) -> Option<DateTime<Local>> {
        self.last_update.or(self.first_seen)
    }

    /// True when the signatures need updating.
    pub fn is_stale_at(&self, now: DateTime<Local>) -> bool {
        self.since().map(|t| now - t >= Duration::hours(STALE_AFTER_HOURS)).unwrap_or(false)
    }

    pub fn is_stale(&self) -> bool {
        self.is_stale_at(Local::now())
    }

    /// True when the tray reminder should be shown now.
    pub fn popup_due_at(&self, now: DateTime<Local>) -> bool {
        self.is_stale_at(now)
            && self.last_popup.map(|t| now - t >= Duration::hours(POPUP_EVERY_HOURS)).unwrap_or(true)
    }

    pub fn record_update(&mut self, added: usize, now: DateTime<Local>) {
        self.last_update = Some(now);
        self.last_added = added;
    }

    /// "today", "1 day ago", "5 days ago" or "never".
    pub fn last_update_text_at(&self, now: DateTime<Local>) -> String {
        match self.last_update {
            None => "never".into(),
            Some(t) => match (now - t).num_days() {
                d if d <= 0 => format!("today at {}", t.format("%H:%M")),
                1 => "1 day ago".into(),
                d => format!("{d} days ago"),
            },
        }
    }

    pub fn last_update_text(&self) -> String {
        self.last_update_text_at(Local::now())
    }

    /// Gentle reminder wording used by the banner and the tray pop-up.
    pub fn reminder_text_at(&self, now: DateTime<Local>) -> String {
        match self.last_update {
            None => "Abim Guard's malware signatures have not been updated yet. \
                     Download the latest list from MalwareBazaar so new threats can be recognised."
                .into(),
            Some(_) => format!(
                "Abim Guard's malware signatures were last updated {}. \
                 Download the latest list from MalwareBazaar so new threats can be recognised.",
                self.last_update_text_at(now)
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(h: i64) -> DateTime<Local> {
        // A fixed point in time plus h hours, so tests do not depend on the clock.
        let base = chrono::TimeZone::with_ymd_and_hms(&Local, 2026, 11, 1, 12, 0, 0).unwrap();
        base + Duration::hours(h)
    }

    #[test]
    fn new_install_is_not_nagged_for_two_days() {
        let s = State { first_seen: Some(at(0)), ..Default::default() };
        assert!(!s.is_stale_at(at(47)));
        assert!(s.is_stale_at(at(48)));
    }

    #[test]
    fn update_resets_the_clock() {
        let mut s = State { first_seen: Some(at(0)), ..Default::default() };
        assert!(s.is_stale_at(at(100)));
        s.record_update(250, at(100));
        assert!(!s.is_stale_at(at(120)));
        assert!(s.is_stale_at(at(148)));
        assert_eq!(s.last_added, 250);
    }

    #[test]
    fn popup_at_most_once_a_day_and_only_when_stale() {
        let mut s = State { first_seen: Some(at(0)), ..Default::default() };
        assert!(!s.popup_due_at(at(10)));
        assert!(s.popup_due_at(at(50)));
        s.last_popup = Some(at(50));
        assert!(!s.popup_due_at(at(60)));
        assert!(s.popup_due_at(at(74)));
        s.record_update(1, at(75));
        assert!(!s.popup_due_at(at(100)));
    }

    #[test]
    fn wording() {
        let mut s = State { first_seen: Some(at(0)), ..Default::default() };
        assert_eq!(s.last_update_text_at(at(5)), "never");
        assert!(s.reminder_text_at(at(50)).contains("not been updated yet"));
        s.record_update(3, at(0));
        assert_eq!(s.last_update_text_at(at(30)), "1 day ago");
        assert_eq!(s.last_update_text_at(at(80)), "3 days ago");
        assert!(s.reminder_text_at(at(80)).contains("3 days ago"));
    }

    #[test]
    fn state_survives_save_and_load() {
        let dir = std::env::temp_dir().join(format!("abim-sig-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = AppPaths::at(&dir).unwrap();
        let mut s = State::load(&paths);
        assert!(s.first_seen.is_some());
        s.record_update(7, at(1));
        s.save(&paths);
        assert_eq!(State::load(&paths), s);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

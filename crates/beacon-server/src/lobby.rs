//! Lobby state without I/O: player names, sticky virtual IPs, host election,
//! kick bans and chat sanitising. The [`hub`](crate::hub) wraps it in a mutex.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use beacon_proto::control::Player;
use beacon_proto::fingerprint::FileEntry;
use beacon_proto::net::{self, VipAllocator};

/// BFME clamps LAN player names to 12 UTF-16 code units (spec 01 §4.1); longer
/// names would collide after truncation, so the server enforces the limit.
pub const NAME_MAX_UTF16: usize = 12;

/// Punctuation allowed in player names besides letters and digits.
const NAME_PUNCTUATION: &str = " -_.!?#()[]{}+*'&@~^=$%";

/// Why a player name was refused (the text goes to the player).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    /// Empty name.
    Empty,
    /// Longer than [`NAME_MAX_UTF16`].
    TooLong,
    /// Leading/trailing or doubled spaces.
    Spaces,
    /// A character outside letters, digits and simple punctuation.
    InvalidChar(char),
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("Der Name ist leer."),
            Self::TooLong => write!(
                f,
                "Der Name ist zu lang (höchstens {NAME_MAX_UTF16} Zeichen; BFME kürzt längere Namen)."
            ),
            Self::Spaces => f.write_str(
                "Der Name darf nicht mit Leerzeichen beginnen oder enden und keine doppelten Leerzeichen enthalten.",
            ),
            Self::InvalidChar(c) => write!(f, "Ungültiges Zeichen im Namen: {c:?}"),
        }
    }
}

/// Checks a player name (also used for `admin_names`).
pub fn validate_name(name: &str) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty);
    }
    if name.encode_utf16().count() > NAME_MAX_UTF16 {
        return Err(NameError::TooLong);
    }
    if name.starts_with(' ') || name.ends_with(' ') || name.contains("  ") {
        return Err(NameError::Spaces);
    }
    match name
        .chars()
        .find(|&c| !(c.is_alphanumeric() || NAME_PUNCTUATION.contains(c)))
    {
        Some(c) => Err(NameError::InvalidChar(c)),
        None => Ok(()),
    }
}

/// Case-insensitive identity of a name (uniqueness, stickiness, admin match).
pub fn name_key(name: &str) -> String {
    name.to_lowercase()
}

/// `true` for a combined fingerprint: 64 hex digits.
pub fn is_valid_fingerprint(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Why a chat line was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatError {
    /// Nothing left after removing whitespace.
    Empty,
    /// Longer than the configured maximum.
    TooLong {
        /// Maximum in characters.
        max: usize,
    },
}

impl fmt::Display for ChatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("Leere Nachricht."),
            Self::TooLong { max } => write!(f, "Nachricht zu lang (höchstens {max} Zeichen)."),
        }
    }
}

/// Normalises a chat line: control characters (including line breaks) become
/// spaces, surrounding whitespace is removed; empty or overlong lines are refused.
pub fn sanitize_chat(text: &str, max_chars: usize) -> Result<String, ChatError> {
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        return Err(ChatError::Empty);
    }
    if cleaned.chars().count() > max_chars {
        return Err(ChatError::TooLong { max: max_chars });
    }
    Ok(cleaned.to_owned())
}

/// Combines the agent-reported (downstream) and server-measured (upstream) loss:
/// `1 - (1 - a)(1 - b)`, in percent.
pub fn combine_loss(a: Option<u8>, b: Option<u8>) -> Option<u8> {
    match (a, b) {
        (None, None) => None,
        (Some(x), None) | (None, Some(x)) => Some(x.min(100)),
        (Some(x), Some(y)) => {
            let fx = f64::from(x.min(100)) / 100.0;
            let fy = f64::from(y.min(100)) / 100.0;
            let p = 1.0 - (1.0 - fx) * (1.0 - fy);
            // Saturating float-to-int conversion; p is within 0..=1.
            Some((p * 100.0).round().clamp(0.0, 100.0) as u8)
        }
    }
}

#[derive(Debug, Clone)]
struct StickyVip {
    vip: Ipv4Addr,
    active: bool,
    last_used: u64,
}

/// Player vIP assignment, sticky per name key: a name gets the same vIP every
/// time while the server runs (and across restarts if persisted). Addresses of
/// absent names are only reused when the pool is otherwise exhausted (least
/// recently used first).
#[derive(Debug, Default)]
pub struct VipBook {
    alloc: VipAllocator,
    sticky: HashMap<String, StickyVip>,
    clock: u64,
}

impl VipBook {
    /// An empty book.
    pub fn new() -> Self {
        Self::default()
    }

    fn tick(&mut self) -> u64 {
        self.clock = self.clock.saturating_add(1);
        self.clock
    }

    /// Assigns the vIP for `key` (marks it active). `None` if the pool is full of
    /// active players.
    pub fn assign(&mut self, key: &str) -> Option<Ipv4Addr> {
        let now = self.tick();
        if let Some(entry) = self.sticky.get_mut(key) {
            if entry.active {
                return None;
            }
            entry.active = true;
            entry.last_used = now;
            return Some(entry.vip);
        }
        let vip = match self.alloc.allocate() {
            Some(vip) => vip,
            None => {
                let victim = self
                    .sticky
                    .iter()
                    .filter(|(_, e)| !e.active)
                    .min_by_key(|(_, e)| e.last_used)
                    .map(|(k, e)| (k.clone(), e.vip))?;
                self.sticky.remove(&victim.0);
                victim.1
            }
        };
        self.sticky.insert(
            key.to_owned(),
            StickyVip {
                vip,
                active: true,
                last_used: now,
            },
        );
        Some(vip)
    }

    /// Marks `key` absent (its vIP stays reserved for it).
    pub fn release(&mut self, key: &str) {
        let now = self.tick();
        if let Some(entry) = self.sticky.get_mut(key) {
            entry.active = false;
            entry.last_used = now;
        }
    }

    /// The remembered `name key → vIP` table (for persistence).
    pub fn table(&self) -> BTreeMap<String, Ipv4Addr> {
        self.sticky.iter().map(|(k, e)| (k.clone(), e.vip)).collect()
    }

    /// Restores remembered entries (all inactive). Invalid or duplicate addresses
    /// and invalid names are skipped; returns the number restored.
    pub fn restore(&mut self, table: &BTreeMap<String, Ipv4Addr>) -> usize {
        let mut restored = 0;
        for (key, &vip) in table {
            if self.sticky.contains_key(key)
                || validate_name(key).is_err()
                || *key != name_key(key)
                || !net::is_assignable(vip)
                || !self.alloc.claim(vip)
            {
                continue;
            }
            let now = self.tick();
            self.sticky.insert(
                key.clone(),
                StickyVip {
                    vip,
                    active: false,
                    last_used: now,
                },
            );
            restored += 1;
        }
        restored
    }
}

/// A fingerprint file list as uploaded by a player.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintList {
    /// Entries as uploaded (possibly cut to fit into one message).
    pub files: Vec<FileEntry>,
    /// `false` if incomplete.
    pub complete: bool,
}

/// A connected player.
#[derive(Debug, Clone)]
pub struct Member {
    /// Display name.
    pub name: String,
    /// [`name_key`] of the name.
    pub key: String,
    /// Virtual IP.
    pub vip: Ipv4Addr,
    /// Relay session id.
    pub session: u32,
    /// Listed in `admin_names`.
    pub is_admin: bool,
    /// Launcher version from `hello`.
    pub version: String,
    /// Combined fingerprint.
    pub fingerprint: Option<String>,
    /// Uploaded fingerprint file list.
    pub files: Option<Arc<FingerprintList>>,
    /// Ready flag.
    pub ready: bool,
    /// BFME is running.
    pub in_game: bool,
    /// RTT reported by the agent.
    pub reported_rtt_ms: Option<u32>,
    /// Loss reported by the agent.
    pub reported_loss_pct: Option<u8>,
    /// Join time.
    pub joined_at: Instant,
}

/// Why a join was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinError {
    /// Invalid name.
    BadName(NameError),
    /// The name is in use.
    NameTaken,
    /// Player limit reached or vIP pool exhausted.
    Full,
    /// The name was kicked recently.
    Kicked {
        /// Time until the name may rejoin.
        remaining: Duration,
    },
}

/// Result of a successful join.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Joined {
    /// Member id (join order).
    pub id: u64,
    /// Assigned vIP.
    pub vip: Ipv4Addr,
    /// The vIP table changed (persist it).
    pub vips_changed: bool,
    /// The host changed with this join (an admin took over).
    pub host_changed: bool,
}

/// Result of a leave.
#[derive(Debug, Clone)]
pub struct Left {
    /// The removed member.
    pub member: Member,
    /// The new host, if the host role moved.
    pub new_host: Option<String>,
}

/// The lobby: members in join order, unique names, sticky vIPs, the host.
#[derive(Debug)]
pub struct Lobby {
    max_players: usize,
    admins: HashSet<String>,
    members: BTreeMap<u64, Member>,
    by_key: HashMap<String, u64>,
    vips: VipBook,
    host: Option<u64>,
    next_id: u64,
    kick_ban: Duration,
    kicked: HashMap<String, Instant>,
}

/// Input of [`Lobby::join`].
#[derive(Debug, Clone)]
pub struct JoinRequest {
    /// Player name.
    pub name: String,
    /// Launcher version.
    pub version: String,
    /// Combined fingerprint (already validated).
    pub fingerprint: Option<String>,
    /// Relay session id chosen by the caller.
    pub session: u32,
}

impl Lobby {
    /// An empty lobby.
    pub fn new(max_players: usize, admin_names: &[String], kick_ban: Duration) -> Self {
        Self {
            max_players,
            admins: admin_names.iter().map(|n| name_key(n)).collect(),
            members: BTreeMap::new(),
            by_key: HashMap::new(),
            vips: VipBook::new(),
            host: None,
            next_id: 1,
            kick_ban,
            kicked: HashMap::new(),
        }
    }

    /// Adds a player.
    pub fn join(&mut self, req: JoinRequest, now: Instant) -> Result<Joined, JoinError> {
        validate_name(&req.name).map_err(JoinError::BadName)?;
        let key = name_key(&req.name);
        if self.by_key.contains_key(&key) {
            return Err(JoinError::NameTaken);
        }
        self.kicked.retain(|_, until| *until > now);
        if let Some(until) = self.kicked.get(&key) {
            return Err(JoinError::Kicked {
                remaining: until.saturating_duration_since(now),
            });
        }
        if self.members.len() >= self.max_players {
            return Err(JoinError::Full);
        }
        let before = self.vips.table();
        let vip = self.vips.assign(&key).ok_or(JoinError::Full)?;
        let vips_changed = self.vips.table() != before;
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let is_admin = self.admins.contains(&key);
        self.members.insert(
            id,
            Member {
                name: req.name,
                key: key.clone(),
                vip,
                session: req.session,
                is_admin,
                version: req.version,
                fingerprint: req.fingerprint,
                files: None,
                ready: false,
                in_game: false,
                reported_rtt_ms: None,
                reported_loss_pct: None,
                joined_at: now,
            },
        );
        self.by_key.insert(key, id);
        let host_changed = self.elect_host();
        Ok(Joined {
            id,
            vip,
            vips_changed,
            host_changed: host_changed && self.host == Some(id) && self.members.len() > 1,
        })
    }

    /// Removes a player.
    pub fn leave(&mut self, id: u64) -> Option<Left> {
        let member = self.members.remove(&id)?;
        self.by_key.remove(&member.key);
        self.vips.release(&member.key);
        let new_host = if self.elect_host() {
            self.host
                .and_then(|h| self.members.get(&h))
                .map(|m| m.name.clone())
        } else {
            None
        };
        Some(Left { member, new_host })
    }

    /// Keeps the current host unless it left or an admin is present while the host
    /// is not an admin; otherwise the earliest admin, else the earliest player.
    /// Returns `true` if the host changed.
    fn elect_host(&mut self) -> bool {
        let first_admin = self
            .members
            .iter()
            .find(|(_, m)| m.is_admin)
            .map(|(id, _)| *id);
        let current = self.host.filter(|h| self.members.contains_key(h));
        let keep = current.filter(|h| {
            first_admin.is_none() || self.members.get(h).is_some_and(|m| m.is_admin)
        });
        let new = keep
            .or(first_admin)
            .or_else(|| self.members.keys().next().copied());
        let changed = new != self.host;
        self.host = new;
        changed
    }

    /// The host's member id.
    pub fn host(&self) -> Option<u64> {
        self.host
    }

    /// `true` if `id` is the host.
    pub fn is_host(&self, id: u64) -> bool {
        self.host == Some(id)
    }

    /// A member.
    pub fn member(&self, id: u64) -> Option<&Member> {
        self.members.get(&id)
    }

    /// A member, mutable.
    pub fn member_mut(&mut self, id: u64) -> Option<&mut Member> {
        self.members.get_mut(&id)
    }

    /// The member id of `name` (case-insensitive).
    pub fn find(&self, name: &str) -> Option<u64> {
        self.by_key.get(&name_key(name)).copied()
    }

    /// Members in join order.
    pub fn members(&self) -> impl Iterator<Item = (u64, &Member)> {
        self.members.iter().map(|(id, m)| (*id, m))
    }

    /// Number of members.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// `true` if nobody is connected.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Blocks `name` from rejoining for the kick ban duration.
    pub fn ban_name(&mut self, name: &str, now: Instant) {
        if !self.kick_ban.is_zero() {
            self.kicked.insert(name_key(name), now + self.kick_ban);
        }
    }

    /// The lobby player list; `measured` returns the server-measured upstream loss
    /// of a member's relay session.
    pub fn players(&self, measured: impl Fn(&Member) -> Option<u8>) -> Vec<Player> {
        self.members
            .iter()
            .map(|(id, m)| Player {
                name: m.name.clone(),
                vip: m.vip,
                rtt_ms: m.reported_rtt_ms,
                loss_pct: combine_loss(m.reported_loss_pct, measured(m)),
                fingerprint: m.fingerprint.clone(),
                ready: m.ready,
                in_game: m.in_game,
                is_host: self.host == Some(*id),
            })
            .collect()
    }

    /// The sticky vIP table.
    pub fn vip_table(&self) -> BTreeMap<String, Ipv4Addr> {
        self.vips.table()
    }

    /// Restores a persisted vIP table (call before anyone joins).
    pub fn restore_vips(&mut self, table: &BTreeMap<String, Ipv4Addr>) -> usize {
        self.vips.restore(table)
    }

    /// `true` if `session` is used by a member.
    pub fn session_in_use(&self, session: u32) -> bool {
        self.members.values().any(|m| m.session == session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(name: &str, session: u32) -> JoinRequest {
        JoinRequest {
            name: name.into(),
            version: "0.1.0".into(),
            fingerprint: None,
            session,
        }
    }

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(198, 18, 0, last)
    }

    #[test]
    fn names() {
        for ok in ["Frodo", "Sam Gamgee", "Éowyn", "x", "a-b_c.d!", "Gandalf[1]", "123456789012"] {
            assert_eq!(validate_name(ok), Ok(()), "{ok}");
        }
        assert_eq!(validate_name(""), Err(NameError::Empty));
        assert_eq!(validate_name("1234567890123"), Err(NameError::TooLong));
        // Non-BMP characters count twice in UTF-16.
        assert_eq!(validate_name("abcdefghijk𝔸"), Err(NameError::TooLong));
        assert_eq!(validate_name(" a"), Err(NameError::Spaces));
        assert_eq!(validate_name("a "), Err(NameError::Spaces));
        assert_eq!(validate_name("a  b"), Err(NameError::Spaces));
        assert_eq!(validate_name("a\tb"), Err(NameError::InvalidChar('\t')));
        assert_eq!(validate_name("a\u{200b}b"), Err(NameError::InvalidChar('\u{200b}')));
        assert_eq!(validate_name("a/b"), Err(NameError::InvalidChar('/')));
        assert_eq!(validate_name("<b>"), Err(NameError::InvalidChar('<')));
        assert_eq!(name_key("FrOdO"), "frodo");
        assert!(NameError::TooLong.to_string().contains("12"));
    }

    #[test]
    fn chat_sanitising() {
        assert_eq!(sanitize_chat("  hi\r\nthere\t", 300), Ok("hi  there".into()));
        assert_eq!(sanitize_chat(" \n ", 300), Err(ChatError::Empty));
        assert_eq!(sanitize_chat("äöü", 3), Ok("äöü".into()));
        assert_eq!(sanitize_chat("abcd", 3), Err(ChatError::TooLong { max: 3 }));
    }

    #[test]
    fn loss_combination() {
        assert_eq!(combine_loss(None, None), None);
        assert_eq!(combine_loss(Some(5), None), Some(5));
        assert_eq!(combine_loss(None, Some(200)), Some(100));
        assert_eq!(combine_loss(Some(10), Some(10)), Some(19));
        assert_eq!(combine_loss(Some(100), Some(0)), Some(100));
        assert_eq!(combine_loss(Some(0), Some(0)), Some(0));
    }

    #[test]
    fn fingerprints() {
        assert!(is_valid_fingerprint(&"ab".repeat(32)));
        assert!(!is_valid_fingerprint(&"ab".repeat(31)));
        assert!(!is_valid_fingerprint(&"zz".repeat(32)));
    }

    #[test]
    fn join_leave_unique_names_and_sticky_vips() {
        let t = Instant::now();
        let mut l = Lobby::new(3, &[], Duration::from_secs(60));
        let a = l.join(req("Frodo", 1), t).unwrap();
        let b = l.join(req("Sam", 2), t).unwrap();
        assert_eq!((a.vip, b.vip), (ip(2), ip(3)));
        assert!(a.vips_changed && b.vips_changed);
        assert_eq!(l.join(req("frodo", 3), t), Err(JoinError::NameTaken));
        assert!(matches!(l.join(req("", 3), t), Err(JoinError::BadName(_))));
        let c = l.join(req("Merry", 3), t).unwrap();
        assert_eq!(l.join(req("Pippin", 4), t), Err(JoinError::Full));
        // Frodo leaves; Pippin gets a new address, not Frodo's.
        l.leave(a.id).unwrap();
        let d = l.join(req("Pippin", 4), t).unwrap();
        assert_eq!(d.vip, ip(5));
        l.leave(d.id).unwrap();
        // Frodo comes back (other case) and gets the same vIP again.
        let a2 = l.join(req("FRODO", 5), t).unwrap();
        assert_eq!(a2.vip, ip(2));
        assert!(!a2.vips_changed);
        assert_eq!(l.find("frodo"), Some(a2.id));
        assert_eq!(l.len(), 3);
        assert!(l.session_in_use(5) && !l.session_in_use(1));
        let _ = c;
    }

    #[test]
    fn vip_pool_reuses_least_recently_used_absent_names() {
        let mut book = VipBook::new();
        for i in 0..net::VIP_POOL_SIZE {
            assert!(book.assign(&format!("p{i}")).is_some());
        }
        assert_eq!(book.assign("late"), None, "all active");
        book.release("p7");
        book.release("p3");
        // p7 left first → its address is reused first.
        let v = book.assign("late").unwrap();
        assert_eq!(v, vip_of(7));
        assert_eq!(book.assign("later").unwrap(), vip_of(3));
        assert_eq!(book.assign("p7"), None, "p7 lost its reservation and the pool is full");
        // An active name cannot be assigned twice.
        assert_eq!(book.assign("late"), None);
    }

    fn vip_of(index: usize) -> Ipv4Addr {
        ip(u8::try_from(index + 2).unwrap())
    }

    #[test]
    fn vip_table_restore() {
        let mut table = BTreeMap::new();
        table.insert("frodo".to_owned(), ip(9));
        table.insert("sam".to_owned(), ip(9)); // duplicate address
        table.insert("Bad".to_owned(), ip(10)); // not a name key
        table.insert("merry".to_owned(), Ipv4Addr::new(10, 0, 0, 1)); // not virtual
        table.insert("pippin".to_owned(), ip(255)); // broadcast
        let mut l = Lobby::new(16, &[], Duration::ZERO);
        assert_eq!(l.restore_vips(&table), 1);
        let t = Instant::now();
        assert_eq!(l.join(req("Frodo", 1), t).unwrap().vip, ip(9));
        assert_eq!(l.join(req("Sam", 2), t).unwrap().vip, ip(2));
    }

    #[test]
    fn host_election() {
        let t = Instant::now();
        let mut l = Lobby::new(8, &["Gandalf".to_owned()], Duration::ZERO);
        let a = l.join(req("Frodo", 1), t).unwrap();
        assert!(l.is_host(a.id));
        assert!(!a.host_changed, "first player: no takeover notice");
        let b = l.join(req("Sam", 2), t).unwrap();
        assert!(l.is_host(a.id) && !b.host_changed);
        // An admin takes over.
        let g = l.join(req("gandalf", 3), t).unwrap();
        assert!(l.is_host(g.id) && g.host_changed);
        // A later non-admin does not.
        l.join(req("Merry", 4), t).unwrap();
        assert!(l.is_host(g.id));
        // Admin leaves → earliest remaining player.
        let left = l.leave(g.id).unwrap();
        assert_eq!(left.new_host.as_deref(), Some("Frodo"));
        // Host leaves → next in join order.
        let left = l.leave(a.id).unwrap();
        assert_eq!(left.new_host.as_deref(), Some("Sam"));
        // A non-host leaving does not change the host.
        let m = l.find("merry").unwrap();
        assert_eq!(l.leave(m).unwrap().new_host, None);
        let players = l.players(|_| None);
        assert_eq!(players.len(), 1);
        assert!(players[0].is_host);
        let s = l.find("sam").unwrap();
        assert!(l.leave(s).is_some());
        assert_eq!(l.host(), None);
        assert!(l.leave(s).is_none());
    }

    #[test]
    fn kick_ban() {
        let t = Instant::now();
        let mut l = Lobby::new(8, &[], Duration::from_secs(60));
        let a = l.join(req("Frodo", 1), t).unwrap();
        l.leave(a.id);
        l.ban_name("FRODO", t);
        assert!(matches!(
            l.join(req("frodo", 2), t + Duration::from_secs(10)),
            Err(JoinError::Kicked { .. })
        ));
        assert!(l.join(req("Frodo", 2), t + Duration::from_secs(61)).is_ok());
    }

    #[test]
    fn player_list_merges_measurements() {
        let t = Instant::now();
        let mut l = Lobby::new(8, &[], Duration::ZERO);
        let a = l.join(req("Frodo", 7), t).unwrap();
        {
            let m = l.member_mut(a.id).unwrap();
            m.reported_rtt_ms = Some(42);
            m.reported_loss_pct = Some(10);
            m.ready = true;
        }
        let players = l.players(|m| (m.session == 7).then_some(10));
        assert_eq!(players[0].rtt_ms, Some(42));
        assert_eq!(players[0].loss_pct, Some(19));
        assert!(players[0].ready && players[0].is_host);
    }
}

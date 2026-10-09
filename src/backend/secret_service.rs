//! The Secret Service backend (v0.2 plan 6.3, slice S10).
//!
//! secrit talks to the daemon that owns `org.freedesktop.secrets` on the
//! user's session bus: gnome-keyring, `KWallet`, or the `KeePassXC`
//! `FdoSecrets` server. Each secrit name is one item with the label
//! `secrit: NAME` and the attributes `application=secrit`,
//! `secrit-store=<store>` and `secrit-name=NAME`, so
//! `secret-tool lookup secrit-name NAME` reads it too.
//!
//! - **Bus.** secrit reads `DBUS_SESSION_BUS_ADDRESS` once, or uses
//!   `$XDG_RUNTIME_DIR/bus` when it is unset. Only `unix:path=<absolute>`
//!   passes, the socket must be this user's, and its directory must not be
//!   writable by group or others (T31). secrit connects to that socket
//!   itself, checks that the peer runs as this user, and hands the stream to
//!   zbus, so zbus never reads the environment.
//! - **Session.** Values cross the bus encrypted: the session is always
//!   [`EncryptionType::Dh`] (T30). There is no code path for the plain
//!   session.
//! - **Deadline and signals.** Every daemon call runs in a spawned thread
//!   that sends its result on a channel. The main thread waits in 100 ms
//!   steps inside a [`Critical`] section: a signal exits 130, and no answer
//!   in 120 s exits 1. Both go through the normal error path, so the lock is
//!   released and secrit's buffers are zeroized. The abandoned thread ends
//!   with the process.
//! - **Locked collection.** Refused with [`BackendError::Locked`], unless the
//!   config says `unlock = "prompt"` and no agent is detected (Q30). `ls`
//!   reads names from the item attributes and works while the daemon shows
//!   them; a daemon that hides them while locked gets the same refusal.
//! - **Memory.** secrit takes the `Vec<u8>` that the crate returns into a
//!   [`SecretValue`] without a copy, and gives the crate a [`Zeroizing`]
//!   copy to send. The crate's AES-CBC buffers and the zbus message buffers
//!   hold more copies that nobody wipes: neither crate uses `zeroize` (T56).
//!   The "zeroized buffers" rule covers secrit's own buffers only.
//! - **No backup.** The daemon replaces and deletes in place, so
//!   `store --replace` and `rm` say so and ask first (T55, Q37).

use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use secret_service::EncryptionType;
use secret_service::blocking::{Collection, SecretService};
use zbus::zvariant::OwnedObjectPath;
use zeroize::{Zeroize, Zeroizing};

use super::{Backend, BackendError, Capabilities, DoctorCtx, Location, PutMode, WriteReport};
use crate::agent;
use crate::config::{BackendKind, Env, SecretServiceStore, Unlock};
use crate::display::escape;
use crate::lock;
use crate::name::Name;
use crate::paths;
use crate::report::{Report, Status};
use crate::secret::{MAX_VALUE_BYTES, SecretValue};
use crate::signals::{self, Critical};
use crate::testhook;

/// The daemon name in messages.
pub const DAEMON: &str = "Secret Service";
const ATTR_APPLICATION: &str = "application";
const ATTR_STORE: &str = "secrit-store";
const ATTR_NAME: &str = "secrit-name";
const APPLICATION: &str = "secrit";
/// Binary values work: the daemon stores the bytes as they are.
const CONTENT_TYPE: &str = "application/octet-stream";
/// How long secrit waits for one daemon call (v0.2 plan 6.3).
const DEADLINE: Duration = Duration::from_secs(120);
/// How often the wait checks for a signal.
const STEP: Duration = Duration::from_millis(100);

/// The session encryption. Always DH, so a value never crosses the bus in
/// cleartext (T30).
fn encryption() -> EncryptionType {
    EncryptionType::Dh
}

#[derive(Debug)]
pub struct SecretServiceBackend {
    /// The secrit store name, the `secrit-store` attribute of each item.
    store: String,
    collection: String,
    unlock: Unlock,
    location: Location,
    /// The checked bus socket, or why the address was refused.
    bus: Result<PathBuf, String>,
    runtime_dir: Option<PathBuf>,
    lock_timeout: Duration,
}

/// The attributes that find the items of one store, and of one name in it.
fn attributes<'a>(store: &'a str, name: Option<&'a str>) -> HashMap<&'a str, &'a str> {
    let mut a = HashMap::from([(ATTR_APPLICATION, APPLICATION), (ATTR_STORE, store)]);
    if let Some(n) = name {
        a.insert(ATTR_NAME, n);
    }
    a
}

fn label(name: &Name) -> String {
    format!("secrit: {name}")
}

impl SecretServiceBackend {
    /// `env` supplies `DBUS_SESSION_BUS_ADDRESS` and `XDG_RUNTIME_DIR`. A bad
    /// bus address does not fail here: every call refuses it, and `doctor`
    /// shows it as a row.
    pub fn new(
        store: &str,
        config: &SecretServiceStore,
        lock_timeout: Duration,
        env: &Env,
    ) -> Self {
        Self {
            store: store.to_owned(),
            collection: config.collection.clone(),
            unlock: config.unlock,
            location: Location::collection(&config.collection, store),
            bus: bus_path(env),
            runtime_dir: paths::runtime_dir(env),
            lock_timeout,
        }
    }

    /// Check the daemon and the collection with no change: `init
    /// --backend secret-service` runs this before it writes the config.
    pub fn check(&self) -> Result<usize, BackendError> {
        let store = self.store.clone();
        self.call("check", Need::Unlocked, move |c, step| {
            Ok(c.search_items(attributes(&store, None))
                .map_err(|e| step.err(e))?
                .len())
        })
    }

    /// Run `f` on the collection in a spawned thread, and wait for it (see
    /// the module docs).
    fn call<T, F>(&self, step: &'static str, need: Need, f: F) -> Result<T, BackendError>
    where
        T: Send + 'static,
        F: FnOnce(&Collection<'_>, &Step) -> Result<T, BackendError> + Send + 'static,
    {
        let bus = self
            .bus
            .clone()
            .map_err(|reason| BackendError::UnsafeBus { reason })?;
        let step = Step {
            name: step,
            location: self.location.clone(),
        };
        let collection = self.collection.clone();
        // Ask the daemon to unlock only when the config allows it and no
        // agent runs secrit (Q30): the prompt is the owner's to answer.
        let may_unlock = self.unlock == Unlock::Prompt && agent::detect().is_none();
        let (tx, rx) = mpsc::channel();
        let worker_step = step.clone();
        std::thread::Builder::new()
            .name("secrit-dbus".into())
            .spawn(move || {
                let step = worker_step;
                let result = connect(&bus, &step).and_then(|ss| {
                    let c = open_collection(&ss, &collection, &step)?;
                    if need == Need::Unlocked {
                        ensure_unlocked(&c, may_unlock, &step)?;
                    }
                    f(&c, &step)
                });
                // The receiver is gone after a signal or the deadline.
                let _ = tx.send(result);
            })
            .map_err(|e| step.failed(format!("could not start the D-Bus thread: {e}")))?;
        wait(&rx, &step, DEADLINE)
    }

    /// Take the secrit lock of this store (v0.2 plan 5.3). It serialises
    /// secrit writers only; other programs can still change the items.
    fn lock(&self) -> Result<lock::StoreLock, BackendError> {
        let dir = self
            .runtime_dir
            .as_deref()
            .ok_or(lock::LockError::NoRuntimeDir)?;
        let path = lock::keyed_lock_path(
            dir,
            BackendKind::SecretService.as_str(),
            &self.location.to_string(),
        );
        Ok(lock::acquire(&path, self.lock_timeout)?)
    }

    fn missing(&self, name: &Name) -> BackendError {
        BackendError::Missing {
            name: name.clone(),
            location: self.location.clone(),
        }
    }

    fn exists_error(&self, name: &Name) -> BackendError {
        BackendError::Exists {
            name: name.clone(),
            location: self.location.clone(),
        }
    }

    /// How many items hold `name`.
    fn count(&self, name: &Name, need: Need) -> Result<usize, BackendError> {
        let store = self.store.clone();
        let name = name.as_str().to_owned();
        self.call("search", need, move |c, step| {
            Ok(c.search_items(attributes(&store, Some(&name)))
                .map_err(|e| step.err(e))?
                .len())
        })
    }
}

/// Whether a call needs the collection unlocked first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Need {
    /// Attributes only: search and list.
    Attributes,
    /// Values, writes, and the checks before a write.
    Unlocked,
}

/// The step of a call, for its errors.
#[derive(Debug, Clone)]
struct Step {
    name: &'static str,
    location: Location,
}

impl Step {
    fn failed(&self, what: String) -> BackendError {
        BackendError::Daemon {
            daemon: DAEMON,
            step: self.name,
            what,
        }
    }

    /// The crate's error as a secrit error. Its text comes from the daemon
    /// or the bus, never from a value.
    fn err(&self, e: secret_service::Error) -> BackendError {
        match e {
            secret_service::Error::Locked => BackendError::Locked(self.location.clone()),
            secret_service::Error::Unavailable => self.failed(
                "no Secret Service on the session bus (start gnome-keyring, KWallet or KeePassXC with its Secret Service integration)".into(),
            ),
            secret_service::Error::Prompt => {
                self.failed("the daemon's unlock prompt was dismissed".into())
            }
            e => self.failed(escape(&e.to_string()).into_owned()),
        }
    }
}

/// Wait for the worker's result, at most `deadline`. A signal ends the
/// wait with exit 130 (R13).
fn wait<T>(
    rx: &Receiver<Result<T, BackendError>>,
    step: &Step,
    deadline: Duration,
) -> Result<T, BackendError> {
    let _critical = Critical::enter();
    let end = Instant::now() + deadline;
    loop {
        match rx.recv_timeout(STEP) {
            Ok(result) => return result,
            Err(RecvTimeoutError::Timeout) => {
                if signals::pending() {
                    return Err(BackendError::DaemonInterrupted {
                        daemon: DAEMON,
                        step: step.name,
                    });
                }
                if Instant::now() >= end {
                    return Err(step.failed(format!(
                        "no answer within {} s; the daemon may be waiting for an unlock prompt",
                        deadline.as_secs()
                    )));
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(step.failed("the D-Bus thread ended with no result".into()));
            }
        }
    }
}

/// The session bus socket that secrit uses: `DBUS_SESSION_BUS_ADDRESS`,
/// else `$XDG_RUNTIME_DIR/bus`. The socket checks run at connect time.
fn bus_path(env: &Env) -> Result<PathBuf, String> {
    match env("DBUS_SESSION_BUS_ADDRESS").filter(|v| !v.is_empty()) {
        Some(v) => {
            let text = v
                .to_str()
                .ok_or_else(|| "DBUS_SESSION_BUS_ADDRESS is not valid UTF-8".to_owned())?;
            parse_bus_address(text)
                .map_err(|reason| format!("DBUS_SESSION_BUS_ADDRESS={}: {reason}", escape(text)))
        }
        None => paths::runtime_dir(env)
            .map(|d| d.join("bus"))
            .ok_or_else(|| {
                "DBUS_SESSION_BUS_ADDRESS is not set and XDG_RUNTIME_DIR is not an absolute path"
                    .to_owned()
            }),
    }
}

/// The socket path of a `unix:path=<absolute>` address. A `guid` key is
/// accepted and ignored; any other transport, key or a list of addresses is
/// refused (T31).
pub fn parse_bus_address(address: &str) -> Result<PathBuf, String> {
    const ONLY: &str = "only a unix:path=<absolute path> address is accepted";
    if address.contains(';') {
        return Err(format!("it lists more than one address; {ONLY}"));
    }
    let Some(rest) = address.strip_prefix("unix:") else {
        return Err(ONLY.to_owned());
    };
    let mut path = None;
    for pair in rest.split(',') {
        let Some((key, value)) = pair.split_once('=') else {
            return Err(format!("'{}' is not key=value; {ONLY}", escape(pair)));
        };
        match key {
            "path" if path.is_none() => path = Some(unescape(value)?),
            "path" => return Err(format!("it names path twice; {ONLY}")),
            "guid" => {}
            other => return Err(format!("key '{}'; {ONLY}", escape(other))),
        }
    }
    let path = path.ok_or_else(|| format!("it has no path; {ONLY}"))?;
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(format!("the path is not absolute; {ONLY}"))
    }
}

/// A D-Bus address value with its `%XX` escapes decoded.
fn unescape(value: &str) -> Result<PathBuf, String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| "a bad %-escape in the path".to_owned())?;
            out.push(hex);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(PathBuf::from(OsStr::from_bytes(&out)))
}

/// What the socket checks look at, so the rule is testable without
/// another user's socket.
#[derive(Debug, Clone, Copy)]
struct SocketFacts {
    is_socket: bool,
    socket_uid: u32,
    dir_uid: u32,
    dir_mode: u32,
    me: u32,
}

/// The socket rule of T31: a socket of this user, in a directory of this
/// user or root that group and others cannot write. A sticky directory such
/// as `/tmp` fails too: anyone can make a socket there.
fn judge_socket(f: SocketFacts) -> Result<(), &'static str> {
    if !f.is_socket {
        return Err("it is not a socket (or it is a symlink)");
    }
    if f.socket_uid != f.me {
        return Err("the socket is owned by another user");
    }
    if f.dir_uid != f.me && f.dir_uid != 0 {
        return Err("its directory is owned by another user");
    }
    if f.dir_mode & 0o022 != 0 {
        return Err(
            "its directory is writable by group or others (a shared directory such as /tmp is not accepted)",
        );
    }
    Ok(())
}

fn check_socket(path: &Path) -> Result<(), String> {
    let shown = crate::display::escape_path(path);
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{shown}: {e}"))?;
    let dir = path
        .parent()
        .ok_or_else(|| format!("{shown} has no directory"))?;
    let dmeta = std::fs::metadata(dir).map_err(|e| format!("{shown}: {e}"))?;
    judge_socket(SocketFacts {
        is_socket: meta.file_type().is_socket(),
        socket_uid: meta.uid(),
        dir_uid: dmeta.uid(),
        dir_mode: dmeta.mode(),
        me: rustix::process::getuid().as_raw(),
    })
    .map_err(|reason| format!("{shown}: {reason}"))
}

/// The uid of the process at the other end of the bus socket
/// (`SO_PEERCRED`).
#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Result<u32, String> {
    rustix::net::sockopt::socket_peercred(stream)
        .map(|c| c.uid.as_raw())
        .map_err(|e| format!("the peer credentials: {e}"))
}

/// Only Linux has `SO_PEERCRED`, and the Secret Service backend is
/// Linux-only (v0.2 plan 8.2), so another platform refuses the bus.
#[cfg(not(target_os = "linux"))]
fn peer_uid(_: &UnixStream) -> Result<u32, String> {
    Err("the Secret Service backend works on Linux only".to_owned())
}

/// Connect to the checked socket and open a DH session.
fn connect(bus: &Path, step: &Step) -> Result<SecretService<'static>, BackendError> {
    let refuse = |reason: String| BackendError::UnsafeBus { reason };
    check_socket(bus).map_err(refuse)?;
    let shown = crate::display::escape_path(bus);
    let stream = UnixStream::connect(bus).map_err(|e| step.failed(format!("{shown}: {e}")))?;
    let peer = peer_uid(&stream).map_err(|e| refuse(format!("{shown}: {e}")))?;
    if peer != rustix::process::getuid().as_raw() {
        return Err(refuse(format!(
            "{shown}: the bus daemon runs as another user"
        )));
    }
    let conn = zbus::blocking::connection::Builder::async_io_unix_stream(stream)
        .build()
        .map_err(|e| step.failed(format!("{shown}: {}", escape(&e.to_string()))))?;
    SecretService::connect_with_existing(encryption(), conn).map_err(|e| step.err(e))
}

/// The configured collection: an object path when it starts with '/', else
/// an alias.
fn open_collection<'a>(
    ss: &'a SecretService<'a>,
    name: &str,
    step: &Step,
) -> Result<Collection<'a>, BackendError> {
    let found = if name.starts_with('/') {
        let path = OwnedObjectPath::try_from(name)
            .map_err(|_| step.failed(format!("'{}' is not a D-Bus object path", escape(name))))?;
        ss.get_collection_by_path(path)
    } else {
        ss.get_collection_by_alias(name)
    };
    match found {
        Err(secret_service::Error::NoResult) => {
            Err(step.failed(format!("the daemon has no collection '{}'", escape(name))))
        }
        r => r.map_err(|e| step.err(e)),
    }
}

fn ensure_unlocked(c: &Collection<'_>, may_unlock: bool, step: &Step) -> Result<(), BackendError> {
    if !c.is_locked().map_err(|e| step.err(e))? {
        return Ok(());
    }
    if !may_unlock {
        return Err(BackendError::Locked(step.location.clone()));
    }
    // May open the daemon's GUI prompt; the wait's deadline bounds it.
    c.unlock().map_err(|e| step.err(e))
}

/// The names of the store's items, from their attributes. A locked daemon
/// can show only hashed attributes; then the names are unknown.
fn names(c: &Collection<'_>, store: &str, step: &Step) -> Result<Vec<String>, BackendError> {
    let items = c
        .search_items(attributes(store, None))
        .map_err(|e| step.err(e))?;
    let mut names = Vec::with_capacity(items.len());
    for item in items {
        let mut attrs = item.get_attributes().map_err(|e| step.err(e))?;
        match attrs.remove(ATTR_NAME) {
            Some(n) => names.push(n),
            None if c.is_locked().map_err(|e| step.err(e))? => {
                return Err(BackendError::Locked(step.location.clone()));
            }
            // An item of another tool that found our attributes; skip it.
            None => {}
        }
    }
    names.sort();
    names.dedup();
    Ok(names)
}

/// The value of the one item that holds `name`.
fn value_of(
    c: &Collection<'_>,
    store: &str,
    name: &Name,
    location: &Location,
    step: &Step,
) -> Result<SecretValue, BackendError> {
    let items = c
        .search_items(attributes(store, Some(name.as_str())))
        .map_err(|e| step.err(e))?;
    let item = match items.as_slice() {
        [] => {
            return Err(BackendError::Missing {
                name: name.clone(),
                location: location.clone(),
            });
        }
        [item] => item,
        more => {
            return Err(step.failed(format!(
                "{} items hold '{name}'; remove the extra ones (for example with seahorse or secret-tool)",
                more.len()
            )));
        }
    };
    let mut bytes = item.get_secret().map_err(|e| step.err(e))?;
    if bytes.len() > MAX_VALUE_BYTES {
        bytes.zeroize();
        return Err(step.failed(format!(
            "'{name}' holds more than {MAX_VALUE_BYTES} bytes; secrit handles values up to 64 KiB"
        )));
    }
    // No copy: the value's own buffer is zeroized on drop.
    Ok(SecretValue::new(bytes))
}

impl Backend for SecretServiceBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::SecretService
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities { backups: false }
    }

    fn location(&self) -> &Location {
        &self.location
    }

    fn list(&self) -> Result<Vec<String>, BackendError> {
        let store = self.store.clone();
        self.call("search", Need::Attributes, move |c, step| {
            names(c, &store, step)
        })
    }

    fn exists(&self, name: &Name) -> Result<bool, BackendError> {
        Ok(self.count(name, Need::Attributes)? > 0)
    }

    /// A locked collection refuses here, before anyone types a value.
    fn check_put(&self, name: &Name, mode: PutMode) -> Result<(), BackendError> {
        let n = self.count(name, Need::Unlocked)?;
        if mode == PutMode::CreateOnly && n > 0 {
            return Err(self.exists_error(name));
        }
        Ok(())
    }

    fn check_remove(&self, name: &Name) -> Result<(), BackendError> {
        if self.count(name, Need::Unlocked)? == 0 {
            return Err(self.missing(name));
        }
        Ok(())
    }

    /// One `GetSecret` per name: each value is consistent on its own, not
    /// across names.
    fn get_many(&self, names: &[Name]) -> Result<Vec<(Name, SecretValue)>, BackendError> {
        let store = self.store.clone();
        let location = self.location.clone();
        let names = names.to_vec();
        self.call("read", Need::Unlocked, move |c, step| {
            names
                .into_iter()
                .map(|n| {
                    let v = value_of(c, &store, &n, &location, step)?;
                    Ok((n, v))
                })
                .collect()
        })
    }

    fn put(
        &self,
        name: &Name,
        value: &SecretValue,
        mode: PutMode,
    ) -> Result<WriteReport, BackendError> {
        let _lock = self.lock()?;
        testhook::hook("after-lock");
        let store = self.store.clone();
        let label = label(name);
        let key = name.as_str().to_owned();
        // The thread may outlive this call (signal or deadline), so it gets
        // its own copy, wiped when the thread drops it.
        let secret = Zeroizing::new(value.expose().to_vec());
        let created = self.call("write", Need::Unlocked, move |c, step| {
            let attrs = attributes(&store, Some(&key));
            if mode == PutMode::Replace {
                c.create_item(&label, attrs, &secret, true, CONTENT_TYPE)
                    .map_err(|e| step.err(e))?;
                return Ok(true);
            }
            // CreateOnly: the daemon does not refuse a duplicate by itself,
            // so search, create, and search again (T32).
            if !c
                .search_items(attrs.clone())
                .map_err(|e| step.err(e))?
                .is_empty()
            {
                return Ok(false);
            }
            let item = c
                .create_item(&label, attrs.clone(), &secret, false, CONTENT_TYPE)
                .map_err(|e| step.err(e))?;
            if c.search_items(attrs).map_err(|e| step.err(e))?.len() > 1 {
                // Another program made the same name meanwhile: keep theirs.
                item.delete().map_err(|e| step.err(e))?;
                return Ok(false);
            }
            Ok(true)
        })?;
        if created {
            Ok(WriteReport::default())
        } else {
            Err(self.exists_error(name))
        }
    }

    fn remove(&self, name: &Name) -> Result<WriteReport, BackendError> {
        let _lock = self.lock()?;
        testhook::hook("after-lock");
        let store = self.store.clone();
        let key = name.as_str().to_owned();
        let removed = self.call("delete", Need::Unlocked, move |c, step| {
            let items = c
                .search_items(attributes(&store, Some(&key)))
                .map_err(|e| step.err(e))?;
            for item in &items {
                item.delete().map_err(|e| step.err(e))?;
            }
            Ok(items.len())
        })?;
        if removed == 0 {
            return Err(self.missing(name));
        }
        Ok(WriteReport::default())
    }

    fn doctor(&self, r: &mut Report, ctx: &DoctorCtx<'_>) {
        doctor_rows(r, self, ctx.store);
    }
}

/// What `doctor` learns from the daemon, one result per row.
#[derive(Debug)]
struct DoctorFacts {
    reachable: Result<(), String>,
    session: Result<(), String>,
    collection: Result<bool, String>,
    items: Result<usize, String>,
}

impl DoctorFacts {
    fn unknown(why: &str) -> Self {
        Self {
            reachable: Err(why.to_owned()),
            session: Err(why.to_owned()),
            collection: Err(why.to_owned()),
            items: Err(why.to_owned()),
        }
    }
}

/// The doctor checks, in the worker thread. Read-only: no unlock, no
/// value.
fn doctor_facts(bus: &Path, collection: &str, store: &str, step: &Step) -> DoctorFacts {
    let mut facts = DoctorFacts::unknown("skipped: the check before it failed");
    let reached = check_socket(bus)
        .and_then(|()| UnixStream::connect(bus).map_err(|e| e.to_string()))
        .and_then(|s| {
            zbus::blocking::connection::Builder::async_io_unix_stream(s)
                .build()
                .map_err(|e| escape(&e.to_string()).into_owned())
        });
    let conn = match reached {
        Ok(c) => {
            facts.reachable = Ok(());
            c
        }
        Err(e) => {
            facts.reachable = Err(e);
            return facts;
        }
    };
    let ss = match SecretService::connect_with_existing(encryption(), conn) {
        Ok(ss) => {
            facts.session = Ok(());
            ss
        }
        Err(e) => {
            facts.session = Err(step.err(e).to_string());
            return facts;
        }
    };
    let c = match open_collection(&ss, collection, step) {
        Ok(c) => c,
        Err(e) => {
            facts.collection = Err(e.to_string());
            return facts;
        }
    };
    facts.collection = c.is_locked().map_err(|e| step.err(e).to_string());
    facts.items = c
        .search_items(attributes(store, None))
        .map(|items| items.len())
        .map_err(|e| step.err(e).to_string());
    facts
}

fn doctor_rows(r: &mut Report, b: &SecretServiceBackend, store: &str) {
    let row = |what: &str| format!("store {store}: {what}");
    let facts = match &b.bus {
        Err(reason) => {
            r.add(row("bus"), Status::Fail, format!("refused: {reason}"));
            return;
        }
        Ok(bus) => {
            r.add(row("bus"), Status::Ok, crate::display::escape_path(bus));
            let step = Step {
                name: "doctor",
                location: b.location.clone(),
            };
            let (tx, rx) = mpsc::channel();
            let (bus, collection, owner) = (bus.clone(), b.collection.clone(), b.store.clone());
            let worker_step = step.clone();
            let spawned = std::thread::Builder::new()
                .name("secrit-dbus".into())
                .spawn(move || {
                    let facts = doctor_facts(&bus, &collection, &owner, &worker_step);
                    let _ = tx.send(Ok(facts));
                });
            match spawned
                .map_err(|e| step.failed(format!("could not start the D-Bus thread: {e}")))
                .and_then(|_| wait(&rx, &step, DEADLINE))
            {
                Ok(f) => f,
                Err(e) => DoctorFacts::unknown(&e.to_string()),
            }
        }
    };
    let fail = |r: &mut Report, what: &str, e: String| r.add(row(what), Status::Fail, e);
    match facts.reachable {
        Ok(()) => r.add(row("daemon"), Status::Ok, "the session bus answers"),
        Err(e) => return fail(r, "daemon", e),
    }
    match facts.session {
        Ok(()) => r.add(
            row("session"),
            Status::Ok,
            "encrypted (DH) session with the Secret Service",
        ),
        Err(e) => return fail(r, "session", e),
    }
    let shown = b.location.to_string();
    match facts.collection {
        Ok(false) => r.add(
            row("collection"),
            Status::Ok,
            format!("{shown} is unlocked"),
        ),
        Ok(true) if b.unlock == Unlock::Prompt => r.add(
            row("collection"),
            Status::Warn,
            format!("{shown} is locked; secrit asks the daemon to unlock it (unlock = \"prompt\")"),
        ),
        Ok(true) => r.add(
            row("collection"),
            Status::Fail,
            BackendError::Locked(b.location.clone()).to_string(),
        ),
        Err(e) => return fail(r, "collection", e),
    }
    match facts.items {
        Ok(n) => r.add(row("items"), Status::Ok, format!("{n} secrit item(s)")),
        Err(e) => fail(r, "items", e),
    }
    r.add(
        row("readers"),
        Status::Info,
        "any process of this user on the session bus can read these values; the 'get' refusal for agents is an accident guard only",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The item attributes: `secret-tool lookup secrit-name NAME` finds
    /// them, and one store never sees another store's items.
    #[test]
    fn the_attribute_set() {
        assert_eq!(
            attributes("desk", None),
            HashMap::from([("application", "secrit"), ("secrit-store", "desk")])
        );
        assert_eq!(
            attributes("desk", Some("tok")),
            HashMap::from([
                ("application", "secrit"),
                ("secrit-store", "desk"),
                ("secrit-name", "tok"),
            ])
        );
        assert_eq!(label(&Name::parse("tok").unwrap()), "secrit: tok");
    }

    /// T30: the session is DH, and no code path names the plain session.
    #[test]
    fn the_session_is_dh_only() {
        assert_eq!(encryption(), EncryptionType::Dh);
        let plain = concat!("EncryptionType", "::", "Plain");
        for (file, text) in [
            ("secret_service.rs", include_str!("secret_service.rs")),
            ("mod.rs", include_str!("mod.rs")),
        ] {
            assert!(!text.contains(plain), "{file} names the plain session");
        }
    }

    /// T31: only `unix:path=<absolute>` passes, with an optional guid.
    #[test]
    fn the_bus_address_rule() {
        let ok = |a: &str| parse_bus_address(a).unwrap();
        assert_eq!(
            ok("unix:path=/run/user/1000/bus"),
            Path::new("/run/user/1000/bus")
        );
        assert_eq!(
            ok("unix:path=/run/user/1000/bus,guid=0123abcd"),
            Path::new("/run/user/1000/bus")
        );
        assert_eq!(ok("unix:path=/r/a%20b"), Path::new("/r/a b"));
        for bad in [
            "tcp:host=localhost,port=1234",
            "unix:abstract=/tmp/dbus-x",
            "unix:tmpdir=/tmp",
            "unix:runtime=yes",
            "unix:path=bus",
            "unix:path=/a;unix:path=/b",
            "unix:path=/a,path=/b",
            "unix:guid=00",
            "unix:path=/a,noequals",
            "unix:path=/a%zz",
            "autolaunch:",
            "",
        ] {
            assert!(parse_bus_address(bad).is_err(), "{bad} passed");
        }
    }

    fn env_of(
        pairs: &'static [(&'static str, &'static str)],
    ) -> impl Fn(&str) -> Option<std::ffi::OsString> {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| std::ffi::OsString::from(v))
        }
    }

    /// An unset variable means `$XDG_RUNTIME_DIR/bus`; an empty one too.
    #[test]
    fn the_bus_falls_back_to_the_runtime_dir() {
        let fallback = env_of(&[("XDG_RUNTIME_DIR", "/run/user/7")]);
        assert_eq!(bus_path(&fallback).unwrap(), Path::new("/run/user/7/bus"));
        let empty = env_of(&[("DBUS_SESSION_BUS_ADDRESS", ""), ("XDG_RUNTIME_DIR", "/r")]);
        assert_eq!(bus_path(&empty).unwrap(), Path::new("/r/bus"));
        let set = env_of(&[
            ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/x/bus"),
            ("XDG_RUNTIME_DIR", "/r"),
        ]);
        assert_eq!(bus_path(&set).unwrap(), Path::new("/x/bus"));
        let tcp = env_of(&[("DBUS_SESSION_BUS_ADDRESS", "tcp:host=h,port=1")]);
        let e = bus_path(&tcp).unwrap_err();
        assert!(
            e.starts_with("DBUS_SESSION_BUS_ADDRESS=tcp:host=h,port=1: only"),
            "{e}"
        );
        assert!(bus_path(&env_of(&[("XDG_RUNTIME_DIR", "rel")])).is_err());
    }

    /// T31: a socket of another owner, a socket in a shared or sticky
    /// directory, and a symlink are refused.
    #[test]
    fn the_socket_rule() {
        let good = SocketFacts {
            is_socket: true,
            socket_uid: 1000,
            dir_uid: 1000,
            dir_mode: 0o40700,
            me: 1000,
        };
        assert!(judge_socket(good).is_ok());
        assert!(
            judge_socket(SocketFacts {
                dir_uid: 0,
                dir_mode: 0o40755,
                ..good
            })
            .is_ok()
        );
        for bad in [
            SocketFacts {
                is_socket: false,
                ..good
            },
            SocketFacts {
                socket_uid: 1001,
                ..good
            },
            SocketFacts {
                dir_uid: 1001,
                ..good
            },
            SocketFacts {
                dir_mode: 0o41777,
                ..good
            },
            SocketFacts {
                dir_mode: 0o40770,
                ..good
            },
        ] {
            assert!(judge_socket(bad).is_err(), "{bad:?} passed");
        }
    }

    /// The same rule on real files: a socket in a private directory passes;
    /// in a sticky world-writable directory, or as a symlink, it fails.
    #[test]
    fn the_socket_rule_on_disk() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("bus");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(check_socket(&sock), Ok(()));
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&sock, &link).unwrap();
        assert!(check_socket(&link).unwrap_err().contains("not a socket"));
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(
            check_socket(&sock)
                .unwrap_err()
                .contains("writable by group or others")
        );
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(check_socket(&d.path().join("missing")).is_err());
    }

    /// The wait gives the result, or ends at the deadline with exit 1.
    #[test]
    fn the_wait_ends_at_the_deadline() {
        let step = Step {
            name: "read",
            location: Location::collection("default", "desk"),
        };
        let (tx, rx) = mpsc::channel::<Result<u8, BackendError>>();
        tx.send(Ok(7)).unwrap();
        assert_eq!(wait(&rx, &step, Duration::from_millis(300)).unwrap(), 7);
        let started = Instant::now();
        let e = wait(&rx, &step, Duration::from_millis(300)).unwrap_err();
        assert!(started.elapsed() >= Duration::from_millis(300));
        assert_eq!(e.exit(), crate::error::Exit::Failed);
        assert!(e.to_string().contains("no answer within 0 s"), "{e}");
        drop(tx);
        let e = wait(&rx, &step, Duration::from_secs(5)).unwrap_err();
        assert!(e.to_string().contains("ended with no result"), "{e}");
    }

    /// No error text shows a value: the crate's errors carry daemon text
    /// only, and secrit escapes it.
    #[test]
    fn daemon_errors_name_the_step() {
        let step = Step {
            name: "write",
            location: Location::collection("default", "desk"),
        };
        assert_eq!(
            step.err(secret_service::Error::Locked).to_string(),
            "Secret Service collection 'default' (secrit-store=desk) is locked; unlock it (log in to the desktop session, or use the keyring manager), or set unlock = \"prompt\" in the config"
        );
        assert!(
            step.err(secret_service::Error::Unavailable)
                .to_string()
                .starts_with("Secret Service write failed: no Secret Service on the session bus")
        );
        assert_eq!(
            step.err(secret_service::Error::Crypto("bad\u{1b}iv"))
                .to_string(),
            "Secret Service write failed: Crypto error: bad\\x1biv"
        );
    }
}

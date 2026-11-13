//! A bounded driver for a server child over its stdio pipes.
//!
//! [`ChildDriver`] spawns a caller-built [`Command`] with stdin, stdout, and
//! stderr piped. It writes each JSON message as one line, exactly as given, and
//! returns the response that carries a requested id. Every wait has a deadline:
//! a response wait ends after [`RESPONSE_DEADLINE`], and an exit wait after
//! [`EXIT_DEADLINE`]. Messages with another id never extend a wait, and a wait
//! whose deadline has passed takes no further message.
//!
//! Two reader threads drain the child's stdout and stderr while it runs, so a
//! child that writes more than a pipe holds never blocks on an unread pipe.
//! The stderr text is available at any time and is returned at exit. Dropping
//! the driver kills the child and reaps it, during an unwind as well.
//!
//! A descendant of the child can inherit its stdout or stderr and keep the
//! pipe open after the child exits. Every join of a reader is bounded by the
//! exit deadline. A reader whose pipe stays open past it is detached, and the
//! driver returns what was read until then. The same deadline covers the kill
//! and the reap: a child still unreaped when it passes goes to a detached
//! reaper thread.

#![allow(dead_code, reason = "shared driver; each suite uses the part it needs")]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test driver; a failed expectation fails the calling test"
)]

use std::collections::VecDeque;
use std::io::{BufRead as _, Read, Write};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// How long a request waits for its response.
pub const RESPONSE_DEADLINE: Duration = Duration::from_secs(30);

/// How long [`ChildDriver::wait`] waits for the child to exit and for its
/// readers to finish.
pub const EXIT_DEADLINE: Duration = Duration::from_secs(30);

/// The pause between two checks of a reader that has not finished.
const JOIN_STEP: Duration = Duration::from_millis(5);

/// The longest pause between two exit checks of a stderr wait.
const EXIT_POLL: Duration = Duration::from_millis(20);

/// How a wait for a text on the child's stderr ends.
#[derive(Debug)]
pub enum StderrWait {
    /// The text is in the collected stderr, which this variant holds.
    Shown(String),
    /// The child exits, its stderr pipe closes, and the complete stderr lacks
    /// the text.
    Exited {
        /// The child's exit status.
        status: ExitStatus,
        /// The complete stderr of the child.
        stderr: String,
    },
    /// The child exits, and its stderr pipe is still open when the deadline
    /// passes. The capture is incomplete and lacks the text so far.
    ExitedWithOpenStderr {
        /// The child's exit status.
        status: ExitStatus,
        /// The stderr collected until the deadline.
        stderr: String,
    },
    /// The child runs when the deadline passes; holds the stderr so far.
    Running(String),
}

/// One event of the stdout reader.
enum StdoutEvent {
    /// A line that parses as JSON.
    Message(Value),
    /// A line that does not parse as JSON.
    Unparsed(String),
    /// The child closed stdout.
    Closed,
}

/// Why a response wait ended without the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseError {
    /// The deadline passed first.
    Deadline,
    /// The child closed stdout first.
    Closed,
    /// The child wrote a line that is not JSON.
    Unparsed(String),
}

/// The events the stdout reader delivered that no wait has taken yet.
#[derive(Default)]
struct StdoutQueue {
    events: Mutex<VecDeque<StdoutEvent>>,
    arrived: Condvar,
}

/// Lets a test stop the stdout reader right after it delivers one response.
#[derive(Default)]
struct StdoutGate {
    state: Mutex<GateState>,
    changed: Condvar,
}

#[derive(Default)]
struct GateState {
    /// The id of the response after which the reader parks.
    park_after: Option<Value>,
    /// The reader has parked and reads nothing until the gate is released.
    parked: bool,
}

impl StdoutGate {
    /// Arms the gate for the response with `id`.
    fn arm(&self, id: Value) {
        self.state.lock().unwrap().park_after = Some(id);
    }

    /// Parks the reader when `id` is the armed response's id, acknowledging
    /// the park, until the gate is released.
    fn park_after(&self, id: &Value) {
        let mut state = self.state.lock().unwrap();
        if state.park_after.as_ref() != Some(id) {
            return;
        }
        state.park_after = None;
        state.parked = true;
        self.changed.notify_all();
        while state.parked {
            state = self.changed.wait(state).unwrap();
        }
    }

    /// Disarms the gate and lets a parked reader go on.
    fn release(&self) {
        let mut state = self.state.lock().unwrap();
        state.park_after = None;
        state.parked = false;
        self.changed.notify_all();
    }

    /// Waits until the reader acknowledges the park, or `deadline` passes.
    fn wait_parked(&self, deadline: Instant) -> bool {
        let mut state = self.state.lock().unwrap();
        while !state.parked {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            state = self.changed.wait_timeout(state, left).unwrap().0;
        }
        true
    }

    fn is_parked(&self) -> bool {
        self.state.lock().unwrap().parked
    }
}

/// The stderr text collected so far, with a signal for each new chunk and for
/// the close of the pipe.
#[derive(Default)]
struct StderrBuffer {
    bytes: Mutex<Vec<u8>>,
    grew: Condvar,
    /// Set under the `bytes` lock when the reader sees the pipe close.
    closed: AtomicBool,
    /// Lets a test hold the reader back before it appends a chunk.
    hold: Mutex<HoldState>,
    hold_changed: Condvar,
}

#[derive(Default)]
struct HoldState {
    /// The reader holds each chunk it reads until the hold is released.
    armed: bool,
    /// The reader holds a chunk and does not append it yet.
    holding: bool,
}

impl StderrBuffer {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes.lock().unwrap()).into_owned()
    }

    /// Appends one chunk from the reader once any hold is released.
    fn append(&self, chunk: &[u8]) {
        let mut hold = self.hold.lock().unwrap();
        while hold.armed {
            hold.holding = true;
            self.hold_changed.notify_all();
            hold = self.hold_changed.wait(hold).unwrap();
        }
        hold.holding = false;
        drop(hold);
        self.bytes.lock().unwrap().extend_from_slice(chunk);
        self.grew.notify_all();
    }

    /// Records that the pipe is closed, so the collected text is complete.
    fn close(&self) {
        let _bytes = self.bytes.lock().unwrap();
        self.closed.store(true, Ordering::SeqCst);
        self.grew.notify_all();
    }

    fn arm_hold(&self) {
        self.hold.lock().unwrap().armed = true;
    }

    fn release_hold(&self) {
        self.hold.lock().unwrap().armed = false;
        self.hold_changed.notify_all();
    }

    /// Waits until the reader holds a chunk, or `deadline` passes.
    fn wait_holding(&self, deadline: Instant) -> bool {
        let mut hold = self.hold.lock().unwrap();
        while !hold.holding {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            hold = self.hold_changed.wait_timeout(hold, left).unwrap().0;
        }
        true
    }
}

/// Joins `reader` if it finishes by `deadline`. A reader still running then
/// is detached: dropping its handle leaves the thread to end with its pipe.
fn join_by(reader: Option<JoinHandle<()>>, deadline: Instant) {
    let Some(reader) = reader else {
        return;
    };
    while !reader.is_finished() {
        if Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(JOIN_STEP);
    }
    let _ = reader.join();
}

/// The process behind a driver.
enum Process {
    /// A child that `std::process` spawns.
    Std(Child),
    /// A child that a pseudoconsole hosts, with an owned process handle.
    #[cfg(windows)]
    Hosted {
        process: std::os::windows::io::OwnedHandle,
        pid: u32,
    },
}

impl Process {
    /// Returns the exit status without waiting, or `None` while the process
    /// runs.
    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        match self {
            Self::Std(child) => child.try_wait(),
            #[cfg(windows)]
            Self::Hosted { process, .. } => pseudo_console::try_wait(process),
        }
    }

    /// Ends the process.
    fn kill(&mut self) -> std::io::Result<()> {
        match self {
            Self::Std(child) => child.kill(),
            #[cfg(windows)]
            Self::Hosted { process, .. } => pseudo_console::kill(process),
        }
    }

    /// Waits for the process to exit and returns its status.
    fn wait(&mut self) -> std::io::Result<ExitStatus> {
        match self {
            Self::Std(child) => child.wait(),
            #[cfg(windows)]
            Self::Hosted { process, .. } => pseudo_console::wait(process),
        }
    }
}

/// Kills and reaps a process on drop, unless [`ProcessGuard::disarm`] takes
/// it first.
struct ProcessGuard(Option<Process>);

impl ProcessGuard {
    /// Takes the process out of the guard.
    fn disarm(mut self) -> Process {
        self.0
            .take()
            .expect("the guard holds its process until disarmed")
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if let Some(mut process) = self.0.take() {
            let _ = process.kill();
            let _ = process.wait();
        }
    }
}

/// Starts a named thread that runs `work` on `resources`.
///
/// The thread exists before it receives `resources`. When it cannot start,
/// the error returns with `resources`, so the caller still owns and drops
/// them.
fn start_worker<T: Send + 'static>(
    name: &str,
    resources: T,
    work: impl FnOnce(T) + Send + 'static,
) -> Result<JoinHandle<()>, (std::io::Error, T)> {
    let (handoff, receiver) = std::sync::mpsc::sync_channel::<T>(1);
    let worker = std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            if let Ok(resources) = receiver.recv() {
                work(resources);
            }
        });
    match worker {
        Ok(worker) => match handoff.send(resources) {
            Ok(()) => Ok(worker),
            Err(std::sync::mpsc::SendError(resources)) => Err((
                std::io::Error::other(format!("the {name} thread ends before its handoff")),
                resources,
            )),
        },
        Err(error) => Err((error, resources)),
    }
}

/// A child process driven over its stdio pipes.
pub struct ChildDriver {
    /// The child, until a reap that outlives the exit deadline hands it to a
    /// detached reaper thread.
    child: Option<Process>,
    pid: u32,
    stdin: Option<std::io::BufWriter<Box<dyn Write + Send>>>,
    stdout: Arc<StdoutQueue>,
    /// Messages read while a wait looked for another id.
    unclaimed: VecDeque<Value>,
    stdout_closed: bool,
    gate: Arc<StdoutGate>,
    stderr: Arc<StderrBuffer>,
    stdout_reader: Option<JoinHandle<()>>,
    stderr_reader: Option<JoinHandle<()>>,
    status: Option<ExitStatus>,
    exit_deadline: Duration,
    /// The time source of every deadline in the response wait.
    clock: Clock,
    next_id: u64,
    #[cfg(target_os = "linux")]
    stdout_fd: std::os::fd::RawFd,
    /// The pseudoconsole that hosts the child, for a hosted child.
    #[cfg(windows)]
    console: Option<pseudo_console::Console>,
}

/// The time source the response wait computes and checks its deadline with.
///
/// The default reads [`Instant::now`]. A test replaces it to decide which
/// check of a wait observes the deadline as passed.
#[derive(Clone)]
pub struct Clock(Arc<dyn Fn() -> Instant + Send + Sync>);

impl Clock {
    /// The system clock.
    pub fn system() -> Self {
        Self(Arc::new(Instant::now))
    }

    /// A clock that returns what `now` returns on each reading.
    pub fn scripted(now: impl Fn() -> Instant + Send + Sync + 'static) -> Self {
        Self(Arc::new(now))
    }

    /// The current instant of this clock.
    pub fn now(&self) -> Instant {
        (self.0)()
    }
}

impl Default for Clock {
    fn default() -> Self {
        Self::system()
    }
}

impl ChildDriver {
    /// Spawns `command` with all three standard streams piped.
    ///
    /// # Panics
    ///
    /// When the child does not spawn.
    pub fn spawn(mut command: Command) -> Self {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the child must spawn");
        let stdin = child.stdin.take().expect("child stdin is piped");
        let stdout_pipe = child.stdout.take().expect("child stdout is piped");
        let stderr_pipe = child.stderr.take().expect("child stderr is piped");
        #[cfg(target_os = "linux")]
        let stdout_fd = std::os::fd::AsRawFd::as_raw_fd(&stdout_pipe);
        let pid = child.id();
        Self::from_parts(
            Process::Std(child),
            pid,
            Box::new(stdin),
            Box::new(stdout_pipe),
            Box::new(stderr_pipe),
            #[cfg(target_os = "linux")]
            stdout_fd,
        )
        .expect("the child's reader threads start")
    }

    /// Spawns `command` in a pseudoconsole of its own, with all three
    /// standard streams piped to this driver.
    ///
    /// The child is a client of the pseudoconsole and leads a new process
    /// group. [`ChildDriver::close_pseudo_console`] closes the pseudoconsole,
    /// which sends `CTRL_CLOSE_EVENT` to the child. The program is a path,
    /// with no search of `PATH`, and the environment honors `env` and
    /// `env_remove`.
    ///
    /// # Errors
    ///
    /// When a pipe, the pseudoconsole, the process, or a reader thread cannot
    /// be created. A failed reader start kills and reaps the child, closes
    /// every stream handle, and closes the pseudoconsole.
    #[cfg(windows)]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "takes the command as `spawn` does"
    )]
    pub fn spawn_in_pseudo_console(command: Command) -> std::io::Result<Self> {
        let pseudo_console::Spawned {
            process,
            pid,
            stdin,
            stdout,
            stderr,
            console,
        } = pseudo_console::spawn(&command)?;
        // On an error return, `from_parts` releases the process and the
        // streams, and the drop of `console` then closes the pseudoconsole.
        let mut driver = Self::from_parts(
            Process::Hosted { process, pid },
            pid,
            Box::new(stdin),
            Box::new(stdout),
            Box::new(stderr),
        )?;
        driver.console = Some(console);
        Ok(driver)
    }

    /// Starts the close of the child's pseudoconsole, once. Returns whether
    /// this call starts it: `false` for a child with no pseudoconsole or one
    /// whose close is underway or complete.
    #[cfg(windows)]
    pub fn close_pseudo_console(&mut self) -> bool {
        self.console
            .as_mut()
            .is_some_and(pseudo_console::Console::close)
    }

    /// Starts the reader threads for the child's streams.
    ///
    /// # Errors
    ///
    /// When a reader thread cannot start. The process guard then kills and
    /// reaps the child, every pipe handle closes, and a running stdout reader
    /// ends at the EOF that follows the kill.
    fn from_parts(
        process: Process,
        pid: u32,
        stdin: Box<dyn Write + Send>,
        stdout_pipe: Box<dyn Read + Send>,
        stderr_pipe: Box<dyn Read + Send>,
        #[cfg(target_os = "linux")] stdout_fd: std::os::fd::RawFd,
    ) -> std::io::Result<Self> {
        let process = ProcessGuard(Some(process));
        let stdin = std::io::BufWriter::new(stdin);
        let gate = Arc::new(StdoutGate::default());
        let stdout = Arc::new(StdoutQueue::default());
        let stdout_reader = {
            let gate = Arc::clone(&gate);
            let stdout = Arc::clone(&stdout);
            start_worker("child-stdout", stdout_pipe, move |stdout_pipe| {
                let mut lines = std::io::BufReader::new(stdout_pipe);
                loop {
                    let mut line = String::new();
                    let event = match lines.read_line(&mut line) {
                        Ok(0) | Err(_) => StdoutEvent::Closed,
                        Ok(_) => match serde_json::from_str::<Value>(line.trim()) {
                            Ok(message) => StdoutEvent::Message(message),
                            Err(_) => StdoutEvent::Unparsed(line),
                        },
                    };
                    let closed = matches!(event, StdoutEvent::Closed);
                    let id = match &event {
                        StdoutEvent::Message(message) => message.get("id").cloned(),
                        _ => None,
                    };
                    stdout.events.lock().unwrap().push_back(event);
                    stdout.arrived.notify_all();
                    if closed {
                        return;
                    }
                    if let Some(id) = id {
                        gate.park_after(&id);
                    }
                }
            })
            .map_err(|(error, _stdout_pipe)| error)?
        };

        let stderr = Arc::new(StderrBuffer::default());
        let stderr_reader = {
            let stderr = Arc::clone(&stderr);
            start_worker("child-stderr", stderr_pipe, move |mut pipe| {
                let mut chunk = [0_u8; 8192];
                loop {
                    match pipe.read(&mut chunk) {
                        Ok(0) | Err(_) => {
                            stderr.close();
                            return;
                        }
                        Ok(read) => stderr.append(&chunk[..read]),
                    }
                }
            })
            .map_err(|(error, _stderr_pipe)| error)?
        };

        Ok(Self {
            pid,
            child: Some(process.disarm()),
            stdin: Some(stdin),
            stdout,
            unclaimed: VecDeque::new(),
            stdout_closed: false,
            gate,
            stderr,
            stdout_reader: Some(stdout_reader),
            stderr_reader: Some(stderr_reader),
            status: None,
            exit_deadline: EXIT_DEADLINE,
            clock: Clock::system(),
            next_id: 1,
            #[cfg(target_os = "linux")]
            stdout_fd,
            #[cfg(windows)]
            console: None,
        })
    }

    /// Replaces [`EXIT_DEADLINE`] for this driver, so a test can observe the
    /// bound on a short scale.
    #[must_use]
    pub fn with_exit_deadline(mut self, deadline: Duration) -> Self {
        self.exit_deadline = deadline;
        self
    }

    /// Replaces the clock of the response wait, so a test can decide which
    /// deadline check observes the deadline as passed.
    #[must_use]
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// Replaces the clock of the response wait between two waits.
    pub fn set_clock(&mut self, clock: Clock) {
        self.clock = clock;
    }

    /// The child's process id.
    pub fn id(&self) -> u32 {
        self.pid
    }

    /// Writes `message` to the child's stdin as one JSON line.
    ///
    /// # Panics
    ///
    /// When stdin is closed or the write fails.
    pub fn send(&mut self, message: &Value) {
        let line = serde_json::to_string(message).unwrap();
        let stdin = self.stdin.as_mut().expect("child stdin is open");
        writeln!(stdin, "{line}").expect("write to child stdin must succeed");
        stdin.flush().expect("flush to child stdin must succeed");
    }

    /// Closes the child's stdin, which ends a stdio session at EOF.
    pub fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// Returns the message whose `id` is `id`, waiting at most `deadline`
    /// from this call. Messages with another id are kept for a later wait.
    /// The deadline starts on entry. Once it passes, the wait returns
    /// [`ResponseError::Deadline`] whatever the kept responses or the queue
    /// hold.
    ///
    /// # Errors
    ///
    /// [`ResponseError`] when the deadline passes, stdout closes, or a line is
    /// not JSON before the response arrives.
    pub fn response_within(
        &mut self,
        id: impl Into<Value>,
        deadline: Duration,
    ) -> Result<Value, ResponseError> {
        let clock = self.clock.clone();
        let deadline = clock.now() + deadline;
        let id = id.into();
        if clock.now() >= deadline {
            return Err(ResponseError::Deadline);
        }
        let found = self
            .unclaimed
            .iter()
            .position(|message| message["id"] == id);
        // The search itself takes time: a deadline that passes during it
        // leaves a found response kept for a later wait.
        if clock.now() >= deadline {
            return Err(ResponseError::Deadline);
        }
        if let Some(index) = found {
            return Ok(self.unclaimed.remove(index).unwrap());
        }
        if self.stdout_closed {
            return Err(ResponseError::Closed);
        }
        let queue = Arc::clone(&self.stdout);
        let mut events = queue.events.lock().unwrap();
        loop {
            let left = deadline.saturating_duration_since(clock.now());
            if left.is_zero() {
                return Err(ResponseError::Deadline);
            }
            match events.pop_front() {
                Some(StdoutEvent::Message(message)) if message["id"] == id => return Ok(message),
                Some(StdoutEvent::Message(message)) => {
                    // A message that carries an id is a response another wait
                    // may claim; a notification is no one's response.
                    if message.get("id").is_some() {
                        self.unclaimed.push_back(message);
                    }
                }
                Some(StdoutEvent::Unparsed(line)) => return Err(ResponseError::Unparsed(line)),
                Some(StdoutEvent::Closed) => {
                    self.stdout_closed = true;
                    return Err(ResponseError::Closed);
                }
                None => events = queue.arrived.wait_timeout(events, left).unwrap().0,
            }
        }
    }

    /// Returns the message whose `id` is `id`, waiting at most
    /// [`RESPONSE_DEADLINE`].
    ///
    /// # Panics
    ///
    /// When the response does not arrive, with the stderr collected so far.
    pub fn response(&mut self, id: impl Into<Value>) -> Value {
        let id = id.into();
        match self.response_within(id.clone(), RESPONSE_DEADLINE) {
            Ok(message) => message,
            Err(error) => panic!(
                "the child gave no response with id {id} within {RESPONSE_DEADLINE:?}: \
                 {error:?}\nstderr: {}",
                self.stderr()
            ),
        }
    }

    /// Sends `message` unchanged and returns the response with its id.
    pub fn exchange(&mut self, message: &Value) -> Value {
        self.send(message);
        self.response(message["id"].clone())
    }

    /// Sends a request with the next id and returns its response.
    pub fn request(&mut self, method: &str, params: &Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.exchange(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }))
    }

    /// Calls `tool` with `arguments` and returns the JSON-RPC response.
    pub fn call(&mut self, tool: &str, arguments: &Value) -> Value {
        self.request(
            "tools/call",
            &json!({ "name": tool, "arguments": arguments }),
        )
    }

    /// Arms the stdout reader to park right after it delivers the response
    /// with `id`. Until [`ChildDriver::resume_stdout`], nothing reads the
    /// child's stdout after that response.
    pub fn pause_after_response(&self, id: impl Into<Value>) {
        self.gate.arm(id.into());
    }

    /// Waits at most `deadline` for the reader to acknowledge its park.
    pub fn wait_until_paused(&self, deadline: Duration) -> bool {
        self.gate.wait_parked(Instant::now() + deadline)
    }

    /// Stops the stdout reader right after it delivers the response to a
    /// `ping`, and returns once the reader acknowledges the stop. Until
    /// [`ChildDriver::resume_stdout`], nothing reads the child's stdout, so
    /// the pipe fills and the child's next large write blocks.
    ///
    /// # Panics
    ///
    /// When the ping fails or the reader does not acknowledge within
    /// [`RESPONSE_DEADLINE`].
    pub fn pause_stdout(&mut self) {
        let id = self.next_id;
        self.pause_after_response(id);
        let ping = self.request("ping", &json!({}));
        assert!(ping.get("result").is_some(), "ping failed: {ping}");
        assert!(
            self.wait_until_paused(RESPONSE_DEADLINE),
            "the stdout reader acknowledges the pause"
        );
    }

    /// Lets the stdout reader read again.
    pub fn resume_stdout(&self) {
        self.gate.release();
    }

    /// Whether the stdout reader is parked by a pause.
    pub fn stdout_is_paused(&self) -> bool {
        self.gate.is_parked()
    }

    /// The number of stdout events the reader delivered that no wait has
    /// taken yet.
    pub fn queued_stdout_events(&self) -> usize {
        self.stdout.events.lock().unwrap().len()
    }

    /// Whether the unread bytes in the stdout pipe fill all but its last
    /// page, so a writer with more to write is blocked.
    ///
    /// # Panics
    ///
    /// When the pipe cannot be queried.
    #[cfg(target_os = "linux")]
    pub fn stdout_pipe_is_full(&self) -> bool {
        let mut unread: libc::c_int = 0;
        // SAFETY: `stdout_fd` is the read end the stdout reader owns, and the
        // reader keeps it open until the child closes stdout. FIONREAD writes
        // one c_int through the valid pointer, and F_GETPIPE_SZ reads nothing.
        #[allow(unsafe_code, reason = "FIONREAD and F_GETPIPE_SZ on a pipe")]
        let (queried, capacity) = unsafe {
            (
                libc::ioctl(self.stdout_fd, libc::FIONREAD, &raw mut unread),
                libc::fcntl(self.stdout_fd, libc::F_GETPIPE_SZ),
            )
        };
        assert!(
            queried == 0 && capacity > 0,
            "the stdout pipe can be queried"
        );
        unread >= capacity - 4096
    }

    /// The stderr text collected so far.
    pub fn stderr(&self) -> String {
        self.stderr.text()
    }

    /// Waits until the collected stderr contains `needle`, at most `deadline`,
    /// and returns the text.
    ///
    /// # Panics
    ///
    /// When the child exits and its complete stderr lacks `needle`, with the
    /// exit status and the stderr. When the deadline passes first, with the
    /// child's state and the stderr collected so far.
    pub fn wait_for_stderr(&mut self, needle: &str, deadline: Duration) -> String {
        match self.await_stderr(needle, deadline) {
            StderrWait::Shown(text) => text,
            StderrWait::Exited { status, stderr } => panic!(
                "child exits before its stderr shows {needle:?}: {status}; its stderr pipe \
                 is closed.\nstderr: {stderr}"
            ),
            StderrWait::ExitedWithOpenStderr { status, stderr } => panic!(
                "child exits before its stderr shows {needle:?}: {status}; its stderr pipe \
                 is open after {deadline:?}, so the capture is incomplete.\n\
                 stderr so far: {stderr}"
            ),
            StderrWait::Running(text) => panic!(
                "the child's stderr does not show {needle:?} within {deadline:?}; the child \
                 still runs.\nstderr: {text}"
            ),
        }
    }

    /// Waits until the collected stderr contains `needle`, the child exits
    /// and its stderr pipe closes, or `deadline` passes, and reports which
    /// comes first.
    ///
    /// The wait checks the child's exit at least every [`EXIT_POLL`]. After an
    /// exit, it goes on until the stderr reader sees the pipe close, so every
    /// line the child writes counts. A pipe still open at the deadline gives
    /// [`StderrWait::ExitedWithOpenStderr`].
    ///
    /// # Panics
    ///
    /// When the child's state cannot be read.
    pub fn await_stderr(&mut self, needle: &str, deadline: Duration) -> StderrWait {
        let deadline = Instant::now() + deadline;
        loop {
            let exited = self.poll_exit();
            let bytes = self.stderr.bytes.lock().unwrap();
            let text = String::from_utf8_lossy(&bytes).into_owned();
            if text.contains(needle) {
                return StderrWait::Shown(text);
            }
            let closed = self.stderr.closed.load(Ordering::SeqCst);
            if let Some(status) = exited
                && closed
            {
                return StderrWait::Exited {
                    status,
                    stderr: text,
                };
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return match exited {
                    Some(status) => StderrWait::ExitedWithOpenStderr {
                        status,
                        stderr: text,
                    },
                    None => StderrWait::Running(text),
                };
            }
            let wait = left.min(EXIT_POLL);
            drop(self.stderr.grew.wait_timeout(bytes, wait).unwrap());
        }
    }

    /// Holds the stderr reader back: each chunk it reads waits, unappended,
    /// until [`ChildDriver::release_stderr`].
    pub fn hold_stderr(&self) {
        self.stderr.arm_hold();
    }

    /// Lets a held stderr reader append its chunks again.
    pub fn release_stderr(&self) {
        self.stderr.release_hold();
    }

    /// Waits at most `deadline` for the held reader to hold a chunk.
    pub fn wait_until_stderr_held(&self, deadline: Duration) -> bool {
        self.stderr.wait_holding(Instant::now() + deadline)
    }

    /// Records and returns the child's exit status, or `None` while it runs.
    fn poll_exit(&mut self) -> Option<ExitStatus> {
        if self.status.is_none() {
            self.status = self.child.as_mut()?.try_wait().unwrap();
        }
        self.status
    }

    /// Waits at most `deadline` for the child to exit and returns its status,
    /// or `None` when it is still running. After the exit, the stderr reader
    /// is joined within what remains of `deadline`, so [`ChildDriver::stderr`]
    /// holds what the child wrote. The stdout reader is left as it is, so a
    /// paused reader stays paused.
    ///
    /// # Panics
    ///
    /// When the child's state cannot be read.
    pub fn wait_for_exit(&mut self, deadline: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + deadline;
        let status = self.exit_by(deadline)?;
        join_by(self.stderr_reader.take(), deadline);
        Some(status)
    }

    /// Waits for the child to exit and for both readers to finish, and
    /// returns the status and the stderr text. One exit deadline covers the
    /// exit, the kill and reap of a child that outlives it, and both reader
    /// joins.
    ///
    /// # Panics
    ///
    /// When the child does not exit in time; the child is killed first.
    pub fn wait(mut self) -> (ExitStatus, String) {
        let deadline = Instant::now() + self.exit_deadline;
        // A held reader stops draining stderr, and a child that fills the
        // pipe cannot exit, so the hold ends before the exit wait starts.
        self.release_stderr();
        let exited = self.exit_by(deadline);
        if exited.is_none() {
            self.reap_by(deadline);
        }
        self.resume_stdout();
        join_by(self.stderr_reader.take(), deadline);
        join_by(self.stdout_reader.take(), deadline);
        let stderr = self.stderr();
        match exited {
            Some(status) => (status, stderr),
            None => panic!(
                "the child did not exit within {:?}.\nstderr: {stderr}",
                self.exit_deadline
            ),
        }
    }

    /// Waits until `deadline` for the child to exit and records its status.
    fn exit_by(&mut self, deadline: Instant) -> Option<ExitStatus> {
        loop {
            if self.status.is_some() {
                return self.status;
            }
            let child = self.child.as_mut()?;
            if let Some(status) = child.try_wait().unwrap() {
                self.status = Some(status);
                return self.status;
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Kills the child unless it has exited, and reaps it by `deadline`. A
    /// child still unreaped then goes to a detached reaper thread, which
    /// reaps it whenever it ends.
    fn reap_by(&mut self, deadline: Instant) {
        if self.status.is_some() {
            return;
        }
        let Some(child) = self.child.as_mut() else {
            return;
        };
        let _ = child.kill();
        loop {
            if let Ok(Some(status)) = child.try_wait() {
                self.status = Some(status);
                return;
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        if let Some(mut child) = self.child.take() {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
    }
}

impl Drop for ChildDriver {
    /// One exit deadline covers the kill, the reap, and both reader joins.
    /// For a hosted child it also covers the pseudoconsole close and the join
    /// of the thread that drains the pseudoconsole output.
    fn drop(&mut self) {
        let deadline = Instant::now() + self.exit_deadline;
        self.reap_by(deadline);
        self.stdin = None;
        self.resume_stdout();
        self.release_stderr();
        #[cfg(windows)]
        self.close_pseudo_console();
        join_by(self.stderr_reader.take(), deadline);
        join_by(self.stdout_reader.take(), deadline);
        #[cfg(windows)]
        if let Some(console) = self.console.as_mut() {
            let (closer, drain) = console.threads();
            join_by(closer, deadline);
            join_by(drain, deadline);
        }
    }
}

/// The pseudoconsole host for a Windows child.
///
/// The host creates two pty pipes and a pseudoconsole, then starts the child
/// as a client of that pseudoconsole with three piped standard streams. A
/// thread drains the pseudoconsole output for the child's life. The pty input
/// writer stays open until `ClosePseudoConsole` returns, because a closed
/// input pipe also ends the session. `ClosePseudoConsole` sends
/// `CTRL_CLOSE_EVENT` to every connected client. It runs once, on a thread
/// of its own, because it waits for the clients on builds before 26100. The
/// close stimulus never attaches the test process to the pseudoconsole. The
/// Ctrl-Break test and the cleanup after a failed close wait do attach, through
/// `AttachConsole`, and detach again before they return.
#[cfg(windows)]
mod pseudo_console {
    #![allow(
        unsafe_code,
        reason = "pseudoconsole and process creation through the Win32 API"
    )]

    use std::ffi::{OsStr, c_void};
    use std::fs::File;
    use std::io;
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use std::os::windows::process::ExitStatusExt as _;
    use std::process::{Command, ExitStatus};
    use std::thread::JoinHandle;

    use super::start_worker;

    use windows_sys::Win32::Foundation::{
        HANDLE, HANDLE_FLAG_INHERIT, S_OK, SetHandleInformation, TRUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Globalization::{
        CSTR_EQUAL, CSTR_GREATER_THAN, CSTR_LESS_THAN, CompareStringOrdinal,
    };
    use windows_sys::Win32::System::Console::{
        COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON,
    };
    use windows_sys::Win32::System::Environment::{
        FreeEnvironmentStringsW, GetEnvironmentStringsW,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CREATE_NEW_PROCESS_GROUP, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
        DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
        PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW, TerminateProcess,
        UpdateProcThreadAttribute, WaitForSingleObject,
    };

    /// The pseudoconsole size in character cells.
    const SIZE: COORD = COORD { X: 80, Y: 25 };

    /// A pseudoconsole, its pty input writer, and the threads that serve it.
    ///
    /// The console owns the `HPCON`. Exactly one `ClosePseudoConsole` runs:
    /// the explicit close or, without one, the drop. The input writer stays
    /// open until that call returns.
    pub(super) struct Console {
        hpc: HPCON,
        /// Set once a close owns the `ClosePseudoConsole` call.
        closed: bool,
        /// The pty input writer, until a close takes it.
        input: Option<OwnedHandle>,
        closer: Option<JoinHandle<()>>,
        drain: Option<JoinHandle<()>>,
    }

    impl Console {
        /// Starts `ClosePseudoConsole` on a thread of its own, which drops the
        /// pty input writer once the call returns. When the thread cannot
        /// start, the close runs on this thread. Returns `false` when the
        /// close is underway or complete.
        pub(super) fn close(&mut self) -> bool {
            if self.closed {
                return false;
            }
            self.closed = true;
            let hpc = self.hpc;
            let input = self.input.take();
            match start_worker("pseudoconsole-close", input, move |input| {
                close_pseudo_console(hpc, input);
            }) {
                Ok(closer) => self.closer = Some(closer),
                Err((_, input)) => close_pseudo_console(hpc, input),
            }
            true
        }

        /// The close thread and the drain thread, for a bounded join.
        pub(super) fn threads(&mut self) -> (Option<JoinHandle<()>>, Option<JoinHandle<()>>) {
            (self.closer.take(), self.drain.take())
        }
    }

    impl Drop for Console {
        /// Closes the pseudoconsole when no explicit close owns the call.
        fn drop(&mut self) {
            if !self.closed {
                self.closed = true;
                close_pseudo_console(self.hpc, self.input.take());
            }
        }
    }

    /// Calls `ClosePseudoConsole` and then drops the pty input writer.
    fn close_pseudo_console(hpc: HPCON, input: Option<OwnedHandle>) {
        // SAFETY: `hpc` is the pseudoconsole `spawn` creates, and the
        // `closed` flag of its console makes this call its only close.
        unsafe { ClosePseudoConsole(hpc) };
        drop(input);
    }

    /// A child the host starts, with the parent ends of its streams.
    pub(super) struct Spawned {
        pub process: OwnedHandle,
        pub pid: u32,
        pub stdin: File,
        pub stdout: File,
        pub stderr: File,
        pub console: Console,
    }

    /// Creates the pseudoconsole and starts `command` as its client.
    pub(super) fn spawn(command: &Command) -> io::Result<Spawned> {
        let (pty_in_read, pty_in_write) = pipe()?;
        let (pty_out_read, pty_out_write) = pipe()?;
        let mut hpc: HPCON = 0;
        // SAFETY: both handles are open pipe ends, and `hpc` is a valid out
        // pointer for the call.
        let created = unsafe {
            CreatePseudoConsole(
                SIZE,
                pty_in_read.as_raw_handle(),
                pty_out_write.as_raw_handle(),
                0,
                &raw mut hpc,
            )
        };
        if created != S_OK {
            return Err(io::Error::other(format!(
                "CreatePseudoConsole returns HRESULT {created:#010x}"
            )));
        }
        // From here on the console owns the pseudoconsole, and an error
        // return drops it, which closes the pseudoconsole.
        let mut console = Console {
            hpc,
            closed: false,
            input: Some(pty_in_write),
            closer: None,
            drain: None,
        };
        let drain = start_worker(
            "pseudoconsole-drain",
            File::from(pty_out_read),
            |mut output| {
                let _ = io::copy(&mut output, &mut io::sink());
            },
        )
        .map_err(|(error, _output)| error)?;
        console.drain = Some(drain);
        let (process, pid, stdin, stdout, stderr) = start(command, hpc)?;
        // The pseudoconsole holds its own duplicates of these pipe ends.
        drop(pty_in_read);
        drop(pty_out_write);
        Ok(Spawned {
            process,
            pid,
            stdin,
            stdout,
            stderr,
            console,
        })
    }

    /// The process handle, the process id, and the parent ends of stdin,
    /// stdout, and stderr.
    type Started = (OwnedHandle, u32, File, File, File);

    /// Starts `command` as a client of `hpc` with three piped streams.
    fn start(command: &Command, hpc: HPCON) -> io::Result<Started> {
        let (stdin_read, stdin_write) = pipe()?;
        let (stdout_read, stdout_write) = pipe()?;
        let (stderr_read, stderr_write) = pipe()?;
        // Only the child ends become inheritable, and the handle list below
        // passes exactly these three to the child.
        for child_end in [&stdin_read, &stdout_write, &stderr_write] {
            inheritable(child_end)?;
        }
        let child_ends: [HANDLE; 3] = [
            stdin_read.as_raw_handle(),
            stdout_write.as_raw_handle(),
            stderr_write.as_raw_handle(),
        ];
        let mut attributes = AttributeList::new(2)?;
        // The pseudoconsole attribute takes the `HPCON` value itself.
        attributes.update(
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
            hpc as *const c_void,
            size_of::<HPCON>(),
        )?;
        attributes.update(
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            child_ends.as_ptr().cast(),
            size_of_val(&child_ends),
        )?;

        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>()).unwrap();
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = child_ends[0];
        startup.StartupInfo.hStdOutput = child_ends[1];
        startup.StartupInfo.hStdError = child_ends[2];
        startup.lpAttributeList = attributes.as_mut_ptr();

        let application = nul_terminated(command.get_program());
        let mut command_line = command_line(command);
        let environment = environment_block(command)?;
        let directory = command
            .get_current_dir()
            .map(|directory| nul_terminated(directory.as_os_str()));
        let mut info = PROCESS_INFORMATION::default();
        // SAFETY: every string is NUL-terminated UTF-16 that outlives the
        // call, and the command line is writable. The environment block ends
        // in two NULs, and the startup data and its attribute list stay valid.
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                TRUE,
                EXTENDED_STARTUPINFO_PRESENT
                    | CREATE_UNICODE_ENVIRONMENT
                    | CREATE_NEW_PROCESS_GROUP,
                environment.as_ptr().cast(),
                directory
                    .as_ref()
                    .map_or(std::ptr::null(), |directory| directory.as_ptr()),
                (&raw const startup).cast::<STARTUPINFOW>(),
                &raw mut info,
            )
        };
        if created == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateProcessW returns two open handles the caller owns.
        let (process, thread) = unsafe {
            (
                OwnedHandle::from_raw_handle(info.hProcess),
                OwnedHandle::from_raw_handle(info.hThread),
            )
        };
        drop(thread);
        // The attribute list refers to `child_ends`, so it goes first.
        drop(attributes);
        drop((stdin_read, stdout_write, stderr_write));
        Ok((
            process,
            info.dwProcessId,
            File::from(stdin_write),
            File::from(stdout_read),
            File::from(stderr_read),
        ))
    }

    /// A process thread attribute list with room for a fixed count.
    struct AttributeList {
        /// Pointer-aligned storage for the opaque list.
        storage: Vec<usize>,
    }

    impl AttributeList {
        fn new(count: u32) -> io::Result<Self> {
            let mut size = 0_usize;
            // SAFETY: a null list asks for the size only; the call reports
            // `ERROR_INSUFFICIENT_BUFFER` and writes the size.
            unsafe {
                InitializeProcThreadAttributeList(std::ptr::null_mut(), count, 0, &raw mut size)
            };
            let mut storage = vec![0_usize; size.div_ceil(size_of::<usize>())];
            // SAFETY: the storage holds at least `size` bytes.
            let initialized = unsafe {
                InitializeProcThreadAttributeList(
                    storage.as_mut_ptr().cast(),
                    count,
                    0,
                    &raw mut size,
                )
            };
            // Only an initialized list becomes `Self`, whose drop deletes it.
            if initialized == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { storage })
        }

        fn as_mut_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
            self.storage.as_mut_ptr().cast()
        }

        /// Sets `attribute` to the `size` bytes at `value`, which must stay
        /// valid until the list is dropped.
        fn update(&mut self, attribute: u32, value: *const c_void, size: usize) -> io::Result<()> {
            // SAFETY: the list is initialized, and the caller keeps `value`
            // valid for the life of the list.
            let updated = unsafe {
                UpdateProcThreadAttribute(
                    self.as_mut_ptr(),
                    0,
                    usize::try_from(attribute).unwrap(),
                    value,
                    size,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                )
            };
            if updated == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    impl Drop for AttributeList {
        fn drop(&mut self) {
            // SAFETY: `new` returns only initialized lists.
            unsafe { DeleteProcThreadAttributeList(self.as_mut_ptr()) };
        }
    }

    /// Creates an anonymous pipe whose ends are not inheritable.
    fn pipe() -> io::Result<(OwnedHandle, OwnedHandle)> {
        let mut read: HANDLE = std::ptr::null_mut();
        let mut write: HANDLE = std::ptr::null_mut();
        // SAFETY: both out pointers are valid; null security attributes make
        // the ends non-inheritable.
        let created = unsafe { CreatePipe(&raw mut read, &raw mut write, std::ptr::null(), 0) };
        if created == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreatePipe returns two open handles the caller owns.
        Ok(unsafe {
            (
                OwnedHandle::from_raw_handle(read),
                OwnedHandle::from_raw_handle(write),
            )
        })
    }

    /// Makes `handle` inheritable.
    fn inheritable(handle: &OwnedHandle) -> io::Result<()> {
        // SAFETY: the handle is open for the duration of the call.
        let set = unsafe {
            SetHandleInformation(
                handle.as_raw_handle(),
                HANDLE_FLAG_INHERIT,
                HANDLE_FLAG_INHERIT,
            )
        };
        if set == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Returns the exit status without waiting, or `None` while the process
    /// runs.
    pub(super) fn try_wait(process: &OwnedHandle) -> io::Result<Option<ExitStatus>> {
        // SAFETY: the handle is an open process handle.
        match unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } {
            WAIT_OBJECT_0 => exit_status(process).map(Some),
            WAIT_TIMEOUT => Ok(None),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Waits for the process to exit and returns its status.
    pub(super) fn wait(process: &OwnedHandle) -> io::Result<ExitStatus> {
        // SAFETY: the handle is an open process handle.
        match unsafe { WaitForSingleObject(process.as_raw_handle(), INFINITE) } {
            WAIT_OBJECT_0 => exit_status(process),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Terminates the process with exit code 1. A process that is already
    /// at its end gives `Ok(())`, as `std::process::Child::kill` does.
    pub(super) fn kill(process: &OwnedHandle) -> io::Result<()> {
        if try_wait(process)?.is_some() {
            return Ok(());
        }
        // SAFETY: the handle is an open process handle.
        if unsafe { TerminateProcess(process.as_raw_handle(), 1) } != 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        // The process can reach its end between the check and the call.
        if try_wait(process).is_ok_and(|status| status.is_some()) {
            return Ok(());
        }
        Err(error)
    }

    fn exit_status(process: &OwnedHandle) -> io::Result<ExitStatus> {
        let mut code = 0_u32;
        // SAFETY: the handle is an open process handle and `code` is a valid
        // out pointer.
        if unsafe { GetExitCodeProcess(process.as_raw_handle(), &raw mut code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ExitStatus::from_raw(code))
    }

    /// `value` as NUL-terminated UTF-16.
    fn nul_terminated(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain([0]).collect()
    }

    /// The quoted program and arguments as a writable, NUL-terminated
    /// command line.
    fn command_line(command: &Command) -> Vec<u16> {
        let mut line = Vec::new();
        append_quoted(&mut line, command.get_program(), true);
        for argument in command.get_args() {
            line.push(u16::from(b' '));
            append_quoted(&mut line, argument, false);
        }
        line.push(0);
        line
    }

    /// Appends `argument` quoted by the MSVC rules: inside quotes, the
    /// backslashes before a quote and before the closing quote double, and a
    /// quote gets one more backslash.
    fn append_quoted(line: &mut Vec<u16>, argument: &OsStr, always: bool) {
        let units: Vec<u16> = argument.encode_wide().collect();
        let needs_quotes = always
            || units.is_empty()
            || units.iter().any(|&unit| {
                [b' ', b'\t', b'\n', 0x0b, b'"']
                    .map(u16::from)
                    .contains(&unit)
            });
        if !needs_quotes {
            line.extend(units);
            return;
        }
        let backslash = u16::from(b'\\');
        let quote = u16::from(b'"');
        line.push(quote);
        let mut backslashes = 0_usize;
        for unit in units {
            if unit == backslash {
                backslashes += 1;
            } else {
                if unit == quote {
                    line.extend(std::iter::repeat_n(backslash, backslashes + 1));
                }
                backslashes = 0;
            }
            line.push(unit);
        }
        line.extend(std::iter::repeat_n(backslash, backslashes));
        line.push(quote);
    }

    /// A variable as UTF-16 units: the name and the value.
    type Variable = (Vec<u16>, Vec<u16>);

    /// Orders two variable names as Windows compares them: ordinal UTF-16,
    /// ignoring case through `CompareStringOrdinal`.
    fn compare_names(left: &[u16], right: &[u16]) -> std::cmp::Ordering {
        // SAFETY: both pointers address the given number of UTF-16 units.
        let result = unsafe {
            CompareStringOrdinal(
                left.as_ptr(),
                i32::try_from(left.len()).unwrap(),
                right.as_ptr(),
                i32::try_from(right.len()).unwrap(),
                TRUE,
            )
        };
        match result {
            CSTR_LESS_THAN => std::cmp::Ordering::Less,
            CSTR_EQUAL => std::cmp::Ordering::Equal,
            CSTR_GREATER_THAN => std::cmp::Ordering::Greater,
            _ => panic!("CompareStringOrdinal fails: {}", io::Error::last_os_error()),
        }
    }

    /// The environment of this process with the `env` and `env_remove` of
    /// `command` applied, as [`build_environment_block`] builds it.
    fn environment_block(command: &Command) -> io::Result<Vec<u16>> {
        let overrides = command.get_envs().map(|(name, value)| {
            (
                name.encode_wide().collect(),
                value.map(|value| value.encode_wide().collect()),
            )
        });
        Ok(build_environment_block(inherited_environment()?, overrides))
    }

    /// Applies `overrides` to `variables` by case-insensitive name, sorts by
    /// name, and returns a block of `NAME=VALUE` strings that ends in two
    /// NULs. A `None` value removes the variable. Names stay UTF-16 units.
    fn build_environment_block(
        mut variables: Vec<Variable>,
        overrides: impl IntoIterator<Item = (Vec<u16>, Option<Vec<u16>>)>,
    ) -> Vec<u16> {
        for (name, value) in overrides {
            variables.retain(|(existing, _)| {
                compare_names(existing, &name) != std::cmp::Ordering::Equal
            });
            if let Some(value) = value {
                variables.push((name, value));
            }
        }
        variables.sort_by(|(left, _), (right, _)| compare_names(left, right));
        let mut block = Vec::new();
        for (name, value) in variables {
            block.extend(name);
            block.push(u16::from(b'='));
            block.extend(value);
            block.push(0);
        }
        if block.is_empty() {
            block.push(0);
        }
        block.push(0);
        block
    }

    /// The variables of this process, from `GetEnvironmentStringsW`.
    fn inherited_environment() -> io::Result<Vec<Variable>> {
        // SAFETY: the call takes no arguments and returns a block or null.
        let block = unsafe { GetEnvironmentStringsW() };
        if block.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut variables = Vec::new();
        let mut entry_start = block.cast_const();
        loop {
            let mut length = 0_usize;
            // SAFETY: the block is a sequence of NUL-terminated strings that
            // ends in an empty string, so every read stays inside it.
            while unsafe { *entry_start.add(length) } != 0 {
                length += 1;
            }
            if length == 0 {
                break;
            }
            // SAFETY: the `length` units before the NUL belong to the block.
            let entry = unsafe { std::slice::from_raw_parts(entry_start, length) };
            // The separator search starts at 1: names such as `=C:` start
            // with `=`.
            let separator = entry
                .iter()
                .skip(1)
                .position(|&unit| unit == u16::from(b'='))
                .map(|position| position + 1);
            if let Some(separator) = separator {
                variables.push((entry[..separator].to_vec(), entry[separator + 1..].to_vec()));
            }
            // SAFETY: the next entry starts after this entry's NUL.
            entry_start = unsafe { entry_start.add(length + 1) };
        }
        // SAFETY: `block` comes from GetEnvironmentStringsW and is freed once.
        unsafe { FreeEnvironmentStringsW(block) };
        Ok(variables)
    }

    #[cfg(test)]
    mod tests {
        use super::{Variable, build_environment_block};

        /// `text` as UTF-16 units.
        fn units(text: &str) -> Vec<u16> {
            text.encode_utf16().collect()
        }

        /// The `NAME=VALUE` entries of an environment block.
        fn entries(block: &[u16]) -> Vec<Vec<u16>> {
            assert_eq!(
                &block[block.len() - 2..],
                &[0, 0],
                "the block ends in two NULs"
            );
            block
                .split(|&unit| unit == 0)
                .filter(|entry| !entry.is_empty())
                .map(<[u16]>::to_vec)
                .collect()
        }

        /// An override whose ASCII name differs only in case replaces exactly
        /// that one variable.
        #[test]
        fn an_override_with_another_case_replaces_one_variable() {
            let base: Vec<Variable> = vec![
                (units("Path"), units("old")),
                (units("Other"), units("kept")),
            ];
            let block = build_environment_block(base, [(units("PATH"), Some(units("new")))]);
            assert_eq!(
                entries(&block),
                vec![units("Other=kept"), units("PATH=new")]
            );
        }

        /// `Straße` and `STRASSE` are two names: an override of one leaves
        /// the other.
        #[test]
        fn names_that_differ_beyond_simple_case_stay_two_variables() {
            let base: Vec<Variable> = vec![(units("Straße"), units("1"))];
            let block = build_environment_block(base, [(units("STRASSE"), Some(units("2")))]);
            let mut found = entries(&block);
            found.sort();
            let mut expected = vec![units("STRASSE=2"), units("Straße=1")];
            expected.sort();
            assert_eq!(found, expected);
        }

        /// A name with an unpaired surrogate keeps its exact units.
        #[test]
        fn a_name_with_an_unpaired_surrogate_survives_unchanged() {
            let name = vec![u16::from(b'A'), 0xD800, u16::from(b'B')];
            let base: Vec<Variable> = vec![(name.clone(), units("v"))];
            let block = build_environment_block(base, [(units("OTHER"), Some(units("w")))]);
            let mut expected_entry = name;
            expected_entry.extend(units("=v"));
            assert!(
                entries(&block).contains(&expected_entry),
                "the block keeps the name's units: {block:?}"
            );
            assert_eq!(entries(&block).len(), 2);
        }
    }
}

/// Tests of the Windows pseudoconsole host that start a process.
#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    /// A kill after the reaped exit of a hosted child returns `Ok`, and a
    /// second kill returns `Ok` too.
    #[test]
    fn a_hosted_kill_after_the_exit_is_ok() {
        let mut command = crate::common::server_binary::server_command();
        command.arg("--no-such-flag");
        let mut driver = ChildDriver::spawn_in_pseudo_console(command).unwrap();
        let status = driver.wait_for_exit(EXIT_DEADLINE);
        assert!(
            status.is_some_and(|status| status.code() == Some(2)),
            "the hosted child exits with the usage code: {status:?}"
        );
        let process = driver.child.as_mut().unwrap();
        assert!(process.kill().is_ok(), "a kill after the exit is Ok");
        assert!(process.kill().is_ok(), "a second kill is Ok");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::sync::mpsc::channel;

    use super::*;

    /// A shell child running `script`.
    fn sh(script: &str) -> Command {
        let mut command = Command::new("sh");
        command.arg("-c").arg(script);
        command
    }

    /// A response line the shell child prints for `id`.
    fn response_line(id: u64) -> String {
        format!(r#"printf '%s\n' '{{"jsonrpc":"2.0","id":{id},"result":{{"id":{id}}}}}'"#)
    }

    /// The notification line the shell children print.
    const NOTIFICATION: &str = r#"{"jsonrpc":"2.0","method":"notifications/message"}"#;

    /// Requests are matched by id: an earlier response with another id and a
    /// notification do not answer the request, and a later wait claims the
    /// response kept for it. A child that writes only notifications fails the
    /// wait within one deadline, however often it writes.
    #[test]
    fn driver_matches_request_ids_with_one_response_deadline() {
        let notification = format!("printf '%s\\n' '{NOTIFICATION}'");
        let mut driver = ChildDriver::spawn(sh(&format!(
            "read line; {notification}; {}; {}; read line",
            response_line(2),
            response_line(1)
        )));
        driver.send(&json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }));
        let first = driver.response(1);
        assert_eq!(first["result"]["id"], 1, "{first}");
        let second = driver
            .response_within(2, Duration::from_millis(1))
            .expect("the response read while waiting for id 1 is kept");
        assert_eq!(second["result"]["id"], 2, "{second}");
        drop(driver);

        let mut chatty =
            ChildDriver::spawn(sh(&format!("while :; do {notification}; sleep 0.05; done")));
        let deadline = Duration::from_millis(500);
        let (done_tx, done_rx) = channel();
        let waiter = std::thread::spawn(move || {
            let started = Instant::now();
            let result = chatty.response_within(1, deadline);
            done_tx.send((result, started.elapsed())).unwrap();
            drop(chatty);
        });
        let (result, elapsed) = done_rx
            .recv_timeout(deadline * 10)
            .expect("notifications do not restart the response deadline");
        waiter.join().unwrap();
        assert_eq!(result, Err(ResponseError::Deadline));
        assert!(
            elapsed >= deadline && elapsed < deadline * 4,
            "the wait ends after one deadline: {elapsed:?}"
        );
    }

    /// The number of unrelated responses queued before the wait in
    /// `driver_takes_no_queued_message_after_the_deadline`.
    const BACKLOG: usize = 10_000;

    /// The number of queue checks that still see time left in that wait.
    const CHECKS_IN_TIME: usize = 1_000;

    /// The id of the first unrelated response of the backlog.
    const FIRST_BACKLOG_ID: usize = 100;

    /// The clock readings a response wait takes before its first queue check:
    /// the deadline computation, the entry check, and the check after the
    /// search of the kept responses.
    const READINGS_BEFORE_THE_QUEUE: usize = 3;

    /// A clock that reads `start` for its first `in_time` readings, except the
    /// readings `expired` names, and a later instant past any test deadline
    /// for those and every reading after.
    fn scripted_clock(start: Instant, in_time: usize, expired: &'static [usize]) -> Clock {
        let readings = std::sync::atomic::AtomicUsize::new(0);
        Clock::scripted(move || {
            let reading = readings.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if reading < in_time && !expired.contains(&reading) {
                start
            } else {
                start + Duration::from_secs(3_600)
            }
        })
    }

    /// The child writes a backlog of responses with other ids and never the
    /// requested one. A scripted clock lets the first queue checks of the wait
    /// see time left and every later check see the deadline as passed. The
    /// wait takes exactly those first responses, in order, returns the
    /// deadline error, and leaves the rest of the backlog queued.
    ///
    /// The child starts writing only after a go line, so the pause is armed
    /// first. The child writes response 7 after the backlog. The reader parks
    /// after delivering it. The child then continues writing notifications.
    #[test]
    fn driver_takes_no_queued_message_after_the_deadline() {
        let last = FIRST_BACKLOG_ID + BACKLOG - 1;
        let mut driver = ChildDriver::spawn(sh(&format!(
            "read go; i={FIRST_BACKLOG_ID}; while [ $i -le {last} ]; do \
             printf '{{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{{}}}}\\n' $i; i=$((i+1)); \
             done; {}; exec yes '{NOTIFICATION}'",
            response_line(7)
        )));
        driver.pause_after_response(7);
        driver.send(&json!({ "jsonrpc": "2.0", "method": "notifications/go" }));
        assert!(
            driver.wait_until_paused(RESPONSE_DEADLINE),
            "the reader queues the backlog and parks after it"
        );
        assert_eq!(
            driver.queued_stdout_events(),
            BACKLOG + 1,
            "the backlog and response 7"
        );

        driver.set_clock(scripted_clock(
            Instant::now(),
            READINGS_BEFORE_THE_QUEUE + CHECKS_IN_TIME,
            &[],
        ));
        let result = driver.response_within(1, Duration::from_secs(1));
        assert_eq!(result, Err(ResponseError::Deadline));
        assert_eq!(
            driver.queued_stdout_events(),
            BACKLOG + 1 - CHECKS_IN_TIME,
            "the expired wait leaves the rest of the backlog queued"
        );
        let taken: Vec<Value> = driver
            .unclaimed
            .iter()
            .map(|message| message["id"].clone())
            .collect();
        let expected: Vec<Value> = (FIRST_BACKLOG_ID..FIRST_BACKLOG_ID + CHECKS_IN_TIME)
            .map(|id| json!(id))
            .collect();
        assert_eq!(
            taken, expected,
            "the wait takes exactly the responses its in-time checks reach, in order"
        );
    }

    /// A deadline that passes during the search of the kept responses ends
    /// the wait with the deadline error and leaves the found response kept.
    /// A later wait with time left takes it.
    #[test]
    fn driver_keeps_a_found_response_when_the_deadline_passes_during_the_search() {
        let mut driver = ChildDriver::spawn(sh(&format!(
            "read line; {}; {}; read line",
            response_line(2),
            response_line(1)
        )));
        driver.send(&json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }));
        let first = driver.response(1);
        assert_eq!(first["result"]["id"], 1, "{first}");

        // Reading 2 is the check after the search of the first wait below.
        driver.set_clock(scripted_clock(Instant::now(), usize::MAX, &[2]));
        assert_eq!(
            driver.response_within(2, Duration::from_secs(1)),
            Err(ResponseError::Deadline),
            "a deadline that passes during the search ends the wait"
        );
        assert_eq!(driver.unclaimed.len(), 1, "the found response stays kept");
        let kept = driver
            .response_within(2, Duration::from_secs(1))
            .expect("a later wait with time left takes the kept response");
        assert_eq!(kept["result"]["id"], 2, "{kept}");
    }

    /// A kept response answers a wait with time left, and a wait whose
    /// deadline has already passed returns the deadline error even though
    /// the response is kept.
    #[test]
    fn driver_applies_the_deadline_to_kept_responses() {
        let mut driver = ChildDriver::spawn(sh(&format!(
            "read line; {}; {}; read line",
            response_line(2),
            response_line(1)
        )));
        driver.send(&json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }));
        let first = driver.response(1);
        assert_eq!(first["result"]["id"], 1, "{first}");

        assert_eq!(
            driver.response_within(2, Duration::ZERO),
            Err(ResponseError::Deadline),
            "an expired wait does not take the kept response"
        );
        let kept = driver
            .response_within(2, Duration::from_secs(1))
            .expect("a wait with time left takes the kept response");
        assert_eq!(kept["result"]["id"], 2, "{kept}");
    }

    /// A wait for an id no kept response carries, after stdout has closed,
    /// returns the deadline error when the deadline passes during the search.
    /// The check after the search precedes the closed check.
    #[test]
    fn driver_reports_the_deadline_before_a_closed_stdout_on_a_cache_miss() {
        let mut driver = ChildDriver::spawn(sh(&format!(
            "read line; {}; {}; read line",
            response_line(2),
            response_line(1)
        )));
        driver.send(&json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }));
        let first = driver.response(1);
        assert_eq!(first["result"]["id"], 1, "{first}");
        assert_eq!(driver.unclaimed.len(), 1, "only response 2 is kept");

        driver.stdout_closed = true;
        // Reading 2 is the check after the search of the kept responses.
        driver.set_clock(scripted_clock(Instant::now(), usize::MAX, &[2]));
        assert_eq!(
            driver.response_within(3, Duration::from_secs(1)),
            Err(ResponseError::Deadline),
            "a deadline that passes during the search wins over the closed stdout"
        );
    }

    /// The pause is keyed to its response: the reader delivers the response
    /// before the designated one, then the designated one, and only then
    /// parks.
    #[test]
    fn driver_pauses_after_the_designated_response() {
        let mut driver = ChildDriver::spawn(sh(&format!(
            "read a; read b; read c; {}; {}; read d",
            response_line(1),
            response_line(2)
        )));
        driver.send(&json!({ "jsonrpc": "2.0", "id": 1, "method": "first" }));
        driver.send(&json!({ "jsonrpc": "2.0", "id": 2, "method": "second" }));
        driver.pause_after_response(2);
        // The child answers only after this third line, so the pause is armed
        // before either response exists.
        driver.send(&json!({ "jsonrpc": "2.0", "method": "notifications/go" }));

        let first = driver.response_within(1, Duration::from_secs(5));
        assert_eq!(
            first.map(|message| message["result"]["id"].clone()),
            Ok(json!(1)),
            "the first response is delivered"
        );
        let second = driver.response_within(2, Duration::from_secs(5));
        assert_eq!(
            second.map(|message| message["result"]["id"].clone()),
            Ok(json!(2)),
            "the designated response is delivered"
        );
        assert!(
            driver.wait_until_paused(Duration::from_secs(5)),
            "the reader parks after the designated response"
        );
        assert!(driver.stdout_is_paused());
    }

    /// A child that writes far more than a pipe holds to stderr before it
    /// answers still answers, and its stderr is returned at exit.
    #[test]
    fn driver_drains_stderr_while_the_child_runs() {
        const STDERR_BYTES: usize = 1 << 20;
        let mut driver = ChildDriver::spawn(sh(&format!(
            "head -c {STDERR_BYTES} /dev/zero | tr '\\000' x >&2; read line; {}; \
             printf 'done\\n' >&2",
            response_line(1)
        )));
        driver.send(&json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }));
        let response = driver.response(1);
        assert_eq!(response["result"]["id"], 1, "{response}");
        driver.close_stdin();
        let (status, stderr) = driver.wait();
        assert!(status.success());
        assert_eq!(stderr.len(), STDERR_BYTES + "done\n".len());
        assert!(
            stderr.ends_with("xdone\n"),
            "the complete stderr is returned"
        );
    }

    /// A server child that refuses an unknown flag exits at once. A wait for
    /// a line it never prints fails within five seconds of its 20-second
    /// deadline, and the failure names the exit status and the expected text.
    #[test]
    fn the_wait_reports_an_early_child_exit() {
        const NEVER_PRINTED: &str = "a line the refused server never prints";
        let mut command = crate::common::server_binary::server_command();
        command.arg("--no-such-flag");
        let mut driver = ChildDriver::spawn(command);
        let started = Instant::now();
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            driver.wait_for_stderr(NEVER_PRINTED, Duration::from_secs(20));
        }))
        .expect_err("the wait fails when the child exits without the line");
        let elapsed = started.elapsed();
        let message = failure
            .downcast_ref::<String>()
            .cloned()
            .unwrap_or_default();
        assert!(
            elapsed < Duration::from_secs(5),
            "the early exit fails the wait at once: {elapsed:?}\n{message}"
        );
        assert!(
            message.starts_with("child exits before"),
            "the failure names the early exit: {message}"
        );
        assert!(
            message.contains(&format!("{NEVER_PRINTED:?}")),
            "the failure quotes the expected text: {message}"
        );
        assert!(
            message.contains("exit status: 2"),
            "the failure names the usage exit status: {message}"
        );
    }

    /// How long the delayed-reader test holds the reader after the wait
    /// observes the exit: longer than any fixed grace shorter than it.
    const HELD_AFTER_EXIT: Duration = Duration::from_millis(1_500);

    /// A child writes the expected line and exits while its stderr reader
    /// holds that line unappended. The wait observes the exit, which reaps
    /// the child, and the reader stays held [`HELD_AFTER_EXIT`] longer. The
    /// wait reports the line once the reader appends it and the pipe closes.
    #[test]
    fn the_wait_reports_a_line_a_held_reader_appends_after_the_exit() {
        const LINE: &str = "the line the child writes before it exits";
        let mut driver =
            ChildDriver::spawn(sh(&format!("read go; printf '%s\\n' '{LINE}' >&2; exit 0")));
        driver.hold_stderr();
        driver.send(&json!({ "jsonrpc": "2.0", "method": "notifications/go" }));
        assert!(
            driver.wait_until_stderr_held(RESPONSE_DEADLINE),
            "the reader holds the line"
        );
        let pid = driver.id();
        let buffer = Arc::clone(&driver.stderr);
        let releaser = std::thread::spawn(move || {
            // The wait's exit check reaps the child, so the process is gone
            // only after the wait observes the exit.
            assert!(reaped_within_deadline(pid), "the wait observes the exit");
            std::thread::sleep(HELD_AFTER_EXIT);
            buffer.release_hold();
        });
        let started = Instant::now();
        let outcome = driver.await_stderr(LINE, Duration::from_secs(20));
        let elapsed = started.elapsed();
        releaser.join().unwrap();
        assert!(
            matches!(&outcome, StderrWait::Shown(text) if text.contains(LINE)),
            "the wait reports the line the held reader appends: {outcome:?}"
        );
        assert!(
            elapsed >= HELD_AFTER_EXIT,
            "the wait spans the hold after the exit: {elapsed:?}"
        );
    }

    /// The bytes the output-pressure child writes after its first chunk,
    /// more than a pipe holds.
    const PRESSURE_BYTES: usize = 1 << 20;

    /// With the hold armed, the child writes a first chunk, which the reader
    /// holds, and then more than the pipe holds. `wait` releases the hold
    /// before its exit wait, so the child exits on its own within the exit
    /// deadline and the capture holds every byte.
    #[test]
    fn wait_releases_a_held_reader_before_the_exit_wait() {
        let deadline = Duration::from_secs(5);
        let mut driver = ChildDriver::spawn(sh(&format!(
            "read go; printf 'first\\n' >&2; head -c {PRESSURE_BYTES} /dev/zero | tr '\\000' x \
             >&2; exit 0"
        )))
        .with_exit_deadline(deadline);
        driver.hold_stderr();
        driver.send(&json!({ "jsonrpc": "2.0", "method": "notifications/go" }));
        assert!(
            driver.wait_until_stderr_held(RESPONSE_DEADLINE),
            "the reader holds the first chunk"
        );
        let started = Instant::now();
        let (status, stderr) = driver.wait();
        let elapsed = started.elapsed();
        assert!(status.success(), "the child exits on its own: {status}");
        assert!(
            elapsed < deadline,
            "the exit precedes the deadline: {elapsed:?}"
        );
        assert_eq!(stderr.len(), "first\n".len() + PRESSURE_BYTES);
        assert!(stderr.starts_with("first\nx") && stderr.ends_with('x'));
    }

    /// A wait returns `Shown` as soon as the text arrives, while the child
    /// runs and its stderr pipe stays open.
    #[test]
    fn the_wait_reports_a_line_while_the_pipe_is_open() {
        const LINE: &str = "a line from a child that keeps running";
        let mut driver =
            ChildDriver::spawn(sh(&format!("printf '%s\\n' '{LINE}' >&2; exec sleep 3600")));
        let outcome = driver.await_stderr(LINE, Duration::from_secs(5));
        assert!(
            matches!(&outcome, StderrWait::Shown(text) if text.contains(LINE)),
            "the wait reports the line before any EOF: {outcome:?}"
        );
        assert_eq!(driver.poll_exit(), None, "the child still runs");
        assert!(
            !driver.stderr.closed.load(Ordering::SeqCst),
            "the stderr pipe stays open"
        );
    }

    /// The deadline of the open-pipe wait.
    const OPEN_PIPE_DEADLINE: Duration = Duration::from_millis(500);

    /// The child writes a line and exits while the reader holds the line, so
    /// the reader sees no EOF. A wait for the line ends at its deadline with
    /// the open-pipe outcome and the line absent. After the release, a later
    /// wait gets the line, with the same reader still attached.
    #[test]
    fn an_open_pipe_wait_keeps_the_reader_for_a_later_wait() {
        const LINE: &str = "a line the reader holds past the first wait";
        let mut driver =
            ChildDriver::spawn(sh(&format!("read go; printf '%s\\n' '{LINE}' >&2; exit 0")));
        driver.hold_stderr();
        driver.send(&json!({ "jsonrpc": "2.0", "method": "notifications/go" }));
        assert!(
            driver.wait_until_stderr_held(RESPONSE_DEADLINE),
            "the reader holds the line"
        );
        assert!(reaped_after_exit(&mut driver), "the child exits");

        let first = driver.await_stderr(LINE, OPEN_PIPE_DEADLINE);
        assert!(
            matches!(&first, StderrWait::ExitedWithOpenStderr { status, stderr }
                if status.success() && !stderr.contains(LINE)),
            "the first wait ends with the open-pipe outcome: {first:?}"
        );

        driver.release_stderr();
        let later = driver.await_stderr(LINE, Duration::from_secs(5));
        assert!(
            matches!(&later, StderrWait::Shown(text) if text.contains(LINE)),
            "a later wait gets the line the reader appends after the release: {later:?}"
        );
        assert!(
            driver.stderr_reader.is_some(),
            "the reader stays attached to the driver"
        );
    }

    /// Polls the driver's exit check until it reports the exit, at most ten
    /// seconds.
    fn reaped_after_exit(driver: &mut ChildDriver) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while driver.poll_exit().is_none() {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        true
    }

    /// Whether a process with `pid` exists, a zombie included.
    fn process_exists(pid: u32) -> bool {
        Command::new("sh")
            .arg("-c")
            .arg(format!("kill -0 {pid} 2>/dev/null"))
            .status()
            .unwrap()
            .success()
    }

    /// Waits at most ten seconds for `pid` to be gone, zombie included.
    fn reaped_within_deadline(pid: u32) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while process_exists(pid) {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        true
    }

    /// Runs `scope` on a thread with a child that ignores stdin and would run
    /// for an hour. Returns the child's id once the thread ends, which must
    /// happen within ten seconds.
    fn drop_on_a_thread(scope: fn(ChildDriver)) -> u32 {
        let (pid_tx, pid_rx) = channel();
        let (done_tx, done_rx) = channel();
        std::thread::spawn(move || {
            let driver = ChildDriver::spawn(sh("exec sleep 3600"));
            pid_tx.send(driver.id()).unwrap();
            scope(driver);
            done_tx.send(()).unwrap();
        });
        let pid = pid_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the child spawns");
        done_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the driver's drop returns within ten seconds");
        pid
    }

    /// Dropping the driver kills and reaps a child that would run on, after a
    /// normal scope exit and during an unwind. A killed but unreaped child
    /// stays a zombie, which `kill -0` still finds.
    #[test]
    fn driver_drop_terminates_and_reaps_the_child() {
        let pid = drop_on_a_thread(|driver| {
            assert!(
                process_exists(driver.id()),
                "the child runs while the driver lives"
            );
        });
        assert!(
            reaped_within_deadline(pid),
            "a normal scope exit kills and reaps the child"
        );

        let pid = drop_on_a_thread(|driver| {
            let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _driver = driver;
                std::panic::resume_unwind(Box::new("unwinding through the driver"));
            }));
            assert!(unwound.is_err(), "the closure unwinds");
        });
        assert!(
            reaped_within_deadline(pid),
            "an unwind kills and reaps the child"
        );
    }

    /// The exit deadline of the descendant-pipe cases.
    #[cfg(target_os = "linux")]
    const SHORT_EXIT_DEADLINE: Duration = Duration::from_millis(500);

    /// A shell that starts a five-second helper with `redirect` applied,
    /// prints the helper's id on its own stderr, and exits.
    #[cfg(target_os = "linux")]
    fn descendant_child(redirect: &str) -> ChildDriver {
        ChildDriver::spawn(sh(&format!(
            "sleep 5 {redirect} & echo \"helper $!\" >&2; exit 0"
        )))
        .with_exit_deadline(SHORT_EXIT_DEADLINE)
    }

    /// The helper id a descendant child printed on stderr.
    #[cfg(target_os = "linux")]
    fn helper_id(stderr: &str) -> u32 {
        stderr
            .lines()
            .find_map(|line| line.strip_prefix("helper "))
            .and_then(|pid| pid.trim().parse().ok())
            .unwrap_or_else(|| panic!("the child prints its helper's id: {stderr}"))
    }

    /// Runs `wait` on a descendant child and asserts it returns within its
    /// exit deadline plus a margin while the helper still runs. The helper
    /// ends on its own.
    #[cfg(target_os = "linux")]
    fn assert_wait_is_bounded(redirect: &str) {
        let driver = descendant_child(redirect);
        let started = Instant::now();
        let (status, stderr) = driver.wait();
        let elapsed = started.elapsed();
        assert!(status.success(), "{stderr}");
        assert!(
            elapsed < SHORT_EXIT_DEADLINE + Duration::from_secs(1),
            "wait returns within its deadline plus a margin: {elapsed:?}"
        );
        assert!(
            process_exists(helper_id(&stderr)),
            "the helper still holds its pipe when wait returns"
        );
    }

    /// The helper inherits both stdout and stderr.
    #[cfg(target_os = "linux")]
    #[test]
    fn driver_wait_is_bounded_when_a_descendant_holds_the_pipes() {
        assert_wait_is_bounded("");
    }

    /// The helper inherits stdout only.
    #[cfg(target_os = "linux")]
    #[test]
    fn driver_wait_is_bounded_when_a_descendant_holds_stdout() {
        assert_wait_is_bounded("2>/dev/null");
    }

    /// The helper inherits stderr only.
    #[cfg(target_os = "linux")]
    #[test]
    fn driver_wait_is_bounded_when_a_descendant_holds_stderr() {
        assert_wait_is_bounded(">/dev/null");
    }

    /// Dropping the driver without a wait returns within the exit deadline
    /// plus a margin while a helper holds both pipes.
    #[cfg(target_os = "linux")]
    #[test]
    fn driver_drop_is_bounded_when_a_descendant_holds_the_pipes() {
        let mut driver = descendant_child("");
        let helper = helper_id(&driver.wait_for_stderr("helper ", RESPONSE_DEADLINE));
        let started = Instant::now();
        drop(driver);
        let elapsed = started.elapsed();
        assert!(
            elapsed < SHORT_EXIT_DEADLINE + Duration::from_secs(1),
            "drop returns within the exit deadline plus a margin: {elapsed:?}"
        );
        assert!(
            process_exists(helper),
            "the helper still holds the pipes when drop returns"
        );
    }

    /// `wait_for_exit` returns within its deadline plus a margin while a
    /// helper holds stderr, and it leaves a paused stdout reader paused.
    ///
    /// The child writes response 7 only after a go line, so the pause is
    /// armed first. The helper inherits stderr only.
    #[cfg(target_os = "linux")]
    #[test]
    fn driver_wait_for_exit_is_bounded_when_a_descendant_holds_stderr() {
        let mut driver = ChildDriver::spawn(sh(&format!(
            "read go; {}; sleep 5 >/dev/null & echo \"helper $!\" >&2; exit 0",
            response_line(7)
        )))
        .with_exit_deadline(SHORT_EXIT_DEADLINE);
        driver.pause_after_response(7);
        driver.send(&json!({ "jsonrpc": "2.0", "method": "notifications/go" }));
        assert!(
            driver.wait_until_paused(RESPONSE_DEADLINE),
            "the reader parks after response 7"
        );
        let helper = helper_id(&driver.wait_for_stderr("helper ", RESPONSE_DEADLINE));

        let started = Instant::now();
        let status = driver.wait_for_exit(SHORT_EXIT_DEADLINE);
        let elapsed = started.elapsed();
        assert!(status.is_some_and(|status| status.success()));
        assert!(
            elapsed < SHORT_EXIT_DEADLINE + Duration::from_secs(1),
            "wait_for_exit returns within its deadline plus a margin: {elapsed:?}"
        );
        assert!(
            driver.stdout_is_paused(),
            "wait_for_exit leaves the paused stdout reader alone"
        );
        assert!(
            process_exists(helper),
            "the helper still holds stderr when wait_for_exit returns"
        );
    }
}

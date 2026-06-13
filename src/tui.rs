//! Interactive terminal UI for the DNS cache (`loader --tui <iface>`).
//!
//! A single background "BPF worker" thread owns the loaded skeleton, attaches
//! XDP, polls the `events` / `dns_capture_rb` ring buffers, and periodically
//! snapshots the in-kernel reverse cache. The main thread owns the terminal and
//! renders two tabbed panels — a live DNS event feed and the reverse cache —
//! consuming the worker's output over channels. Because both the ring-buffer
//! poller and the cache iterator need only *shared* access to the skeleton, and
//! the skeleton borrows its `OpenObject`, the worker is launched via
//! `thread::scope` so the borrow need never become `'static`.

use std::collections::{BTreeMap, VecDeque};
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use libbpf_rs::{RingBufferBuilder, XdpFlags};

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table, TableState, Tabs};
use ratatui::{Frame, Terminal};

use crate::dns_parser::DnsParserSkel;
use crate::{
    capture_callback, live_reverse_entries, local_hms, monotonic_now_ns, read_dns_event,
    write_payloads, Capture, DnsEvent, ReverseEntry,
};

/// Maximum number of feed rows retained in memory.
const FEED_CAP: usize = 1000;
/// How often the worker re-reads the reverse cache (also forceable with `r`).
const CACHE_REFRESH_NS: u64 = 5_000_000_000;
/// Feed channel capacity; on overflow events are dropped and counted.
const FEED_CHAN_CAP: usize = 4096;

/// Column headers / sort keys for each panel (index order matches the rendered
/// columns and [`cmp_event`] / [`cmp_cache`]).
const EVENTS_COLS: [&str; 6] = ["Time", "Name", "Type", "Address", "TTL", "TxID/Ans"];
const CACHE_COLS: [&str; 6] = ["Time", "Address", "Name", "TTL", "Age", "Left"];

/// One decoded DNS answer, owned so it can cross the channel to the UI thread.
struct FeedEvent {
    /// Local arrival time, formatted `HH:MM:SS` for display.
    time:        String,
    /// Monotonic insertion order, assigned by [`App::push_event`]. Used as the
    /// sort key for the Time column so ordering is stable and survives ties /
    /// midnight rollover that the formatted `time` string can't express.
    seq:         u64,
    name:        String,
    record_type: &'static str,
    addr:        String,
    ttl:         u32,
    txid:        u16,
    answer_idx:  u16,
}

impl From<&DnsEvent> for FeedEvent {
    fn from(ev: &DnsEvent) -> Self {
        FeedEvent {
            time:        local_hms(),
            seq:         0, // assigned on push into the feed
            name:        ev.name(),
            record_type: ev.record_type(),
            addr:        ev.addr(),
            ttl:         ev.ttl,
            txid:        ev.txid,
            answer_idx:  ev.answer_idx,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tab {
    Events,
    Cache,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SortDir {
    Asc,
    Desc,
}

/// Which IP address family to show in both panels.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum IpFilter {
    Both,
    V4,
    V6,
}

impl IpFilter {
    /// Cycle Both → v4 → v6 → Both.
    fn next(self) -> Self {
        match self {
            IpFilter::Both => IpFilter::V4,
            IpFilter::V4 => IpFilter::V6,
            IpFilter::V6 => IpFilter::Both,
        }
    }

    fn label(self) -> &'static str {
        match self {
            IpFilter::Both => "all",
            IpFilter::V4 => "v4",
            IpFilter::V6 => "v6",
        }
    }

    /// `true` if an address of the given family should be shown.
    fn accepts(self, addr: &str) -> bool {
        match self {
            IpFilter::Both => true,
            // IPv6 textual addresses contain a colon; IPv4 ones never do.
            IpFilter::V4 => !addr.contains(':'),
            IpFilter::V6 => addr.contains(':'),
        }
    }
}

/// Sort selection for a panel: a column index (or `None` for the panel's
/// natural order) plus a direction.
#[derive(Clone, Copy)]
struct SortState {
    col: Option<usize>,
    dir: SortDir,
}

impl Default for SortState {
    fn default() -> Self {
        SortState {
            col: None,
            dir: SortDir::Asc,
        }
    }
}

/// `true` if the query is empty or matches `name`/`addr` case-insensitively.
/// `query` is assumed already lowercased.
fn matches_filter(query: &str, name: &str, addr: &str) -> bool {
    query.is_empty()
        || name.to_lowercase().contains(query)
        || addr.to_lowercase().contains(query)
}

fn cmp_event(a: &FeedEvent, b: &FeedEvent, col: usize) -> std::cmp::Ordering {
    match col {
        0 => a.seq.cmp(&b.seq), // Time: order by arrival, not the formatted string
        1 => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
        2 => a.record_type.cmp(b.record_type),
        3 => a.addr.cmp(&b.addr),
        4 => a.ttl.cmp(&b.ttl),
        _ => (a.txid, a.answer_idx).cmp(&(b.txid, b.answer_idx)),
    }
}

/// Seconds left before an entry's TTL elapses (`TTL - age`, clamped at 0).
fn remaining_secs(e: &ReverseEntry) -> u64 {
    (e.ttl as u64).saturating_sub(e.age_secs)
}

fn cmp_cache(a: &ReverseEntry, b: &ReverseEntry, col: usize) -> std::cmp::Ordering {
    match col {
        // Time (insertion): order by age so it's monotonic and midnight-safe.
        // A smaller age is a more recent timestamp, so reverse the comparison.
        0 => b.age_secs.cmp(&a.age_secs),
        1 => a.addr.cmp(&b.addr),
        2 => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
        3 => a.ttl.cmp(&b.ttl),
        4 => a.age_secs.cmp(&b.age_secs),
        _ => remaining_secs(a).cmp(&remaining_secs(b)),
    }
}

/// Channels and shared state the UI thread reads and the worker writes.
struct Shared {
    cache:   Mutex<Vec<ReverseEntry>>,
    dropped: AtomicU64,
    status:  Mutex<Option<String>>,
    refresh: AtomicBool,
}

/// All UI-thread state.
struct App {
    feed:         VecDeque<FeedEvent>,
    active:       Tab,
    feed_state:   TableState,
    cache_state:  TableState,
    dropped:      u64,
    status:       Option<String>,
    paused:       bool,
    /// Whether captured DNS payloads are being written to `payloads.json`.
    /// Mirrors the shared flag the worker reads; toggled with `p`.
    payload_on:   bool,
    /// Active substring filter (case-insensitive, name + address).
    filter:       String,
    /// `true` while the user is typing into the filter input.
    filtering:    bool,
    /// Address-family filter applied to both panels.
    ip_filter:    IpFilter,
    /// `true` while the keyboard-shortcut help overlay is shown.
    show_help:    bool,
    events_sort:  SortState,
    cache_sort:   SortState,
    /// Indices into `feed` / the cache snapshot that pass the filter, in display
    /// order. Rebuilt each frame by [`App::rebuild_views`].
    events_view:  Vec<usize>,
    cache_view:   Vec<usize>,
    /// Monotonic counter stamped onto each event as it enters the feed.
    seq_counter:  u64,
}

impl App {
    fn new() -> Self {
        App {
            feed:        VecDeque::new(),
            active:      Tab::Events,
            feed_state:  TableState::default(),
            cache_state: TableState::default(),
            dropped:     0,
            status:      None,
            paused:      false,
            payload_on:  false,
            filter:      String::new(),
            filtering:   false,
            ip_filter:   IpFilter::Both,
            show_help:   false,
            // Default to the "latest first" view: sort by Time (col 0), newest
            // at the top. `l` resets to exactly this.
            events_sort: SortState {
                col: Some(0),
                dir: SortDir::Desc,
            },
            cache_sort:  SortState::default(),
            events_view: Vec::new(),
            cache_view:  Vec::new(),
            seq_counter: 0,
        }
    }

    fn push_event(&mut self, mut ev: FeedEvent) {
        ev.seq = self.seq_counter;
        self.seq_counter += 1;
        self.feed.push_back(ev);
        while self.feed.len() > FEED_CAP {
            self.feed.pop_front();
        }
    }

    /// Recompute the filtered + sorted index lists for both panels. Must run
    /// before [`App::sync_selection`] and rendering each frame.
    fn rebuild_views(&mut self, cache: &[ReverseEntry]) {
        let q = self.filter.to_lowercase();

        let mut ev: Vec<usize> = (0..self.feed.len())
            .filter(|&i| {
                self.ip_filter.accepts(&self.feed[i].addr)
                    && matches_filter(&q, &self.feed[i].name, &self.feed[i].addr)
            })
            .collect();
        if let Some(col) = self.events_sort.col {
            ev.sort_by(|&a, &b| cmp_event(&self.feed[a], &self.feed[b], col));
            if self.events_sort.dir == SortDir::Desc {
                ev.reverse();
            }
        }
        self.events_view = ev;

        let mut cv: Vec<usize> = (0..cache.len())
            .filter(|&i| {
                self.ip_filter.accepts(&cache[i].addr)
                    && matches_filter(&q, &cache[i].name, &cache[i].addr)
            })
            .collect();
        if let Some(col) = self.cache_sort.col {
            cv.sort_by(|&a, &b| cmp_cache(&cache[a], &cache[b], col));
            if self.cache_sort.dir == SortDir::Desc {
                cv.reverse();
            }
        }
        self.cache_view = cv;
    }

    /// `true` when the feed is in its default "latest first" view: sorted by
    /// Time (col 0) descending, so the newest event is at the top.
    fn is_latest_view(&self) -> bool {
        self.events_sort.col == Some(0) && self.events_sort.dir == SortDir::Desc
    }

    /// The feed auto-pins to the newest row only in the default latest view
    /// while live. In that view the newest row is row 0 (the top).
    fn events_follow(&self) -> bool {
        self.is_latest_view() && !self.paused
    }

    /// Keep the feed pinned to the newest row while following, and clamp both
    /// selections to their current (filtered) row counts.
    fn sync_selection(&mut self) {
        let n = self.events_view.len();
        if n == 0 {
            self.feed_state.select(None);
        } else if self.events_follow() {
            self.feed_state.select(Some(0));
        } else {
            let i = self.feed_state.selected().unwrap_or(0).min(n - 1);
            self.feed_state.select(Some(i));
        }

        let m = self.cache_view.len();
        if m == 0 {
            self.cache_state.select(None);
        } else {
            let i = self.cache_state.selected().unwrap_or(0).min(m - 1);
            self.cache_state.select(Some(i));
        }
    }

    /// Move the active panel's selection by `delta` rows. Scrolling the feed
    /// pauses tail-following so the view holds still.
    fn scroll(&mut self, delta: isize) {
        match self.active {
            Tab::Events => {
                self.paused = true;
                let n = self.events_view.len();
                if n == 0 {
                    return;
                }
                let cur = self.feed_state.selected().unwrap_or(0) as isize;
                let next = (cur + delta).clamp(0, n as isize - 1) as usize;
                self.feed_state.select(Some(next));
            }
            Tab::Cache => {
                let n = self.cache_view.len();
                if n == 0 {
                    return;
                }
                let cur = self.cache_state.selected().unwrap_or(0) as isize;
                let next = (cur + delta).clamp(0, n as isize - 1) as usize;
                self.cache_state.select(Some(next));
            }
        }
    }

    fn scroll_to_top(&mut self) {
        match self.active {
            // In the latest view, the top row is the newest event — going there
            // is the live position, so resume following.
            Tab::Events => {
                self.feed_state.select(Some(0));
                if self.is_latest_view() {
                    self.paused = false;
                }
            }
            Tab::Cache => self.cache_state.select(Some(0)),
        }
    }

    fn scroll_to_bottom(&mut self) {
        match self.active {
            // The bottom row is the oldest event; pause so the view holds still.
            Tab::Events => {
                self.paused = true;
                if !self.events_view.is_empty() {
                    self.feed_state.select(Some(self.events_view.len() - 1));
                }
            }
            Tab::Cache if !self.cache_view.is_empty() => {
                self.cache_state.select(Some(self.cache_view.len() - 1))
            }
            Tab::Cache => {}
        }
    }

    /// Reset the feed to its default "latest first" view: sort by Time
    /// descending, resume the live feed, and jump to the newest row.
    fn reset_latest(&mut self) {
        self.active = Tab::Events;
        self.events_sort = SortState {
            col: Some(0),
            dir: SortDir::Desc,
        };
        self.paused = false;
        self.feed_state.select(Some(0));
    }

    /// Cycle the active panel's sort column: none → col 0 → … → last → none.
    fn cycle_sort(&mut self) {
        let ncols = match self.active {
            Tab::Events => EVENTS_COLS.len(),
            Tab::Cache => CACHE_COLS.len(),
        };
        let st = self.active_sort_mut();
        st.col = match st.col {
            None => Some(0),
            Some(c) if c + 1 < ncols => Some(c + 1),
            Some(_) => None,
        };
    }

    fn toggle_sort_dir(&mut self) {
        let st = self.active_sort_mut();
        st.dir = match st.dir {
            SortDir::Asc => SortDir::Desc,
            SortDir::Desc => SortDir::Asc,
        };
    }

    fn active_sort_mut(&mut self) -> &mut SortState {
        match self.active {
            Tab::Events => &mut self.events_sort,
            Tab::Cache => &mut self.cache_sort,
        }
    }

    fn handle_key(
        &mut self,
        key: KeyEvent,
        stop: &AtomicBool,
        refresh: &AtomicBool,
        payload: &AtomicBool,
    ) {
        // Ctrl-C always quits, even mid-typing.
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            stop.store(true, Ordering::SeqCst);
            return;
        }

        // While the help overlay is up, any key dismisses it.
        if self.show_help {
            self.show_help = false;
            return;
        }

        // While typing a filter, keystrokes edit the query instead of acting.
        if self.filtering {
            match key.code {
                KeyCode::Esc => {
                    self.filter.clear();
                    self.filtering = false;
                }
                KeyCode::Enter => self.filtering = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                }
                KeyCode::Char(c) => self.filter.push(c),
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => stop.store(true, Ordering::SeqCst),
            KeyCode::Tab => {
                self.active = match self.active {
                    Tab::Events => Tab::Cache,
                    Tab::Cache => Tab::Events,
                }
            }
            KeyCode::Char('?') | KeyCode::Char('h') => self.show_help = true,
            KeyCode::Char('/') => self.filtering = true,
            KeyCode::Char('c') => self.filter.clear(),
            KeyCode::Char('v') => self.ip_filter = self.ip_filter.next(),
            KeyCode::Char('s') => self.cycle_sort(),
            KeyCode::Char('S') => self.toggle_sort_dir(),
            KeyCode::Char('l') => self.reset_latest(),
            KeyCode::Char(' ') => self.paused = !self.paused,
            KeyCode::Char('p') => {
                // Toggle payload capture; the worker's callback reads this flag.
                let on = !payload.load(Ordering::Relaxed);
                payload.store(on, Ordering::Relaxed);
                self.payload_on = on;
            }
            KeyCode::Char('r') => refresh.store(true, Ordering::SeqCst),
            KeyCode::Up => self.scroll(-1),
            KeyCode::Down => self.scroll(1),
            KeyCode::PageUp => self.scroll(-10),
            KeyCode::PageDown => self.scroll(10),
            KeyCode::Char('g') => self.scroll_to_top(),
            KeyCode::Char('G') => self.scroll_to_bottom(),
            _ => {}
        }
    }

    /// A short label for the active panel's sort, e.g. `Name↑` or `off`.
    fn sort_label(&self) -> String {
        let (st, cols): (SortState, &[&str]) = match self.active {
            Tab::Events => (self.events_sort, &EVENTS_COLS),
            Tab::Cache => (self.cache_sort, &CACHE_COLS),
        };
        match st.col {
            None => "off".to_string(),
            Some(c) => format!(
                "{}{}",
                cols[c],
                if st.dir == SortDir::Asc { "↑" } else { "↓" }
            ),
        }
    }

    /// Right-aligned status for the top bar: row stats, active IP family and
    /// filter. `shown`/`total` are the active panel's filtered and unfiltered
    /// row counts.
    fn top_bar_line(&self, shown: usize, total: usize) -> String {
        let filt = if self.filter.is_empty() {
            "none".to_string()
        } else {
            format!("\"{}\"", self.filter)
        };
        format!(
            " rows:{}/{}  ip:{}  filter:{} ",
            shown,
            total,
            self.ip_filter.label(),
            filt,
        )
    }

    fn footer_line(&self) -> String {
        if self.filtering {
            return format!(" Filter: {}_    (Enter to apply · Esc to clear)", self.filter);
        }
        let filt = if self.filter.is_empty() {
            String::new()
        } else {
            format!("  filter:\"{}\"", self.filter)
        };
        let mut s = format!(
            " [?]help [/]filter [c]clear [v]ip [s/S]sort [l]latest [Tab]panel [Space]pause [p]payload [r]refresh [q]quit    {}  ip:{}  sort:{}  payload:{}  cache:{}  drop:{}{}",
            if self.paused { "PAUSED" } else { "LIVE" },
            self.ip_filter.label(),
            self.sort_label(),
            if self.payload_on { "on" } else { "off" },
            self.cache_view.len(),
            self.dropped,
            filt,
        );
        if let Some(err) = &self.status {
            s.push_str("    ! ");
            s.push_str(err);
        }
        s
    }
}

/// Run the interactive UI. Takes ownership of the loaded skeleton; attaches XDP,
/// polls, and detaches on its worker thread. Returns once the user quits or the
/// worker hits a fatal error.
pub fn run(
    skel: DnsParserSkel<'_>,
    ifindex: i32,
    stop: Arc<AtomicBool>,
    payload_enabled: bool,
) -> Result<()> {
    let (feed_tx, feed_rx) = sync_channel::<FeedEvent>(FEED_CHAN_CAP);
    let shared = Shared {
        cache:   Mutex::new(Vec::new()),
        dropped: AtomicU64::new(0),
        status:  Mutex::new(None),
        refresh: AtomicBool::new(false),
    };
    // Shared between the worker's capture callback (reader) and the UI's `p`
    // toggle (writer); cloned into the worker, borrowed by the UI loop.
    let payload = Arc::new(AtomicBool::new(payload_enabled));

    // ratatui::init installs a panic hook that restores the terminal, so a panic
    // on either thread won't leave the user's terminal in raw mode.
    let mut terminal = ratatui::init();

    // `stop` and `shared` outlive the scope, so the worker borrows them while
    // taking ownership of the (non-`Send`-lifetime) skeleton and the sender.
    let stop_ref: &AtomicBool = &stop;
    let shared_ref: &Shared = &shared;

    let payload_worker = payload.clone();
    let res = thread::scope(|s| -> Result<()> {
        let worker = s.spawn(move || {
            worker_loop(skel, ifindex, stop_ref, feed_tx, shared_ref, payload_worker)
        });

        let ui_res = ui_loop(&mut terminal, &feed_rx, &shared, &stop, &payload);

        // Make sure the worker leaves its poll loop and runs teardown (XDP
        // detach + payloads flush) before we restore the terminal.
        stop.store(true, Ordering::SeqCst);
        let worker_res = worker
            .join()
            .unwrap_or_else(|_| Err(anyhow!("BPF worker thread panicked")));

        ui_res.and(worker_res)
    });

    ratatui::restore();
    res
}

/// Record a fatal worker error both to the log file and the on-screen status.
fn set_status(shared: &Shared, msg: String) {
    log::error!("{msg}");
    *shared.status.lock().unwrap() = Some(msg);
}

/// The BPF worker: attach, poll the ring buffers, snapshot the reverse cache,
/// and tear down on `stop`.
fn worker_loop(
    skel: DnsParserSkel<'_>,
    ifindex: i32,
    stop: &AtomicBool,
    feed_tx: SyncSender<FeedEvent>,
    shared: &Shared,
    payload: Arc<AtomicBool>,
) -> Result<()> {
    let xdp = libbpf_rs::Xdp::new(skel.progs.xdp_dns_ingress.as_fd());
    if let Err(e) = xdp.attach(ifindex, XdpFlags::UPDATE_IF_NOEXIST) {
        set_status(shared, format!("attach failed: {e}"));
        stop.store(true, Ordering::SeqCst);
        return Err(anyhow::Error::new(e).context("bpf_xdp_attach"));
    }

    // Seed the cache panel before the first refresh tick so it isn't blank.
    *shared.cache.lock().unwrap() = live_reverse_entries(&skel);

    let captures: Arc<Mutex<BTreeMap<String, Capture>>> = Arc::new(Mutex::new(BTreeMap::new()));

    // Build the ring buffers and run the poll loop; any setup error still falls
    // through to the detach/flush below.
    let result = (|| -> Result<()> {
        let mut rb_builder = RingBufferBuilder::new();
        rb_builder
            .add(
                &skel.maps.dns_capture_rb,
                capture_callback(captures.clone(), payload.clone()),
            )
            .context("ringbuf add capture")?;
        rb_builder
            .add(&skel.maps.events, move |data: &[u8]| -> i32 {
                if let Some(ev) = read_dns_event(data) {
                    if feed_tx.try_send(FeedEvent::from(&ev)).is_err() {
                        shared.dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
                0
            })
            .context("ringbuf add events")?;
        let rb = rb_builder.build().context("ringbuf build")?;

        let mut last = monotonic_now_ns();
        while !stop.load(Ordering::SeqCst) {
            let _ = rb.poll(Duration::from_millis(100));
            let now = monotonic_now_ns();
            if shared.refresh.swap(false, Ordering::SeqCst)
                || now.saturating_sub(last) >= CACHE_REFRESH_NS
            {
                let entries = live_reverse_entries(&skel);
                *shared.cache.lock().unwrap() = entries;
                last = now;
            }
        }
        Ok(())
    })();

    if let Err(e) = &result {
        set_status(shared, format!("{e:#}"));
        stop.store(true, Ordering::SeqCst);
    }

    let _ = xdp.detach(ifindex, XdpFlags::UPDATE_IF_NOEXIST);
    if payload.load(Ordering::Relaxed) {
        write_payloads("payloads.json", &captures.lock().unwrap());
    }
    result
}

/// The render + input loop, driven on the main thread.
fn ui_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    feed_rx: &Receiver<FeedEvent>,
    shared: &Shared,
    stop: &AtomicBool,
    payload: &AtomicBool,
) -> Result<()> {
    let mut app = App::new();

    while !stop.load(Ordering::SeqCst) {
        // Drain everything the worker has queued since the last frame.
        while let Ok(ev) = feed_rx.try_recv() {
            app.push_event(ev);
        }
        app.dropped = shared.dropped.load(Ordering::Relaxed);
        app.status = shared.status.lock().unwrap().clone();
        app.payload_on = payload.load(Ordering::Relaxed);

        // Render the cache straight out of the shared snapshot — no per-frame
        // clone of a potentially large map.
        let cache = shared.cache.lock().unwrap();
        app.rebuild_views(&cache);
        app.sync_selection();
        terminal.draw(|f| draw(f, &mut app, &cache))?;
        drop(cache);

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.handle_key(key, stop, &shared.refresh, payload);
                }
            }
        }
    }
    Ok(())
}

fn draw(f: &mut Frame, app: &mut App, cache: &[ReverseEntry]) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(f.area());

    // Top bar: tabs on the left, row stats + IP-family + filter on the right.
    let (shown, total) = match app.active {
        Tab::Events => (app.events_view.len(), app.feed.len()),
        Tab::Cache => (app.cache_view.len(), cache.len()),
    };
    let status = app.top_bar_line(shown, total);
    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(status.chars().count() as u16)])
        .split(chunks[0]);

    let selected = match app.active {
        Tab::Events => 0,
        Tab::Cache => 1,
    };
    let tabs = Tabs::new(vec!["Events", "Cache"])
        .select(selected)
        .divider(" ")
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, top[0]);

    let status_widget = Paragraph::new(status)
        .alignment(ratatui::layout::Alignment::Right)
        .style(
            Style::default()
                .fg(Color::Cyan)
                .bg(Color::Rgb(30, 30, 40))
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(status_widget, top[1]);

    match app.active {
        Tab::Events => draw_events(f, app, chunks[1]),
        Tab::Cache => draw_cache(f, app, cache, chunks[1]),
    }

    let footer = Paragraph::new(app.footer_line())
        .style(Style::default().fg(Color::Gray).bg(Color::Rgb(30, 30, 40)));
    f.render_widget(footer, chunks[2]);

    if app.show_help {
        draw_help(f);
    }
}

/// Keyboard shortcuts shown in the help overlay.
const HELP_LINES: [&str; 16] = [
    "",
    "  ?, h        Toggle this help",
    "  /           Filter by name / address (Enter apply · Esc clear)",
    "  c           Clear the active filter",
    "  v           Cycle IP family: all → v4 → v6",
    "  s / S        Cycle sort column / toggle direction",
    "  l            Latest: events newest-first (Time ↓)",
    "  Tab          Switch panel (Events / Cache)",
    "  Space        Pause / resume the live feed",
    "  p            Toggle writing payloads to payloads.json",
    "  r            Refresh the reverse cache now",
    "  ↑ ↓          Move selection (PgUp/PgDn by 10)",
    "  g / G        Jump to top / bottom",
    "  q, Esc       Quit",
    "",
    "  Press any key to close",
];

/// Render the centered keyboard-shortcut help overlay.
fn draw_help(f: &mut Frame) {
    let area = centered_rect(64, HELP_LINES.len() as u16 + 2, f.area());
    let text = HELP_LINES.join("\n");
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Keyboard Shortcuts ")
        .style(Style::default().bg(Color::Black).fg(Color::White));
    f.render_widget(ratatui::widgets::Clear, area);
    f.render_widget(Paragraph::new(text).block(block), area);
}

/// A `Rect` of the given width/height (in cells, clamped to `area`) centered
/// within `area`.
fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    Rect {
        x,
        y,
        width,
        height,
    }
}

/// Build header cells, marking the sorted column with a direction arrow.
fn header_row(cols: &[&str], sort: SortState) -> Row<'static> {
    let cells = cols.iter().enumerate().map(|(i, c)| {
        if sort.col == Some(i) {
            format!("{c}{}", if sort.dir == SortDir::Asc { " ↑" } else { " ↓" })
        } else {
            c.to_string()
        }
    });
    Row::new(cells.collect::<Vec<_>>()).style(
        Style::default()
            .fg(Color::White)
            .bg(Color::Rgb(40, 40, 55))
            .add_modifier(Modifier::BOLD),
    )
}

fn draw_events(f: &mut Frame, app: &mut App, area: Rect) {
    let title = format!(" DNS Events ({}) ", app.events_view.len());
    let header = header_row(&EVENTS_COLS, app.events_sort);
    let rows = app.events_view.iter().map(|&i| {
        let e = &app.feed[i];
        Row::new([
            e.time.clone(),
            e.name.clone(),
            e.record_type.to_string(),
            e.addr.clone(),
            format!("{}s", e.ttl),
            format!("{}/{}", e.txid, e.answer_idx),
        ])
    });
    let widths = [
        Constraint::Length(10),
        Constraint::Min(20),
        Constraint::Length(6),
        Constraint::Length(39),
        Constraint::Length(8),
        Constraint::Length(14),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(table, area, &mut app.feed_state);
}

fn draw_cache(f: &mut Frame, app: &mut App, cache: &[ReverseEntry], area: Rect) {
    let title = format!(" Reverse Cache · address → name ({}) ", app.cache_view.len());
    let header = header_row(&CACHE_COLS, app.cache_sort);
    let rows = app.cache_view.iter().map(|&i| {
        let e = &cache[i];
        Row::new([
            e.inserted.clone(),
            e.addr.clone(),
            e.name.clone(),
            format!("{}s", e.ttl),
            format!("{}s", e.age_secs),
            format!("{}s", remaining_secs(e)),
        ])
    });
    let widths = [
        Constraint::Length(10),
        Constraint::Length(39),
        Constraint::Min(20),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(10),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(table, area, &mut app.cache_state);
}

#[cfg(test)]
mod tui_tests {
    use super::*;
    use std::mem::size_of;

    /// Build the raw bytes of a `DnsEvent` for an IPv4 A record.
    fn a_record_bytes(name: &str, ip: [u8; 4], ttl: u32, txid: u16, answer_idx: u16) -> Vec<u8> {
        let mut ev: DnsEvent = unsafe { std::mem::zeroed() };
        ev.qtype = 1;
        ev.name_len = name.len() as u16;
        ev.txid = txid;
        ev.answer_idx = answer_idx;
        ev.is_ipv6 = 0;
        ev.ip4 = u32::from_ne_bytes(ip);
        ev.ttl = ttl;
        ev.name[..name.len()].copy_from_slice(name.as_bytes());
        // SAFETY: DnsEvent is repr(C) with no padding requirements that forbid a
        // byte view; we only read it back through read_dns_event.
        let bytes = unsafe {
            std::slice::from_raw_parts(&ev as *const DnsEvent as *const u8, size_of::<DnsEvent>())
        };
        bytes.to_vec()
    }

    #[test]
    fn decodes_a_record_into_feed_event() {
        let bytes = a_record_bytes("example.com", [93, 184, 216, 34], 300, 0x1234, 2);
        let ev = read_dns_event(&bytes).expect("decoded event");
        let fe = FeedEvent::from(&ev);
        assert_eq!(fe.name, "example.com");
        assert_eq!(fe.record_type, "A");
        assert_eq!(fe.addr, "93.184.216.34");
        assert_eq!(fe.ttl, 300);
        assert_eq!(fe.txid, 0x1234);
        assert_eq!(fe.answer_idx, 2);
    }

    #[test]
    fn short_buffer_decodes_to_none() {
        assert!(read_dns_event(&[0u8; 4]).is_none());
    }

    /// Push a feed event with the given name/address (other fields filled in).
    fn push(app: &mut App, name: &str, addr: &str) {
        app.push_event(FeedEvent {
            time:        "00:00:00".to_string(),
            seq:         0, // overwritten by push_event
            name:        name.to_string(),
            record_type: "A",
            addr:        addr.to_string(),
            ttl:         60,
            txid:        0,
            answer_idx:  0,
        });
    }

    #[test]
    fn feed_respects_cap_and_follows_newest() {
        let mut app = App::new();
        for i in 0..(FEED_CAP + 50) {
            push(&mut app, &format!("h{i}.example.com"), "1.2.3.4");
        }
        assert_eq!(app.feed.len(), FEED_CAP, "feed capped at FEED_CAP");
        app.rebuild_views(&[]);
        app.sync_selection();
        // Default latest-first view: the live feed pins to the newest row (top).
        assert_eq!(
            app.feed_state.selected(),
            Some(0),
            "live feed follows the newest event at the top"
        );
    }

    #[test]
    fn scrolling_feed_pauses_follow() {
        let mut app = App::new();
        for i in 0..10 {
            push(&mut app, &format!("h{i}"), "1.2.3.4");
        }
        app.rebuild_views(&[]);
        app.sync_selection();
        // Latest-first view starts pinned to the top (newest); scroll down into
        // older rows.
        assert_eq!(app.feed_state.selected(), Some(0));
        app.scroll(3);
        assert!(app.paused, "scrolling the feed pauses follow");
        assert_eq!(app.feed_state.selected(), Some(3));
        // Once paused, sync_selection must not snap back to the newest row.
        app.rebuild_views(&[]);
        app.sync_selection();
        assert_eq!(app.feed_state.selected(), Some(3));
    }

    #[test]
    fn filter_narrows_feed_rows() {
        let mut app = App::new();
        push(&mut app, "api.example.com", "1.1.1.1");
        push(&mut app, "cdn.test.net", "2.2.2.2");
        push(&mut app, "mail.example.com", "3.3.3.3");

        // Default view is Time-descending, so matching rows come back newest
        // (highest index) first.
        app.filter = "EXAMPLE".to_string(); // case-insensitive
        app.rebuild_views(&[]);
        assert_eq!(app.events_view, vec![2, 0], "only example.com rows match");

        // A filter against the address field also matches.
        app.filter = "2.2.2.2".to_string();
        app.rebuild_views(&[]);
        assert_eq!(app.events_view, vec![1]);

        // Empty filter shows everything again (newest first).
        app.filter.clear();
        app.rebuild_views(&[]);
        assert_eq!(app.events_view, vec![2, 1, 0]);
    }

    #[test]
    fn ip_filter_narrows_by_family() {
        let mut app = App::new();
        push(&mut app, "v4.example.com", "93.184.216.34");
        push(&mut app, "v6.example.com", "2606:2800:220:1:248:1893:25c8:1946");
        push(&mut app, "also4.example.com", "1.2.3.4");

        // Both families by default (newest first).
        app.rebuild_views(&[]);
        assert_eq!(app.events_view, vec![2, 1, 0]);

        // v4 only.
        app.ip_filter = IpFilter::V4;
        app.rebuild_views(&[]);
        assert_eq!(app.events_view, vec![2, 0]);

        // v6 only.
        app.ip_filter = IpFilter::V6;
        app.rebuild_views(&[]);
        assert_eq!(app.events_view, vec![1]);

        // The toggle cycles Both → v4 → v6 → Both.
        assert_eq!(IpFilter::Both.next(), IpFilter::V4);
        assert_eq!(IpFilter::V4.next(), IpFilter::V6);
        assert_eq!(IpFilter::V6.next(), IpFilter::Both);
    }

    #[test]
    fn sorting_reorders_and_disables_follow() {
        let mut app = App::new();
        push(&mut app, "ccc", "1.1.1.1");
        push(&mut app, "aaa", "2.2.2.2");
        push(&mut app, "bbb", "3.3.3.3");

        // Sort by Name (column 1) ascending.
        app.events_sort = SortState {
            col: Some(1),
            dir: SortDir::Asc,
        };
        app.rebuild_views(&[]);
        assert_eq!(app.events_view, vec![1, 2, 0], "aaa, bbb, ccc");
        assert!(
            !app.events_follow(),
            "a non-default sort disables follow"
        );

        // Toggle to descending.
        app.toggle_sort_dir();
        app.rebuild_views(&[]);
        assert_eq!(app.events_view, vec![0, 2, 1], "ccc, bbb, aaa");
    }

    #[test]
    fn default_view_is_latest_first_and_l_resets() {
        let mut app = App::new();
        // The feed defaults to the latest-first view (Time ↓).
        assert!(app.is_latest_view());
        assert_eq!(app.events_sort.col, Some(0));
        assert_eq!(app.events_sort.dir, SortDir::Desc);

        push(&mut app, "first", "1.1.1.1");
        push(&mut app, "second", "2.2.2.2");
        push(&mut app, "third", "3.3.3.3");
        app.rebuild_views(&[]);
        assert_eq!(app.events_view, vec![2, 1, 0], "newest event on top");

        // Move away: another panel, a different sort, paused. `l` restores the
        // latest-first events view.
        app.active = Tab::Cache;
        app.events_sort = SortState {
            col: Some(1),
            dir: SortDir::Asc,
        };
        app.paused = true;

        app.reset_latest();
        assert_eq!(app.active, Tab::Events);
        assert!(app.is_latest_view());
        assert!(!app.paused, "l resumes the live feed");
        app.rebuild_views(&[]);
        assert_eq!(app.events_view, vec![2, 1, 0]);
    }

    #[test]
    fn sort_cycles_through_columns_and_off() {
        let mut app = App::new();
        assert_eq!(app.cache_sort.col, None);
        app.active = Tab::Cache;
        for expected in 0..CACHE_COLS.len() {
            app.cycle_sort();
            assert_eq!(app.cache_sort.col, Some(expected));
        }
        app.cycle_sort();
        assert_eq!(app.cache_sort.col, None, "wraps back to natural order");
    }

    #[test]
    fn filter_typing_consumes_keys() {
        let stop = AtomicBool::new(false);
        let refresh = AtomicBool::new(false);
        let payload = AtomicBool::new(false);
        let mut app = App::new();

        app.handle_key(key(KeyCode::Char('/')), &stop, &refresh, &payload);
        assert!(app.filtering);
        // 'q' is typed into the filter, not treated as quit.
        app.handle_key(key(KeyCode::Char('q')), &stop, &refresh, &payload);
        app.handle_key(key(KeyCode::Char('z')), &stop, &refresh, &payload);
        assert_eq!(app.filter, "qz");
        assert!(!stop.load(Ordering::SeqCst), "typing must not quit");

        // Enter applies and exits the input; Esc would clear it.
        app.handle_key(key(KeyCode::Enter), &stop, &refresh, &payload);
        assert!(!app.filtering);
        assert_eq!(app.filter, "qz");

        app.handle_key(key(KeyCode::Char('q')), &stop, &refresh, &payload);
        assert!(stop.load(Ordering::SeqCst), "q quits in normal mode");
    }

    #[test]
    fn p_toggles_payload_flag() {
        let stop = AtomicBool::new(false);
        let refresh = AtomicBool::new(false);
        let payload = AtomicBool::new(false);
        let mut app = App::new();

        app.handle_key(key(KeyCode::Char('p')), &stop, &refresh, &payload);
        assert!(payload.load(Ordering::Relaxed), "p turns payload writing on");
        assert!(app.payload_on);

        app.handle_key(key(KeyCode::Char('p')), &stop, &refresh, &payload);
        assert!(!payload.load(Ordering::Relaxed), "p toggles it back off");
        assert!(!app.payload_on);

        // Space still pauses without touching the payload flag.
        app.handle_key(key(KeyCode::Char(' ')), &stop, &refresh, &payload);
        assert!(app.paused);
        assert!(!payload.load(Ordering::Relaxed));
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }
}

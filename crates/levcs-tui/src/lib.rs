//! levcs-tui: merge-review TUI per §6.7.
//!
//! Architecture:
//!   * `state` — pure state machine (no terminal I/O), unit tested.
//!   * `lib.rs` (this file) — terminal driver: opens raw mode, draws,
//!     reads key events, calls into the state machine, applies the
//!     resolutions on quit.
//!
//! The view is four panes: file list (left), then ours / base / theirs
//! laid out horizontally for the selected file. The currently-selected
//! conflict region is highlighted in each of ours/base/theirs panes by
//! reverse-video on the byte range the engine reported. A status line
//! at the bottom shows keybindings and the current per-file resolution.
//!
//! Keys (all single-press, no modifiers):
//!   * j / Down   — next file
//!   * k / Up     — previous file
//!   * n          — next conflict region in current file
//!   * p          — previous conflict region
//!   * o          — accept ours for current file
//!   * t          — accept theirs for current file
//!   * c          — keep current (working-tree) bytes for current file
//!   * s          — skip current file
//!   * q / Esc    — quit (caller decides whether to apply resolutions)

use std::io;
use std::path::Path;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Terminal;

use levcs_merge::{ConflictRegion, MergeStatus};

pub mod editor;
pub mod state;

pub use editor::{run_editor_on, EditError, EditOutcome};
pub use state::{ApplyReport, FileEntry, Resolution, ReviewState};

/// Backwards-compatible alias kept so older call sites that built
/// `FileMerge` continue to compile. New code should use `FileEntry`.
pub type FileMerge = FileEntry;

/// Run the interactive review loop. Blocks until the user quits.
/// Returns the per-file resolutions; the caller chooses whether to
/// apply them (e.g. via `state.apply(workdir)`).
pub fn review(files: Vec<FileEntry>) -> Result<ReviewState> {
    let mut state = ReviewState::new(files);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let outcome = run_loop(&mut terminal, &mut state);

    // Always restore the terminal, even if the loop bailed with an
    // error — leaving raw mode enabled would render the user's shell
    // unusable.
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    outcome?;
    Ok(state)
}

/// Run the review and apply the resolutions in one step. Convenience
/// wrapper for the common `levcs merge --review` path.
pub fn review_and_apply(files: Vec<FileEntry>, workdir: &Path) -> Result<ApplyReport> {
    let state = review(files)?;
    Ok(state.apply(workdir)?)
}

/// Drive the same TUI in inspect-only mode (`merge --explain`).
/// Resolution-changing keys are no-ops; navigation and the three-pane
/// diff still work. Returns when the user quits.
pub fn review_read_only(files: Vec<FileEntry>) -> Result<ReviewState> {
    let mut state = ReviewState::new_read_only(files);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let outcome = run_loop(&mut terminal, &mut state);

    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    outcome?;
    Ok(state)
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut ReviewState,
) -> Result<()> {
    while !state.quitting {
        terminal.draw(|frame| draw(frame, state))?;
        if let Event::Key(k) = event::read()? {
            // The `e` key (external editor) needs the terminal restored
            // before we hand control to vi/nano/etc., so it can't go
            // through the pure state machine — we handle it here and
            // route everything else to handle_key. Errors from the
            // editor are swallowed to keep the user in the loop; the
            // current resolution is left untouched on failure.
            if k.code == KeyCode::Char('e') {
                let _ = invoke_editor(terminal, state);
            } else {
                handle_key(state, k.code);
            }
        }
    }
    Ok(())
}

/// Suspend the TUI, run the configured external editor on the current
/// file's bytes, then resume the TUI. The editor's saved bytes (if any)
/// become a `Resolution::Edit` on the current file. Specialized to
/// `CrosstermBackend` so we can call `execute!` on its underlying
/// stdout — generalizing to any `Backend` doesn't gain anything since
/// the rest of the driver is already crossterm-only.
fn invoke_editor(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut ReviewState,
) -> Result<()> {
    let file = match state.current_file() {
        Some(f) => f.clone(),
        None => return Ok(()),
    };
    // Tear down raw mode + alt screen so the editor gets a clean
    // controlling terminal. Re-enter both on return regardless of
    // outcome so an editor crash doesn't leave the user stranded.
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);

    let outcome = editor::run_editor_on(&file.current, std::path::Path::new(&file.path));

    enable_raw_mode()?;
    execute!(terminal.backend_mut(), EnterAlternateScreen)?;
    terminal.clear()?;

    match outcome {
        Ok(EditOutcome::Edited(bytes)) => {
            state.set_current_resolution(Resolution::Edit { bytes });
            Ok(())
        }
        Ok(EditOutcome::Unchanged) => Ok(()),
        Err(e) => Err(anyhow::anyhow!("editor: {e}")),
    }
}

/// Map a single keypress to a state-machine method. Pulled out of the
/// loop so it can be unit-tested without ratatui or a real terminal.
pub fn handle_key(state: &mut ReviewState, code: KeyCode) {
    match code {
        KeyCode::Char('q') | KeyCode::Esc => state.quit(),
        KeyCode::Char('j') | KeyCode::Down => state.move_down(),
        KeyCode::Char('k') | KeyCode::Up => state.move_up(),
        KeyCode::Char('n') => state.next_region(),
        KeyCode::Char('p') => state.prev_region(),
        KeyCode::Char('o') => state.accept_ours(),
        KeyCode::Char('t') => state.accept_theirs(),
        KeyCode::Char('c') => state.keep_current(),
        KeyCode::Char('s') => state.skip(),
        _ => {}
    }
}

fn draw(frame: &mut ratatui::Frame, state: &ReviewState) {
    let area = frame.area();
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(2),
        ])
        .split(area);

    draw_title(frame, outer[0], state);
    draw_main(frame, outer[1], state);
    draw_status(frame, outer[2], state);
}

fn draw_title(frame: &mut ratatui::Frame, area: Rect, state: &ReviewState) {
    let total = state.files.len();
    let conflicted = state
        .files
        .iter()
        .filter(|f| matches!(f.status, MergeStatus::Conflict { .. }))
        .count();
    let mode = if state.read_only {
        "--explain"
    } else {
        "--review"
    };
    let title = format!(" levcs merge {mode}   {total} file(s), {conflicted} with conflicts  ");
    frame.render_widget(
        Paragraph::new(title)
            .style(Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED)),
        area,
    );
}

fn draw_main(frame: &mut ratatui::Frame, area: Rect, state: &ReviewState) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(22),
            Constraint::Percentage(26),
            Constraint::Percentage(26),
            Constraint::Percentage(26),
        ])
        .split(area);

    draw_file_list(frame, cols[0], state);
    if let Some(file) = state.current_file() {
        let region = file.conflict_regions().get(state.selected_region);
        draw_pane(
            frame,
            cols[1],
            "ours",
            &file.ours,
            region.map(|r| r.ours.clone()),
        );
        draw_pane(
            frame,
            cols[2],
            "base",
            &file.base,
            region.map(|r| r.base.clone()),
        );
        draw_pane(
            frame,
            cols[3],
            "theirs",
            &file.theirs,
            region.map(|r| r.theirs.clone()),
        );
    }
}

fn draw_file_list(frame: &mut ratatui::Frame, area: Rect, state: &ReviewState) {
    let items: Vec<ListItem> = state
        .files
        .iter()
        .zip(&state.resolutions)
        .enumerate()
        .map(|(i, (f, r))| {
            let label = match &f.status {
                MergeStatus::Merged { .. } => format!("[ok] {}", f.path),
                MergeStatus::Conflict { regions, .. } => {
                    format!("[{}] {}", regions.len(), f.path)
                }
                MergeStatus::NotApplicable => format!("[--] {}", f.path),
            };
            let tag = match r {
                Resolution::KeepCurrent => "keep",
                Resolution::AcceptOurs => "ours",
                Resolution::AcceptTheirs => "theirs",
                Resolution::Edit { .. } => "edited",
                Resolution::Skip => "skip",
            };
            let line = format!("{label}  ({tag})");
            let mut style = Style::default();
            if i == state.selected_file {
                style = style.add_modifier(Modifier::REVERSED);
            }
            ListItem::new(line).style(style)
        })
        .collect();
    let list = List::new(items).block(Block::default().borders(Borders::ALL).title("files"));
    frame.render_widget(list, area);
}

fn draw_pane(
    frame: &mut ratatui::Frame,
    area: Rect,
    title: &str,
    bytes: &[u8],
    highlight: Option<std::ops::Range<usize>>,
) {
    // Convert to text best-effort. Non-UTF-8 bytes pass through as the
    // replacement character — better than an empty pane.
    let text = String::from_utf8_lossy(bytes);

    // Build lines with highlighting for any byte range that falls within
    // the conflict region. The highlight is computed in *byte* space
    // (since that's what ConflictRegion uses) and translated to the
    // current line as we walk.
    let mut lines: Vec<Line> = Vec::new();
    let mut byte_offset = 0usize;
    for raw_line in text.split('\n') {
        let line_start = byte_offset;
        let line_end = line_start + raw_line.len();
        // We split on '\n' so the byte itself wasn't included in
        // raw_line — account for it in byte_offset.
        byte_offset = line_end + 1;

        let line_span = match &highlight {
            Some(range) if range.start < line_end && range.end > line_start => {
                let h_start = range.start.saturating_sub(line_start);
                let h_end = range.end.saturating_sub(line_start).min(raw_line.len());
                let mut spans = Vec::new();
                if h_start > 0 {
                    spans.push(Span::raw(safe_substr(raw_line, 0, h_start)));
                }
                if h_end > h_start {
                    spans.push(Span::styled(
                        safe_substr(raw_line, h_start, h_end),
                        Style::default().add_modifier(Modifier::REVERSED),
                    ));
                }
                if h_end < raw_line.len() {
                    spans.push(Span::raw(safe_substr(raw_line, h_end, raw_line.len())));
                }
                Line::from(spans)
            }
            _ => Line::from(raw_line.to_string()),
        };
        lines.push(line_span);
    }

    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title.to_string()),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(p, area);
}

/// Slice `&str` by byte range, snapping each end to the nearest later
/// char boundary. Without this, slicing into a multi-byte UTF-8
/// sequence panics — and `ConflictRegion` ranges are byte ranges.
fn safe_substr(s: &str, start: usize, end: usize) -> String {
    let mut a = start.min(s.len());
    while a < s.len() && !s.is_char_boundary(a) {
        a += 1;
    }
    let mut b = end.min(s.len());
    while b < s.len() && !s.is_char_boundary(b) {
        b += 1;
    }
    if a > b {
        a = b;
    }
    s[a..b].to_string()
}

fn draw_status(frame: &mut ratatui::Frame, area: Rect, state: &ReviewState) {
    let file = state.current_file();
    let region_info = file
        .map(|f| {
            let n = f.conflict_regions().len();
            if n == 0 {
                "no conflicts".to_string()
            } else {
                format!("region {}/{}", state.selected_region + 1, n)
            }
        })
        .unwrap_or_default();
    let line1 = if state.read_only {
        // Explain mode shows the handler that produced the file's
        // outcome plus any engine notes — that's the whole point of
        // stepping through auto-resolutions per §6.7.
        let handler = file.map(|f| f.handler.as_str()).unwrap_or("");
        let notes = file.map(|f| f.notes.as_str()).unwrap_or("");
        if notes.is_empty() {
            format!(" {region_info}    handler: {handler}")
        } else {
            format!(" {region_info}    handler: {handler}    notes: {notes}")
        }
    } else {
        let resolution = match state.current_resolution() {
            Resolution::KeepCurrent => "keep current".to_string(),
            Resolution::AcceptOurs => "accept ours".into(),
            Resolution::AcceptTheirs => "accept theirs".into(),
            Resolution::Edit { bytes } => format!("edited ({} bytes)", bytes.len()),
            Resolution::Skip => "skip".into(),
        };
        format!(" {region_info}    resolution: {resolution}")
    };
    let line2 = if state.read_only {
        " j/k file  n/p region                                                    q quit"
    } else {
        " j/k file  n/p region   o ours  t theirs  e edit  c keep  s skip   q quit"
    };
    let p = Paragraph::new(vec![
        Line::from(line1).style(Style::default().add_modifier(Modifier::REVERSED)),
        Line::from(line2),
    ]);
    frame.render_widget(p, area);
}

/// Build a non-interactive textual summary of structured conflicts.
/// Useful when the caller invokes `levcs merge --explain` or wants
/// to drive the JSON reporter described in §6.7.
pub fn summarize(regions: &[ConflictRegion]) -> String {
    let mut s = String::new();
    for r in regions {
        s.push_str(&format!(
            "- {} (base {}..{}, ours {}..{}, theirs {}..{})\n",
            r.description,
            r.base.start,
            r.base.end,
            r.ours.start,
            r.ours.end,
            r.theirs.start,
            r.theirs.end
        ));
    }
    s
}

#[cfg(test)]
mod key_tests {
    use super::*;
    use crossterm::event::KeyCode;
    use std::ops::Range;

    fn entry(path: &str, regions: usize) -> FileEntry {
        let regs: Vec<ConflictRegion> = (0..regions)
            .map(|i| ConflictRegion {
                description: format!("region {i}"),
                base: Range { start: 0, end: 0 },
                ours: Range { start: 0, end: 0 },
                theirs: Range { start: 0, end: 0 },
            })
            .collect();
        FileEntry {
            path: path.into(),
            status: if regions == 0 {
                MergeStatus::Merged {
                    content: vec![],
                    notes: vec![],
                }
            } else {
                MergeStatus::Conflict {
                    regions: regs,
                    partial: vec![],
                }
            },
            current: vec![],
            ours: vec![],
            theirs: vec![],
            base: vec![],
            handler: String::new(),
            notes: String::new(),
        }
    }

    #[test]
    fn handle_key_routes_resolutions() {
        let mut s = ReviewState::new(vec![entry("a", 1), entry("b", 1)]);
        handle_key(&mut s, KeyCode::Char('o'));
        assert_eq!(s.current_resolution(), Resolution::AcceptOurs);
        handle_key(&mut s, KeyCode::Char('j'));
        handle_key(&mut s, KeyCode::Char('t'));
        assert_eq!(s.current_resolution(), Resolution::AcceptTheirs);
    }

    #[test]
    fn handle_key_quits_on_q_and_esc() {
        let mut s = ReviewState::new(vec![entry("a", 0)]);
        handle_key(&mut s, KeyCode::Char('q'));
        assert!(s.quitting);

        let mut s2 = ReviewState::new(vec![entry("a", 0)]);
        handle_key(&mut s2, KeyCode::Esc);
        assert!(s2.quitting);
    }

    #[test]
    fn handle_key_navigates_regions() {
        let mut s = ReviewState::new(vec![entry("a", 4)]);
        handle_key(&mut s, KeyCode::Char('n'));
        handle_key(&mut s, KeyCode::Char('n'));
        assert_eq!(s.selected_region, 2);
        handle_key(&mut s, KeyCode::Char('p'));
        assert_eq!(s.selected_region, 1);
    }

    #[test]
    fn handle_key_ignores_unknown_keys() {
        let mut s = ReviewState::new(vec![entry("a", 1)]);
        handle_key(&mut s, KeyCode::Char('x'));
        handle_key(&mut s, KeyCode::F(5));
        assert_eq!(s.current_resolution(), Resolution::KeepCurrent);
        assert!(!s.quitting);
    }

    #[test]
    fn safe_substr_handles_multibyte_correctly() {
        let s = "héllo wörld";
        // Ranges that fall inside multi-byte characters must not panic.
        let _ = safe_substr(s, 1, 4);
        let _ = safe_substr(s, 0, s.len() + 100);
        let _ = safe_substr(s, 100, 200);
    }

    #[test]
    fn safe_substr_returns_full_slice_when_aligned() {
        let s = "hello world";
        assert_eq!(safe_substr(s, 0, 5), "hello");
        assert_eq!(safe_substr(s, 6, 11), "world");
    }
}

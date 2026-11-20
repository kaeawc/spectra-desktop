//! The process list: a search field over a virtualised table of groups (an app with its
//! helpers, several of one program) that open onto their processes.

use std::borrow::Cow;

use rune::{Align, El, col, el, icon, row, text};
use rune_kit::{Cell, Kit, Table, TableColumn, TextInput};

use super::card::notice;
use crate::app::App;
use crate::groups::{GroupKind, Nav, RowRef};
use crate::procs::{SignStatus, fmt_count, fmt_cpu, fmt_mem};

/// A signature as a word and a shape, so it reads without colour: trusted ones plain with a
/// check, unidentified ones outlined, an invalid one outlined with a cross.
pub fn sign_badge(status: SignStatus, k: &Kit) -> El {
    let c = &k.c;
    let font = k.ty.text_xsmall_medium;
    let pill = |ink, mark: Option<&'static rune::Icon>| {
        let mut r = row()
            .gap(3.0)
            .center_y()
            .px(6.0)
            .h(18.0)
            .radius(9.0)
            .border(1.0, ink);
        if let Some(m) = mark {
            r = r.child(icon(m, 11.0).color(ink));
        }
        r.child(text(status.label()).font(font).color(ink))
    };
    let badge = match status {
        SignStatus::Apple | SignStatus::DeveloperId => row()
            .gap(3.0)
            .center_y()
            .child(icon(k.glyph.check_small, 12.0).color(c.icon_faint))
            .child(text(status.label()).font(k.ty.text_xsmall).color(c.text_muted)),
        SignStatus::Adhoc | SignStatus::Unsigned => pill(c.warning.fg, None),
        SignStatus::Invalid => pill(c.danger.fg, Some(k.glyph.circle_x)),
        SignStatus::Unknown => row().child(text("Unknown").font(k.ty.text_xsmall).color(c.text_faint)),
    };
    badge.label(format!("Signature: {}", status.label()))
}

/// A number, right-aligned in its column with figures of one width.
fn number(v: String, k: &Kit) -> Cell {
    Cell::el(
        text(v)
            .font(k.ty.text_small.features("'tnum' 1"))
            .color(k.c.text_base),
    )
}

/// The name column: an open/closed mark for a group, the name, and a faint runtime and role.
fn name_cell(name: String, kind: String, depth: u8, open: Option<bool>, k: &Kit) -> Cell {
    let c = &k.c;
    let mark = match open {
        Some(o) => icon(if o { k.glyph.triangle_down } else { k.glyph.triangle_right }, 10.0).color(c.icon_muted),
        None => el().size(10.0, 10.0),
    };
    Cell::el(
        row()
            .gap(6.0)
            .center_y()
            .min_w(0.0)
            .shrink()
            .pl(f32::from(depth) * 18.0)
            .child(mark)
            .child(
                text(name.clone())
                    .font(k.ty.text_small)
                    .color(c.text_base)
                    .truncate()
                    .shrink()
                    .min_w(0.0)
                    .help_when_truncated(name),
            )
            // Capped, so a long name keeps most of the room.
            .child(
                text(kind)
                    .font(k.ty.text_xsmall)
                    .color(c.text_faint)
                    .truncate()
                    .shrink()
                    .min_w(0.0)
                    .max_w(110.0),
            ),
    )
}

fn cell(s: &App, i: usize, column: &str, k: &Kit) -> Cell {
    let Some(r) = s.rows.get(i) else {
        return Cell::text("");
    };
    match r.item {
        RowRef::Group(g) => {
            let g = &s.groups[g];
            match column {
                "name" => {
                    let kind = match g.kind {
                        GroupKind::App => format!("{} · {}", g.runtime.label(), g.role.label()),
                        _ => g.runtime.label().to_owned(),
                    };
                    name_cell(g.name.clone(), kind, 0, Some(s.open_groups.contains(&g.id)), k)
                }
                "sign" => Cell::el(sign_badge(g.signing, k)),
                "cpu" => number(fmt_cpu(g.cpu), k),
                "mem" => number(fmt_mem(g.rss_kib), k),
                "threads" => number(fmt_count(g.threads), k),
                "count" => number(fmt_count(g.pids.len() as u64), k),
                _ => Cell::text(""),
            }
        }
        RowRef::Process(pid) => {
            let Some(p) = s.process(pid) else {
                return Cell::text("");
            };
            match column {
                "name" => {
                    // Under its group the runtime is the group's; the role tells helpers apart.
                    let kind = if r.depth > 0 {
                        p.role.label().to_owned()
                    } else {
                        format!("{} · {}", p.runtime.label(), p.role.label())
                    };
                    name_cell(p.name(), kind, r.depth, None, k)
                }
                "sign" => Cell::el(sign_badge(p.sign_status(), k)),
                "cpu" => number(fmt_cpu(p.cpu_pct), k),
                "mem" => number(fmt_mem(p.rss_kib), k),
                "threads" => number(fmt_count(p.thread_count), k),
                "pid" => Cell::text(pid.to_string()).muted(),
                _ => Cell::text(""),
            }
        }
    }
}

fn row_id(s: &App, i: usize) -> Cow<'_, str> {
    Cow::Borrowed(s.rows[i].id.as_str())
}

fn table(s: &App, k: &Kit) -> El {
    let ck = k.clone();
    let num = |id: &str, title: &str, w: f32| TableColumn::new(id, title).width(w).min(w - 12.0).max(w + 60.0).align(Align::End);
    Table::new(|s: &App| &s.table, |s: &mut App| &mut s.table, |s: &App| s.rows.len(), row_id)
        .name("Processes")
        .column(TableColumn::new("name", "Name").flex(1.0).min(180.0).sortable())
        .column(TableColumn::new("sign", "Signature").width(104.0).min(90.0).max(160.0))
        .column(num("cpu", "CPU", 72.0).sortable())
        .column(num("mem", "Memory", 80.0).sortable())
        .column(num("threads", "Threads", 74.0))
        .column(num("count", "Processes", 90.0))
        .column(num("pid", "PID", 64.0))
        .cell(move |s: &App, i, column| cell(s, i, column, &ck))
        .on_sort(|s: &mut App, column, dir, _| s.sort_by(column, dir))
        .on_select(|s: &mut App, id, _| s.press_row(id))
        .on_open(|s: &mut App, id, _| s.press_row(id))
        .build(s, k)
        .grow(1.0)
        .min_h(0.0)
}

pub fn list(s: &App, k: &Kit) -> El {
    let c = &k.c;
    let page = col().key("list").w_full().h_full().min_h(0.0).padding(16.0).gap(12.0);
    if let Some(n) = super::home::feed_notice(s, k) {
        return page.child(n);
    }
    let shown: usize = s.groups.iter().map(|g| g.pids.len()).sum();
    let what = if s.nav == Nav::All { "processes".to_owned() } else { format!("of {} processes", fmt_count(s.procs.len() as u64)) };
    let count = format!("{} {what} · {} rows", fmt_count(shown as u64), fmt_count(s.groups.len() as u64));
    let search = TextInput::new(&s.query)
        .placeholder("Search name, pid, bundle id or path")
        .label("Search processes")
        .leading_icon(k.glyph.search)
        .clear_button()
        .width(Some(300.0))
        .on_edit(|s: &mut App| &mut s.query)
        .on_change(|s: &mut App, _| s.rebuild())
        .build(k)
        .key("search");
    let bar = row()
        .w_full()
        .gap(12.0)
        .center_y()
        .child(search)
        .child(el().grow(1.0))
        .child(text(count).key("list-count").font(k.ty.small).color(c.text_muted));
    let body = if s.rows.is_empty() {
        col().w_full().child(notice("Nothing matches", "Try another word, or clear the search.", k))
    } else {
        col()
            .key("frame")
            .w_full()
            .grow(1.0)
            .min_h(0.0)
            .radius(k.radius.md)
            .fill(c.bg_base)
            .border(1.0, c.border_weak)
            .clip_rounded(k.radius.md)
            .child(table(s, k))
    };
    page.child(bar).child(body)
}

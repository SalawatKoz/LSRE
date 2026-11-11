//! Лента переключения режимов: закладки в стиле браузера — Чат · Код · Архитектура · Графика.

use crate::state::Screen;
use crate::theme::{self, Tokens};
use crate::CraftApp;
use egui::{Align2, FontId, Pos2, Rect, Sense, Stroke, Vec2};

const TAB_H: f32 = 34.0;

fn is_chat(screen: Screen) -> bool {
    matches!(screen, Screen::Home | Screen::Project | Screen::Ask)
}

fn is_active(screen: Screen, tab: Screen) -> bool {
    match tab {
        Screen::Home => is_chat(screen),
        other => screen == other,
    }
}

/// Нарисовать закладки и переключить экран по клику.
pub fn ribbon(app: &mut CraftApp, ui: &mut egui::Ui) {
    let t = Tokens::get(ui.ctx());
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, TAB_H), Sense::hover());
    ui.painter().rect_filled(rect, 0.0, t.chrome);

    let tabs: [(&str, Screen); 4] = [
        ("Чат", Screen::Home),
        ("Код", Screen::Code),
        ("Архитектура", Screen::Architecture),
        ("Графика", Screen::Graphics),
    ];

    let mut x = rect.left() + 8.0;
    let mut clicked: Option<Screen> = None;
    for (label, screen) in tabs {
        let font = FontId::proportional(theme::SMALL);
        let galley = ui.painter().layout_no_wrap(label.to_owned(), font.clone(), t.text);
        let w = galley.size().x + 40.0;
        let active = is_active(app.state.screen, screen);
        let tab = Rect::from_min_size(Pos2::new(x, rect.top() + 5.0), Vec2::new(w, TAB_H - 5.0));
        let resp = ui.interact(tab, egui::Id::new(("view-tab", label)), Sense::click());
        let hot = resp.hovered();
        let fill = if active { t.canvas } else if hot { t.hover } else { t.chrome };
        ui.painter().rect_filled(tab, egui::CornerRadius { nw: 8, ne: 8, sw: 0, se: 0 }, fill);
        if active {
            // Тонкая акцентная полоса сверху — активная закладка «растёт» из панели.
            ui.painter().rect_filled(
                Rect::from_min_size(tab.min, Vec2::new(tab.width(), 2.0)),
                egui::CornerRadius { nw: 8, ne: 8, sw: 0, se: 0 },
                t.accent,
            );
        }
        let ink = if active { t.text } else if hot { t.text } else { t.text_dim };
        ui.painter().text(
            Pos2::new(tab.center().x, tab.center().y + 1.0),
            Align2::CENTER_CENTER,
            label,
            font,
            ink,
        );
        if resp.clicked() {
            clicked = Some(screen);
        }
        if hot {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        x += w + 2.0;
    }

    // Линия под закладками; под активной её нет, поэтому она «сливается» с экраном.
    let y = rect.bottom() - 0.5;
    if let Some(active_screen) = tabs.iter().find(|(_, s)| is_active(app.state.screen, *s)).map(|(_, s)| *s) {
        let mut ax = rect.left() + 8.0;
        for (label, screen) in tabs {
            let font = FontId::proportional(theme::SMALL);
            let w = ui.painter().layout_no_wrap(label.to_owned(), font, t.text).size().x + 40.0;
            if screen != active_screen {
                ui.painter().hline(egui::Rangef::new(ax, ax + w + 2.0), y, Stroke::new(1.0, t.separator));
            }
            ax += w + 2.0;
        }
    }

    if let Some(screen) = clicked {
        app.state.screen = match screen {
            Screen::Home => if app.workspace.is_some() { Screen::Project } else { Screen::Home },
            other => other,
        };
    }
}

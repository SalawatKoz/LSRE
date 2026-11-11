//! Встроенный редактор макетов: UI-крейт FigCraft как вкладка «Графика» внутри LSRE.
//! Шрифт общий — IBM Plex Sans Condensed; диалоги файлов отдаём через rfd.

use crate::theme;
use egui::Ui;
use figcraft_ui_egui::{ContentsFuture, DialogFuture, Services};
use std::path::PathBuf;
use std::sync::OnceLock;

static INIT: OnceLock<()> = OnceLock::new();

/// Нативные сервисы для редактора: файловые диалоги, URL, проводник.
struct LsreServices;

impl Services for LsreServices {
    fn pick_open(&mut self, title: &str, exts: &[&str]) -> DialogFuture {
        let mut dialog = rfd::FileDialog::new().set_title(title);
        for ext in exts {
            dialog = dialog.add_filter(ext.to_uppercase(), &[*ext]);
        }
        Box::pin(std::future::ready(dialog.pick_file()))
    }

    fn pick_save(&mut self, title: &str, name: &str, exts: &[&str]) -> DialogFuture {
        let mut dialog = rfd::FileDialog::new().set_title(title).set_file_name(name);
        for ext in exts {
            dialog = dialog.add_filter(ext.to_uppercase(), &[*ext]);
        }
        Box::pin(std::future::ready(dialog.save_file()))
    }

    fn pick_folder(&mut self, title: &str) -> DialogFuture {
        Box::pin(std::future::ready(rfd::FileDialog::new().set_title(title).pick_folder()))
    }

    fn pick_open_contents(&mut self, _title: &str, _exts: &[&str]) -> Option<ContentsFuture> {
        None
    }

    fn open_url(&mut self, url: &str) {
        let _ = std::process::Command::new("cmd").args(["/c", "start", "", url]).spawn();
    }

    fn reveal_path(&mut self, path: &std::path::Path) {
        let _ = std::process::Command::new("explorer").arg(path).spawn();
    }

    fn system_dark(&self) -> Option<bool> {
        // Одна тема на всё приложение: редактор тёмный, как LSRE.
        Some(true)
    }

    fn system_language(&self) -> Option<String> {
        Some("ru".to_string())
    }
}

/// Создать редактор один раз и зарегистрировать его в глобальном слоте FigCraft.
fn ensure_installed(ctx: &egui::Context) {
    INIT.get_or_init(|| {
        let mut session = figcraft_engine::Session::empty();
        session.prefs.theme = "dark".to_string();
        let mut app = figcraft_ui_egui::FigApp::new(session, Box::new(LsreServices));
        // Без приветственного экрана и его логотипа: сразу рабочий холст.
        app.ui.home = false;
        figcraft_ui_egui::windows::install(app);
        theme::install_fonts(ctx);
    });
}

/// Нарисовать редактор (холст, панели, меню) в текущей области.
pub fn show(ui: &mut Ui) {
    let ctx = ui.ctx().clone();
    ensure_installed(&ctx);
    let drawn = figcraft_ui_egui::windows::with_app(|fig| {
        figcraft_ui_egui::windows::guard(fig, &ctx, |fig| fig.ui(ui));
    });
    if drawn.is_none() {
        ui.label("Редактор макетов не инициализировался");
    }
}

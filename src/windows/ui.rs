use std::{
    cell::{Cell, OnceCell, RefCell},
    cmp::Ordering,
    mem::size_of,
    path::PathBuf,
    ptr::{null, null_mut},
    sync::{Arc, mpsc},
};

use anyhow::{Context, Result, bail, ensure};
use tokio::runtime::Runtime;
use windows_sys::Win32::{
    Foundation::*,
    Graphics::{Dwm::*, Gdi::*},
    System::{LibraryLoader::GetModuleHandleW, SystemServices::SS_CENTER},
    UI::{
        Accessibility::{HCF_HIGHCONTRASTON, HIGHCONTRASTW},
        Controls::*,
        HiDpi::*,
        Input::KeyboardAndMouse::*,
        Shell::ShellExecuteW,
        WindowsAndMessaging::*,
    },
};

use super::{
    demo,
    native::*,
    system::{self, ProxyLease, SingleInstance, wide},
};
use crate::{
    archive::Format,
    capture::{CaptureStore, SessionKind, SessionSummary, Side},
    certificate::CertificateAuthority,
    filter::Filter,
    har::ExportMode,
    inspect::{self, Inspector},
    proxy::{self, ProxyConfig, ProxyHandle},
    saz, troubleshoot,
};

const CAPTURE: u16 = 100;
const STOP: u16 = 101;
const CLEAR: u16 = 102;
const EXPORT: u16 = 103;
const SYSTEM_PROXY: u16 = 104;
const HTTPS: u16 = 105;
const PORT: u16 = 106;
const AUTOSCROLL: u16 = 107;
const SEARCH: u16 = 108;
const SCOPE: u16 = 109;
const SESSIONS: u16 = 110;
const MAIN_TABS: u16 = 111;
const REQUEST_TABS: u16 = 112;
const RESPONSE_TABS: u16 = 113;
const REQUEST_BODY: u16 = 114;
const RESPONSE_BODY: u16 = 115;
const DETAIL_BODY: u16 = 116;
const URL: u16 = 117;
const COPY_URL: u16 = 118;
const EXPORT_FULL: u16 = 200;
const TRUST_CA: u16 = 201;
const EXPORT_CA: u16 = 202;
const REMOVE_CA: u16 = 203;
const RESET_CA: u16 = 204;
const DATA_FOLDER: u16 = 205;
const GUIDE: u16 = 206;
const ABOUT: u16 = 207;
const EXIT: u16 = 208;
const FOCUS_SEARCH: u16 = 209;
const IMPORT_SAZ: u16 = 210;
const EXPORT_SAZ: u16 = 211;
const EXPORT_SAZ_SANITIZED: u16 = 212;
const HIDE_ASSETS: u16 = 213;
const RECENT_FIRST: u16 = 230;
const RECENT_LAST: u16 = 234;
const CLEAR_RECENT: u16 = 235;
const REVIEW_FIRST: u16 = 215;
const FIND: u16 = 216;
const FIND_QUERY: u16 = 217;
const FIND_CASE: u16 = 218;
const FIND_NEXT: u16 = 219;
const FIND_PREVIOUS: u16 = 220;
const FIND_CLOSE: u16 = 221;
const FIND_INFO: u16 = 222;
const CAPTURE_WINDOWS: i32 = 1001;
const CAPTURE_MANUAL: i32 = 1002;
const HTTPS_TRUST_WINDOWS: i32 = 1101;
const HTTPS_CLIENT_TRUST: i32 = 1102;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaptureMode {
    Windows,
    Manual,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HttpsTrust {
    Windows,
    ClientManaged,
}

const COLUMNS: [(&str, i32); 9] = [
    ("#", 42),
    ("Result", 88),
    ("Method", 76),
    ("Protocol", 70),
    ("Host", 166),
    ("URL", 230),
    ("Size", 74),
    ("Time", 76),
    ("Content type", 144),
];

struct Controls {
    hide_assets: HWND,
    review: HWND,
    find_query: HWND,
    find_case: HWND,
    find_next: HWND,
    find_previous: HWND,
    find_close: HWND,
    find_info: HWND,
    capture: HWND,
    stop: HWND,
    clear: HWND,
    export: HWND,
    system_proxy: HWND,
    https: HWND,
    port_label: HWND,
    port: HWND,
    autoscroll: HWND,
    search: HWND,
    scope: HWND,
    list: HWND,
    main_tabs: HWND,
    request_tabs: HWND,
    response_tabs: HWND,
    request: HWND,
    response: HWND,
    detail: HWND,
    url: HWND,
    copy: HWND,
}

impl Controls {
    fn all(&self) -> [HWND; 28] {
        [
            self.hide_assets,
            self.review,
            self.find_query,
            self.find_case,
            self.find_next,
            self.find_previous,
            self.find_close,
            self.find_info,
            self.capture,
            self.stop,
            self.clear,
            self.export,
            self.system_proxy,
            self.https,
            self.port_label,
            self.port,
            self.autoscroll,
            self.search,
            self.scope,
            self.list,
            self.main_tabs,
            self.request_tabs,
            self.response_tabs,
            self.request,
            self.response,
            self.detail,
            self.url,
            self.copy,
        ]
    }
}

type ExportResult = std::result::Result<(PathBuf, ExportMode), String>;
type ImportResult = std::result::Result<(PathBuf, saz::ImportedArchive), String>;

// Shared references plus narrowly scoped interior borrows allow Win32's synchronous reentrancy.
// No mutable App reference is ever created from window user data.
struct App {
    hide_assets: Cell<bool>,
    review_cursor: Cell<Option<u64>>,
    find_open: Cell<bool>,
    find_target: Cell<usize>,
    find_cursor: Cell<Option<(usize, usize)>>,
    hwnd: Cell<HWND>,
    dpi: Cell<u32>,
    controls: OnceCell<Controls>,
    fonts: RefCell<Fonts>,
    runtime: Runtime,
    store: Arc<CaptureStore>,
    proxy: RefCell<Option<ProxyHandle>>,
    lease: RefCell<Option<ProxyLease>>,
    ca: RefCell<Option<Arc<CertificateAuthority>>>,
    active: Cell<bool>,
    decrypt: Cell<bool>,
    https_trust: Cell<HttpsTrust>,
    routed: Cell<bool>,
    demo: Cell<bool>,
    busy: Cell<bool>,
    failure_reported: Cell<bool>,
    rebuilding: Cell<bool>,
    rows: RefCell<Vec<SessionSummary>>,
    selected: Cell<Option<u64>>,
    filter: RefCell<Filter>,
    filter_error: RefCell<Option<String>>,
    scope: Cell<usize>,
    sort: Cell<(usize, bool)>,
    main_tab: Cell<usize>,
    request_tab: Cell<Inspector>,
    response_tab: Cell<Inspector>,
    split: Cell<f64>,
    dragging: Cell<bool>,
    revision: Cell<u64>,
    footer: RefCell<String>,
    status: RefCell<String>,
    request_info: RefCell<String>,
    response_info: RefCell<String>,
    viewer_text: RefCell<[String; 3]>,
    export: RefCell<Option<mpsc::Receiver<ExportResult>>>,
    import: RefCell<Option<mpsc::Receiver<ImportResult>>>,
    archive_name: RefCell<Option<String>>,
    initialization_error: RefCell<Option<String>>,
    recent: RefCell<super::recent::RecentFiles>,
    recent_warning: RefCell<Option<String>>,
}

impl App {
    fn new(demo: bool) -> Result<Self> {
        // SAFETY: GetDpiForSystem is available on the minimum supported Windows 10 release.
        let dpi = unsafe { GetDpiForSystem() }.max(96);
        let store = Arc::new(CaptureStore::default());
        if let Some(message) = system::recover_proxy()? {
            store.notice(message);
        }
        if demo {
            demo::populate(&store);
        }
        let directory = system::data_directory()?;
        let (recent, recent_warning) = match super::recent::RecentFiles::load(&directory) {
            Ok(history) => (history, None),
            Err(error) => (
                super::recent::RecentFiles::empty(&directory),
                Some(format!(
                    "Recent-file history could not be loaded: {error:#}"
                )),
            ),
        };
        Ok(Self {
            hide_assets: Cell::new(troubleshoot::HIDE_ASSETS_DEFAULT),
            review_cursor: Cell::new(None),
            find_open: Cell::new(false),
            find_target: Cell::new(1),
            find_cursor: Cell::new(None),
            hwnd: Cell::new(null_mut()),
            dpi: Cell::new(dpi),
            controls: OnceCell::new(),
            fonts: RefCell::new(Fonts::new(dpi)?),
            runtime: tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .context("Create proxy runtime")?,
            store,
            proxy: RefCell::new(None),
            lease: RefCell::new(None),
            ca: RefCell::new(None),
            active: Cell::new(false),
            decrypt: Cell::new(false),
            https_trust: Cell::new(HttpsTrust::ClientManaged),
            routed: Cell::new(false),
            demo: Cell::new(demo),
            busy: Cell::new(false),
            failure_reported: Cell::new(false),
            rebuilding: Cell::new(false),
            rows: RefCell::new(Vec::new()),
            selected: Cell::new(if demo { Some(7) } else { None }),
            filter: RefCell::new(Filter::default()),
            filter_error: RefCell::new(None),
            scope: Cell::new(0),
            sort: Cell::new((0, true)),
            main_tab: Cell::new(0),
            request_tab: Cell::new(Inspector::Headers),
            response_tab: Cell::new(Inspector::Json),
            split: Cell::new(0.57),
            dragging: Cell::new(false),
            revision: Cell::new(0),
            footer: RefCell::new(String::new()),
            status: RefCell::new(if demo {
                "Demo data - no traffic is being intercepted".into()
            } else {
                "Ready - nothing is being captured".into()
            }),
            request_info: RefCell::new(String::new()),
            response_info: RefCell::new(String::new()),
            viewer_text: RefCell::new(Default::default()),
            export: RefCell::new(None),
            import: RefCell::new(None),
            archive_name: RefCell::new(None),
            initialization_error: RefCell::new(None),
            recent: RefCell::new(recent),
            recent_warning: RefCell::new(recent_warning),
        })
    }

    fn s(&self, value: i32) -> i32 {
        scaled(value, self.dpi.get())
    }

    fn initialize(&self) -> Result<()> {
        let parent = self.hwnd.get();
        let button = |text, id| {
            child(
                parent,
                "BUTTON",
                text,
                WS_TABSTOP | BS_OWNERDRAW as u32,
                0,
                id,
            )
        };
        let checkbox = |text, id| {
            child(
                parent,
                "BUTTON",
                text,
                WS_TABSTOP | BS_AUTOCHECKBOX as u32,
                0,
                id,
            )
        };
        let editor = |id| {
            child(
                parent,
                "EDIT",
                "",
                WS_TABSTOP
                    | WS_VSCROLL
                    | WS_HSCROLL
                    | ES_MULTILINE as u32
                    | ES_READONLY as u32
                    | ES_NOHIDESEL as u32
                    | ES_AUTOVSCROLL as u32
                    | ES_AUTOHSCROLL as u32,
                0,
                id,
            )
        };
        let tabs = |id| child(parent, "SysTabControl32", "", WS_TABSTOP, 0, id);
        let controls = Controls {
            hide_assets: checkbox("Hide assets", HIDE_ASSETS)?,
            review: button("Review first (0 visible)", REVIEW_FIRST)?,
            find_query: child(
                parent,
                "EDIT",
                "",
                WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL as u32,
                0,
                FIND_QUERY,
            )?,
            find_case: checkbox("Match case", FIND_CASE)?,
            find_next: child(
                parent,
                "BUTTON",
                "Next",
                WS_TABSTOP | BS_PUSHBUTTON as u32,
                0,
                FIND_NEXT,
            )?,
            find_previous: child(
                parent,
                "BUTTON",
                "Previous",
                WS_TABSTOP | BS_PUSHBUTTON as u32,
                0,
                FIND_PREVIOUS,
            )?,
            find_close: child(
                parent,
                "BUTTON",
                "Close",
                WS_TABSTOP | BS_PUSHBUTTON as u32,
                0,
                FIND_CLOSE,
            )?,
            find_info: child(
                parent,
                "STATIC",
                "Find in displayed preview only",
                0,
                0,
                FIND_INFO,
            )?,
            capture: button("Start capture", CAPTURE)?,
            stop: button("Stop", STOP)?,
            clear: button("Clear", CLEAR)?,
            export: button("Save HAR", EXPORT)?,
            system_proxy: checkbox("Windows proxy", SYSTEM_PROXY)?,
            https: checkbox("Decrypt HTTPS", HTTPS)?,
            port_label: child(parent, "STATIC", "PORT", SS_CENTER, 0, 0)?,
            port: child(
                parent,
                "EDIT",
                "8866",
                WS_TABSTOP | WS_BORDER | ES_NUMBER as u32 | ES_CENTER as u32,
                0,
                PORT,
            )?,
            autoscroll: checkbox("Auto-scroll", AUTOSCROLL)?,
            search: child(
                parent,
                "EDIT",
                "",
                WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL as u32,
                0,
                SEARCH,
            )?,
            scope: child(
                parent,
                "COMBOBOX",
                "",
                WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST as u32,
                0,
                SCOPE,
            )?,
            list: child(
                parent,
                "SysListView32",
                "",
                WS_TABSTOP | LVS_REPORT | LVS_OWNERDATA | LVS_SHOWSELALWAYS | LVS_SINGLESEL,
                0,
                SESSIONS,
            )?,
            main_tabs: tabs(MAIN_TABS)?,
            request_tabs: tabs(REQUEST_TABS)?,
            response_tabs: tabs(RESPONSE_TABS)?,
            request: editor(REQUEST_BODY)?,
            response: editor(RESPONSE_BODY)?,
            detail: editor(DETAIL_BODY)?,
            url: child(
                parent,
                "EDIT",
                "",
                WS_TABSTOP | ES_READONLY as u32 | ES_AUTOHSCROLL as u32,
                0,
                URL,
            )?,
            copy: button("Copy URL", COPY_URL)?,
        };
        // SAFETY: Every message here targets a just-created native control with correctly typed buffers.
        unsafe {
            SetWindowTheme(controls.list, wide("Explorer").as_ptr(), null());
            SendMessageW(
                controls.list,
                LVM_SETEXTENDEDLISTVIEWSTYLE,
                0,
                (LVS_EX_FULLROWSELECT
                    | LVS_EX_DOUBLEBUFFER
                    | LVS_EX_HEADERDRAGDROP
                    | LVS_EX_INFOTIP) as isize,
            );
            SendMessageW(controls.list, LVM_SETBKCOLOR, 0, WHITE as isize);
            SendMessageW(controls.list, LVM_SETTEXTBKCOLOR, 0, WHITE as isize);
            SendMessageW(controls.list, LVM_SETTEXTCOLOR, 0, TEXT as isize);
            for (index, (name, width)) in COLUMNS.iter().enumerate() {
                let mut name = wide(name);
                let column = LVCOLUMNW {
                    mask: LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM,
                    pszText: name.as_mut_ptr(),
                    cx: self.s(*width),
                    iSubItem: index as i32,
                    ..Default::default()
                };
                if SendMessageW(
                    controls.list,
                    LVM_INSERTCOLUMNW,
                    index,
                    &column as *const _ as isize,
                ) == -1
                {
                    bail!("Create session table columns");
                }
            }
            for value in [
                "All traffic",
                "HTTP only",
                "HTTPS only",
                "Errors only",
                "JSON only",
                "Hide tunnels",
            ] {
                SendMessageW(
                    controls.scope,
                    CB_ADDSTRING,
                    0,
                    wide(value).as_ptr() as isize,
                );
            }
            set_checked(controls.hide_assets, self.hide_assets.get());
            SendMessageW(controls.scope, CB_SETCURSEL, 0, 0);
            SendMessageW(
                controls.search,
                EM_SETCUEBANNER,
                1,
                wide("Search traffic...  host:api  status:4xx").as_ptr() as isize,
            );
            SendMessageW(controls.search, EM_SETLIMITTEXT, 2048, 0);
            SendMessageW(controls.find_query, EM_SETLIMITTEXT, 256, 0);
            SendMessageW(
                controls.find_query,
                EM_SETCUEBANNER,
                1,
                wide("Find in message (Ctrl+F)").as_ptr() as isize,
            );
            SendMessageW(controls.port, EM_SETLIMITTEXT, 5, 0);
            for editor in [controls.request, controls.response, controls.detail] {
                SendMessageW(editor, EM_SETLIMITTEXT, 4 * 1024 * 1024, 0);
                SendMessageW(
                    editor,
                    EM_SETMARGINS,
                    (EC_LEFTMARGIN | EC_RIGHTMARGIN) as usize,
                    (self.s(8) | (self.s(8) << 16)) as isize,
                );
            }
            add_tabs(controls.main_tabs, &["Inspectors", "Timing", "Diagnostics"])?;
            add_tabs(controls.request_tabs, &["Headers", "Text", "JSON", "Hex"])?;
            add_tabs(controls.response_tabs, &["Headers", "Text", "JSON", "Hex"])?;
            SendMessageW(controls.response_tabs, TCM_SETCURSEL, 2, 0);
        }
        set_checked(controls.autoscroll, true);
        self.controls
            .set(controls)
            .map_err(|_| anyhow::anyhow!("Controls initialized twice"))?;
        self.apply_fonts(&self.fonts.borrow());
        self.update_toolbar();
        self.layout();
        self.refresh(true);
        // SAFETY: Frame colors are cosmetic Windows 11 enhancements; Windows 10 keeps its native frame.
        unsafe {
            let corner = DWMWCP_ROUND;
            let caption = NAVY;
            let color = WHITE;
            let result = DwmSetWindowAttribute(
                parent,
                DWMWA_WINDOW_CORNER_PREFERENCE as u32,
                (&corner as *const DWM_WINDOW_CORNER_PREFERENCE).cast(),
                size_of_val(&corner) as u32,
            );
            if result >= 0 {
                DwmSetWindowAttribute(
                    parent,
                    DWMWA_CAPTION_COLOR as u32,
                    (&caption as *const COLORREF).cast(),
                    4,
                );
                DwmSetWindowAttribute(
                    parent,
                    DWMWA_TEXT_COLOR as u32,
                    (&color as *const COLORREF).cast(),
                    4,
                );
            }
            if SetTimer(parent, 1, 250, None) == 0 {
                bail!("Create desktop refresh timer");
            }
        }
        Ok(())
    }

    fn apply_fonts(&self, fonts: &Fonts) {
        if let Some(c) = self.controls.get() {
            for handle in c.all() {
                set_font(handle, fonts.text.raw());
            }
            for handle in [c.request, c.response, c.detail] {
                set_font(handle, fonts.mono.raw());
            }
            set_font(c.port_label, fonts.small.raw());
            set_font(c.url, fonts.bold.raw());
        }
    }

    fn dimensions(&self) -> (i32, i32, i32) {
        let mut area = RECT::default();
        // SAFETY: hwnd is the live parent owned by this App.
        unsafe {
            GetClientRect(self.hwnd.get(), &mut area);
        }
        (
            area.right,
            area.bottom,
            (area.right as f64 * self.split.get()) as i32,
        )
    }

    fn layout(&self) {
        let Some(c) = self.controls.get() else { return };
        let (width, height, split) = self.dimensions();
        let s = |n| self.s(n);
        for (handle, x, w) in [
            (c.capture, 16, 140),
            (c.stop, 164, 60),
            (c.clear, 232, 64),
            (c.export, 304, 96),
            (c.system_proxy, 424, 136),
            (c.https, 572, 128),
            (c.port_label, 716, 34),
            (c.port, 754, 58),
        ] {
            position(handle, s(x), s(84), s(w), s(32));
        }
        position(c.autoscroll, width - s(126), s(84), s(114), s(32));
        position(c.search, s(16), s(151), split - s(174), s(29));
        position(c.scope, split - s(150), s(150), s(138), s(240));
        position(c.hide_assets, s(16), s(183), s(220), s(26));
        let list_top = if split >= s(460) {
            position(c.review, s(242), s(183), split - s(253), s(29));
            218
        } else {
            position(c.review, s(16), s(213), split - s(27), s(29));
            248
        };
        position(
            c.list,
            s(16),
            s(list_top),
            split - s(27),
            height - s(list_top + 43),
        );
        position(
            c.main_tabs,
            split + s(14),
            s(149),
            width - split - s(29),
            s(32),
        );
        position(c.url, split + s(22), s(198), width - split - s(142), s(27));
        position(c.copy, width - s(112), s(195), s(90), s(29));
        let right = width - split - s(44);
        let find_height = if self.find_open.get() { s(80) } else { 0 };
        let body_top = s(286) + find_height;
        let available = (height - body_top - s(109)).max(s(100));
        let request_height = (available as f64 * 0.43) as i32;
        let response_label = body_top + request_height + s(15);
        position(
            c.request_tabs,
            split + s(16),
            s(252) + find_height,
            right + s(12),
            s(30),
        );
        position(
            c.find_query,
            split + s(22),
            s(230),
            (right - s(220)).max(s(50)),
            s(26),
        );
        position(c.find_previous, width - s(233), s(230), s(78), s(26));
        position(c.find_next, width - s(151), s(230), s(58), s(26));
        position(c.find_close, width - s(89), s(230), s(64), s(26));
        position(c.find_case, split + s(22), s(260), s(110), s(22));
        position(c.find_info, split + s(22), s(285), right, s(22));
        position(c.request, split + s(21), body_top, right, request_height);
        position(
            c.response_tabs,
            split + s(16),
            response_label + s(22),
            right + s(12),
            s(30),
        );
        position(
            c.response,
            split + s(21),
            response_label + s(58),
            right,
            height - response_label - s(102),
        );
        position(c.detail, split + s(21), s(238), right, height - s(282));
        let inspectors = self.main_tab.get() == 0;
        for handle in [
            c.find_query,
            c.find_case,
            c.find_next,
            c.find_previous,
            c.find_close,
            c.find_info,
        ] {
            visible(handle, inspectors && self.find_open.get());
        }
        for handle in [c.request_tabs, c.response_tabs, c.request, c.response] {
            visible(handle, inspectors);
        }
        visible(c.detail, !inspectors);
        // SAFETY: The parent paints only chrome; native children repaint their own client areas.
        unsafe {
            InvalidateRect(self.hwnd.get(), null(), 0);
        }
    }

    fn update_toolbar(&self) {
        let Some(c) = self.controls.get() else { return };
        set_text(
            c.capture,
            if !self.active.get() {
                "Start capture"
            } else if self.store.recording() {
                "Pause capture"
            } else {
                "Resume capture"
            },
        );
        enable(c.stop, self.active.get());
        enable(c.capture, self.import.borrow().is_none());
        enable(c.clear, self.import.borrow().is_none());
        enable(c.port, !self.active.get());
        enable(c.https, !self.active.get());
        enable(c.system_proxy, self.active.get());
        enable(
            c.export,
            self.export.borrow().is_none() && self.import.borrow().is_none(),
        );
        enable(c.copy, self.selected.get().is_some());
        set_checked(c.https, self.decrypt.get());
        set_checked(c.system_proxy, self.routed.get());
        let title = if let Some(name) = self.archive_name.borrow().as_ref() {
            format!("Juan - {name} (archive)")
        } else if self.demo.get() {
            "Juan - Demo data (no traffic intercepted)".to_owned()
        } else {
            "Juan - Web Traffic Debugger".to_owned()
        };
        set_text(self.hwnd.get(), &title);
    }

    fn set_status(&self, status: impl Into<String>) {
        *self.status.borrow_mut() = status.into();
        // SAFETY: Invalidating posts a paint request rather than synchronously dispatching it.
        unsafe {
            InvalidateRect(self.hwnd.get(), null(), 0);
        }
    }

    fn refresh_recent_menu(&self) -> Result<()> {
        let history = make_recent_menu(&self.recent.borrow())?;
        // SAFETY: The live window owns File and its old submenu. The new submenu
        // transfers ownership only after SetMenuItemInfoW succeeds.
        unsafe {
            let file = GetSubMenu(GetMenu(self.hwnd.get()), 0);
            let old = GetSubMenu(file, 1);
            let info = MENUITEMINFOW {
                cbSize: size_of::<MENUITEMINFOW>() as u32,
                fMask: MIIM_SUBMENU,
                hSubMenu: history,
                ..Default::default()
            };
            if SetMenuItemInfoW(file, 1, 1, &info) == 0 {
                DestroyMenu(history);
                bail!("Update recent-file menu");
            }
            DestroyMenu(old);
            DrawMenuBar(self.hwnd.get());
        }
        Ok(())
    }

    fn report(&self, error: anyhow::Error) {
        let was_busy = self.busy.replace(true);
        let error = format!("{error:#}");
        self.store.notice(&error);
        self.set_status(&error);
        message(self.hwnd.get(), "Juan", &error, MB_OK | MB_ICONERROR);
        self.update_toolbar();
        self.busy.set(was_busy);
    }

    fn command(&self, id: u16) {
        if self.busy.replace(true) {
            return;
        }
        struct Busy<'a>(&'a Cell<bool>);
        impl Drop for Busy<'_> {
            fn drop(&mut self) {
                self.0.set(false);
            }
        }
        let _busy = Busy(&self.busy);
        if let Err(error) = self.execute(id) {
            self.report(error);
        }
    }

    fn execute(&self, id: u16) -> Result<()> {
        let Some(c) = self.controls.get() else {
            return Ok(());
        };
        match id {
            RECENT_FIRST..=RECENT_LAST => {
                let path = self
                    .recent
                    .borrow()
                    .paths()
                    .get((id - RECENT_FIRST) as usize)
                    .cloned()
                    .context("Recent-file entry is no longer available")?;
                let path = super::recent::local_archive_path(&path)?;
                self.begin_import(path, true)?;
            }
            CLEAR_RECENT => {
                ensure!(
                    self.import.borrow().is_none(),
                    "Wait for the archive import before clearing recent files"
                );
                self.recent
                    .borrow_mut()
                    .clear()
                    .context("Clear recent-file history")?;
                self.refresh_recent_menu()?;
                self.set_status("Recent-file history cleared. Archive files and retained sessions are unchanged.");
            }
            HIDE_ASSETS => {
                self.hide_assets.set(checked(c.hide_assets));
                self.review_cursor.set(None);
                self.refresh(true);
            }
            REVIEW_FIRST => {
                let order = troubleshoot::review_order(&self.rows.borrow());
                if !order.is_empty() {
                    let index = self
                        .review_cursor
                        .get()
                        .and_then(|id| order.iter().position(|v| *v == id))
                        .map_or(0, |i| (i + 1) % order.len());
                    let id = order[index];
                    self.review_cursor.set(Some(id));
                    self.selected.set(Some(id));
                    self.refresh(true);
                    self.render_details(true);
                    let row = self.rows.borrow().iter().position(|r| r.id == id);
                    if let Some(row) = row {
                        // SAFETY: Scroll the selected visible row without changing the sort or filters.
                        unsafe {
                            SendMessageW(c.list, LVM_ENSUREVISIBLE, row, 0);
                        }
                    }
                    self.set_status(format!("Review {} of {} visible candidates; evidence, not a diagnosis. Order and filters unchanged.", index + 1, order.len()));
                }
            }
            FIND => self.open_find(),
            FIND_NEXT | FIND_PREVIOUS => {
                if !self.find_open.get() || self.main_tab.get() != 0 {
                    self.open_find();
                }
                self.find_step(id == FIND_PREVIOUS);
            }
            FIND_CASE => {
                self.find_cursor.set(None);
                self.find_step(false);
            }
            FIND_CLOSE => self.close_find(),
            CAPTURE => {
                ensure!(
                    self.import.borrow().is_none(),
                    "Wait for the archive import to finish before capturing"
                );
                self.toggle_capture()?;
            }
            STOP => self.stop_proxy()?,
            CLEAR => {
                ensure!(
                    self.import.borrow().is_none(),
                    "Wait for the archive import to finish before clearing"
                );
                if self.store.snapshot().sessions.is_empty()
                    || self.demo.get()
                    || confirm(
                        self.hwnd.get(),
                        "Clear captured sessions?",
                        "All retained sessions and payloads will be removed from memory. Export any evidence you need before clearing.",
                    )
                {
                    self.store.clear();
                    self.archive_name.borrow_mut().take();
                    self.selected.set(None);
                    self.refresh(true);
                }
            }
            EXPORT => self.begin_export(Format::Har, ExportMode::Sanitized)?,
            EXPORT_FULL => self.begin_export(Format::Har, ExportMode::Full)?,
            EXPORT_SAZ => self.begin_export(Format::Saz, ExportMode::Full)?,
            EXPORT_SAZ_SANITIZED => self.begin_export(Format::Saz, ExportMode::Sanitized)?,
            IMPORT_SAZ => {
                ensure!(
                    !self.active.get(),
                    "Stop the proxy before opening an archive; live traffic must not replace imported evidence"
                );
                if let Some(path) = open_saz_dialog(self.hwnd.get())? {
                    self.begin_import(path, true)?;
                }
            }
            SYSTEM_PROXY => self.toggle_system_proxy()?,
            HTTPS => self.toggle_https()?,
            TRUST_CA | EXPORT_CA | REMOVE_CA | RESET_CA => self.certificate_action(id)?,
            COPY_URL => {
                let id = self.selected.get().context("Select a session first")?;
                let session = self
                    .store
                    .get(id)
                    .context("This session was evicted from capture storage")?;
                copy_text(self.hwnd.get(), &session.url)?;
                self.set_status("Copied the selected request URL.");
            }
            FOCUS_SEARCH => {
                // SAFETY: Both operations apply to the live search edit.
                unsafe {
                    SetFocus(c.search);
                    SendMessageW(c.search, EM_SETSEL, 0, -1);
                }
            }
            DATA_FOLDER => {
                let folder = system::data_directory()?;
                // SAFETY: Opening a local data directory is an explicit user action; no external URL is launched.
                let result = unsafe {
                    ShellExecuteW(
                        self.hwnd.get(),
                        wide("open").as_ptr(),
                        wide(&folder.to_string_lossy()).as_ptr(),
                        null(),
                        null(),
                        SW_SHOWNORMAL,
                    )
                };
                ensure!(
                    result as usize > 32,
                    "Windows could not open the data folder"
                );
            }
            GUIDE => {
                message(
                    self.hwnd.get(),
                    "Capture guide",
                    &format!(
                        "1. Click Start capture and choose Capture Windows traffic to route proxy-aware apps automatically.\n\
                     2. Or choose Manual proxy and set your test application's HTTP and HTTPS proxy to 127.0.0.1:{}.\n\
                     3. With HTTPS decryption off, HTTPS connections appear as CONNECT tunnels, not decrypted requests.\n\
                     4. Reproduce the issue, select a session, then save a HAR.\n\n\
                     HTTPS: stop the proxy and select Decrypt HTTPS. If trust is missing, choose Trust CA and enable HTTPS, or explicitly use client-specific trust and export the CA from the HTTPS menu. Start capture again.\n\n\
                     curl.exe --proxy http://127.0.0.1:{} --noproxy \"\" http://example.com\n\n\
                     F12: start/pause/resume | Ctrl+L: filter | Ctrl+S: sanitized HAR\n\
                     Filters: host:api status:4xx method:POST type:json -host:telemetry\n\n\
                     Captures only traffic routed through the proxy. HTTP/3, certificate pinning, mTLS decryption, NTLM/Negotiate inspection, process attribution and upstream proxy chaining are not supported.\n\n\
                     Sanitized exports omit bodies and common credentials, but are not anonymized. Review before sharing.",
                        text(c.port),
                        text(c.port)
                    ),
                    MB_OK | MB_ICONINFORMATION,
                );
            }
            ABOUT => {
                message(
                    self.hwnd.get(),
                    "About Juan",
                    concat!(
                        "Juan ",
                        env!("CARGO_PKG_VERSION"),
                        "\nNative Windows HTTP(S) debugging proxy\n\n\
                     Built for support engineers. Rust, Win32, Hyper, and rustls.\n\
                     Open source under the MIT license. No telemetry or embedded browser.\n\n\
                     An independent implementation inspired by classic debugging-proxy workflows.\n\
                     Not affiliated with or endorsed by Fiddler or its owners.\n\n\
                     Capture only traffic you are authorized to inspect."
                    ),
                    MB_OK | MB_ICONINFORMATION,
                );
            }
            EXIT => {
                // SAFETY: Defer closing until the command's reentrancy guard has been released.
                unsafe {
                    PostMessageW(self.hwnd.get(), WM_CLOSE, 0, 0);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn toggle_capture(&self) -> Result<()> {
        if self.active.get() {
            self.store.set_recording(!self.store.recording());
            self.set_status(if self.store.recording() {
                "Recording resumed. Traffic is being captured."
            } else {
                "Recording paused. The proxy still forwards traffic; in-flight sessions may finish."
            });
            self.update_toolbar();
            return Ok(());
        }
        let c = self.controls.get().expect("initialized controls");
        let port: u16 = text(c.port)
            .parse()
            .context("Enter a proxy port between 1 and 65535")?;
        ensure!(port > 0, "Port must be between 1 and 65535");
        if self.decrypt.get() && self.https_trust.get() == HttpsTrust::Windows {
            let ca = self
                .ca
                .borrow()
                .clone()
                .context("HTTPS decryption has no configured CA")?;
            if !system::certificate_is_trusted(ca.der())? && !self.configure_https()? {
                return Ok(());
            }
        }
        let Some(mode) = self.choose_capture_mode(port)? else {
            return Ok(());
        };
        self.archive_name.borrow_mut().take();
        if self.demo.replace(false) {
            self.store.clear();
            self.selected.set(None);
        }
        let config = ProxyConfig {
            listen: ([127, 0, 0, 1], port).into(),
            certificate: if self.decrypt.get() {
                self.ca.borrow().clone()
            } else {
                None
            },
            ..ProxyConfig::default()
        };
        let was_recording = self.store.recording();
        self.store.set_recording(true);
        let handle = match self
            .runtime
            .block_on(proxy::start(config, self.store.clone()))
        {
            Ok(handle) => handle,
            Err(error) => {
                self.store.set_recording(was_recording);
                return Err(error);
            }
        };
        *self.proxy.borrow_mut() = Some(handle);
        self.active.set(true);
        self.failure_reported.set(false);
        if mode == CaptureMode::Windows {
            if let Err(error) = self.apply_windows_proxy(true) {
                return Err(match self.stop_proxy() {
                    Ok(()) => error.context("Capture did not start because Windows proxy setup failed"),
                    Err(recovery) => error.context(format!(
                        "Windows proxy setup failed, and recovery also failed: {recovery:#}. The listener was kept alive for network safety; correct Windows proxy settings before stopping."
                    )),
                });
            }
        } else {
            self.set_status(format!(
                "Manual proxy at 127.0.0.1:{port}. Windows apps are NOT routed automatically; configure your test app."
            ));
        }
        self.update_toolbar();
        self.refresh(true);
        Ok(())
    }

    fn choose_capture_mode(&self, port: u16) -> Result<Option<CaptureMode>> {
        let content = format!(
            "Applications must send traffic through 127.0.0.1:{port} for Juan to record it.\n\n\
             Windows capture temporarily changes this user's HTTP and HTTPS proxy settings. \
             Previous settings are restored on Stop or Exit. Automatic proxy detection is suspended; \
             existing explicit proxies and PAC scripts are not overwritten."
        );
        let footer = if self.decrypt.get() && self.https_trust.get() == HttpsTrust::Windows {
            "HTTPS decryption is enabled with a CA trusted in the Windows user store. Clients must use that trust store or trust the CA separately."
        } else if self.decrypt.get() {
            "HTTPS uses client-specific trust. The client must trust Juan's exported CA; no Windows root certificate was installed by that choice."
        } else {
            "HTTPS decryption is off: HTTPS connections will appear as CONNECT tunnels. Certificate trust is not changed."
        };
        let selected = choose_action(
            self.hwnd.get(),
            "Start capture",
            "Choose how to capture traffic",
            &content,
            footer,
            &[
                (
                    CAPTURE_WINDOWS,
                    "Capture Windows traffic\nRoute proxy-aware Windows apps through Juan.",
                ),
                (
                    CAPTURE_MANUAL,
                    "Manual proxy\nStart the listener only. I will configure my test app's proxy.",
                ),
            ],
        )?;
        capture_mode_from_button(selected)
    }

    fn stop_proxy(&self) -> Result<()> {
        // Restore routing before closing sockets. A restoration error leaves the listener alive.
        {
            let mut lease = self.lease.borrow_mut();
            if let Some(lease) = lease.as_mut() {
                let message = lease.restore()?;
                self.store.notice(message);
            }
        }
        if let Some(message) = system::recover_proxy()? {
            self.store.notice(message);
        }
        self.lease.borrow_mut().take();
        self.routed.set(false);
        let handle = self.proxy.borrow_mut().take();
        self.active.set(false);
        self.update_toolbar();
        let result = if let Some(handle) = handle {
            self.runtime.block_on(handle.shutdown())
        } else {
            Ok(())
        };
        self.set_status(
            "Proxy stopped - retained sessions are still available for inspection and export.",
        );
        self.refresh(true);
        result
    }

    fn toggle_system_proxy(&self) -> Result<()> {
        let c = self.controls.get().expect("initialized controls");
        let enabled = checked(c.system_proxy);
        if enabled {
            ensure!(
                self.active.get(),
                "Start the local listener before changing Windows proxy settings"
            );
            if !confirm(
                self.hwnd.get(),
                "Route Windows web traffic through Juan?",
                "This temporarily changes HTTP and HTTPS proxy settings for your Windows user. Proxy-aware apps may include browsers and applications carrying credentials.\n\n\
                 Previous settings will be saved and restored on Stop or Exit. Automatic proxy detection is suspended during capture. Existing explicit proxies or PAC scripts will not be overwritten.\n\n\
                 Apps that ignore Windows proxy settings are not captured. HTTPS bodies remain encrypted unless decryption is enabled.\n\nContinue?",
            ) {
                set_checked(c.system_proxy, false);
                return Ok(());
            }
        }
        self.apply_windows_proxy(enabled)
    }

    fn apply_windows_proxy(&self, enabled: bool) -> Result<()> {
        if enabled {
            let address = self
                .proxy
                .borrow()
                .as_ref()
                .filter(|proxy| proxy.running())
                .context("The proxy listener is not running")?
                .address();
            *self.lease.borrow_mut() = Some(ProxyLease::enable(address)?);
            self.routed.set(true);
            self.store
                .notice("Windows HTTP/HTTPS proxy routing enabled explicitly by the user.");
            self.set_status(
            "Windows traffic is routed through Juan. Reproduce the issue in a proxy-aware application.",
            );
        } else {
            {
                let mut lease = self.lease.borrow_mut();
                if let Some(lease) = lease.as_mut() {
                    self.store.notice(lease.restore()?);
                }
            }
            self.lease.borrow_mut().take();
            self.routed.set(false);
            self.set_status("Previous Windows proxy settings restored. Manually configured apps can still use Juan.");
        }
        self.update_toolbar();
        Ok(())
    }

    fn toggle_https(&self) -> Result<()> {
        ensure!(
            !self.active.get(),
            "Stop the proxy before changing HTTPS decryption"
        );
        let c = self.controls.get().expect("initialized controls");
        if checked(c.https) {
            self.configure_https()?;
        } else {
            self.decrypt.set(false);
            self.set_status("HTTPS will be tunneled without decrypting payloads. Existing CA trust was not removed.");
            self.update_toolbar();
        }
        Ok(())
    }

    fn configure_https(&self) -> Result<bool> {
        let c = self.controls.get().expect("initialized controls");
        self.decrypt.set(false);
        set_checked(c.https, false);
        let ca = system::load_or_create_ca()?;
        let trust = resolve_https_trust(
            || system::certificate_is_trusted(ca.der()),
            || self.choose_https_trust(&ca),
            || system::trust_certificate(&ca),
        )?;
        let Some(trust) = trust else {
            self.set_status("HTTPS setup cancelled. Decryption remains off; no certificate trust was installed.");
            self.update_toolbar();
            return Ok(false);
        };
        *self.ca.borrow_mut() = Some(ca);
        self.https_trust.set(trust);
        self.decrypt.set(true);
        let status = match trust {
            HttpsTrust::Windows => {
                "HTTPS enabled: the CA is trusted in the Windows user store. Restart Firefox if it has cached a certificate error; remove CA trust after troubleshooting."
            }
            HttpsTrust::ClientManaged => {
                "HTTPS enabled with client-specific trust. Use HTTPS > Export public CA and configure the client. Windows CA trust was not installed by this choice."
            }
        };
        self.store.notice(status);
        self.set_status(status);
        self.update_toolbar();
        Ok(true)
    }

    fn choose_https_trust(&self, ca: &CertificateAuthority) -> Result<Option<HttpsTrust>> {
        let content = format!(
            "Juan's CA is not trusted in your Windows user store. Browsers will reject its generated certificates until the CA is trusted.\n\n\
             Trusting this CA lets Juan inspect HTTPS requests and responses, including passwords, cookies, and tokens. \
             This is a persistent change for the CURRENT USER only, not machine-wide. The private key is not exported.\n\n\
             CA SHA-256:\n{}\n\nExpires: {}",
            ca.fingerprint(),
            ca.expires()
        );
        let selected = choose_action(
            self.hwnd.get(),
            "HTTPS setup",
            "Trust Juan's CA to inspect HTTPS",
            &content,
            "Capture only traffic you are authorized to inspect. Firefox must use Windows root trust or trust the exported CA itself. Remove trust when finished. Pinning and mutual TLS remain unsupported.",
            &[
                (
                    HTTPS_TRUST_WINDOWS,
                    "Trust CA and enable HTTPS\nInstall this CA in the Windows user trust store, verify it, then enable decryption.",
                ),
                (
                    HTTPS_CLIENT_TRUST,
                    "Use client-specific trust\nNo Windows trust changes. I will configure my client with Juan's exported CA.",
                ),
            ],
        )?;
        https_trust_from_button(selected)
    }

    fn certificate_action(&self, id: u16) -> Result<()> {
        if id == TRUST_CA || id == EXPORT_CA {
            let ca = system::load_or_create_ca()?;
            if id == TRUST_CA {
                if system::certificate_is_trusted(ca.der())? {
                    self.https_trust.set(HttpsTrust::Windows);
                    self.set_status("Juan's CA is already trusted in the Windows user store.");
                } else {
                    if !confirm(
                        self.hwnd.get(),
                        "Trust Juan's local CA?",
                        &format!(
                            "This adds a TLS debugging root certificate to the CURRENT USER trust store. Apps using this store will trust certificates signed by Juan.\n\n\
                     SHA-256 fingerprint:\n{}\n\nExpires: {}\n\n\
                     This is a security-sensitive, persistent change. Trust only while needed and remove it when finished. No machine-wide trust or private key import is performed.\n\nContinue?",
                            ca.fingerprint(),
                            ca.expires()
                        ),
                    ) {
                        return Ok(());
                    }
                    system::trust_certificate(&ca)?;
                    self.https_trust.set(HttpsTrust::Windows);
                    self.store.notice("The user explicitly trusted Juan's local CA in the current-user ROOT store.");
                    self.set_status("Local CA trusted for the current Windows user. Remove trust after troubleshooting.");
                }
            } else if let Some(path) = save_dialog(
                self.hwnd.get(),
                "Export public CA certificate",
                "juan-root-ca.pem",
                FileKind::Certificate,
            )? {
                std::fs::write(&path, ca.pem()).context("Export public CA certificate")?;
                self.set_status(format!(
                    "Exported public CA to {}. No private key was exported.",
                    path.display()
                ));
            }
            *self.ca.borrow_mut() = Some(ca);
        } else {
            ensure!(
                !self.active.get(),
                "Stop the proxy before removing trust or resetting its CA"
            );
            let der = system::stored_ca_der()?.context("No Juan CA has been created yet")?;
            if id == REMOVE_CA {
                if confirm(
                    self.hwnd.get(),
                    "Remove local CA trust?",
                    "Remove this exact Juan CA from the current-user Windows trust store? Other certificates are not affected. Also remove any copies you imported into separate browser or application trust stores.",
                ) {
                    let removed = system::untrust_certificate(&der)?;
                    self.decrypt.set(false);
                    self.https_trust.set(HttpsTrust::ClientManaged);
                    self.update_toolbar();
                    self.set_status(if removed {
                        "Juan CA trust removed for this Windows user. HTTPS decryption is off."
                    } else {
                        "This Juan CA was not in the current-user trust store. HTTPS decryption is off."
                    });
                }
            } else if confirm(
                self.hwnd.get(),
                "Reset Juan's local CA?",
                "Delete the protected local CA key? Remove Windows trust first. Also remove manually imported copies from separate client trust stores.\n\nA new, different CA will be generated on the next HTTPS setup.",
            ) {
                system::reset_ca()?;
                self.ca.borrow_mut().take();
                self.decrypt.set(false);
                self.https_trust.set(HttpsTrust::ClientManaged);
                self.update_toolbar();
                self.set_status("Local CA reset. HTTPS decryption is disabled.");
            }
        }
        Ok(())
    }

    fn begin_export(&self, format: Format, mode: ExportMode) -> Result<()> {
        ensure!(
            self.import.borrow().is_none(),
            "Wait for the archive import before exporting"
        );
        ensure!(
            self.export.borrow().is_none(),
            "An archive export is already running"
        );
        let ids: Vec<_> = self.rows.borrow().iter().map(|row| row.id).collect();
        ensure!(!ids.is_empty(), "There are no visible sessions to export");
        let sessions = self.store.sessions(&ids);
        ensure!(
            format != Format::Saz
                || sessions
                    .iter()
                    .all(|s| s.archive.as_ref().is_none_or(|a| a.har.is_none())),
            "HAR-origin sessions cannot be exported to SAZ; HAR-to-SAZ conversion is deferred. Save HAR instead."
        );
        ensure!(
            sessions.len() == ids.len(),
            "Some visible sessions were evicted before the export snapshot. Pause capture, refresh the view, and export again."
        );
        if mode == ExportMode::Full
            && !confirm(
                self.hwnd.get(),
                &format!("Export sensitive full {}?", format.name()),
                &format!(
                    "A full {} includes retained request/response bodies, authorization headers, cookies, and URLs. It may contain passwords, personal information, and active credentials.\n\n\
             Save only to an authorized location and review before sharing. Prefer the default sanitized export when bodies are not needed.\n\nContinue?",
                    format.name()
                ),
            )
        {
            return Ok(());
        }
        let now = time::OffsetDateTime::now_utc();
        let name = format!(
            "juan-{:04}{:02}{:02}-{:02}{:02}{:02}.{}",
            now.year(),
            now.month() as u8,
            now.day(),
            now.hour(),
            now.minute(),
            now.second(),
            format.extension()
        );
        let Some(path) = save_dialog(
            self.hwnd.get(),
            &format!("Save visible sessions as {}", format.name()),
            &name,
            match format {
                Format::Har => FileKind::Har,
                Format::Saz => FileKind::Saz,
            },
        )?
        else {
            return Ok(());
        };
        let (sender, receiver) = mpsc::channel();
        std::thread::Builder::new()
            .name("juan-archive-export".into())
            .spawn(move || {
                let result = format
                    .export(&path, &sessions, mode)
                    .map(|()| (path, mode))
                    .map_err(|error| format!("{error:#}"));
                if sender.send(result).is_err() {
                    eprintln!("Juan export completed after its UI receiver closed.");
                }
            })
            .context("Start archive export worker")?;
        *self.export.borrow_mut() = Some(receiver);
        self.set_status("Exporting visible sessions...");
        self.update_toolbar();
        Ok(())
    }

    fn begin_import(&self, path: PathBuf, confirm_replace: bool) -> Result<()> {
        ensure!(
            !self.active.get(),
            "Stop the proxy before opening an archive"
        );
        ensure!(
            self.import.borrow().is_none() && self.export.borrow().is_none(),
            "An archive operation is already running"
        );
        if confirm_replace
            && !self.demo.get()
            && !self.store.snapshot().sessions.is_empty()
            && !confirm(
                self.hwnd.get(),
                "Replace retained sessions?",
                "Opening an archive replaces the sessions currently in memory after the archive has been parsed successfully. Export any evidence you need first.\n\nNo proxy routing or certificate trust will be changed. Continue?",
            )
        {
            return Ok(());
        }
        let limits = saz::Limits {
            capture: self.store.limits(),
            ..saz::Limits::default()
        };
        let (sender, receiver) = mpsc::channel();
        std::thread::Builder::new()
            .name("juan-archive-import".into())
            .spawn(move || {
                let result = crate::archive::load(&path, limits)
                    .map(|archive| (path, archive))
                    .map_err(|error| format!("{error:#}"));
                if sender.send(result).is_err() {
                    eprintln!("Archive import completed after its UI receiver closed.");
                }
            })
            .context("Start archive import worker")?;
        *self.import.borrow_mut() = Some(receiver);
        self.set_status(
            "Reading archive... Existing sessions are unchanged until import succeeds.",
        );
        self.update_toolbar();
        Ok(())
    }

    fn complete_import(&self, path: PathBuf, archive: saz::ImportedArchive) -> Result<()> {
        ensure!(
            !self.active.get(),
            "Capture started during archive import; the existing sessions were preserved"
        );
        let count = archive.sessions.len();
        let warnings = archive.warnings.len();
        self.store.replace_from_archive(archive.sessions)?;
        self.demo.set(false);
        *self.archive_name.borrow_mut() = Some(
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
        );
        self.selected.set(
            self.store
                .snapshot()
                .sessions
                .first()
                .map(|session| session.id),
        );
        *self.filter.borrow_mut() = Filter::default();
        self.hide_assets.set(troubleshoot::HIDE_ASSETS_DEFAULT);
        self.review_cursor.set(None);
        self.filter_error.borrow_mut().take();
        self.scope.set(0);
        if let Some(c) = self.controls.get() {
            set_checked(c.hide_assets, self.hide_assets.get());
            // SAFETY: The selection change targets our live native combo box and retains no pointers.
            unsafe {
                SendMessageW(c.scope, CB_SETCURSEL, 0, 0);
            }
            set_text(c.search, "");
        }
        self.store.notice(format!(
            "Opened {count} sessions from an archive without starting the proxy."
        ));
        for warning in archive.warnings {
            self.store.notice(warning);
        }
        self.set_status(format!("Opened {count} archive sessions; {warnings} archive notes. See Timing and Diagnostics for fidelity details."));
        let recorded = self.recent.borrow_mut().record_success(&path);
        if let Err(error) = recorded {
            self.report(error.context(
                "Archive opened successfully, but recent-file history could not be saved",
            ));
        } else if let Err(error) = self.refresh_recent_menu() {
            self.report(error);
        }
        self.refresh(true);
        self.render_details(true);
        Ok(())
    }

    fn tick(&self) {
        if self.busy.get() {
            return;
        }
        let imported = self
            .import
            .borrow()
            .as_ref()
            .map(|receiver| receiver.try_recv());
        match imported {
            Some(Ok(result)) => {
                self.import.borrow_mut().take();
                match result {
                    Ok((path, archive)) => {
                        if let Err(error) = self.complete_import(path, archive) {
                            self.report(error);
                        }
                    }
                    Err(error) => self.report(anyhow::anyhow!(error)),
                }
                self.update_toolbar();
            }
            Some(Err(mpsc::TryRecvError::Disconnected)) => {
                self.import.borrow_mut().take();
                self.report(anyhow::anyhow!(
                    "The archive import worker stopped without returning a result"
                ));
            }
            _ => {}
        }
        let exported = self
            .export
            .borrow()
            .as_ref()
            .map(|receiver| receiver.try_recv());
        match exported {
            Some(Ok(result)) => {
                self.export.borrow_mut().take();
                self.update_toolbar();
                match result {
                    Ok((path, mode)) => self.set_status(format!(
                        "Saved {}{}. Review before sharing.",
                        path.display(),
                        if mode == ExportMode::Sanitized {
                            " (sanitized)"
                        } else {
                            " (sensitive full capture)"
                        }
                    )),
                    Err(error) => self.report(anyhow::anyhow!(error)),
                }
            }
            Some(Err(mpsc::TryRecvError::Disconnected)) => {
                self.export.borrow_mut().take();
                self.report(anyhow::anyhow!(
                    "The archive export worker stopped without returning a result"
                ));
            }
            _ => {}
        }
        let failed = self
            .proxy
            .borrow()
            .as_ref()
            .is_some_and(|proxy| !proxy.running());
        if failed
            && !self.failure_reported.replace(true)
            && let Err(error) = self.stop_proxy()
        {
            self.report(error);
        }
        self.refresh(false);
    }

    fn refresh(&self, force: bool) {
        let Some(c) = self.controls.get() else { return };
        let revision = self.store.revision();
        if !force && revision == self.revision.get() {
            return;
        }
        let snapshot = self.store.snapshot();
        self.revision.set(snapshot.revision);
        let total = snapshot.sessions.len();
        let errors = snapshot
            .sessions
            .iter()
            .filter(|row| row.is_error())
            .count();
        let old_count = self.rows.borrow().len();
        let mut hidden = 0;
        let mut rows: Vec<_> = if self.filter_error.borrow().is_some() {
            Vec::new()
        } else {
            let filter = self.filter.borrow();
            snapshot
                .sessions
                .into_iter()
                .filter(|row| {
                    filter.matches(row)
                        && match self.scope.get() {
                            1 => !row.is_https(),
                            2 => row.is_https(),
                            3 => row.is_error(),
                            4 => row.content_type.contains("json"),
                            5 => row.kind != SessionKind::Tunnel,
                            _ => true,
                        }
                })
                .filter(|row| {
                    let hide = self.hide_assets.get() && troubleshoot::static_asset(row);
                    if hide {
                        hidden += 1;
                    }
                    !hide
                })
                .collect()
        };
        set_text(c.hide_assets, &format!("Hide assets ({hidden} hidden)"));
        let order = troubleshoot::review_order(&rows);
        set_text(c.review, &format!("Review first ({} visible)", order.len()));
        enable(c.review, !order.is_empty());
        let (column, ascending) = self.sort.get();
        rows.sort_by(|a, b| {
            let order = compare_rows(a, b, column).then_with(|| a.id.cmp(&b.id));
            if ascending { order } else { order.reverse() }
        });
        let selected_index = self
            .selected
            .get()
            .and_then(|id| rows.iter().position(|row| row.id == id));
        if selected_index.is_none() {
            self.selected.set(None);
        }
        let count = rows.len();
        *self.rows.borrow_mut() = rows;
        self.rebuilding.set(true);
        // SAFETY: Release row borrows before list-view messages, which can synchronously request row text.
        unsafe {
            SendMessageW(c.list, WM_SETREDRAW, 0, 0);
            SendMessageW(
                c.list,
                LVM_SETITEMCOUNT,
                count,
                (LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL) as isize,
            );
            let mut state = LVITEMW {
                stateMask: LVIS_SELECTED | LVIS_FOCUSED,
                ..Default::default()
            };
            SendMessageW(
                c.list,
                LVM_SETITEMSTATE,
                usize::MAX,
                &state as *const _ as isize,
            );
            if let Some(index) = selected_index {
                state.state = LVIS_SELECTED | LVIS_FOCUSED;
                SendMessageW(c.list, LVM_SETITEMSTATE, index, &state as *const _ as isize);
            }
            SendMessageW(c.list, WM_SETREDRAW, 1, 0);
            if count > old_count && checked(c.autoscroll) && self.sort.get() == (0, true) {
                SendMessageW(c.list, LVM_ENSUREVISIBLE, count - 1, 0);
            }
            InvalidateRect(c.list, null(), 0);
        }
        self.rebuilding.set(false);
        *self.footer.borrow_mut() = format!(
            "{count} / {total} sessions    {errors} errors    {} retained{}{}",
            inspect::bytes_label(snapshot.retained_bytes as u64),
            if snapshot.evicted > 0 {
                format!("    {} evicted", snapshot.evicted)
            } else {
                String::new()
            },
            if snapshot.body_limit_hit {
                "    [payload limit reached]"
            } else {
                ""
            }
        );
        self.render_details(false);
        self.update_toolbar();
        // SAFETY: Counts and labels are native chrome painted by the parent.
        unsafe {
            InvalidateRect(self.hwnd.get(), null(), 0);
        }
    }

    fn render_details(&self, reset_scroll: bool) {
        let Some(c) = self.controls.get() else { return };
        let session = self.selected.get().and_then(|id| self.store.get(id));
        let (url, request, response, detail, request_info, response_info) = if let Some(session) =
            session
        {
            let request = if self.main_tab.get() == 0 {
                inspect::render(&session, Side::Request, self.request_tab.get())
            } else {
                String::new()
            };
            let response = if self.main_tab.get() == 0 {
                inspect::render(&session, Side::Response, self.response_tab.get())
            } else {
                String::new()
            };
            let detail = if self.main_tab.get() == 1 {
                format!(
                    "STATUS: {}\r\nRed/marker indicates recorded status or failure, not a root-cause diagnosis.\r\n\r\n{}",
                    troubleshoot::reason(&session.summary()),
                    inspect::render_timing(&session)
                )
            } else {
                inspect::render_notices(&self.store.notices())
            };
            let request_info = format!(
                "{}  /  {}",
                session.method,
                inspect::bytes_label(session.request.total_bytes)
            );
            let response_info = format!(
                "{}  /  {}  /  {}",
                troubleshoot::reason(&session.summary()),
                inspect::bytes_label(session.response.total_bytes),
                session
                    .elapsed_ms()
                    .map_or("time not recorded".into(), |ms| format!("{ms} ms"))
            );
            (
                session.url,
                request,
                response,
                detail,
                request_info,
                response_info,
            )
        } else {
            (
                "Select a session to inspect".into(),
                "SELECT A SESSION\r\n\r\nStart capture offers two choices:\r\n- Capture Windows traffic: route apps.\r\n- Manual proxy: configure your test app.\r\n\r\nThe Windows proxy checkbox controls\r\nrouting while the listener is running.\r\nEnabling HTTPS guides you through CA\r\ntrust with your explicit approval.".into(),
                "YOUR RESPONSE, IN DETAIL\r\n\r\nInspect headers, text, formatted JSON,\r\nor original body bytes in Hex.\r\n\r\nNo HTML or scripts are executed.\r\nCapture payloads stay in memory unless\r\nyou explicitly export a HAR.".into(),
                if self.main_tab.get() == 2 { inspect::render_notices(&self.store.notices()) }
                    else { "Select a session to see its measured timings.\r\n\r\nDNS, TCP and TLS phase timings are not\r\nindividually instrumented in this version.".into() },
                String::new(), String::new(),
            )
        };
        *self.request_info.borrow_mut() = request_info;
        *self.response_info.borrow_mut() = response_info;
        set_text(c.url, &url);
        for (index, (handle, value)) in [
            (c.request, request),
            (c.response, response),
            (c.detail, detail),
        ]
        .into_iter()
        .enumerate()
        {
            if self.viewer_text.borrow()[index] == value && !reset_scroll {
                continue;
            }
            // SAFETY: Preserve native edit scroll position for in-flight body updates, but reset on selection.
            let first_line = unsafe { SendMessageW(handle, EM_GETFIRSTVISIBLELINE, 0, 0) };
            set_text(handle, &value);
            if !reset_scroll {
                // SAFETY: EM_LINESCROLL uses a line delta after SetWindowText reset the view to its first line.
                unsafe {
                    SendMessageW(handle, EM_LINESCROLL, 0, first_line);
                }
            }
            self.viewer_text.borrow_mut()[index] = value;
            if self.find_open.get() && index == self.find_target.get() {
                self.find_cursor.set(None);
                set_text(
                    c.find_info,
                    "Preview changed; Next searches the current displayed text only.",
                );
            }
        }
        enable(c.copy, self.selected.get().is_some());
        // SAFETY: Chrome includes the selected request and response byte counters.
        unsafe {
            InvalidateRect(self.hwnd.get(), null(), 0);
        }
    }

    fn filter_changed(&self) {
        self.review_cursor.set(None);
        let Some(c) = self.controls.get() else { return };
        match Filter::parse(&text(c.search)) {
            Ok(filter) => {
                *self.filter.borrow_mut() = filter;
                self.filter_error.borrow_mut().take();
            }
            Err(error) => {
                *self.filter_error.borrow_mut() = Some(format!("Invalid filter: {error}"));
            }
        }
        self.refresh(true);
    }
    fn select_find_pane(&self, target: usize) {
        let previous = self.find_target.replace(target);
        if previous == target {
            return;
        }
        self.find_cursor.set(None);
        if self.find_open.get()
            && let Some(c) = self.controls.get()
        {
            // SAFETY: A pane change invalidates the old inspector's search selection.
            unsafe {
                SendMessageW(
                    if previous == 0 { c.request } else { c.response },
                    EM_SETSEL,
                    0,
                    0,
                );
            }
            set_text(
                c.find_info,
                if target == 0 {
                    "Request preview selected; Next searches displayed text only."
                } else {
                    "Response preview selected; Next searches displayed text only."
                },
            );
        }
    }

    fn open_find(&self) {
        let Some(c) = self.controls.get() else { return };
        // SAFETY: Read focus from this UI thread and focus our own query edit.
        unsafe {
            let focus = GetFocus();
            if focus == c.request || focus == c.request_tabs {
                self.select_find_pane(0);
            }
            if focus == c.response || focus == c.response_tabs {
                self.select_find_pane(1);
            }
            self.main_tab.set(0);
            SendMessageW(c.main_tabs, TCM_SETCURSEL, 0, 0);
            self.find_open.set(true);
            self.find_cursor.set(None);
            self.layout();
            self.render_details(false);
            set_text(
                c.find_info,
                "Find in displayed preview only; Ctrl+L filters sessions.",
            );
            SetFocus(c.find_query);
            SendMessageW(c.find_query, EM_SETSEL, 0, -1);
        }
    }

    fn close_find(&self) {
        let Some(c) = self.controls.get() else { return };
        self.find_open.set(false);
        self.find_cursor.set(None);
        self.layout();
        // SAFETY: Restore focus to the remembered live inspector control.
        unsafe {
            SetFocus(if self.find_target.get() == 0 {
                c.request
            } else {
                c.response
            });
        }
    }

    fn find_step(&self, backwards: bool) {
        let Some(c) = self.controls.get() else { return };
        let target = self.find_target.get();
        let tab = if target == 0 {
            self.request_tab.get()
        } else {
            self.response_tab.get()
        };
        if self.selected.get().is_none() || tab == Inspector::Hex {
            set_text(
                c.find_info,
                "Select a session and Headers, Text or JSON; search is preview-only.",
            );
            return;
        }
        let query = text(c.find_query);
        if query.is_empty() {
            self.find_cursor.set(None);
            // SAFETY: Clear only the current inspector's stale search selection.
            unsafe {
                SendMessageW(
                    if target == 0 { c.request } else { c.response },
                    EM_SETSEL,
                    0,
                    0,
                );
            }
            set_text(
                c.find_info,
                "Enter text; search is limited to this displayed preview.",
            );
            return;
        }
        let handle = if target == 0 { c.request } else { c.response };
        let (value, capped) = {
            let viewer = self.viewer_text.borrow();
            let original = &viewer[target];
            let mut end = original.len().min(inspect::PREVIEW_LIMIT);
            while !original.is_char_boundary(end) {
                end -= 1;
            }
            (original[..end].to_owned(), end < original.len())
        };
        let matches = troubleshoot::find_matches(&value, &query, checked(c.find_case));
        let Some((index, wrapped)) =
            troubleshoot::next_match(&matches.ranges, self.find_cursor.get(), backwards)
        else {
            self.find_cursor.set(None);
            // SAFETY: Clear only our inspector's old match selection.
            unsafe {
                SendMessageW(handle, EM_SETSEL, 0, 0);
            }
            set_text(
                c.find_info,
                if capped {
                    "Not found in first 2 MiB of displayed text; search limited."
                } else {
                    "Not found in displayed preview (not the whole capture)."
                },
            );
            return;
        };
        let range = matches.ranges[index];
        self.find_cursor.set(Some(range));
        // SAFETY: Positions are mapped to UTF-16 offsets within this current edit text.
        unsafe {
            SendMessageW(handle, EM_SETSEL, range.0, range.1 as isize);
            SendMessageW(handle, EM_SCROLLCARET, 0, 0);
        }
        set_text(
            c.find_info,
            &format!(
                "{}: {} / {}{}{}; {}",
                if target == 0 { "Request" } else { "Response" },
                index + 1,
                matches.ranges.len(),
                if matches.limited {
                    " (first 10000)"
                } else {
                    ""
                },
                if wrapped { " (wrapped)" } else { "" },
                if capped {
                    "first 2 MiB of displayed text only"
                } else {
                    "displayed preview only"
                }
            ),
        );
    }

    fn find_key(&self, message: &MSG) -> bool {
        if !self.find_open.get() || message.message != WM_KEYDOWN {
            return false;
        }
        if message.wParam as u16 == VK_ESCAPE && self.main_tab.get() == 0 {
            self.close_find();
            return true;
        }
        if self.controls.get().is_none() || message.wParam as u16 != VK_RETURN {
            return false;
        }
        // SAFETY: Read this UI thread's focus/key state and click only our focused
        // native Find button. A modeless non-dialog window has no default-button ID.
        unsafe {
            let focus = GetFocus();
            let id = GetDlgCtrlID(focus);
            if [FIND_NEXT, FIND_PREVIOUS, FIND_CLOSE]
                .map(i32::from)
                .contains(&id)
            {
                SendMessageW(focus, BM_CLICK, 0, 0);
                return true;
            }
            if !find_enter_search_control(id) {
                return false;
            }
            self.find_step(GetKeyState(VK_SHIFT as i32) < 0);
            true
        }
    }
    fn paint(&self) {
        let mut paint = PAINTSTRUCT::default();
        // SAFETY: BeginPaint/EndPaint bracket this UI-thread paint DC; helper routines restore selected objects.
        unsafe {
            let dc = BeginPaint(self.hwnd.get(), &mut paint);
            let (width, height, split) = self.dimensions();
            let s = |n| self.s(n);
            let fonts = self.fonts.borrow();
            fill(dc, rect(0, 0, width, height), CANVAS);
            fill(dc, rect(0, 0, width, s(72)), NAVY);
            rounded(dc, rect(s(17), s(18), s(51), s(52)), ACCENT, ACCENT, s(7));
            label(
                dc,
                rect(s(17), s(16), s(52), s(53)),
                "J",
                fonts.brand.raw(),
                WHITE,
                DT_CENTER,
            );
            label(
                dc,
                rect(s(65), s(7), s(300), s(46)),
                "Juan",
                fonts.brand.raw(),
                WHITE,
                DT_LEFT,
            );
            label(
                dc,
                rect(s(67), s(44), s(400), s(64)),
                "HTTP(S) DEBUGGING PROXY",
                fonts.small.raw(),
                rgb(172, 196, 207),
                DT_LEFT,
            );
            label(
                dc,
                rect(width - s(500), s(14), width - s(138), s(39)),
                "Native. Local. Built for troubleshooting.",
                fonts.text.raw(),
                rgb(207, 222, 230),
                DT_RIGHT,
            );
            label(
                dc,
                rect(width - s(450), s(39), width - s(138), s(59)),
                https_status(self.decrypt.get(), self.https_trust.get()),
                fonts.small.raw(),
                rgb(137, 166, 184),
                DT_RIGHT,
            );
            rounded(
                dc,
                rect(width - s(116), s(24), width - s(20), s(49)),
                rgb(34, 59, 70),
                rgb(54, 78, 88),
                s(7),
            );
            label(
                dc,
                rect(width - s(116), s(24), width - s(20), s(49)),
                if !self.active.get() && self.archive_name.borrow().is_some() {
                    "ARCHIVE"
                } else {
                    capture_badge(
                        self.demo.get(),
                        self.active.get(),
                        self.store.recording(),
                        self.routed.get(),
                    )
                },
                fonts.bold.raw(),
                rgb(139, 222, 208),
                DT_CENTER,
            );
            fill(dc, rect(0, s(72), width, s(127)), WHITE);
            fill(dc, rect(0, s(126), width, s(127)), BORDER);
            fill(dc, rect(s(411), s(87), s(412), s(112)), BORDER);
            label(
                dc,
                rect(s(17), s(130), split - s(20), s(149)),
                "LIVE TRAFFIC",
                fonts.bold.raw(),
                MUTED,
                DT_LEFT,
            );
            fill(
                dc,
                rect(s(15), s(247), split - s(10), height - s(42)),
                BORDER,
            );
            fill(
                dc,
                rect(split + s(13), s(192), width - s(16), height - s(42)),
                BORDER,
            );
            fill(
                dc,
                rect(split + s(14), s(193), width - s(17), height - s(43)),
                WHITE,
            );
            if self.main_tab.get() == 0 {
                let find_height = if self.find_open.get() { s(80) } else { 0 };
                let available = (height - s(286) - find_height - s(109)).max(s(100));
                let response_y = s(286) + find_height + (available as f64 * 0.43) as i32 + s(15);
                for (y, title, info) in [
                    (
                        s(229) + find_height,
                        "REQUEST",
                        self.request_info.borrow().clone(),
                    ),
                    (response_y, "RESPONSE", self.response_info.borrow().clone()),
                ] {
                    label(
                        dc,
                        rect(split + s(23), y, split + s(128), y + s(22)),
                        title,
                        fonts.bold.raw(),
                        ACCENT,
                        DT_LEFT,
                    );
                    label(
                        dc,
                        rect(split + s(128), y, width - s(25), y + s(22)),
                        &info,
                        fonts.small.raw(),
                        MUTED,
                        DT_RIGHT,
                    );
                }
            }
            fill(dc, rect(0, height - s(31), width, height), WHITE);
            fill(dc, rect(0, height - s(32), width, height - s(31)), BORDER);
            label(
                dc,
                rect(s(16), height - s(28), split + s(90), height - s(3)),
                &self.footer.borrow(),
                fonts.small.raw(),
                MUTED,
                DT_LEFT,
            );
            let filter_error = self.filter_error.borrow();
            let status = filter_error
                .as_deref()
                .map(str::to_owned)
                .unwrap_or_else(|| self.status.borrow().clone());
            label(
                dc,
                rect(split + s(105), height - s(28), width - s(16), height - s(3)),
                &status,
                fonts.small.raw(),
                if filter_error.is_some() { RED } else { ACCENT },
                DT_RIGHT,
            );
            EndPaint(self.hwnd.get(), &paint);
        }
    }

    fn draw_button(&self, item: &DRAWITEMSTRUCT) {
        let id = item.CtlID as u16;
        let primary = id == CAPTURE;
        let disabled = item.itemState & ODS_DISABLED != 0;
        let pressed = item.itemState & ODS_SELECTED != 0;
        let background = if disabled {
            CANVAS
        } else if primary {
            if pressed { rgb(5, 94, 91) } else { ACCENT }
        } else if pressed {
            rgb(225, 237, 242)
        } else {
            WHITE
        };
        rounded(
            item.hDC,
            item.rcItem,
            background,
            if primary && !disabled {
                background
            } else {
                BORDER
            },
            self.s(7),
        );
        let foreground = if disabled {
            rgb(153, 165, 173)
        } else if primary {
            WHITE
        } else {
            TEXT
        };
        label(
            item.hDC,
            item.rcItem,
            &text(item.hwndItem),
            self.fonts.borrow().text.raw(),
            foreground,
            DT_CENTER,
        );
        if item.itemState & ODS_FOCUS != 0 {
            let mut focus = item.rcItem;
            focus.left += self.s(4);
            focus.top += self.s(4);
            focus.right -= self.s(4);
            focus.bottom -= self.s(4);
            // SAFETY: This focus cue preserves keyboard accessibility on owner-drawn buttons.
            unsafe {
                DrawFocusRect(item.hDC, &focus);
            }
        }
    }

    fn notify(&self, lparam: LPARAM) -> Option<LRESULT> {
        if lparam == 0 {
            return None;
        }
        let c = self.controls.get()?;
        // SAFETY: WM_NOTIFY payload types are determined by the originating native control and notification code.
        unsafe {
            let header = &*(lparam as *const NMHDR);
            if header.hwndFrom == c.list {
                match header.code {
                    LVN_GETINFOTIPW => {
                        let info = &mut *(lparam as *mut NMLVGETINFOTIPW);
                        if let Some(row) = self.rows.borrow().get(info.iItem as usize) {
                            copy_wide(
                                &troubleshoot::reason(row),
                                info.pszText,
                                info.cchTextMax.max(0) as usize,
                            );
                        }
                        return Some(0);
                    }
                    LVN_GETDISPINFOW => {
                        let info = &mut *(lparam as *mut NMLVDISPINFOW);
                        if info.item.mask & LVIF_TEXT != 0 {
                            let value = self
                                .rows
                                .borrow()
                                .get(info.item.iItem as usize)
                                .map_or(String::new(), |row| {
                                    cell_text(row, info.item.iSubItem as usize)
                                });
                            copy_wide(&value, info.item.pszText, info.item.cchTextMax as usize);
                        }
                        return Some(0);
                    }
                    LVN_GETEMPTYMARKUP => {
                        let info = &mut *(lparam as *mut NMLVEMPTYMARKUP);
                        info.dwFlags = EMF_CENTERED;
                        let text = if self.filter_error.borrow().is_some() {
                            "Invalid filter. Correct the search expression to show sessions."
                                .to_owned()
                        } else if self.store.snapshot().sessions.is_empty() {
                            empty_capture_message(
                                self.active.get(),
                                self.store.recording(),
                                self.routed.get(),
                                &super::native::text(c.port),
                            )
                        } else {
                            "No sessions match the current filters.".to_owned()
                        };
                        copy_wide(&text, info.szMarkup.as_mut_ptr(), info.szMarkup.len());
                        return Some(1);
                    }
                    LVN_ITEMCHANGED if !self.rebuilding.get() => {
                        let event = &*(lparam as *const NMLISTVIEW);
                        if event.uNewState & LVIS_SELECTED != 0 {
                            let id = self
                                .rows
                                .borrow()
                                .get(event.iItem as usize)
                                .map(|row| row.id);
                            self.selected.set(id);
                            self.render_details(true);
                        }
                        return Some(0);
                    }
                    LVN_COLUMNCLICK => {
                        let event = &*(lparam as *const NMLISTVIEW);
                        let column = event.iSubItem as usize;
                        let (previous, ascending) = self.sort.get();
                        self.sort.set((column, previous != column || !ascending));
                        self.refresh(true);
                        return Some(0);
                    }
                    NM_CUSTOMDRAW => {
                        let draw = &mut *(lparam as *mut NMLVCUSTOMDRAW);
                        let mut contrast = HIGHCONTRASTW {
                            cbSize: size_of::<HIGHCONTRASTW>() as u32,
                            ..Default::default()
                        };
                        if SystemParametersInfoW(
                            SPI_GETHIGHCONTRAST,
                            contrast.cbSize,
                            (&mut contrast as *mut HIGHCONTRASTW).cast(),
                            0,
                        ) != 0
                            && contrast.dwFlags & HCF_HIGHCONTRASTON != 0
                            && draw.nmcd.dwDrawStage == CDDS_ITEMPREPAINT | CDDS_SUBITEM
                            && draw.nmcd.uItemState & CDIS_SELECTED == 0
                        {
                            draw.clrText = GetSysColor(COLOR_WINDOWTEXT);
                            draw.clrTextBk = GetSysColor(COLOR_WINDOW);
                            return Some(if draw.iSubItem == 1 {
                                CDRF_NOTIFYPOSTPAINT as isize
                            } else {
                                CDRF_DODEFAULT as isize
                            });
                        }
                        match draw.nmcd.dwDrawStage {
                            stage if stage == CDDS_ITEMPOSTPAINT | CDDS_SUBITEM => {
                                if draw.iSubItem == 1
                                    && self
                                        .rows
                                        .borrow()
                                        .get(draw.nmcd.dwItemSpec)
                                        .is_some_and(troubleshoot::problem_marker)
                                {
                                    let mut bounds = RECT {
                                        top: 1,
                                        left: LVIR_BOUNDS as i32,
                                        ..Default::default()
                                    };
                                    if SendMessageW(
                                        c.list,
                                        LVM_GETSUBITEMRECT,
                                        draw.nmcd.dwItemSpec,
                                        &mut bounds as *mut RECT as isize,
                                    ) != 0
                                        && bounds.right - bounds.left >= self.s(64)
                                    {
                                        let size = self.s(16).min(bounds.bottom - bounds.top);
                                        let saved = SaveDC(draw.nmcd.hdc);
                                        if saved != 0 {
                                            IntersectClipRect(
                                                draw.nmcd.hdc,
                                                bounds.left,
                                                bounds.top,
                                                bounds.right,
                                                bounds.bottom,
                                            );
                                            // Shared stock icon: no font dependency or owned handle to destroy.
                                            DrawIconEx(
                                                draw.nmcd.hdc,
                                                bounds.right - size - self.s(6),
                                                bounds.top
                                                    + (bounds.bottom - bounds.top - size) / 2,
                                                LoadIconW(null_mut(), IDI_ERROR),
                                                size,
                                                size,
                                                0,
                                                null_mut(),
                                                DI_NORMAL,
                                            );
                                            RestoreDC(draw.nmcd.hdc, saved);
                                        }
                                    }
                                }
                                return Some(CDRF_DODEFAULT as isize);
                            }
                            CDDS_PREPAINT => return Some(CDRF_NOTIFYITEMDRAW as isize),
                            CDDS_ITEMPREPAINT => return Some(CDRF_NOTIFYSUBITEMDRAW as isize),
                            stage if stage == CDDS_ITEMPREPAINT | CDDS_SUBITEM => {
                                let selected = SendMessageW(
                                    c.list,
                                    LVM_GETITEMSTATE,
                                    draw.nmcd.dwItemSpec,
                                    LVIS_SELECTED as isize,
                                ) & LVIS_SELECTED as isize
                                    != 0;
                                if !selected
                                    && let Some(row) = self.rows.borrow().get(draw.nmcd.dwItemSpec)
                                    && troubleshoot::problem_marker(row)
                                    && draw_error_cell(c.list, draw, row, self.dpi.get())
                                {
                                    // Explorer's themed default pass must not repaint our red glyphs.
                                    return Some(CDRF_SKIPDEFAULT as isize);
                                }
                                if let Some(row) = self.rows.borrow().get(draw.nmcd.dwItemSpec)
                                    && !selected
                                {
                                    let problem = problem_row_colors(row, false, false);
                                    draw.clrTextBk = if let Some((_, background)) = problem {
                                        background
                                    } else if draw.nmcd.dwItemSpec.is_multiple_of(2) {
                                        WHITE
                                    } else {
                                        rgb(249, 251, 252)
                                    };
                                    draw.clrText = if let Some((foreground, _)) = problem {
                                        foreground
                                    } else if draw.iSubItem == 1 {
                                        if row.status.is_some_and(|s| (300..400).contains(&s)) {
                                            AMBER
                                        } else {
                                            ACCENT
                                        }
                                    } else if row.kind == SessionKind::Tunnel {
                                        MUTED
                                    } else {
                                        TEXT
                                    };
                                }
                                return Some(if draw.iSubItem == 1 {
                                    (CDRF_NEWFONT | CDRF_NOTIFYPOSTPAINT) as isize
                                } else {
                                    CDRF_NEWFONT as isize
                                });
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            } else if header.code == TCN_SELCHANGE {
                if header.hwndFrom == c.main_tabs {
                    self.main_tab
                        .set(SendMessageW(c.main_tabs, TCM_GETCURSEL, 0, 0) as usize);
                    self.layout();
                } else if header.hwndFrom == c.request_tabs {
                    self.select_find_pane(0);
                    self.find_cursor.set(None);
                    self.request_tab.set(tab_kind(SendMessageW(
                        c.request_tabs,
                        TCM_GETCURSEL,
                        0,
                        0,
                    )));
                } else if header.hwndFrom == c.response_tabs {
                    self.select_find_pane(1);
                    self.find_cursor.set(None);
                    self.response_tab.set(tab_kind(SendMessageW(
                        c.response_tabs,
                        TCM_GETCURSEL,
                        0,
                        0,
                    )));
                }
                self.render_details(true);
                return Some(0);
            }
        }
        None
    }

    fn close(&self) {
        if self.busy.get() {
            return;
        }
        if self.export.borrow().is_some() || self.import.borrow().is_some() {
            message(
                self.hwnd.get(),
                "Archive operation in progress",
                "Wait for the archive operation to finish before closing Juan.",
                MB_OK | MB_ICONINFORMATION,
            );
            return;
        }
        if let Err(error) = self.stop_proxy() {
            self.report(error);
            return;
        }
        // SAFETY: All system routing has been restored before destroying the window and its child controls.
        unsafe {
            DestroyWindow(self.hwnd.get());
        }
    }

    fn pointer_on_splitter(&self) -> bool {
        let mut point = POINT::default();
        // SAFETY: Convert the current pointer to this window's physical client coordinates.
        unsafe {
            GetCursorPos(&mut point);
            ScreenToClient(self.hwnd.get(), &mut point);
        }
        let (_, height, split) = self.dimensions();
        (point.x - split).abs() < self.s(7)
            && point.y > self.s(127)
            && point.y < height - self.s(35)
    }

    fn change_dpi(&self, dpi: u32, suggested: &RECT) -> Result<()> {
        let fonts = Fonts::new(dpi)?;
        self.apply_fonts(&fonts);
        *self.fonts.borrow_mut() = fonts;
        self.dpi.set(dpi);
        // SAFETY: The suggested rectangle is supplied by WM_DPICHANGED and is valid for this callback.
        unsafe {
            SetWindowPos(
                self.hwnd.get(),
                null_mut(),
                suggested.left,
                suggested.top,
                suggested.right - suggested.left,
                suggested.bottom - suggested.top,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
        }
        self.layout();
        Ok(())
    }
}

pub fn run(demo: bool, initial_archive: Option<PathBuf>) -> Result<()> {
    let _instance = SingleInstance::acquire()?;
    // SAFETY: Initialize only the common-control classes used by this application.
    unsafe {
        let init = INITCOMMONCONTROLSEX {
            dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES | ICC_STANDARD_CLASSES,
        };
        ensure!(
            InitCommonControlsEx(&init) != 0,
            "Initialize Windows common controls"
        );
    }
    let app = Box::new(App::new(demo)?);
    let class = wide("Juan.NativeDesktop");
    let menu = make_menu(&app.recent.borrow())?;
    // SAFETY: The Box keeps App at a stable address until after WM_NCDESTROY and the message loop ends.
    unsafe {
        let instance = GetModuleHandleW(null());
        let icon = LoadIconW(instance, std::ptr::without_provenance(1));
        let window_class = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            hIcon: icon,
            hIconSm: icon,
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            lpszClassName: class.as_ptr(),
            ..Default::default()
        };
        if RegisterClassExW(&window_class) == 0 {
            DestroyMenu(menu);
            bail!("Register Juan window: {}", std::io::Error::last_os_error());
        }
        let mut work = RECT::default();
        SystemParametersInfoW(SPI_GETWORKAREA, 0, (&mut work as *mut RECT).cast(), 0);
        let width = app.s(1460).min(work.right - work.left - app.s(32));
        let height = app.s(900).min(work.bottom - work.top - app.s(32));
        let hwnd = CreateWindowExW(
            WS_EX_APPWINDOW,
            class.as_ptr(),
            wide("Juan").as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            work.left + (work.right - work.left - width) / 2,
            work.top + (work.bottom - work.top - height) / 2,
            width,
            height,
            null_mut(),
            menu,
            instance,
            (&*app as *const App).cast(),
        );
        if hwnd.is_null() {
            if app.hwnd.get().is_null() {
                DestroyMenu(menu);
            }
            bail!(
                "{}",
                app.initialization_error
                    .borrow()
                    .as_deref()
                    .unwrap_or("Create Juan main window failed")
            );
        }
        let accelerators = [
            ACCEL {
                fVirt: FVIRTKEY | FCONTROL,
                key: b'F' as u16,
                cmd: FIND,
            },
            ACCEL {
                fVirt: FVIRTKEY,
                key: VK_F3,
                cmd: FIND_NEXT,
            },
            ACCEL {
                fVirt: FVIRTKEY | FSHIFT,
                key: VK_F3,
                cmd: FIND_PREVIOUS,
            },
            ACCEL {
                fVirt: FVIRTKEY | FCONTROL,
                key: b'O' as u16,
                cmd: IMPORT_SAZ,
            },
            ACCEL {
                fVirt: FVIRTKEY,
                key: VK_F12,
                cmd: CAPTURE,
            },
            ACCEL {
                fVirt: FVIRTKEY | FSHIFT,
                key: VK_F12,
                cmd: STOP,
            },
            ACCEL {
                fVirt: FVIRTKEY | FCONTROL,
                key: b'L' as u16,
                cmd: FOCUS_SEARCH,
            },
            ACCEL {
                fVirt: FVIRTKEY | FCONTROL,
                key: b'S' as u16,
                cmd: EXPORT,
            },
            ACCEL {
                fVirt: FVIRTKEY | FCONTROL | FSHIFT,
                key: b'S' as u16,
                cmd: EXPORT_FULL,
            },
            ACCEL {
                fVirt: FVIRTKEY | FCONTROL,
                key: VK_DELETE,
                cmd: CLEAR,
            },
        ];
        let accelerator = CreateAcceleratorTableW(accelerators.as_ptr(), accelerators.len() as i32);
        if accelerator.is_null() {
            DestroyWindow(hwnd);
            bail!(
                "Create keyboard shortcuts: {}",
                std::io::Error::last_os_error()
            );
        }
        ShowWindow(hwnd, SW_SHOWNORMAL);
        UpdateWindow(hwnd);
        let recent_warning = app.recent_warning.borrow_mut().take();
        if let Some(warning) = recent_warning {
            app.report(anyhow::anyhow!(warning));
        }
        if let Some(path) = initial_archive
            && let Err(error) = app.begin_import(path, false)
        {
            app.report(error);
        }
        let mut message = MSG::default();
        let result = loop {
            let status = GetMessageW(&mut message, null_mut(), 0, 0);
            if status == 0 {
                break Ok(());
            }
            if status == -1 {
                break Err(anyhow::anyhow!(
                    "Windows message loop failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if !app.find_key(&message)
                && TranslateAcceleratorW(hwnd, accelerator, &message) == 0
                && IsDialogMessageW(hwnd, &message) == 0
            {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        };
        DestroyAcceleratorTable(accelerator);
        if IsWindow(hwnd) != 0 {
            let shutdown = app.stop_proxy();
            DestroyWindow(hwnd);
            if let Err(shutdown) = shutdown {
                return Err(match result {
                    Ok(()) => shutdown,
                    Err(error) => {
                        error.context(format!("Proxy shutdown also failed: {shutdown:#}"))
                    }
                });
            }
        }
        result
    }
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // SAFETY: Windows supplies the documented message payloads. User data is a shared, UI-thread-only App pointer.
    unsafe {
        if message == WM_NCCREATE {
            let create = &*(lparam as *const CREATESTRUCTW);
            let app = &*(create.lpCreateParams as *const App);
            app.hwnd.set(hwnd);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, create.lpCreateParams as isize);
        }
        let pointer = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const App;
        if pointer.is_null() {
            return DefWindowProcW(hwnd, message, wparam, lparam);
        }
        let app = &*pointer;
        match message {
            WM_CREATE => match app.initialize() {
                Ok(()) => return 0,
                Err(error) => {
                    *app.initialization_error.borrow_mut() = Some(format!("{error:#}"));
                    return -1;
                }
            },
            WM_SIZE => {
                app.layout();
                return 0;
            }
            WM_GETMINMAXINFO => {
                let info = &mut *(lparam as *mut MINMAXINFO);
                info.ptMinTrackSize = POINT {
                    x: app.s(980),
                    y: app.s(620),
                };
                return 0;
            }
            WM_DPICHANGED => {
                if let Err(error) =
                    app.change_dpi((wparam & 0xffff) as u32, &*(lparam as *const RECT))
                {
                    app.report(error);
                }
                return 0;
            }
            WM_PAINT => {
                app.paint();
                return 0;
            }
            WM_ERASEBKGND => return 1,
            WM_DRAWITEM if lparam != 0 => {
                app.draw_button(&*(lparam as *const DRAWITEMSTRUCT));
                return 1;
            }
            WM_CTLCOLORSTATIC | WM_CTLCOLOREDIT => {
                let dc = wparam as HDC;
                SetTextColor(dc, TEXT);
                SetBkColor(dc, WHITE);
                return GetStockObject(WHITE_BRUSH) as isize;
            }
            WM_COMMAND => {
                let id = (wparam & 0xffff) as u16;
                let code = ((wparam >> 16) & 0xffff) as u32;
                if id == SEARCH && code == EN_CHANGE {
                    app.filter_changed();
                } else if id == FIND_QUERY && code == EN_CHANGE {
                    app.find_cursor.set(None);
                    if app.find_open.get() {
                        app.find_step(false);
                    }
                } else if (id == REQUEST_BODY || id == RESPONSE_BODY) && code == EN_SETFOCUS {
                    let target = if id == REQUEST_BODY { 0 } else { 1 };
                    app.select_find_pane(target);
                } else if id == SCOPE && code == CBN_SELCHANGE {
                    if let Some(c) = app.controls.get() {
                        app.scope
                            .set(SendMessageW(c.scope, CB_GETCURSEL, 0, 0) as usize);
                        app.review_cursor.set(None);
                        app.refresh(true);
                    }
                } else if code == 0 || code == 1 {
                    app.command(id);
                }
                return 0;
            }
            WM_NOTIFY => {
                if let Some(result) = app.notify(lparam) {
                    return result;
                }
            }
            WM_NEXTDLGCTL => {
                // This is a modeless top-level window, not a dialog using DefDlgProc.
                // Honor native dialog focus requests before routing Enter by focus.
                let target = if lparam != 0 {
                    wparam as HWND
                } else {
                    GetNextDlgTabItem(hwnd, GetFocus(), (wparam != 0) as i32)
                };
                if !target.is_null() && IsChild(hwnd, target) != 0 {
                    SetFocus(target);
                }
                return 0;
            }
            WM_TIMER => {
                app.tick();
                return 0;
            }
            WM_LBUTTONDOWN if app.pointer_on_splitter() => {
                app.dragging.set(true);
                SetCapture(hwnd);
                return 0;
            }
            WM_MOUSEMOVE if app.dragging.get() => {
                let x = (lparam & 0xffff) as u16 as i16 as i32;
                let (width, _, _) = app.dimensions();
                if width > 0 {
                    app.split.set((x as f64 / width as f64).clamp(0.35, 0.72));
                    app.layout();
                }
                return 0;
            }
            WM_LBUTTONUP if app.dragging.replace(false) => {
                ReleaseCapture();
                return 0;
            }
            WM_CAPTURECHANGED => {
                app.dragging.set(false);
                return 0;
            }
            WM_SETCURSOR if app.pointer_on_splitter() => {
                SetCursor(LoadCursorW(null_mut(), IDC_SIZEWE));
                return 1;
            }
            WM_CLOSE => {
                app.close();
                return 0;
            }
            WM_DESTROY => {
                KillTimer(hwnd, 1);
                PostQuitMessage(0);
                return 0;
            }
            WM_NCDESTROY => {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            }
            _ => {}
        }
        DefWindowProcW(hwnd, message, wparam, lparam)
    }
}

unsafe fn add_tabs(hwnd: HWND, names: &[&str]) -> Result<()> {
    // SAFETY: TCM_INSERTITEM copies each UTF-16 tab caption before its temporary buffer is released.
    unsafe {
        for (index, name) in names.iter().enumerate() {
            let mut name = wide(name);
            let item = TCITEMW {
                mask: TCIF_TEXT,
                pszText: name.as_mut_ptr(),
                ..Default::default()
            };
            ensure!(
                SendMessageW(hwnd, TCM_INSERTITEMW, index, &item as *const _ as isize) != -1,
                "Create inspector tab"
            );
        }
    }
    Ok(())
}

unsafe fn copy_wide(value: &str, pointer: *mut u16, capacity: usize) {
    if pointer.is_null() || capacity == 0 {
        return;
    }
    // SAFETY: The native notification supplies a writable buffer with this explicit character capacity.
    unsafe {
        let buffer = std::slice::from_raw_parts_mut(pointer, capacity);
        let mut length = 0;
        for unit in value.encode_utf16().take(capacity - 1) {
            buffer[length] = unit;
            length += 1;
        }
        buffer[length] = 0;
    }
}

fn tab_kind(index: isize) -> Inspector {
    match index {
        1 => Inspector::Text,
        2 => Inspector::Json,
        3 => Inspector::Hex,
        _ => Inspector::Headers,
    }
}

fn capture_mode_from_button(button: i32) -> Result<Option<CaptureMode>> {
    match button {
        CAPTURE_WINDOWS => Ok(Some(CaptureMode::Windows)),
        CAPTURE_MANUAL => Ok(Some(CaptureMode::Manual)),
        IDCANCEL => Ok(None),
        _ => bail!("Capture setup returned an unexpected selection: {button}"),
    }
}

fn https_trust_from_button(button: i32) -> Result<Option<HttpsTrust>> {
    match button {
        HTTPS_TRUST_WINDOWS => Ok(Some(HttpsTrust::Windows)),
        HTTPS_CLIENT_TRUST => Ok(Some(HttpsTrust::ClientManaged)),
        IDCANCEL => Ok(None),
        _ => bail!("HTTPS setup returned an unexpected selection: {button}"),
    }
}

fn resolve_https_trust(
    mut check: impl FnMut() -> Result<bool>,
    choose: impl FnOnce() -> Result<Option<HttpsTrust>>,
    install: impl FnOnce() -> Result<()>,
) -> Result<Option<HttpsTrust>> {
    if check()? {
        return Ok(Some(HttpsTrust::Windows));
    }
    let choice = choose()?;
    if choice == Some(HttpsTrust::Windows) {
        install()?;
        ensure!(
            check()?,
            "The CA could not be verified in the Windows user trust store. HTTPS decryption remains off."
        );
    }
    Ok(choice)
}

fn https_status(enabled: bool, trust: HttpsTrust) -> &'static str {
    if !enabled {
        "HTTPS decryption: OFF"
    } else if trust == HttpsTrust::Windows {
        "HTTPS: Windows CA trusted"
    } else {
        "HTTPS: client trust required"
    }
}

fn capture_badge(demo: bool, active: bool, recording: bool, routed: bool) -> &'static str {
    if demo {
        "DEMO DATA"
    } else if !active {
        "READY"
    } else if !recording {
        "PAUSED"
    } else if routed {
        "WIN PROXY ON"
    } else {
        "LISTENER ONLY"
    }
}

fn empty_capture_message(active: bool, recording: bool, routed: bool, port: &str) -> String {
    if !active {
        "Ready when you are.\n\nClick Start capture and choose Capture Windows traffic\nor Manual proxy. No traffic is routed until you choose.\n\nF12  Start capture     |     Ctrl+L  Filter     |     Ctrl+S  Save HAR".into()
    } else if !recording {
        "Recording is paused.\n\nClick Resume capture to record new sessions.\nThe proxy still forwards existing traffic.".into()
    } else if routed {
        "Windows proxy capture is enabled.\n\nReproduce the issue in a proxy-aware application.\nWith HTTPS decryption off, look for CONNECT tunnels.\nApps that bypass Windows proxy settings need manual configuration.".into()
    } else {
        format!(
            "Listener only - Windows traffic is NOT routed.\n\nSet your test app's HTTP/HTTPS proxy to 127.0.0.1:{port},\nor enable Windows proxy in the toolbar.\n\nStarting the listener alone does not capture browser traffic."
        )
    }
}

fn find_enter_search_control(id: i32) -> bool {
    [FIND_QUERY, REQUEST_BODY, RESPONSE_BODY]
        .into_iter()
        .any(|control| i32::from(control) == id)
}

fn problem_row_colors(
    row: &SessionSummary,
    selected: bool,
    high_contrast: bool,
) -> Option<(u32, u32)> {
    (troubleshoot::problem_marker(row) && !selected && !high_contrast)
        .then_some((RED, rgb(255, 238, 238)))
}

fn draw_error_cell(list: HWND, draw: &NMLVCUSTOMDRAW, row: &SessionSummary, dpi: u32) -> bool {
    let column = draw.iSubItem;
    if column < 0 || column as usize >= COLUMNS.len() {
        return false;
    }
    // SAFETY: The list and paint DC are live during NM_CUSTOMDRAW. Buffers are local;
    // the saved DC is restored and the only owned GDI brush is deleted before return.
    unsafe {
        let mut bounds = RECT {
            top: column,
            left: LVIR_BOUNDS as i32,
            ..Default::default()
        };
        if SendMessageW(
            list,
            LVM_GETSUBITEMRECT,
            draw.nmcd.dwItemSpec,
            &mut bounds as *mut RECT as isize,
        ) == 0
        {
            return false;
        }
        // Subitem zero's bounds cover the entire row, unlike the other subitems.
        if column == 0 {
            bounds.right = bounds.left + SendMessageW(list, LVM_GETCOLUMNWIDTH, 0, 0) as i32;
        }
        let dc = draw.nmcd.hdc;
        let saved = SaveDC(dc);
        if saved == 0 {
            return false;
        }
        IntersectClipRect(dc, bounds.left, bounds.top, bounds.right, bounds.bottom);
        let brush = CreateSolidBrush(rgb(255, 238, 238));
        if brush.is_null() {
            RestoreDC(dc, saved);
            return false;
        }
        FillRect(dc, &bounds, brush);
        DeleteObject(brush);
        let font = SendMessageW(list, WM_GETFONT, 0, 0) as HFONT;
        if !font.is_null() {
            SelectObject(dc, font);
        }
        SetBkMode(dc, TRANSPARENT as i32);
        SetTextColor(dc, RED);
        let mut text_bounds = bounds;
        text_bounds.left += scaled(6, dpi);
        text_bounds.right -= scaled(6, dpi);
        if column == 1 && bounds.right - bounds.left >= scaled(64, dpi) {
            let size = scaled(16, dpi).min(bounds.bottom - bounds.top);
            text_bounds.right -= size + scaled(4, dpi);
            DrawIconEx(
                dc,
                bounds.right - size - scaled(6, dpi),
                bounds.top + (bounds.bottom - bounds.top - size) / 2,
                LoadIconW(null_mut(), IDI_ERROR),
                size,
                size,
                0,
                null_mut(),
                DI_NORMAL,
            );
        }
        let text = wide(&cell_text(row, column as usize));
        DrawTextW(
            dc,
            text.as_ptr(),
            (text.len() - 1) as i32,
            &mut text_bounds,
            DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX,
        );
        RestoreDC(dc, saved);
        true
    }
}

fn cell_text(row: &SessionSummary, column: usize) -> String {
    match column {
        0 => row.id.to_string(),
        1 => row.status.map_or(
            if row.failed {
                "Error".into()
            } else if row.complete {
                "-".into()
            } else {
                "...".into()
            },
            |s| s.to_string(),
        ),
        2 => row.method.clone(),
        3 => {
            if row.kind == SessionKind::Tunnel {
                "Tunnel".into()
            } else {
                row.protocol.clone()
            }
        }
        4 => row.host.clone(),
        5 => row.path.clone(),
        6 => inspect::bytes_label(row.bytes),
        7 => row.elapsed_ms.map_or("-".into(), |ms| {
            format!("{ms} ms{}", if row.complete { "" } else { "+" })
        }),
        8 => row.content_type.clone(),
        _ => String::new(),
    }
}

fn compare_rows(a: &SessionSummary, b: &SessionSummary, column: usize) -> Ordering {
    match column {
        0 => a.id.cmp(&b.id),
        1 => a.status.cmp(&b.status),
        2 => a.method.cmp(&b.method),
        3 => a.protocol.cmp(&b.protocol),
        4 => a.host.cmp(&b.host),
        5 => a.path.cmp(&b.path),
        6 => a.bytes.cmp(&b.bytes),
        7 => a.elapsed_ms.cmp(&b.elapsed_ms),
        8 => a.content_type.cmp(&b.content_type),
        _ => a.id.cmp(&b.id),
    }
}

fn make_menu(recent: &super::recent::RecentFiles) -> Result<HMENU> {
    // SAFETY: Ownership of the completed menu tree transfers to the main window.
    unsafe {
        let menu = CreateMenu();
        ensure!(!menu.is_null(), "Create main menu");
        let result = (|| -> Result<()> {
            for (title, items) in [
                (
                    "&File",
                    vec![
                        (IMPORT_SAZ, "Open HAR or SAZ...\tCtrl+O"),
                        (EXPORT_SAZ, "Save SAZ (sensitive)..."),
                        (EXPORT_SAZ_SANITIZED, "Save sanitized SAZ..."),
                        (0, ""),
                        (EXPORT, "Save sanitized HAR...\tCtrl+S"),
                        (EXPORT_FULL, "Save full HAR (sensitive)...\tCtrl+Shift+S"),
                        (0, ""),
                        (EXIT, "Exit\tAlt+F4"),
                    ],
                ),
                (
                    "&Capture",
                    vec![
                        (CAPTURE, "Start / pause / resume\tF12"),
                        (STOP, "Stop proxy\tShift+F12"),
                        (0, ""),
                        (CLEAR, "Clear sessions\tCtrl+Delete"),
                        (FOCUS_SEARCH, "Focus filter\tCtrl+L"),
                    ],
                ),
                (
                    "&View",
                    vec![
                        (FIND, "Find in message...\tCtrl+F"),
                        (FIND_NEXT, "Next message match\tF3"),
                        (FIND_PREVIOUS, "Previous message match\tShift+F3"),
                        (0, ""),
                        (REVIEW_FIRST, "Review next visible candidate"),
                    ],
                ),
                (
                    "&HTTPS",
                    vec![
                        (TRUST_CA, "Trust local CA..."),
                        (EXPORT_CA, "Export public CA..."),
                        (REMOVE_CA, "Remove local CA trust..."),
                        (0, ""),
                        (RESET_CA, "Reset local CA..."),
                    ],
                ),
                (
                    "&Tools",
                    vec![
                        (DATA_FOLDER, "Open local data folder"),
                        (GUIDE, "Capture guide"),
                    ],
                ),
                (
                    "&Help",
                    vec![(GUIDE, "Getting started"), (ABOUT, "About Juan")],
                ),
            ] {
                let popup = CreatePopupMenu();
                ensure!(!popup.is_null(), "Create submenu");
                if AppendMenuW(menu, MF_POPUP, popup as usize, wide(title).as_ptr()) == 0 {
                    DestroyMenu(popup);
                    bail!("Attach submenu");
                }
                for (id, label) in items {
                    ensure!(
                        AppendMenuW(
                            popup,
                            if id == 0 { MF_SEPARATOR } else { MF_STRING },
                            id as usize,
                            wide(label).as_ptr()
                        ) != 0,
                        "Create menu item"
                    );
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            DestroyMenu(menu);
            return Err(error);
        }
        let file = GetSubMenu(menu, 0);
        let history = match make_recent_menu(recent) {
            Ok(history) => history,
            Err(error) => {
                DestroyMenu(menu);
                return Err(error);
            }
        };
        if InsertMenuW(
            file,
            1,
            MF_BYPOSITION | MF_POPUP,
            history as usize,
            wide("&Recent files").as_ptr(),
        ) == 0
        {
            DestroyMenu(history);
            DestroyMenu(menu);
            bail!("Attach recent-file menu");
        }
        Ok(menu)
    }
}

fn make_recent_menu(recent: &super::recent::RecentFiles) -> Result<HMENU> {
    // SAFETY: This function exclusively owns the menu until returning it; every
    // error destroys it and successful callers attach it to the window's menu.
    unsafe {
        let menu = CreatePopupMenu();
        ensure!(!menu.is_null(), "Create recent-file menu");
        let result = (|| -> Result<()> {
            if recent.paths().is_empty() {
                ensure!(
                    AppendMenuW(
                        menu,
                        MF_STRING | MF_GRAYED,
                        0,
                        wide("(No recent files)").as_ptr()
                    ) != 0,
                    "Create empty history label"
                );
            }
            for (index, path) in recent.paths().iter().enumerate() {
                let label = super::recent::menu_label(path, index);
                ensure!(
                    AppendMenuW(
                        menu,
                        MF_STRING,
                        RECENT_FIRST as usize + index,
                        wide(&label).as_ptr()
                    ) != 0,
                    "Create recent-file entry"
                );
            }
            ensure!(
                AppendMenuW(menu, MF_SEPARATOR, 0, null()) != 0,
                "Create history separator"
            );
            // Always available, even after a corrupt history failed to load.
            ensure!(
                AppendMenuW(
                    menu,
                    MF_STRING,
                    CLEAR_RECENT as usize,
                    wide("&Clear history").as_ptr()
                ) != 0,
                "Create clear history command"
            );
            Ok(())
        })();
        if let Err(error) = result {
            DestroyMenu(menu);
            return Err(error);
        }
        Ok(menu)
    }
}

#[cfg(test)]
mod capture_start_tests {
    use super::*;

    #[test]
    fn file_menu_contains_recent_archive_commands_and_clear_history() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("capture.har");
        std::fs::write(&path, "{}").unwrap();
        let mut recent = super::super::recent::RecentFiles::empty(directory.path());
        recent.record_success(&path).unwrap();
        let menu = make_menu(&recent).unwrap();
        // SAFETY: This test owns the unattached menu tree and destroys it once.
        unsafe {
            let file = GetSubMenu(menu, 0);
            let history = GetSubMenu(file, 1);
            assert_eq!(GetMenuItemCount(history), 3);
            assert_eq!(GetMenuItemID(history, 0), RECENT_FIRST as u32);
            assert_eq!(GetMenuItemID(history, 2), CLEAR_RECENT as u32);
            DestroyMenu(menu);
        }
    }

    #[test]
    fn find_enter_preserves_native_button_actions() {
        for id in [FIND_QUERY, REQUEST_BODY, RESPONSE_BODY] {
            assert!(find_enter_search_control(i32::from(id)));
        }
        for id in [FIND_NEXT, FIND_PREVIOUS, FIND_CLOSE, FIND_CASE, SEARCH, 0] {
            assert!(!find_enter_search_control(i32::from(id)));
        }
        assert!(!find_enter_search_control(-1));
    }

    #[test]
    fn problem_cells_are_compact_with_reasons_in_details_and_accessible_colors() {
        let imported = crate::har_import::read(
            include_bytes!("../../tests/fixtures/har/troubleshooting.har").as_slice(),
            crate::capture::CaptureLimits::default(),
        )
        .unwrap();
        let rows: Vec<_> = imported.sessions.iter().map(|s| s.summary()).collect();
        assert_eq!(cell_text(&rows[5], 1), "403");
        assert_eq!(cell_text(&rows[6], 1), "429");
        assert_eq!(cell_text(&rows[7], 1), "500");
        assert_eq!(cell_text(&rows[8], 1), "401");
        assert_eq!(cell_text(&rows[10], 1), "200");
        assert!(troubleshoot::reason(&rows[9]).contains("recorded transport/source error"));
        for row in &rows {
            assert_eq!(
                problem_row_colors(row, false, false).is_some(),
                troubleshoot::problem_marker(row)
            );
            assert_eq!(problem_row_colors(row, true, false), None);
            assert_eq!(problem_row_colors(row, false, true), None);
        }
        let mut row = rows[0].clone();
        for status in 400..=599 {
            row.status = Some(status);
            assert_eq!(cell_text(&row, 1), status.to_string());
            assert_eq!(
                problem_row_colors(&row, false, false),
                Some((RED, rgb(255, 238, 238)))
            );
        }
        row.status = Some(400);
        assert_eq!(troubleshoot::reason(&row), "400 Bad Request");
    }

    #[test]
    fn routing_requires_an_explicit_choice_and_cancel_does_not_default_to_capture() {
        assert_eq!(
            capture_mode_from_button(CAPTURE_WINDOWS).unwrap(),
            Some(CaptureMode::Windows)
        );
        assert_eq!(
            capture_mode_from_button(CAPTURE_MANUAL).unwrap(),
            Some(CaptureMode::Manual)
        );
        assert_eq!(capture_mode_from_button(IDCANCEL).unwrap(), None);
        assert!(capture_mode_from_button(0).is_err());
    }

    #[test]
    fn listener_only_state_does_not_claim_windows_traffic_is_captured() {
        assert_eq!(capture_badge(false, true, true, false), "LISTENER ONLY");
        let empty = empty_capture_message(true, true, false, "8866");
        assert!(empty.contains("NOT routed"));
        assert!(empty.contains("127.0.0.1:8866"));
        assert!(empty.contains("Windows proxy"));
    }

    #[test]
    fn stopped_paused_and_windows_capture_have_distinct_guidance() {
        assert_eq!(capture_badge(false, false, true, false), "READY");
        assert_eq!(capture_badge(false, true, false, true), "PAUSED");
        assert_eq!(capture_badge(false, true, true, true), "WIN PROXY ON");
        assert!(empty_capture_message(false, true, false, "8866").contains("choose"));
        assert!(empty_capture_message(true, false, true, "8866").contains("paused"));
        assert!(empty_capture_message(true, true, true, "8866").contains("CONNECT"));
    }

    #[test]
    fn trusted_ca_is_reused_without_prompting_or_reinstalling() {
        let result = resolve_https_trust(
            || Ok(true),
            || panic!("An already trusted CA must not prompt again"),
            || panic!("An already trusted CA must not be reinstalled"),
        );
        assert_eq!(result.unwrap(), Some(HttpsTrust::Windows));
    }

    #[test]
    fn cancelling_https_never_installs_trust_or_enables_decryption() {
        let result = resolve_https_trust(
            || Ok(false),
            || Ok(None),
            || panic!("Cancelling must not install a root"),
        );
        assert_eq!(result.unwrap(), None);
        assert_eq!(https_trust_from_button(IDCANCEL).unwrap(), None);
        assert!(https_trust_from_button(0).is_err());
    }

    #[test]
    fn client_managed_trust_does_not_change_windows() {
        let result = resolve_https_trust(
            || Ok(false),
            || Ok(Some(HttpsTrust::ClientManaged)),
            || panic!("Client-managed trust must not install a Windows root"),
        );
        assert_eq!(result.unwrap(), Some(HttpsTrust::ClientManaged));
        assert_eq!(
            https_status(true, HttpsTrust::ClientManaged),
            "HTTPS: client trust required"
        );
    }

    #[test]
    fn approved_installation_is_verified_before_enabling_https() {
        let trusted = Cell::new(false);
        let installs = Cell::new(0);
        let result = resolve_https_trust(
            || Ok(trusted.get()),
            || Ok(Some(HttpsTrust::Windows)),
            || {
                installs.set(installs.get() + 1);
                trusted.set(true);
                Ok(())
            },
        );
        assert_eq!(result.unwrap(), Some(HttpsTrust::Windows));
        assert_eq!(installs.get(), 1);
    }

    #[test]
    fn failed_or_unverified_installation_cannot_enable_https() {
        let failed = resolve_https_trust(
            || Ok(false),
            || Ok(Some(HttpsTrust::Windows)),
            || bail!("Installation was denied"),
        );
        assert!(failed.is_err());
        let unverified =
            resolve_https_trust(|| Ok(false), || Ok(Some(HttpsTrust::Windows)), || Ok(()));
        assert!(unverified.is_err());
        let unreadable = resolve_https_trust(
            || bail!("Store is unreadable"),
            || panic!("Do not guess trust when the store cannot be read"),
            || panic!("Do not install after a trust-check failure"),
        );
        assert!(unreadable.is_err());
    }
}

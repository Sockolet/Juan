use std::{mem::size_of, path::PathBuf, ptr::null};

use anyhow::{Context, Result, bail, ensure};
use windows_sys::Win32::{
    Foundation::*,
    Graphics::Gdi::*,
    System::{DataExchange::*, LibraryLoader::GetModuleHandleW, Memory::*},
    UI::{
        Controls::Dialogs::*, Controls::*, Input::KeyboardAndMouse::EnableWindow,
        WindowsAndMessaging::*,
    },
};

use super::system::wide;

pub const fn rgb(red: u8, green: u8, blue: u8) -> COLORREF {
    red as u32 | ((green as u32) << 8) | ((blue as u32) << 16)
}

pub const NAVY: COLORREF = rgb(18, 34, 46);
pub const ACCENT: COLORREF = rgb(9, 117, 111);
pub const TEXT: COLORREF = rgb(30, 47, 60);
pub const MUTED: COLORREF = rgb(102, 119, 132);
pub const BORDER: COLORREF = rgb(222, 230, 235);
pub const CANVAS: COLORREF = rgb(245, 248, 250);
pub const WHITE: COLORREF = rgb(255, 255, 255);
pub const RED: COLORREF = rgb(178, 48, 65);
pub const AMBER: COLORREF = rgb(161, 101, 12);

pub fn scaled(value: i32, dpi: u32) -> i32 {
    ((value as i64 * dpi as i64 + 48) / 96) as i32
}

pub struct Font(HFONT);

impl Font {
    fn new(points: i32, weight: i32, face: &str, dpi: u32) -> Result<Self> {
        // SAFETY: CreateFont copies the face name and returns a uniquely owned GDI handle.
        let font = unsafe {
            CreateFontW(
                -(points * dpi as i32 / 72),
                0,
                0,
                0,
                weight,
                0,
                0,
                0,
                DEFAULT_CHARSET as u32,
                OUT_DEFAULT_PRECIS as u32,
                CLIP_DEFAULT_PRECIS as u32,
                CLEARTYPE_QUALITY as u32,
                DEFAULT_PITCH as u32,
                wide(face).as_ptr(),
            )
        };
        if font.is_null() {
            bail!("Create UI font: {}", std::io::Error::last_os_error());
        }
        Ok(Self(font))
    }
    pub fn raw(&self) -> HFONT {
        self.0
    }
}

impl Drop for Font {
    fn drop(&mut self) {
        // SAFETY: Windows no longer references the font when Fonts is replaced or the window is destroyed.
        unsafe {
            DeleteObject(self.0);
        }
    }
}

pub struct Fonts {
    pub text: Font,
    pub small: Font,
    pub bold: Font,
    pub brand: Font,
    pub mono: Font,
}

impl Fonts {
    pub fn new(dpi: u32) -> Result<Self> {
        Ok(Self {
            text: Font::new(10, 400, "Segoe UI", dpi)?,
            small: Font::new(9, 400, "Segoe UI", dpi)?,
            bold: Font::new(9, 600, "Segoe UI", dpi)?,
            brand: Font::new(22, 600, "Segoe UI", dpi)?,
            mono: Font::new(10, 400, "Consolas", dpi)?,
        })
    }
}

pub fn child(
    parent: HWND,
    class: &str,
    text: &str,
    style: u32,
    ex_style: u32,
    id: u16,
) -> Result<HWND> {
    // SAFETY: Handles are created and used only on the owning UI thread; strings are copied synchronously.
    let hwnd = unsafe {
        CreateWindowExW(
            ex_style,
            wide(class).as_ptr(),
            wide(text).as_ptr(),
            WS_CHILD | WS_VISIBLE | style,
            0,
            0,
            10,
            10,
            parent,
            id as usize as HMENU,
            GetModuleHandleW(null()),
            null(),
        )
    };
    if hwnd.is_null() {
        bail!(
            "Create {class} control: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(hwnd)
}

pub fn set_text(hwnd: HWND, text: &str) {
    // SAFETY: The window owns a copy after this synchronous call. Embedded NULs are made visible.
    unsafe {
        SetWindowTextW(hwnd, wide(&text.replace('\0', "\\0")).as_ptr());
    }
}

pub fn text(hwnd: HWND) -> String {
    // SAFETY: The length and copy are queried on the owning UI thread without intervening message dispatch.
    unsafe {
        let length = GetWindowTextLengthW(hwnd).max(0) as usize;
        let mut buffer = vec![0u16; length + 1];
        let written =
            GetWindowTextW(hwnd, buffer.as_mut_ptr(), buffer.len() as i32).max(0) as usize;
        String::from_utf16_lossy(&buffer[..written])
    }
}

pub fn set_font(hwnd: HWND, font: HFONT) {
    // SAFETY: The Fonts owner keeps the font alive until every control has been rebound or destroyed.
    unsafe {
        SendMessageW(hwnd, WM_SETFONT, font as usize, 1);
    }
}

pub fn position(hwnd: HWND, x: i32, y: i32, width: i32, height: i32) {
    // SAFETY: These are live child handles belonging to the current UI thread.
    unsafe {
        MoveWindow(hwnd, x, y, width.max(1), height.max(1), 1);
    }
}

pub fn visible(hwnd: HWND, shown: bool) {
    // SAFETY: Child windows are owned by the parent and remain valid while laid out.
    unsafe {
        ShowWindow(hwnd, if shown { SW_SHOW } else { SW_HIDE });
    }
}

pub fn enable(hwnd: HWND, enabled: bool) {
    // SAFETY: This only changes input state on a live UI-thread control.
    unsafe {
        EnableWindow(hwnd, enabled.into());
    }
}

pub fn checked(hwnd: HWND) -> bool {
    // SAFETY: The handle refers to a standard checkbox control.
    unsafe { SendMessageW(hwnd, BM_GETCHECK, 0, 0) == BST_CHECKED as isize }
}

pub fn set_checked(hwnd: HWND, checked: bool) {
    // SAFETY: BM_SETCHECK does not send a user click notification.
    unsafe {
        SendMessageW(
            hwnd,
            BM_SETCHECK,
            if checked { BST_CHECKED } else { BST_UNCHECKED } as usize,
            0,
        );
    }
}

pub fn message(parent: HWND, title: &str, text: &str, flags: u32) -> i32 {
    // SAFETY: The modal dialog copies both strings and is associated with our UI window.
    unsafe { MessageBoxW(parent, wide(text).as_ptr(), wide(title).as_ptr(), flags) }
}

pub fn confirm(parent: HWND, title: &str, text: &str) -> bool {
    message(
        parent,
        title,
        text,
        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2,
    ) == IDYES
}

pub fn choose_action(
    parent: HWND,
    title: &str,
    instruction: &str,
    content: &str,
    footer: &str,
    choices: &[(i32, &str)],
) -> Result<i32> {
    let default = choices
        .first()
        .context("An action dialog needs at least one choice")?
        .0;
    let (title, instruction, content, footer) =
        (wide(title), wide(instruction), wide(content), wide(footer));
    let captions: Vec<_> = choices.iter().map(|(_, caption)| wide(caption)).collect();
    let buttons: Vec<_> = choices
        .iter()
        .zip(&captions)
        .map(|((id, _), caption)| TASKDIALOG_BUTTON {
            nButtonID: *id,
            pszButtonText: caption.as_ptr(),
        })
        .collect();
    let config = TASKDIALOGCONFIG {
        cbSize: size_of::<TASKDIALOGCONFIG>() as u32,
        hwndParent: parent,
        dwFlags: TDF_USE_COMMAND_LINKS
            | TDF_ALLOW_DIALOG_CANCELLATION
            | TDF_POSITION_RELATIVE_TO_WINDOW,
        dwCommonButtons: TDCBF_CANCEL_BUTTON,
        pszWindowTitle: title.as_ptr(),
        pszMainInstruction: instruction.as_ptr(),
        pszContent: content.as_ptr(),
        cButtons: buttons.len().try_into()?,
        pButtons: buttons.as_ptr(),
        nDefaultButton: default,
        pszFooter: footer.as_ptr(),
        cxWidth: 340,
        ..Default::default()
    };
    let mut selected = 0;
    // SAFETY: The UI-thread parent and all text/button buffers remain valid throughout the modal call.
    let result = unsafe {
        TaskDialogIndirect(
            &config,
            &mut selected,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    ensure!(
        result >= 0,
        "Could not show setup dialog (HRESULT 0x{:08X})",
        result as u32
    );
    Ok(selected)
}

pub fn rect(left: i32, top: i32, right: i32, bottom: i32) -> RECT {
    RECT {
        left,
        top,
        right,
        bottom,
    }
}

pub fn fill(dc: HDC, area: RECT, color: COLORREF) {
    // SAFETY: DC_BRUSH is a stock object; its color is local to this paint DC.
    unsafe {
        SetDCBrushColor(dc, color);
        FillRect(dc, &area, GetStockObject(DC_BRUSH) as HBRUSH);
    }
}

pub fn rounded(dc: HDC, area: RECT, color: COLORREF, border: COLORREF, radius: i32) {
    // SAFETY: Restore selected stock objects so the caller retains its original DC state.
    unsafe {
        let old_brush = SelectObject(dc, GetStockObject(DC_BRUSH));
        let old_pen = SelectObject(dc, GetStockObject(DC_PEN));
        SetDCBrushColor(dc, color);
        SetDCPenColor(dc, border);
        RoundRect(
            dc,
            area.left,
            area.top,
            area.right,
            area.bottom,
            radius,
            radius,
        );
        SelectObject(dc, old_pen);
        SelectObject(dc, old_brush);
    }
}

pub fn label(dc: HDC, area: RECT, value: &str, font: HFONT, color: COLORREF, alignment: u32) {
    // SAFETY: The DC and font remain live for this paint operation; DrawText does not retain the text.
    unsafe {
        let old = SelectObject(dc, font);
        SetBkMode(dc, TRANSPARENT as i32);
        SetTextColor(dc, color);
        let mut area = area;
        DrawTextW(
            dc,
            wide(value).as_ptr(),
            -1,
            &mut area,
            DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX | alignment,
        );
        SelectObject(dc, old);
    }
}

#[derive(Clone, Copy)]
pub enum FileKind {
    Har,
    Saz,
    Certificate,
}

pub fn save_dialog(
    parent: HWND,
    title: &str,
    default_name: &str,
    kind: FileKind,
) -> Result<Option<PathBuf>> {
    file_dialog(parent, title, default_name, kind, true)
}

pub fn open_saz_dialog(parent: HWND) -> Result<Option<PathBuf>> {
    file_dialog(
        parent,
        "Open Fiddler session archive",
        "",
        FileKind::Saz,
        false,
    )
}

fn file_dialog(
    parent: HWND,
    title: &str,
    default_name: &str,
    kind: FileKind,
    save: bool,
) -> Result<Option<PathBuf>> {
    let mut buffer = vec![0u16; 32_768];
    for (slot, value) in buffer.iter_mut().zip(default_name.encode_utf16()) {
        *slot = value;
    }
    let (filter, extension) = match kind {
        FileKind::Certificate => (
            "PEM certificate (*.pem)\0*.pem\0All files (*.*)\0*.*\0\0",
            "pem",
        ),
        FileKind::Har => (
            "HTTP Archive (*.har)\0*.har\0All files (*.*)\0*.*\0\0",
            "har",
        ),
        FileKind::Saz => (
            "Fiddler session archive (*.saz)\0*.saz\0All files (*.*)\0*.*\0\0",
            "saz",
        ),
    };
    let filter: Vec<u16> = filter.encode_utf16().collect();
    let title = wide(title);
    let extension = wide(extension);
    let mut options = OPENFILENAMEW {
        lStructSize: size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: parent,
        lpstrFilter: filter.as_ptr(),
        lpstrFile: buffer.as_mut_ptr(),
        nMaxFile: buffer.len() as u32,
        lpstrTitle: title.as_ptr(),
        lpstrDefExt: extension.as_ptr(),
        Flags: OFN_EXPLORER
            | OFN_PATHMUSTEXIST
            | OFN_NOCHANGEDIR
            | if save {
                OFN_OVERWRITEPROMPT
            } else {
                OFN_FILEMUSTEXIST
            },
        ..Default::default()
    };
    // SAFETY: The native dialog writes a NUL-terminated UTF-16 path into the explicitly sized buffer.
    unsafe {
        let result = if save {
            GetSaveFileNameW(&mut options)
        } else {
            GetOpenFileNameW(&mut options)
        };
        if result == 0 {
            let error = CommDlgExtendedError();
            if error == 0 {
                return Ok(None);
            }
            bail!("Windows file dialog failed (0x{error:08X})");
        }
    }
    let length = buffer
        .iter()
        .position(|c| *c == 0)
        .context("Invalid filename returned by Windows")?;
    use std::os::windows::ffi::OsStringExt;
    Ok(Some(PathBuf::from(std::ffi::OsString::from_wide(
        &buffer[..length],
    ))))
}

pub fn copy_text(parent: HWND, value: &str) -> Result<()> {
    let value = wide(value);
    // SAFETY: Clipboard ownership of movable global memory transfers only after SetClipboardData succeeds.
    unsafe {
        if OpenClipboard(parent) == 0 {
            bail!("Open clipboard: {}", std::io::Error::last_os_error());
        }
        let result = (|| -> Result<()> {
            let memory = GlobalAlloc(GMEM_MOVEABLE, value.len() * size_of::<u16>());
            if memory.is_null() {
                bail!(
                    "Allocate clipboard text: {}",
                    std::io::Error::last_os_error()
                );
            }
            let pointer = GlobalLock(memory);
            if pointer.is_null() {
                GlobalFree(memory);
                bail!("Lock clipboard text: {}", std::io::Error::last_os_error());
            }
            std::ptr::copy_nonoverlapping(value.as_ptr(), pointer.cast::<u16>(), value.len());
            GlobalUnlock(memory);
            if EmptyClipboard() == 0 || SetClipboardData(13, memory).is_null() {
                let error = std::io::Error::last_os_error();
                GlobalFree(memory);
                bail!("Write clipboard text: {error}");
            }
            Ok(())
        })();
        CloseClipboard();
        result
    }
}

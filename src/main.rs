#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [] => juan::windows::ui::run(false, None),
        [arg] if arg == "--demo" => juan::windows::ui::run(true, None),
        [arg]
            if std::path::Path::new(arg)
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| {
                    extension.eq_ignore_ascii_case("saz") || extension.eq_ignore_ascii_case("har")
                }) =>
        {
            juan::windows::ui::run(false, Some(std::path::PathBuf::from(arg)))
        }
        _ => Err(anyhow::anyhow!(
            "Usage: juan [--demo | capture.saz | capture.har]\nFor headless capture or archive inspection use juan-cli --help."
        )),
    };
    if let Err(error) = result {
        use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
        let text = juan::windows::system::wide(&format!("{error:#}"));
        let title = juan::windows::system::wide("Juan");
        // SAFETY: Display startup failures even though the GUI binary has no console.
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                text.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONERROR,
            );
        }
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Juan's native desktop UI requires Windows. Use juan-cli for headless HTTP capture.");
    std::process::exit(1);
}

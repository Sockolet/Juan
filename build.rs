use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=resources/juan.manifest");
    println!("cargo:rerun-if-changed=build.rs");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let icon = out.join("juan.ico");
    fs::write(&icon, make_icon()).expect("write generated app icon");
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"))
        .join("resources")
        .join("juan.manifest");
    let escaped = |p: &std::path::Path| p.to_string_lossy().replace('\\', "\\\\");
    let resource = out.join("juan.rc");
    let version = env::var("CARGO_PKG_VERSION").expect("package version");
    let file_version = format!(
        "{},{},{},0",
        env::var("CARGO_PKG_VERSION_MAJOR").expect("major version"),
        env::var("CARGO_PKG_VERSION_MINOR").expect("minor version"),
        env::var("CARGO_PKG_VERSION_PATCH").expect("patch version")
    );
    fs::write(
        &resource,
        format!(
            r#"#include <windows.h>
1 RT_MANIFEST "{}"
1 ICON "{}"
1 VERSIONINFO
FILEVERSION {file_version}
PRODUCTVERSION {file_version}
FILEOS VOS_NT_WINDOWS32
FILETYPE VFT_APP
BEGIN
 BLOCK "StringFileInfo"
 BEGIN
  BLOCK "040904b0"
  BEGIN
   VALUE "FileDescription", "Juan - HTTP(S) Debugging Proxy\0"
   VALUE "FileVersion", "{version}\0"
   VALUE "ProductName", "Juan\0"
   VALUE "ProductVersion", "{version}\0"
   VALUE "LegalCopyright", "Copyright (c) 2026 Juan contributors\0"
  END
 END
 BLOCK "VarFileInfo"
 BEGIN
  VALUE "Translation", 0x409, 1200
 END
END
"#,
            escaped(&manifest),
            escaped(&icon)
        ),
    )
    .expect("write app resources");
    embed_resource::compile_for(&resource, ["juan"], embed_resource::NONE)
        .manifest_required()
        .expect("compile native app resources");
}

fn make_icon() -> Vec<u8> {
    let size = 32u32;
    let image_len = 40 + size * size * 4 + size * 4;
    let mut bytes = Vec::new();
    for n in [0u16, 1, 1] {
        bytes.extend(n.to_le_bytes());
    }
    bytes.extend([32, 32, 0, 0]);
    bytes.extend(1u16.to_le_bytes());
    bytes.extend(32u16.to_le_bytes());
    bytes.extend(image_len.to_le_bytes());
    bytes.extend(22u32.to_le_bytes());
    bytes.extend(40u32.to_le_bytes());
    bytes.extend(size.to_le_bytes());
    bytes.extend((size * 2).to_le_bytes());
    bytes.extend(1u16.to_le_bytes());
    bytes.extend(32u16.to_le_bytes());
    bytes.extend([0; 24]);
    let points = [
        (7.0f32, 8.0f32),
        (24.0, 8.0),
        (24.0, 21.0),
        (21.0, 25.0),
        (13.0, 25.0),
        (9.0, 21.0),
        (9.0, 18.0),
    ];
    for y in (0..size).rev() {
        for x in 0..size {
            let ink = points.windows(2).any(|pair| {
                let (ax, ay) = pair[0];
                let (bx, by) = pair[1];
                let (dx, dy) = (bx - ax, by - ay);
                let t = (((x as f32 - ax) * dx + (y as f32 - ay) * dy) / (dx * dx + dy * dy))
                    .clamp(0.0, 1.0);
                (x as f32 - ax - t * dx).powi(2) + (y as f32 - ay - t * dy).powi(2) < 2.5
            });
            bytes.extend(if ink {
                [216, 246, 241, 255]
            } else {
                [111, 111, 10, 255]
            });
        }
    }
    bytes.extend(vec![0; (size * 4) as usize]);
    bytes
}

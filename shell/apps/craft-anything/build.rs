//! Windows only: embed the app icon and version info (VERSIONINFO) into `craft-anything.exe`.
//!
//! On every other target this does nothing. A missing resource compiler is a warning, so a
//! cross-compile from macOS or Linux still links, unless `CRAFT_ANYTHING_REQUIRE_WINRES=1` (set by
//! the release workflow) turns it into an error.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../assets/app-icon/lsre.ico");
    println!("cargo:rerun-if-env-changed=CRAFT_ANYTHING_REQUIRE_WINRES");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut res = winresource::WindowsResource::new();
    res.set_icon("../../assets/app-icon/lsre.ico")
        .set("ProductName", "LSRE")
        .set("FileDescription", "LSRE: deep software analysis")
        .set("LegalCopyright", "Based on Craft Anything (c) the ArtCraft Team and the Craft Anything contributors, MIT OR Apache-2.0. LSRE changes (c) SalawatKoz.")
        .set("OriginalFilename", "lsre.exe")
        .set("InternalName", "lsre");
    if let Err(e) = res.compile() {
        if std::env::var_os("CRAFT_ANYTHING_REQUIRE_WINRES").is_some() {
            println!("cargo::error=embedding Windows resources failed: {e}");
            return;
        }
        println!("cargo:warning=craft-anything.exe built without icon/version resources: {e}");
    }
}

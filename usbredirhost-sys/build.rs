extern crate pkg_config;

fn main() {
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-lib=libusbredirhost");
    }
    #[cfg(not(target_os = "windows"))]
    {
        pkg_config::find_library("libusbredirhost").unwrap();
    }
}

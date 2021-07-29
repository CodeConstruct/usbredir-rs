extern crate pkg_config;

fn main() {
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-lib=libusbredirparser");
    }
    #[cfg(not(target_os = "windows"))]
    {
        pkg_config::find_library("libusbredirparser-0.5 >= 0.10").unwrap();
    }
}

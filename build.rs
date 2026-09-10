fn main() {
    let runtime_only = [
        "/usr/lib64/libpam.so.0",
        "/usr/lib/x86_64-linux-gnu/libpam.so.0",
        "/lib/x86_64-linux-gnu/libpam.so.0",
    ]
    .into_iter()
    .find(|path| std::path::Path::new(path).exists());
    if let Some(path) = runtime_only {
        println!("cargo:rustc-link-arg-bin=vega-web-auth-helper={path}");
    } else {
        println!("cargo:rustc-link-arg-bin=vega-web-auth-helper=-lpam");
    }
}

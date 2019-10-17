pub fn report_permission_error() {
    let user = std::env::var("USER").expect(
        "Unexpected error reading value of $USER!");
    let home = std::env::var("HOME").expect(
        "Unexpected error reading value of $HOME!");
    let current_executable = std::env::current_exe()
        .expect("Unexpected error reporting executable path!");
    eprintln!("USER: {}", user);
    eprintln!("HOME: {}", home);
    eprintln!("Executable: {}", current_executable.display());
    if home == "/" {
        eprintln!("User {} must have permission to write to '{}.zcash/' .",
                  user,
                  home);
    } else {
        eprintln!("User {} must have permission to write to '{}/.zcash/' .",
                  user,
                  home);
    }
}

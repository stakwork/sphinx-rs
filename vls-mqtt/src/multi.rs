use std::process::Command;

fn main() {
    while Command::new("cargo")
        .arg("run")
        .spawn()
        .expect("couldn't start child")
        .wait()
        .expect("command wasn't running")
        .success()
    {
        println!("Restarting vls-mqtt!");
    }
}

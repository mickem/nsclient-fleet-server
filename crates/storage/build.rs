use std::path::Path;

fn main() {
    // `sqlx::migrate!` embeds the migration files at compile time, but on stable Rust the
    // macro cannot tell Cargo which files it read. So adding a migration changes nothing
    // Cargo can see, the crate is considered up to date, and the new migration silently
    // does not exist — the symptom is a constraint that "was not applied" and a test that
    // fails for no visible reason.
    //
    // Naming the directory and every file in it fixes that. A directory alone is not
    // enough: Cargo hashes the directory's own mtime, which does not change when a file
    // inside it is edited.
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
    println!("cargo:rerun-if-changed={}", dir.display());
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            println!("cargo:rerun-if-changed={}", entry.path().display());
        }
    }
}

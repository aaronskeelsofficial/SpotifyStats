use std::fs;
use std::path::Path;
use walkdir::WalkDir;


fn main() {
    // Define the source and destination directories
    let src_dir = Path::new("assets");
    let target_dir = Path::new("target/release/assets");

    // Ensure the target directory exists
    if let Err(e) = fs::create_dir_all(target_dir) {
        eprintln!("Failed to create target directory: {}", e);
        return;
    }

    // Walk through the source directory and copy each file to the target directory
    for entry in WalkDir::new(src_dir).into_iter().filter_map(Result::ok) {
        let src_path = entry.path();
        // Create a relative path for the file, relative to the source directory
        let relative_path = src_path.strip_prefix(src_dir).unwrap();
        
        // Construct the destination path by joining the target directory with the relative path
        let dest_path = target_dir.join(relative_path);
        
        if src_path.is_dir() {
            // Create the directory in the target directory
            if let Err(e) = fs::create_dir_all(&dest_path) {
                eprintln!("Failed to create directory {}: {}", dest_path.display(), e);
            }
        } else {
            // Copy the file
            if let Err(e) = fs::copy(src_path, &dest_path) {
                eprintln!("Failed to copy file {} to {}: {}", src_path.display(), dest_path.display(), e);
            }
        }
    }

    println!("Copied folder {} to target/release", src_dir.display());
}
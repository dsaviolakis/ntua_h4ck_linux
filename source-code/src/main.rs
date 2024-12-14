use rand::Rng;
use std::fs::{self, File};
use std::io::{self, Write};
use std::time::Instant;
use signal_hook::iterator::Signals;
use signal_hook::consts::SIGUSR1;
use std::time::Duration;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::env;
use sha2::{Sha256, Digest}; // Add sha2 crate in Cargo.toml
use std::process; // Import to get the PID

const TOTAL_LEVELS: u8 = 6;
const SECRET_KEY: &str = "supersecretkey"; // Change this to a more secure value

fn main() {
    // Get the current working directory where the binary is being run
    let current_dir = env::current_dir().expect("Failed to get current directory");

    // Define the progress file path in the same directory as the binary
    let progress_path = current_dir.join(".minoan_progress");

    // Check if the progress file exists, if not, create it and show the intro message
    if !Path::new(&progress_path).exists() {
        // First run - Display intro and initialize level 0
        println!("This is the Minoan Labyrinth, a multi-level **beginner friendly** challenge...");
        println!("\nDo you have what it takes to uncover all the flags and conquer the labyrinth? Dive in and see for yourself!");

        // Create level 0
        create_level(0);

        // Create the progress file with an initial hash (level 0)
        let initial_hash = generate_hash(0);
        fs::write(&progress_path, initial_hash).expect("Failed to write progress file.");
    } else {
        // Read the current hash from the progress file
        let stored_hash = fs::read_to_string(&progress_path)
            .expect("Failed to read progress file.");

        // Check the current level based on the stored hash
        let current_level = get_current_level_from_hash(&stored_hash);

        if current_level == 7 {
            println!("Congratulations! You've completed the Minoan Labyrinth challenge!");
            return;
        }

        // Check if the files for the current level exist, if not, create them
        let level_dir = format!("./level{}", current_level);
        if !Path::new(&level_dir).exists() {
            println!("Files for level {} are missing. Creating them now...", current_level);
            create_level(current_level);
        }

        if current_level == 6 {
            // Level 6: Wait for the SIGUSR1 signal
            println!("Level 6: Please send the SIGUSR1 signal to continue. You have 2 minutes to do so.");

            // Print the PID to help the user send the signal
            let pid = process::id();
            println!("The PID of this process is: {}", pid);
            println!("To proceed, send the SIGUSR1 signal to this PID within 2 minutes.");

            // Start a timer for 2 minutes
            let start_time = Instant::now();

            // Set up signal handling for SIGUSR1
            let mut signals = Signals::new(&[SIGUSR1]).expect("Failed to register signal handler.");

            for signal in signals.forever() {
                match signal {
                    SIGUSR1 => {
                        let elapsed = start_time.elapsed();
                        if elapsed <= Duration::new(120, 0) {
                            println!("Signal received! Congratulations you finished the labyrinth!");

                            // Delete current level files and move to level -1
                            delete_level_files(current_level);
                            let next_level = 7;

                            // Update progress file for the next level
                            let next_level_hash = generate_hash(next_level);
                            fs::write(progress_path, next_level_hash).expect("Failed to update progress file.");
                            return;
                        } else {
                            println!("Timeout reached. You did not send the signal in time. Please try again.");
                            return;
                        }
                    },
                    _ => {} // Ignore other signals
                }

                // Check if 2 minutes have passed
                if start_time.elapsed() > Duration::new(120, 0) {
                    println!("Timeout reached. You did not send the signal in time. Please try again.");
                    return;
                }
            }
        } else {
            // For other levels, prompt for flag input as usual
            println!("Enter the flag for level {}: ", current_level);

            let mut user_flag = String::new();
            io::stdin().read_line(&mut user_flag).expect("Failed to read input.");
            user_flag = user_flag.trim().to_string();

            // Verify the flag for the current level
            if verify_flag(current_level, &user_flag) {
                // Correct flag, delete current level files and create the next level
                println!("Correct! Moving on to the next level.");
                delete_level_files(current_level);
                let next_level = current_level + 1;
                create_level(next_level);

                // Update the progress file with a new hash for the next level
                let next_level_hash = generate_hash(next_level);
                fs::write(&progress_path, next_level_hash).expect("Failed to update progress file.");
            } else {
                println!("Incorrect flag. Try again.");
            }
        }
    }
}

fn create_level(level: u8) {
    let level_dir = format!("./level{}", level);
    fs::create_dir_all(&level_dir).expect("Failed to create level directory.");

    match level {
        0 => {
            // Create level 0: Just create the flag.txt file
            let flag_filename = format!("{}/flag.txt", level_dir);
            let flag = generate_flag(level);
            let mut file = File::create(flag_filename.clone()).expect("Failed to create flag file.");
            file.write_all(flag.as_bytes()).expect("Failed to write flag to file.");
            file.write_all(b"\n").expect("Failed to write newline to flag file.");
        }
        1 => {
            // Create level 1:
            // Create flag/ directory with a fake flag
            let flag_dir = format!("{}/flag", level_dir);
            fs::create_dir_all(&flag_dir).expect("Failed to create flag directory.");
            let fake_flag_filename = format!("{}/flag.txt", flag_dir);
            let fake_flag = "oops! try elsewhere".to_string();
            let mut fake_flag_file = File::create(fake_flag_filename).expect("Failed to create fake flag file.");
            fake_flag_file.write_all(fake_flag.as_bytes()).expect("Failed to write fake flag to file.");
            fake_flag_file.write_all(b"\n").expect("Failed to write newline to fake flag file.");

            // Create .hidden/ directory with the real flag
            let hidden_dir = format!("{}/.hidden", level_dir);
            fs::create_dir_all(&hidden_dir).expect("Failed to create .hidden directory.");
            let real_flag_filename = format!("{}/flag.txt", hidden_dir);
            let real_flag = generate_flag(level);
            let mut real_flag_file = File::create(real_flag_filename).expect("Failed to create real flag file.");
            real_flag_file.write_all(real_flag.as_bytes()).expect("Failed to write real flag to file.");
            real_flag_file.write_all(b"\n").expect("Failed to write newline to real flag file.");
        }
        2 => {
            // Create level 2: Generate a file with 10,000 lines and place the flag randomly
            let level2_filename = format!("{}/level2.txt", level_dir);
            let mut file = File::create(&level2_filename).expect("Failed to create level 2 file.");

            // Randomly select a line to insert the flag (between 1 and 10,000)
            let flag_line = rand::thread_rng().gen_range(1..=10000);

            // Write 10,000 lines to the file
            for i in 1..=10000 {
                if i == flag_line {
                    let flag = generate_flag(level);
                    file.write_all(flag.as_bytes()).expect("Failed to write flag line.");
                    file.write_all(b"\n").expect("Failed to write newline after flag.");
                } else {
                    let random_line = "This is a random line.".to_string();
                    file.write_all(random_line.as_bytes()).expect("Failed to write random line.");
                    file.write_all(b"\n").expect("Failed to write newline after random line.");
                }
            }

        }
        3 => {
                        // Level 3: Create hidden file with restricted permissions
            let level3_filename = format!("{}/.flag.txt", level_dir);
            let flag = generate_flag(level);
            let mut file = File::create(&level3_filename).expect("Failed to create hidden flag file.");
            file.write_all(flag.as_bytes()).expect("Failed to write flag to file.");
            file.write_all(b"\n").expect("Failed to write newline to flag file.");

            // Set file permissions to be restrictive (e.g., read-only for the owner)
            std::fs::set_permissions(&level3_filename, std::fs::Permissions::from_mode(0o200))
                .expect("Failed to set file permissions.");

            // Give hints 
            println!("Level 3: You have found a hidden file. Can you find the flag?");
            println!("Hint: Use `ls -la` to explore file permissions and `chmod` to change them.");
        }
        4 => {
// Level 4: Create symbolic link challenge

            // Create the hidden directory and flag file
            let hidden_dir = format!("{}/.hidden_flag", level_dir);
            fs::create_dir_all(&hidden_dir).expect("Failed to create .hidden_flag directory.");

            let hidden_flag_filename = format!("{}/flag.txt", hidden_dir);
            let flag = generate_flag(level);
            let mut file = File::create(&hidden_flag_filename).expect("Failed to create hidden flag file.");
            file.write_all(flag.as_bytes()).expect("Failed to write flag to hidden file.");
            file.write_all(b"\n").expect("Failed to write newline to hidden file.");

            // Set permissions for the hidden flag file to be read-write for the owner only
            std::fs::set_permissions(&hidden_flag_filename, std::fs::Permissions::from_mode(0o600))
                .expect("Failed to set hidden flag file permissions.");

            // Create the symbolic link file pointing to the hidden flag file
            let symlink_filename = format!("{}/file_to_flag", level_dir);
            std::os::unix::fs::symlink(&hidden_flag_filename, &symlink_filename)
                .expect("Failed to create symbolic link.");

            // Print a hint for the user
            println!("Level 4: You've found a file that might lead to the flag.");
            println!("Hint: Use `ls -l` to see where the file_to_flag points.");
            println!("You might need to follow the symlink to discover the flag.");
        }
        5 => {
                        // Level 5: Deeply nested directories with the flag
            let level5_dir = format!("{}/level5", level_dir);
            fs::create_dir_all(&level5_dir).expect("Failed to create base directory for level 5.");

            // Create 50 deeply nested directories for flag placement
            let mut rng = rand::thread_rng();
            let mut dir_counter = 1;
            for _ in 0..50 {
                let mut nested_dir = format!("{}/subdir{}", level5_dir, dir_counter);
                fs::create_dir_all(&nested_dir).expect("Failed to create nested directory.");
                for _ in 0..5 {
                    nested_dir = format!("{}/nested", nested_dir);
                    fs::create_dir_all(&nested_dir).expect("Failed to create additional nested directory.");
                }
                dir_counter += 1;
            }

            // Choose a random deeply nested directory and place the flag there
            let random_subdir = rng.gen_range(1..=50);
            let mut flag_dir = format!("{}/subdir{}", level5_dir, random_subdir);
            for _ in 0..5 {
                flag_dir = format!("{}/nested", flag_dir);
            }

            let flag_file = format!("{}/flag.txt", flag_dir);
            let flag = generate_flag(level);
            let mut file = File::create(flag_file).expect("Failed to create flag file.");
            file.write_all(flag.as_bytes()).expect("Failed to write flag to file.");
            file.write_all(b"\n").expect("Failed to write newline to flag file.");

            println!("Level 5: Flag is somewhere deep inside nested directories.");
            println!("Hint: You might need to use `find` to search for the flag file.");    
        }
        6 => {
            // Level 6: No flag creation, only waits for SIGUSR1
            println!("Level 6: You need to send a SIGUSR1 signal to proceed.");
            // The signal handling will be done in main directly
        }
        _ => {}
    }
}


fn delete_level_files(level: u8) {
    let level_dir = format!("./level{}", level);
    if Path::new(&level_dir).exists() {
        fs::remove_dir_all(&level_dir).expect("Failed to delete level directory.");
    }
}

fn generate_flag(level: u8) -> String {
    // Create a unique flag by hashing the combination of level and secret key
    let data = format!("{}{}", level, SECRET_KEY); // Combine level number and secret key
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    // Return the flag in the format: flag{<hashed_flag>}
    format!("flag{{{}}}", hex::encode(result)) // Wrap the hashed value in flag{}
}


fn verify_flag(level: u8, user_flag: &str) -> bool {
    // Generate the expected flag for the level
    let expected_flag = generate_flag(level);
    
    // Compare the user's input flag with the expected flag
    user_flag == expected_flag
}

fn generate_hash(level: u8) -> String {
    // Generate a SHA-256 hash for the combination of level and the secret key
    let data = format!("{}{}", level, SECRET_KEY);
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result) // Convert the hash to a hexadecimal string
}

fn get_current_level_from_hash(stored_hash: &str) -> u8 {
    // For simplicity, let's assume we can reverse the hash by brute force.
    // This should be replaced by an actual method if you want stronger protection.
    for level in 0..=TOTAL_LEVELS+1 {
        let generated_hash = generate_hash(level);
        if generated_hash == stored_hash {
            return level;
        }
    }
    panic!("Failed to determine current level from hash.");
}

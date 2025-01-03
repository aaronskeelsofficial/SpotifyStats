pub mod modules;

fn main() {
    println!("Launched");

    //Load Environment Variables
    dotenv::from_path("./assets/.env").unwrap();

    // Spawn a separate thread for the web server
    let webserver_thread = std::thread::spawn(|| {
        // This is the entry point of the Actix server, managed by the `#[actix_web::main]` macro
        modules::webserver::main(); // Unwrap safely if no error expected
    });

    // Other tasks can run in the main thread here
    println!("Main thread is doing other tasks...");

    // Wait for the web server thread to finish
    webserver_thread.join().unwrap();
    println!("Main thread has finished.");
}
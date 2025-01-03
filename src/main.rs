pub mod modules;

fn main() {
    println!("Launched");

    //Load Environment Variables
    dotenv::from_path("./assets/.env").unwrap();

    let webserver_thread = std::thread::spawn(|| {
        modules::webserver::main().unwrap();
    });
    webserver_thread.join().unwrap();
    // modules::webserver::main().unwrap();
    println!("Main Thread has passed web server startup.");
}
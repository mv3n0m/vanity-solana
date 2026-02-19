use core_affinity;
use ed25519_dalek::SigningKey;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::thread;

fn main() {
    // ---- CONFIG ----
    let prefixes: Vec<&'static str> = vec!["test"];
    // ----------------

    let cores = core_affinity::get_core_ids().expect("Failed to get cores");
    let thread_count = cores.len();

    println!("Using {} threads", thread_count);

    let counter = Arc::new(AtomicU64::new(0));

    for core_id in cores {
        let counter = counter.clone();
        let prefixes = prefixes.clone();

        thread::spawn(move || {
            core_affinity::set_for_current(core_id);

            let mut rng = ChaCha20Rng::from_entropy();

            // Pre-open files once per thread
            let mut writers: Vec<(&str, BufWriter<std::fs::File>)> = prefixes
                .iter()
                .map(|&p| {
                    let file = OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open(format!("{}.txt", p))
                        .unwrap();

                    (p, BufWriter::new(file))
                })
                .collect();

            let mut address_buffer = String::with_capacity(44);

            loop {
                let signing_key = SigningKey::generate(&mut rng);
                let pubkey = signing_key.verifying_key();

                address_buffer.clear();

                bs58::encode(pubkey.to_bytes())
                    .onto(&mut address_buffer)
                    .unwrap();

                counter.fetch_add(1, Ordering::Relaxed);

                for (prefix, writer) in writers.iter_mut() {
                    if address_buffer.starts_with(*prefix) {
                        let mut full_key = Vec::with_capacity(64);

                        full_key.extend_from_slice(&signing_key.to_bytes());
                        full_key.extend_from_slice(&pubkey.to_bytes());

                        let private_b58 = bs58::encode(full_key).into_string();

                        writeln!(
                            writer,
                            "Address: {}\nPrivateKey(base58 64-byte): {}\n",
                            address_buffer, private_b58
                        )
                        .unwrap();

                        writer.flush().unwrap();

                        println!("Found {} => {}", prefix, address_buffer);
                    }
                }
            }
        });
    }

    // ---- Stats Thread ----
    let mut last = 0;

    loop {
        thread::sleep(std::time::Duration::from_secs(5));
        let current = counter.load(Ordering::Relaxed);
        let delta = current - last;
        last = current;

        println!("Total: {} | Speed: {} keys/sec", current, delta / 5);
    }
}

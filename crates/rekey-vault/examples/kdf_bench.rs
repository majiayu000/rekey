//! Synthetic, offline measurements; never opens a vault or accepts real secrets.
use std::time::Instant;

use rekey_vault::crypto::kdf::{Argon2Params, derive_password_kek};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let memory_mib: u32 = std::env::args()
        .nth(1)
        .ok_or("expected memory MiB")?
        .parse()?;
    let params = Argon2Params {
        memory_kib: memory_mib.checked_mul(1024).ok_or("memory overflow")?,
        iterations: 3,
        parallelism: 4,
    };
    params.validate()?;
    println!("memory_mib,iterations,parallelism,sample,elapsed_ms");
    for sample in 0..4 {
        let started = Instant::now();
        let key = derive_password_kek(b"synthetic benchmark password", &[42; 16], &params)?;
        std::hint::black_box(&key);
        drop(key);
        println!(
            "{memory_mib},3,4,{sample},{:.2}",
            started.elapsed().as_secs_f64() * 1000.0
        );
    }
    Ok(())
}

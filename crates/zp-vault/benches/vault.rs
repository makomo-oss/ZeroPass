//! Performance benchmarks of the vault (P1-15).
//!
//! ```text
//! cargo bench -p zp-vault
//! ```
//!
//! Targets: unlocking with the master password takes under one second with
//! calibrated Argon2id parameters, and listing 10 000 items takes under 100 ms.
//! Results are recorded in `docs/bench/phase1.md`.

#![allow(clippy::unwrap_used, reason = "benchmark setup may panic")]

use std::hint::black_box;
use std::path::Path;
use std::time::Duration;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use zp_crypto::{InsecureSoftwareKeyStore, KdfParams, Password};
use zp_vault::model::Login;
use zp_vault::{AutoLock, CreateOptions, KdfChoice, Vault};

const PASSWORD: &str = "correct horse battery staple";
const ITEMS: usize = 10_000;

fn login(n: usize) -> Login {
    let mut login = Login::new(
        format!("Service number {n}"),
        format!("user{n}@example.com"),
        format!("a-reasonably-long-password-{n:05}"),
    )
    .with_url(format!("https://service-{n}.example.com/login"));
    login.notes = "recovery codes: 1111-2222 3333-4444".into();
    login
}

fn never_lock(vault: &mut Vault) {
    vault.set_auto_lock(AutoLock {
        password: None,
        hardware: None,
    });
}

/// A vault holding `ITEMS` logins, protected with the weakest allowed KDF so that
/// setup stays quick (the KDF is measured separately).
fn populated_vault(path: &Path) -> Vault {
    let options = CreateOptions {
        kdf: KdfChoice::Fixed(KdfParams::MINIMUM),
        clock: None,
    };
    let mut vault = Vault::create(path, PASSWORD, None, options).unwrap();
    never_lock(&mut vault);
    vault.insert_many((0..ITEMS).map(login)).unwrap();
    vault
}

fn unlock(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unlock.zpvault");
    // Calibrated exactly as `zp-cli init` does: aim for about 500 ms.
    let vault = Vault::create(&path, PASSWORD, None, CreateOptions::default()).unwrap();
    let params = vault.kdf_params().unwrap();
    eprintln!(
        "calibrated Argon2id parameters: m={} KiB, t={}, p={}",
        params.m_kib(),
        params.t(),
        params.p()
    );
    drop(vault);

    let mut group = c.benchmark_group("unlock");
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(12));
    group.bench_function("master_password_calibrated", |b| {
        b.iter_batched(
            || Vault::open(&path).unwrap(),
            |mut vault| {
                vault.unlock_password(black_box(PASSWORD)).unwrap();
                vault
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn items(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("items.zpvault");
    let mut vault = populated_vault(&path);
    let ids: Vec<_> = vault
        .list::<Password>()
        .unwrap()
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    assert_eq!(ids.len(), ITEMS);
    eprintln!(
        "vault file with {ITEMS} logins: {:.1} MiB",
        std::fs::metadata(&path).unwrap().len() as f64 / (1024.0 * 1024.0)
    );

    let mut group = c.benchmark_group("items_10k");
    group.sample_size(20);
    group.bench_function("list", |b| {
        b.iter(|| black_box(vault.list::<Password>().unwrap()).len());
    });
    group.bench_function("search_few_hits", |b| {
        b.iter(|| {
            let hits = vault.search::<Password>(black_box("number 4242")).unwrap();
            assert_eq!(hits.len(), 1);
            hits
        });
    });
    group.bench_function("search_many_hits", |b| {
        b.iter(|| {
            let hits = vault.search::<Password>(black_box("USER12")).unwrap();
            assert_eq!(hits.len(), 111);
            hits
        });
    });
    let mut next = 0;
    group.bench_function("get_one", |b| {
        b.iter(|| {
            next = (next + 7919) % ids.len();
            vault.get::<Login>(ids[next]).unwrap()
        });
    });
    group.finish();
}

fn writes(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let options = CreateOptions {
        kdf: KdfChoice::Fixed(KdfParams::MINIMUM),
        clock: None,
    };
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let mut vault = Vault::create(
        &dir.path().join("writes.zpvault"),
        PASSWORD,
        Some(&hardware),
        options,
    )
    .unwrap();
    never_lock(&mut vault);

    let mut group = c.benchmark_group("write");
    group.sample_size(20);
    let mut n = 0;
    group.bench_function("insert_one_durable", |b| {
        b.iter(|| {
            n += 1;
            vault.insert(login(n)).unwrap()
        });
    });
    group.bench_function("insert_1000_batched", |b| {
        b.iter(|| vault.insert_many((0..1000).map(login)).unwrap().len());
    });
    group.finish();
}

criterion_group!(benches, unlock, items, writes);
criterion_main!(benches);

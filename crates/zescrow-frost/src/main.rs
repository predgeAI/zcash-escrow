//! zescrow-frost: one small CLI that each escrow party (buyer, seller, arbiter) runs
//! locally for its own FROST steps. All cryptography comes from the Zcash Foundation's
//! `reddsa` (RedPallas FROST ciphersuite) and `frost-rerandomized` crates, called exactly
//! the way `frost-client` calls them. This crate only moves bytes between files.
//!
//! Round messages are plain JSON files so the transport is pluggable: in the demo they are
//! passed through the escrow coordinator; in milestone 2 they go over ZF `frostd`.

use std::{collections::BTreeMap, fs, path::PathBuf};

use clap::{Parser, Subcommand};
use eyre::{eyre, Result, WrapErr};
use rand::thread_rng;
use reddsa::frost::redpallas as rp;
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Trusted-dealer 2-of-3 key generation (MVP only; DKG is milestone 2).
    /// Writes buyer.key.json, seller.key.json, arbiter.key.json and group.json.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the group verifying key (Orchard/Ironwood `ak`) as hex.
    Ak {
        #[arg(long)]
        group: PathBuf,
    },
    /// Round 1: make fresh single-use nonces and the public commitment.
    Commit {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        nonces_out: PathBuf,
        #[arg(long)]
        commitments_out: PathBuf,
    },
    /// Coordinator: build the signing package for a message from 2 commitments.
    Package {
        /// Message to sign (the transaction sighash), hex.
        #[arg(long)]
        message: String,
        #[arg(long, num_args = 1..)]
        commitments: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Round 2: produce this party's signature share. Consumes (deletes) the nonces file.
    Sign {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        nonces: PathBuf,
        #[arg(long)]
        package: PathBuf,
        /// The spend's randomizer (alpha) from the PCZT, hex.
        #[arg(long)]
        randomizer: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Coordinator: aggregate shares into one RedPallas spend-auth signature and verify
    /// it against the rerandomized key. Prints the 64-byte signature as hex.
    Aggregate {
        #[arg(long)]
        group: PathBuf,
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        randomizer: String,
        #[arg(long, num_args = 1..)]
        shares: Vec<PathBuf>,
    },
    /// Re-encode a unified address or UFVK for another network (e.g. testnet -> regtest).
    /// `zcash-sign generate` only emits main/test encodings.
    Reencode {
        #[arg(long)]
        value: String,
        /// main | test | regtest
        #[arg(long)]
        network: String,
    },
}

#[derive(Serialize, Deserialize)]
struct PartyKey {
    party: String,
    identifier: rp::Identifier,
    key_package: rp::keys::KeyPackage,
}

#[derive(Serialize, Deserialize)]
struct Group {
    threshold: u16,
    parties: BTreeMap<String, rp::Identifier>,
    public_key_package: rp::keys::PublicKeyPackage,
}

#[derive(Serialize, Deserialize)]
struct Commitment {
    identifier: rp::Identifier,
    commitments: rp::round1::SigningCommitments,
}

#[derive(Serialize, Deserialize)]
struct Share {
    identifier: rp::Identifier,
    share: rp::round2::SignatureShare,
}

const PARTIES: [&str; 3] = ["buyer", "seller", "arbiter"];

fn read_json<T: for<'de> Deserialize<'de>>(p: &PathBuf) -> Result<T> {
    let s = fs::read_to_string(p).wrap_err_with(|| format!("reading {}", p.display()))?;
    serde_json::from_str(&s).wrap_err_with(|| format!("parsing {}", p.display()))
}

fn write_json<T: Serialize>(p: &PathBuf, v: &T) -> Result<()> {
    if let Some(dir) = p.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(p, serde_json::to_string_pretty(v)?)?;
    Ok(())
}

fn randomizer(hex_str: &str) -> Result<rp::Randomizer> {
    let bytes = hex::decode(hex_str.trim())?;
    frost_rerandomized::Randomizer::deserialize(&bytes).map_err(|e| eyre!("bad randomizer: {e:?}"))
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen { out } => {
            let (shares, pubkeys) = rp::keys::generate_with_dealer(
                3,
                2,
                rp::keys::IdentifierList::Default,
                thread_rng(),
            )
            .map_err(|e| eyre!("{e:?}"))?;
            let mut parties = BTreeMap::new();
            for ((id, share), name) in shares.into_iter().zip(PARTIES) {
                // KeyPackage::try_from runs the VSS check of the share against its commitment.
                let key_package =
                    rp::keys::KeyPackage::try_from(share).map_err(|e| eyre!("{e:?}"))?;
                write_json(
                    &out.join(format!("{name}.key.json")),
                    &PartyKey { party: name.into(), identifier: id, key_package },
                )?;
                parties.insert(name.to_string(), id);
            }
            write_json(
                &out.join("group.json"),
                &Group { threshold: 2, parties, public_key_package: pubkeys },
            )?;
            println!("wrote 3 key packages and group.json to {}", out.display());
        }
        Cmd::Ak { group } => {
            let g: Group = read_json(&group)?;
            let ak = g.public_key_package.verifying_key().serialize().map_err(|e| eyre!("{e:?}"))?;
            println!("{}", hex::encode(ak));
        }
        Cmd::Commit { key, nonces_out, commitments_out } => {
            let k: PartyKey = read_json(&key)?;
            let (nonces, commitments) =
                rp::round1::commit(k.key_package.signing_share(), &mut thread_rng());
            write_json(&nonces_out, &nonces)?;
            write_json(&commitments_out, &Commitment { identifier: k.identifier, commitments })?;
            println!("{} committed", k.party);
        }
        Cmd::Package { message, commitments, out } => {
            let msg = hex::decode(message.trim())?;
            let mut map = BTreeMap::new();
            for p in &commitments {
                let c: Commitment = read_json(p)?;
                map.insert(c.identifier, c.commitments);
            }
            if map.len() < 2 {
                return Err(eyre!("need commitments from 2 distinct parties"));
            }
            write_json(&out, &rp::SigningPackage::new(map, &msg))?;
        }
        Cmd::Sign { key, nonces, package, randomizer: r, out } => {
            let k: PartyKey = read_json(&key)?;
            let n: rp::round1::SigningNonces = read_json(&nonces)?;
            // Nonces are single-use: remove them before anything else can reuse them.
            fs::remove_file(&nonces)?;
            let pkg: rp::SigningPackage = read_json(&package)?;
            let share = rp::round2::sign(&pkg, &n, &k.key_package, randomizer(&r)?)
                .map_err(|e| eyre!("{e:?}"))?;
            write_json(&out, &Share { identifier: k.identifier, share })?;
            println!("{} signed message {}", k.party, hex::encode(pkg.message()));
        }
        Cmd::Aggregate { group, package, randomizer: r, shares } => {
            let g: Group = read_json(&group)?;
            let pkg: rp::SigningPackage = read_json(&package)?;
            let mut map = BTreeMap::new();
            for p in &shares {
                let s: Share = read_json(p)?;
                map.insert(s.identifier, s.share);
            }
            let params = rp::RandomizedParams::from_randomizer(
                g.public_key_package.verifying_key(),
                randomizer(&r)?,
            );
            let sig = rp::aggregate(&pkg, &map, &g.public_key_package, &params)
                .map_err(|e| eyre!("aggregate failed: {e:?}"))?;
            params
                .randomized_verifying_key()
                .verify(pkg.message(), &sig)
                .map_err(|e| eyre!("signature does not verify: {e:?}"))?;
            println!("{}", hex::encode(sig.serialize().map_err(|e| eyre!("{e:?}"))?));
        }
        Cmd::Reencode { value, network } => {
            use zcash_address::unified::{Address, Encoding, Ufvk};
            use zcash_protocol::consensus::NetworkType;
            let net = match network.as_str() {
                "main" => NetworkType::Main,
                "test" => NetworkType::Test,
                "regtest" => NetworkType::Regtest,
                _ => return Err(eyre!("unknown network")),
            };
            if let Ok((_, ufvk)) = Ufvk::decode(&value) {
                println!("{}", ufvk.encode(&net));
            } else if let Ok((_, ua)) = Address::decode(&value) {
                println!("{}", ua.encode(&net));
            } else {
                return Err(eyre!("not a unified address or UFVK"));
            }
        }
    }
    Ok(())
}

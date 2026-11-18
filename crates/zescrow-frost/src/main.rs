//! zescrow-frost: one small CLI that each escrow party (buyer, seller, arbiter) runs
//! locally for its own FROST steps. All cryptography comes from the Zcash Foundation's
//! `reddsa` (RedPallas FROST ciphersuite) and `frost-rerandomized` crates, called exactly
//! the way `frost-client` calls them. This crate only moves bytes between files.
//! The PCZT output check (`outputs`) likewise only calls the `pczt` and `orchard` crates.
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
        /// The sighash this signer derived itself from the PCZT, hex. The share is refused
        /// unless the signing package's message is exactly this value.
        #[arg(long)]
        expected_message: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Signer check: open every Orchard/Ironwood output of a PCZT against its note commitment
    /// and print the verified (value, receiver) of each as JSON. Fails if any output cannot be
    /// verified, or if the PCZT has transparent or Sapling outputs.
    Outputs {
        #[arg(long)]
        pczt: PathBuf,
        /// The agreed payee (unified address); each output reports whether it pays its Orchard receiver.
        #[arg(long)]
        to: String,
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

/// Round 2 behind the signer's own check: the coordinator-supplied signing package must carry
/// exactly the message (sighash) this signer derived itself from the PCZT.
fn sign_share(
    pkg: &rp::SigningPackage,
    nonces: &rp::round1::SigningNonces,
    key: &rp::keys::KeyPackage,
    randomizer: rp::Randomizer,
    expected_message: &[u8],
) -> Result<rp::round2::SignatureShare> {
    if expected_message.is_empty() {
        return Err(eyre!("refusing to sign: no locally derived sighash given"));
    }
    if pkg.message()[..] != *expected_message {
        return Err(eyre!(
            "refusing to sign: signing package message {} is not the locally derived sighash {}",
            hex::encode(pkg.message()),
            hex::encode(expected_message)
        ));
    }
    rp::round2::sign(pkg, nonces, key, randomizer).map_err(|e| eyre!("{e:?}"))
}

/// One shielded output, as recovered from its note commitment (not from PCZT labels).
#[derive(Serialize, Debug)]
struct VerifiedOutput {
    pool: &'static str,
    action: usize,
    value: u64,
    /// Raw 43-byte Orchard receiver, hex.
    receiver: String,
    to_expected: bool,
}

/// The Orchard receiver of a unified address (any network).
fn orchard_receiver(ua: &str) -> Result<[u8; 43]> {
    use zcash_address::unified::{Address, Container, Encoding, Receiver};
    let (_, addr) = Address::decode(ua.trim()).map_err(|e| eyre!("not a unified address: {e}"))?;
    addr.items()
        .into_iter()
        .find_map(|r| match r {
            Receiver::Orchard(b) => Some(b),
            _ => None,
        })
        .ok_or_else(|| eyre!("unified address has no Orchard receiver"))
}

/// Parse a PCZT and open each Orchard and Ironwood output against its `cmx`: the note
/// (recipient, value, rseed, rho = the action's spend nullifier) must commit to exactly the
/// `cmx` that the sighash covers. Any output that cannot be opened is an error; none is skipped.
/// The free-form `user_address` label is ignored.
fn verify_outputs(pczt_bytes: &[u8], expected: &[u8; 43]) -> Result<Vec<VerifiedOutput>> {
    use pczt::roles::verifier::{OrchardError, Verifier};
    let pczt = pczt::Pczt::parse(pczt_bytes).map_err(|e| eyre!("cannot parse PCZT: {e:?}"))?;
    if !pczt.transparent().outputs().is_empty() {
        return Err(eyre!("PCZT has transparent outputs, which this signer does not accept"));
    }
    if !pczt.sapling().outputs().is_empty() {
        return Err(eyre!("PCZT has Sapling outputs, which this signer does not accept"));
    }
    let mut outs = Vec::new();
    let mut check =
        |pool: &'static str, bundle: &orchard::pczt::Bundle| -> Result<(), OrchardError<String>> {
            for (i, action) in bundle.actions().iter().enumerate() {
                let o = action.output();
                o.verify_note_commitment(action.spend()).map_err(|e| {
                    OrchardError::Custom(format!(
                        "{pool} action {i}: output does not open its note commitment: {e:?}"
                    ))
                })?;
                // verify_note_commitment requires both, so these are set from here on.
                let (Some(value), Some(recipient)) = (o.value(), o.recipient()) else {
                    return Err(OrchardError::Custom(format!(
                        "{pool} action {i}: output value or recipient missing"
                    )));
                };
                let receiver = recipient.to_raw_address_bytes();
                outs.push(VerifiedOutput {
                    pool,
                    action: i,
                    value: value.inner(),
                    receiver: hex::encode(receiver),
                    to_expected: &receiver == expected,
                });
            }
            Ok(())
        };
    let show = |e: OrchardError<String>| match e {
        OrchardError::Custom(s) => eyre!(s),
        e => eyre!("{e:?}"),
    };
    Verifier::new(pczt)
        .with_orchard(|b| check("orchard", b))
        .map_err(show)?
        .with_ironwood(|b| check("ironwood", b))
        .map_err(show)?;
    Ok(outs)
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
            let ak =
                g.public_key_package.verifying_key().serialize().map_err(|e| eyre!("{e:?}"))?;
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
        Cmd::Sign { key, nonces, package, randomizer: r, expected_message, out } => {
            let k: PartyKey = read_json(&key)?;
            let n: rp::round1::SigningNonces = read_json(&nonces)?;
            // Nonces are single-use: remove them before anything else can reuse them.
            fs::remove_file(&nonces)?;
            let pkg: rp::SigningPackage = read_json(&package)?;
            let expected = hex::decode(expected_message.trim())?;
            let share = sign_share(&pkg, &n, &k.key_package, randomizer(&r)?, &expected)?;
            write_json(&out, &Share { identifier: k.identifier, share })?;
            println!("{} signed message {}", k.party, hex::encode(pkg.message()));
        }
        Cmd::Outputs { pczt, to } => {
            let bytes = fs::read(&pczt).wrap_err_with(|| format!("reading {}", pczt.display()))?;
            let outs = verify_outputs(&bytes, &orchard_receiver(&to)?)?;
            println!("{}", serde_json::to_string(&outs)?);
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

#[cfg(test)]
mod tests {
    use super::*;

    // ---- FROST round 2 is bound to the locally derived sighash ----

    struct Round {
        keys: BTreeMap<rp::Identifier, rp::keys::KeyPackage>,
        nonces: BTreeMap<rp::Identifier, rp::round1::SigningNonces>,
        pkg: rp::SigningPackage,
        randomizer: rp::Randomizer,
    }

    fn round(message: &[u8]) -> Round {
        let mut rng = thread_rng();
        let (shares, pubkeys) =
            rp::keys::generate_with_dealer(3, 2, rp::keys::IdentifierList::Default, &mut rng)
                .unwrap();
        let mut keys = BTreeMap::new();
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for (id, share) in shares.into_iter().take(2) {
            let kp = rp::keys::KeyPackage::try_from(share).unwrap();
            let (n, c) = rp::round1::commit(kp.signing_share(), &mut rng);
            nonces.insert(id, n);
            commitments.insert(id, c);
            keys.insert(id, kp);
        }
        let pkg = rp::SigningPackage::new(commitments, message);
        let params = rp::RandomizedParams::new(pubkeys.verifying_key(), &pkg, &mut rng).unwrap();
        Round { keys, nonces, pkg, randomizer: *params.randomizer() }
    }

    #[test]
    fn sign_refuses_package_whose_message_is_not_the_local_sighash() {
        let r = round(&[0xaa; 32]);
        for (id, kp) in &r.keys {
            let err = sign_share(&r.pkg, &r.nonces[id], kp, r.randomizer, &[0xbb; 32]).unwrap_err();
            assert!(err.to_string().contains("refusing to sign"), "{err}");
        }
    }

    #[test]
    fn sign_refuses_without_a_local_sighash() {
        let r = round(&[0xaa; 32]);
        let (id, kp) = r.keys.iter().next().unwrap();
        assert!(sign_share(&r.pkg, &r.nonces[id], kp, r.randomizer, &[]).is_err());
    }

    #[test]
    fn sign_accepts_package_with_the_local_sighash() {
        let r = round(&[0xaa; 32]);
        for (id, kp) in &r.keys {
            sign_share(&r.pkg, &r.nonces[id], kp, r.randomizer, &[0xaa; 32]).unwrap();
        }
    }

    // ---- PCZT outputs are verified against their note commitments ----

    /// A real regtest payout PCZT (zcash-devtool `pczt create-max` + `pczt prove`): two Ironwood
    /// actions, a zero-value dummy output and 99_990_000 zat to `PAYEE`.
    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/regtest-payout.proven.pczt");
    const PAYEE: &str = "uregtest1jfjdyhl4ac8q4qmgm3t3gws8n39axpp0x9vs2mnjwaa6eql6rxqd9uytf6mys68rlnx76kaghpp48g4kzrxeh0zq7q8qudyv9vd6t75v";
    const PAID: u64 = 99_990_000;

    fn payee() -> [u8; 43] {
        orchard_receiver(PAYEE).unwrap()
    }

    /// A unified address with a different Orchard receiver (the fixture's dummy output's).
    fn other_ua(outs: &[VerifiedOutput]) -> String {
        use zcash_address::unified::{Address, Encoding, Receiver};
        let dummy = outs.iter().find(|o| !o.to_expected).unwrap();
        let bytes: [u8; 43] = hex::decode(&dummy.receiver).unwrap().try_into().unwrap();
        Address::try_from_items(vec![Receiver::Orchard(bytes)])
            .unwrap()
            .encode(&zcash_protocol::consensus::NetworkType::Regtest)
    }

    fn redact(f: impl FnOnce(&mut pczt::roles::redactor::orchard::ActionRedactor<'_>)) -> Vec<u8> {
        let p = pczt::Pczt::parse(FIXTURE).unwrap();
        pczt::roles::redactor::Redactor::new(p)
            .redact_ironwood_with(|mut r| r.redact_action(1, |mut a| f(&mut a)))
            .finish()
            .serialize()
            .unwrap()
    }

    #[test]
    fn outputs_of_an_honest_pczt_open_their_commitments() {
        let outs = verify_outputs(FIXTURE, &payee()).unwrap();
        assert_eq!(outs.len(), 2);
        let paid: Vec<_> = outs.iter().filter(|o| o.to_expected).collect();
        assert_eq!(paid.len(), 1);
        assert_eq!((paid[0].pool, paid[0].action, paid[0].value), ("ironwood", 1, PAID));
        let dummy = outs.iter().find(|o| !o.to_expected).unwrap();
        assert_eq!(dummy.value, 0);
    }

    #[test]
    fn output_value_that_does_not_match_its_commitment_is_refused() {
        // Postcard encodes the paid output's `value: Some(99_990_000)` as 01 f0 f3 d6 2f;
        // 01 f1 f3 d6 2f is Some(99_990_001). The cmx is unchanged, so it no longer opens.
        let needle = [0x01, 0xf0, 0xf3, 0xd6, 0x2f];
        let at: Vec<_> =
            FIXTURE.windows(5).enumerate().filter(|(_, w)| *w == needle).map(|(i, _)| i).collect();
        assert_eq!(at.len(), 1, "fixture layout changed");
        let mut bytes = FIXTURE.to_vec();
        bytes[at[0] + 1] = 0xf1;
        let err = verify_outputs(&bytes, &payee()).unwrap_err().to_string();
        assert!(
            err.contains("ironwood action 1") && err.contains("InvalidExtractedNoteCommitment"),
            "{err}"
        );
    }

    #[test]
    fn output_without_value_is_refused_not_skipped() {
        let err =
            verify_outputs(&redact(|a| a.clear_output_value()), &payee()).unwrap_err().to_string();
        assert!(err.contains("ironwood action 1") && err.contains("MissingValue"), "{err}");
    }

    #[test]
    fn output_without_recipient_or_rseed_is_refused() {
        let e1 = verify_outputs(&redact(|a| a.clear_output_recipient()), &payee())
            .unwrap_err()
            .to_string();
        assert!(e1.contains("MissingRecipient"), "{e1}");
        let e2 =
            verify_outputs(&redact(|a| a.clear_output_rseed()), &payee()).unwrap_err().to_string();
        assert!(e2.contains("MissingRandomSeed"), "{e2}");
    }

    #[test]
    fn user_address_label_is_ignored() {
        let honest = verify_outputs(FIXTURE, &payee()).unwrap();
        let attacker = other_ua(&honest);
        // Relabel the paid output as going to `attacker`; the committed recipient is still PAYEE.
        let p = pczt::Pczt::parse(FIXTURE).unwrap();
        let relabeled = pczt::roles::updater::Updater::new(p)
            .update_ironwood_with(|mut u| {
                u.update_action_with(1, |mut a| {
                    a.set_output_user_address(attacker.clone());
                    Ok(())
                })
            })
            .unwrap()
            .finish()
            .serialize()
            .unwrap();
        let outs = verify_outputs(&relabeled, &orchard_receiver(&attacker).unwrap()).unwrap();
        let to_attacker: u64 = outs.iter().filter(|o| o.to_expected).map(|o| o.value).sum();
        assert_eq!(to_attacker, 0, "label must not count as payment");
        let outs = verify_outputs(&relabeled, &payee()).unwrap();
        assert!(outs.iter().any(|o| o.to_expected && o.value == PAID));
    }

    #[test]
    fn garbage_is_not_a_pczt() {
        assert!(verify_outputs(b"not a pczt", &payee()).is_err());
    }
}

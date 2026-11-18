//! zescrow-frost: one small CLI that each escrow party (buyer, seller, arbiter) runs
//! locally for its own FROST steps. All cryptography comes from the Zcash Foundation's
//! `reddsa` (RedPallas FROST ciphersuite) and `frost-rerandomized` crates, called exactly
//! the way `frost-client` calls them. This crate only moves bytes between files.
//! The PCZT checks (`outputs`, `sign-pczt`) likewise only call the `pczt`, `orchard` and
//! `zcash_note_encryption` crates.
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
    /// Signer check, without signing: parse the PCZT once, open every Orchard/Ironwood output
    /// against its note commitment and its note ciphertext, check the fee and the payout policy,
    /// and print the verified outputs, fee and sighash as JSON. Fails if any check fails.
    Outputs {
        #[arg(long)]
        pczt: PathBuf,
        /// The agreed payee (unified address); each output reports whether it pays its Orchard receiver.
        #[arg(long)]
        to: String,
        /// Minimum the payee must receive, zat.
        #[arg(long, default_value_t = 0)]
        min: u64,
        /// Memo every output to the payee must carry (e.g. the verdict hash), as text.
        #[arg(long)]
        memo: Option<String>,
    },
    /// Round 2 from the PCZT itself: read the PCZT once, run every `outputs` check on it, derive
    /// the sighash from those same bytes, and produce this party's signature share only if the
    /// signing package carries that sighash and the randomizer is one of the PCZT's spends.
    /// Consumes (deletes) the nonces file.
    SignPczt {
        #[arg(long)]
        pczt: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        min: u64,
        #[arg(long)]
        memo: Option<String>,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        nonces: PathBuf,
        #[arg(long)]
        package: PathBuf,
        /// The spend's randomizer (alpha), hex. Must be the alpha of a spend in this PCZT.
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

/// One shielded output, as recovered from its note commitment (not from PCZT labels).
#[derive(Serialize, Debug)]
struct VerifiedOutput {
    pool: &'static str,
    action: usize,
    value: u64,
    /// Raw 43-byte Orchard receiver, hex.
    receiver: String,
    to_expected: bool,
    /// The memo the recipient will read, for an output that carries value: its text, `""` when
    /// empty, or null when it is not a text memo. Null for zero-value outputs (not opened).
    memo: Option<String>,
}

/// What the signer requires of a payout before it releases a share.
struct Policy {
    /// Orchard receiver of the agreed payee.
    to: [u8; 43],
    /// At least this much must reach `to`.
    min: u64,
    /// When set, every output that pays `to` must carry exactly this memo (ZIP 302 encoding).
    memo: Option<[u8; 512]>,
}

/// The result of checking a PCZT: its verified outputs, the fee it pays, and the sighash and
/// spend randomizers derived from the same parsed bytes.
#[derive(Serialize, Debug)]
struct Checked {
    outputs: Vec<VerifiedOutput>,
    fee: u64,
    actions: u64,
    /// Shielded sighash, hex, computed by the `pczt` Signer role from this PCZT.
    sighash: String,
    /// `alpha` of every spend that has one, hex.
    alphas: Vec<String>,
}

/// ZIP 317: marginal fee per logical action, and the grace number of actions.
const MARGINAL_FEE: u64 = 5_000;
const GRACE_ACTIONS: u64 = 2;

/// ZIP 317 conventional fee for a transaction with `logical_actions` logical actions.
fn conventional_fee(logical_actions: u64) -> u64 {
    MARGINAL_FEE * logical_actions.max(GRACE_ACTIONS)
}

/// The ZIP 302 encoding of a text memo, as `zcash-devtool --memo` writes it.
fn text_memo(text: &str) -> Result<[u8; 512]> {
    use std::str::FromStr;
    use zcash_protocol::memo::Memo;
    let memo = Memo::from_str(text).map_err(|e| eyre!("bad memo: {e:?}"))?;
    Ok(*memo.encode().as_array())
}

fn memo_text(bytes: &[u8; 512]) -> Option<String> {
    use zcash_protocol::memo::{Memo, MemoBytes};
    match Memo::try_from(MemoBytes::from_bytes(bytes).ok()?).ok()? {
        Memo::Empty => Some(String::new()),
        Memo::Text(t) => Some(String::from(t)),
        _ => None,
    }
}

/// Open an output the way its recipient will and return the memo plaintext, or None if the
/// ciphertext does not open. The ephemeral secret key is re-derived from the note (rseed, rho)
/// whose fields `verify_note_commitment` has already bound to `cmx`, so no viewing key is
/// needed; recovery also re-checks the note against `cmx` and `epk`.
fn recover_memo<D>(
    domain: D,
    note: &orchard::Note,
    action: &orchard::pczt::Action,
) -> Option<[u8; 512]>
where
    D: zcash_note_encryption::Domain<Note = orchard::Note, Memo = [u8; 512]>,
    orchard::pczt::Action: zcash_note_encryption::ShieldedOutput<D>,
{
    let esk = D::derive_esk(note)?;
    let pk_d = D::get_pk_d(note);
    zcash_note_encryption::try_output_recovery_with_pkd_esk(&domain, pk_d, esk, action)
        .map(|(_, _, memo)| memo)
}

/// Open the output of `action` in `pool`'s note encryption domain.
fn open_output(pool: &str, action: &orchard::pczt::Action) -> Option<[u8; 512]> {
    use orchard::note_encryption::{IronwoodDomain, OrchardDomain};
    let o = action.output();
    let rho = Option::from(orchard::note::Rho::from_bytes(&action.spend().nullifier().to_bytes()))?;
    let note = Option::from(orchard::Note::from_parts(
        (*o.recipient())?,
        (*o.value())?,
        rho,
        (*o.rseed())?,
        *o.note_version(),
    ))?;
    // The domain follows the bundle's pool, never a field of the action.
    match pool {
        "orchard" => recover_memo(OrchardDomain::for_pczt_action(action), &note, action),
        "ironwood" => recover_memo(IronwoodDomain::for_pczt_action(action), &note, action),
        _ => None,
    }
}

/// Per-bundle counts for the fee rule.
struct BundleStats {
    pool: &'static str,
    actions: u64,
    spends: u64,
    paying: u64,
    value_balance: i64,
}

/// The fee a PCZT pays, if it is exactly ZIP 317's conventional fee for its actions.
///
/// The value balance of the shielded bundles is what leaves them, i.e. the fee (no transparent
/// or Sapling parts are accepted), and the sighash covers it. ZIP 317's fee grows with the
/// action count, so the count is capped too: a bundle needs at most one action per real spend
/// plus one per paying output (and the grace minimum); more would be padding that raises the fee.
fn fee_rule(stats: &[BundleStats]) -> Result<u64> {
    let fee: i64 = stats.iter().map(|s| s.value_balance).sum();
    let fee = u64::try_from(fee).map_err(|_| {
        eyre!(
            "PCZT moves {} zat into the shielded pools instead of paying a fee",
            fee.unsigned_abs()
        )
    })?;
    for s in stats {
        let enough = (s.spends + s.paying).max(GRACE_ACTIONS);
        if s.actions > enough {
            return Err(eyre!(
                "{} bundle has {} actions where {enough} are enough",
                s.pool,
                s.actions
            ));
        }
    }
    let actions: u64 = stats.iter().map(|s| s.actions).sum();
    let want = conventional_fee(actions);
    if fee != want {
        return Err(eyre!(
            "PCZT pays a fee of {fee} zat, not the ZIP 317 conventional fee of {want} zat for {actions} actions"
        ));
    }
    Ok(fee)
}

/// Parse a PCZT once and check everything the signer relies on, from those same bytes:
///
/// - every Orchard and Ironwood output opens against its `cmx` (recipient, value, rseed,
///   rho = the action's spend nullifier); none is skipped and the `user_address` label is ignored;
/// - every output that carries value has a note ciphertext that opens, so the payee's wallet
///   will see the note, and an output to the payee carries the expected memo when one is given;
/// - the fee (the bundles' value balance) is exactly the ZIP 317 conventional fee for the
///   transaction's actions, and no bundle is padded with more actions than it needs;
/// - at least `min` reaches the payee and no value goes anywhere else;
/// - the shielded sighash, which `sign-pczt` then requires the signing package to carry.
fn check_pczt(pczt_bytes: &[u8], policy: &Policy) -> Result<Checked> {
    use ff::PrimeField;
    use pczt::roles::verifier::{OrchardError, Verifier};
    let pczt = pczt::Pczt::parse(pczt_bytes).map_err(|e| eyre!("cannot parse PCZT: {e:?}"))?;
    if !pczt.transparent().inputs().is_empty() || !pczt.transparent().outputs().is_empty() {
        return Err(eyre!(
            "PCZT has transparent inputs or outputs, which this signer does not accept"
        ));
    }
    if !pczt.sapling().spends().is_empty() || !pczt.sapling().outputs().is_empty() {
        return Err(eyre!("PCZT has Sapling spends or outputs, which this signer does not accept"));
    }
    if *pczt.sapling().value_sum() != 0 {
        return Err(eyre!("PCZT has a Sapling value balance with no Sapling spends or outputs"));
    }
    let mut outs = Vec::new();
    let mut stats = Vec::new();
    let mut alphas = Vec::new();
    let mut check = |pool: &'static str,
                     bundle: &orchard::pczt::Bundle|
     -> Result<(), OrchardError<String>> {
        let err = |s: String| OrchardError::Custom(s);
        let (mut spends, mut paying) = (0u64, 0u64);
        for (i, action) in bundle.actions().iter().enumerate() {
            let o = action.output();
            o.verify_note_commitment(action.spend()).map_err(|e| {
                err(format!("{pool} action {i}: output does not open its note commitment: {e:?}"))
            })?;
            // verify_note_commitment requires both, so these are set from here on.
            let (Some(value), Some(recipient)) = (o.value(), o.recipient()) else {
                return Err(err(format!("{pool} action {i}: output value or recipient missing")));
            };
            let receiver = recipient.to_raw_address_bytes();
            let to_expected = receiver == policy.to;
            // A zero-value output (padding) has a random ciphertext by design; one that
            // carries value must open, or its recipient's wallet never sees the note.
            let memo = if value.inner() > 0 {
                paying += 1;
                let memo = open_output(pool, action).ok_or_else(|| {
                        err(format!(
                            "{pool} action {i}: output pays {} zat in a note ciphertext its recipient cannot decrypt",
                            value.inner()
                        ))
                    })?;
                if let (true, Some(want)) = (to_expected, policy.memo.as_ref()) {
                    if &memo != want {
                        return Err(err(format!(
                            "{pool} action {i}: payout memo {:?} is not the expected memo {:?}",
                            memo_text(&memo).unwrap_or_else(|| "<not text>".into()),
                            memo_text(want).unwrap_or_default()
                        )));
                    }
                }
                memo_text(&memo)
            } else {
                None
            };
            // A spend whose value is not shown as zero counts as real (needing a signature).
            if action.spend().value().is_none_or(|v| v.inner() > 0) {
                spends += 1;
            }
            if let Some(a) = action.spend().alpha() {
                alphas.push(hex::encode(a.to_repr()));
            }
            outs.push(VerifiedOutput {
                pool,
                action: i,
                value: value.inner(),
                receiver: hex::encode(receiver),
                to_expected,
                memo,
            });
        }
        let value_balance = i64::try_from(*bundle.value_sum())
            .map_err(|_| err(format!("{pool}: value balance out of range")))?;
        stats.push(BundleStats {
            pool,
            actions: bundle.actions().len() as u64,
            spends,
            paying,
            value_balance,
        });
        Ok(())
    };
    let show = |e: OrchardError<String>| match e {
        OrchardError::Custom(s) => eyre!(s),
        e => eyre!("{e:?}"),
    };
    let pczt = Verifier::new(pczt)
        .with_orchard(|b| check("orchard", b))
        .map_err(show)?
        .with_ironwood(|b| check("ironwood", b))
        .map_err(show)?
        .finish();

    let fee = fee_rule(&stats)?;
    let actions: u64 = stats.iter().map(|s| s.actions).sum();

    // Payout policy, on the verified outputs.
    let paid: u64 = outs.iter().filter(|o| o.to_expected).map(|o| o.value).sum();
    if paid < policy.min {
        return Err(eyre!(
            "PCZT pays {paid} zat to the agreed address, expected >= {}",
            policy.min
        ));
    }
    if outs.iter().any(|o| !o.to_expected && o.value > 0) {
        return Err(eyre!("PCZT has outputs to other addresses"));
    }

    let signer = pczt::roles::signer::Signer::new(pczt)
        .map_err(|e| eyre!("cannot derive sighash: {e:?}"))?;
    Ok(Checked {
        outputs: outs,
        fee,
        actions,
        sighash: hex::encode(signer.shielded_sighash()),
        alphas,
    })
}

/// The policy from command-line values.
fn policy(to: &str, min: u64, memo: Option<&str>) -> Result<Policy> {
    Ok(Policy { to: orchard_receiver(to)?, min, memo: memo.map(text_memo).transpose()? })
}

/// Check a PCZT (see `check_pczt`) and sign its sighash, all from one byte buffer.
fn sign_pczt(
    pczt_bytes: &[u8],
    policy: &Policy,
    pkg: &rp::SigningPackage,
    nonces: &rp::round1::SigningNonces,
    key: &rp::keys::KeyPackage,
    randomizer_hex: &str,
) -> Result<(Checked, rp::round2::SignatureShare)> {
    let checked = check_pczt(pczt_bytes, policy)?;
    let alpha = randomizer_hex.trim().to_ascii_lowercase();
    if !checked.alphas.contains(&alpha) {
        return Err(eyre!(
            "refusing to sign: randomizer {alpha} is not the alpha of any spend in this PCZT"
        ));
    }
    let sighash = hex::decode(&checked.sighash)?;
    let share = sign_share(pkg, nonces, key, randomizer(&alpha)?, &sighash)?;
    Ok((checked, share))
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
        Cmd::Outputs { pczt, to, min, memo } => {
            let bytes = fs::read(&pczt).wrap_err_with(|| format!("reading {}", pczt.display()))?;
            let checked = check_pczt(&bytes, &policy(&to, min, memo.as_deref())?)?;
            println!("{}", serde_json::to_string(&checked)?);
        }
        Cmd::SignPczt { pczt, to, min, memo, key, nonces, package, randomizer: r, out } => {
            let k: PartyKey = read_json(&key)?;
            let n: rp::round1::SigningNonces = read_json(&nonces)?;
            // Nonces are single-use: remove them before anything else can reuse them.
            fs::remove_file(&nonces)?;
            let pkg: rp::SigningPackage = read_json(&package)?;
            // The only read of the PCZT: every check and the sighash come from these bytes.
            let bytes = fs::read(&pczt).wrap_err_with(|| format!("reading {}", pczt.display()))?;
            let (checked, share) = sign_pczt(
                &bytes,
                &policy(&to, min, memo.as_deref())?,
                &pkg,
                &n,
                &k.key_package,
                &r,
            )?;
            write_json(&out, &Share { identifier: k.identifier, share })?;
            println!("{}", serde_json::to_string(&checked)?);
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

    // ---- PCZT checks: commitments, ciphertexts, memo, fee, payout policy, sighash ----

    /// A real regtest payout PCZT (zcash-devtool `pczt create-max` + `pczt prove`): two Ironwood
    /// actions, a zero-value dummy output and 99_990_000 zat to `PAYEE`.
    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/regtest-payout.proven.pczt");
    const PAYEE: &str = "uregtest1jfjdyhl4ac8q4qmgm3t3gws8n39axpp0x9vs2mnjwaa6eql6rxqd9uytf6mys68rlnx76kaghpp48g4kzrxeh0zq7q8qudyv9vd6t75v";
    const PAID: u64 = 99_990_000;
    const MEMO: &str = "zescrow release A-mvvmoke4";
    /// What ZF `zcash-sign sign` prints for this PCZT.
    const SIGHASH: &str = "bbcb9c7afe04005fc867693a91a666f54331e0c067a7d15f48918d6ef68ffc30";
    const ALPHA: &str = "79738e65791ba08f71f00a2bdc7c7629032b53298f6b7dee4e4b6db3480eb819";

    /// Testnet and mainnet payout PCZTs from the public runs, with spend-side wallet metadata
    /// (fvk, witness, ZIP 32 paths, spent-note fields) redacted. None of it is in the sighash.
    struct Real {
        name: &'static str,
        bytes: &'static [u8],
        to: &'static str,
        min: u64,
        memo: &'static str,
        sighash: &'static str,
    }
    const REAL: [Real; 3] = [
        Real { name: "regtest release", bytes: FIXTURE, to: PAYEE, min: 99_980_000, memo: MEMO, sighash: SIGHASH },
        Real {
            name: "testnet release",
            bytes: include_bytes!("../tests/fixtures/testnet-release.proven.pczt"),
            to: "utest197jhccyr9h55qx8603krk2ju9zvgnjstuj2uy0x9fsrm9jntdmxrdccl9syffa93d9csf7wew6czml70mryudvetjttza7vuusqckzuz",
            min: 4_980_000,
            memo: "zescrow release A-mvvl31wk",
            sighash: "f9405b367d64ef6377bf3caa47e1fa0e22ae474f1177a013266f45cb896d2fa2",
        },
        Real {
            name: "mainnet verdict refund",
            bytes: include_bytes!("../tests/fixtures/mainnet-verdict.proven.pczt"),
            to: "u1k5ghdvwa530qnqgz7q35hqgg9t6x4lpryfss6xhv3dal0gfp7hrmnyzyt85cea2ld8pu3uxwfsd5fpj76q4z6es6gv5xae7ssc598mvs",
            min: 1_980_000,
            memo: "zescrow verdict 9132705bc154edf621ad0c7e8b2bbbfb",
            sighash: "f2d5fc610cd5e6e92b5e9bdc75b7adf19702028d2e3a0df388b6f3ad85784050",
        },
    ];
    /// Testnet run B: the payout the demo builds to show the arbiter refusing it. It pays the
    /// seller with an empty memo, while the verdict names the buyer and its own memo.
    const WRONG_PAYEE_PCZT: &[u8] =
        include_bytes!("../tests/fixtures/testnet-wrong-payee.proven.pczt");
    const TESTNET_SELLER: &str = "utest197jhccyr9h55qx8603krk2ju9zvgnjstuj2uy0x9fsrm9jntdmxrdccl9syffa93d9csf7wew6czml70mryudvetjttza7vuusqckzuz";
    const TESTNET_BUYER: &str = "utest1zp4373naexyut5gppxx4cyw09mh8876qhq6cyn0rnemy85s68rddcqrnht7lyvlyxz7gc9vk8cvp0zl4gh0g9su80swr8yfepgcr9j90";
    const TESTNET_B_MEMO: &str = "zescrow verdict a215a3336f9906500e3875ac33b57327";

    fn pol(to: &str, min: u64, memo: Option<&str>) -> Policy {
        policy(to, min, memo).unwrap()
    }
    fn any() -> Policy {
        pol(PAYEE, 0, None)
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

    fn only(bytes: &[u8], needle: &[u8]) -> usize {
        let at: Vec<_> = bytes
            .windows(needle.len())
            .enumerate()
            .filter(|(_, w)| *w == needle)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(at.len(), 1, "fixture layout changed");
        at[0]
    }

    #[test]
    fn real_payout_pczts_pass_every_check_and_match_zcash_sign_sighash() {
        for r in &REAL {
            let c = check_pczt(r.bytes, &pol(r.to, r.min, Some(r.memo)))
                .unwrap_or_else(|e| panic!("{}: {e}", r.name));
            assert_eq!(c.sighash, r.sighash, "{}", r.name);
            assert_eq!((c.fee, c.actions), (10_000, 2), "{}", r.name);
            let paid: Vec<_> = c.outputs.iter().filter(|o| o.to_expected).collect();
            assert_eq!(paid.len(), 1, "{}", r.name);
            assert_eq!(paid[0].memo.as_deref(), Some(r.memo), "{}", r.name);
            assert_eq!(paid[0].value, r.min + 10_000, "{}", r.name);
        }
    }

    #[test]
    fn outputs_of_an_honest_pczt_open_their_commitments() {
        let outs = check_pczt(FIXTURE, &any()).unwrap().outputs;
        assert_eq!(outs.len(), 2);
        let paid: Vec<_> = outs.iter().filter(|o| o.to_expected).collect();
        assert_eq!(paid.len(), 1);
        assert_eq!((paid[0].pool, paid[0].action, paid[0].value), ("ironwood", 1, PAID));
        let dummy = outs.iter().find(|o| !o.to_expected).unwrap();
        assert_eq!((dummy.value, dummy.memo.as_deref()), (0, None));
    }

    #[test]
    fn output_value_that_does_not_match_its_commitment_is_refused() {
        // Postcard encodes the paid output's `value: Some(99_990_000)` as 01 f0 f3 d6 2f;
        // 01 f1 f3 d6 2f is Some(99_990_001). The cmx is unchanged, so it no longer opens.
        let at = only(FIXTURE, &[0x01, 0xf0, 0xf3, 0xd6, 0x2f]);
        let mut bytes = FIXTURE.to_vec();
        bytes[at + 1] = 0xf1;
        let err = check_pczt(&bytes, &any()).unwrap_err().to_string();
        assert!(
            err.contains("ironwood action 1") && err.contains("InvalidExtractedNoteCommitment"),
            "{err}"
        );
    }

    #[test]
    fn output_without_value_is_refused_not_skipped() {
        let err = check_pczt(&redact(|a| a.clear_output_value()), &any()).unwrap_err().to_string();
        assert!(err.contains("ironwood action 1") && err.contains("MissingValue"), "{err}");
    }

    #[test]
    fn output_without_recipient_or_rseed_is_refused() {
        let e1 =
            check_pczt(&redact(|a| a.clear_output_recipient()), &any()).unwrap_err().to_string();
        assert!(e1.contains("MissingRecipient"), "{e1}");
        let e2 = check_pczt(&redact(|a| a.clear_output_rseed()), &any()).unwrap_err().to_string();
        assert!(e2.contains("MissingRandomSeed"), "{e2}");
    }

    /// The paying output's note ciphertext, as it sits in the serialized PCZT.
    fn paying_ciphertext() -> Vec<u8> {
        let p = pczt::Pczt::parse(FIXTURE).unwrap();
        let mut ct = Vec::new();
        pczt::roles::verifier::Verifier::new(p)
            .with_ironwood::<String, _>(|b| {
                ct = b.actions()[1].output().encrypted_note().enc_ciphertext.0.to_vec();
                Ok(())
            })
            .unwrap();
        ct
    }

    #[test]
    fn paying_output_whose_ciphertext_does_not_decrypt_is_refused() {
        // Commitment honest (recipient, value, rseed all open cmx), ciphertext not decryptable
        // by the payee: one flipped byte breaks the AEAD tag.
        let ct = paying_ciphertext();
        let at = only(FIXTURE, &ct[..64]);
        let mut bytes = FIXTURE.to_vec();
        bytes[at + 200] ^= 0x01;
        let err = check_pczt(&bytes, &any()).unwrap_err().to_string();
        assert!(err.contains("ironwood action 1") && err.contains("cannot decrypt"), "{err}");
    }

    #[test]
    fn payout_encrypted_with_another_memo_is_refused() {
        // The PCZT redactor can swap the note ciphertext for a memo plaintext, from which the
        // ciphertext is re-derived on parse: a payee-decryptable note with another memo.
        let other = text_memo("zescrow release someone-else").unwrap();
        let bytes = redact(|a| a.replace_enc_ciphertext_with_memo_plaintext(other));
        let c = check_pczt(&bytes, &pol(PAYEE, PAID, None)).unwrap();
        assert_eq!(c.outputs[1].memo.as_deref(), Some("zescrow release someone-else"));
        let err = check_pczt(&bytes, &pol(PAYEE, PAID, Some(MEMO))).unwrap_err().to_string();
        assert!(err.contains("is not the expected memo"), "{err}");
    }

    #[test]
    fn wrong_memo_is_refused() {
        // The honest fixture, but the signer expects a different verdict hash in the memo.
        let err = check_pczt(
            FIXTURE,
            &pol(PAYEE, PAID, Some("zescrow verdict 00000000000000000000000000000000")),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("is not the expected memo"), "{err}");
        // A real PCZT whose payout carries an empty memo where the verdict's memo is expected.
        let err = check_pczt(WRONG_PAYEE_PCZT, &pol(TESTNET_SELLER, 0, Some(TESTNET_B_MEMO)))
            .unwrap_err()
            .to_string();
        assert!(err.contains("payout memo \"\" is not the expected memo"), "{err}");
        // And it pays nothing to the payee the verdict names.
        let err =
            check_pczt(WRONG_PAYEE_PCZT, &pol(TESTNET_BUYER, 9_980_000, Some(TESTNET_B_MEMO)))
                .unwrap_err()
                .to_string();
        assert!(err.contains("pays 0 zat"), "{err}");
    }

    #[test]
    fn excess_fee_is_refused() {
        // The Ironwood bundle's value_sum (10_000, positive) is postcard 90 4e 00; 98 75 00 is
        // 15_000: 5_000 zat more fee, taken out of what the payee would otherwise get.
        let at = only(FIXTURE, &[0x90, 0x4e, 0x00]);
        let mut bytes = FIXTURE.to_vec();
        bytes[at..at + 2].copy_from_slice(&[0x98, 0x75]);
        let err = check_pczt(&bytes, &any()).unwrap_err().to_string();
        assert!(
            err.contains("fee of 15000 zat, not the ZIP 317 conventional fee of 10000"),
            "{err}"
        );
    }

    fn stats(actions: u64, spends: u64, paying: u64, value_balance: i64) -> BundleStats {
        BundleStats { pool: "ironwood", actions, spends, paying, value_balance }
    }

    #[test]
    fn fee_rule_is_exactly_zip317() {
        assert_eq!(fee_rule(&[stats(2, 1, 1, 10_000)]).unwrap(), 10_000);
        assert_eq!(fee_rule(&[stats(3, 2, 1, 15_000)]).unwrap(), 15_000);
        assert!(fee_rule(&[stats(2, 1, 1, 10_001)])
            .unwrap_err()
            .to_string()
            .contains("not the ZIP 317"));
        assert!(fee_rule(&[stats(2, 1, 1, 9_999)])
            .unwrap_err()
            .to_string()
            .contains("not the ZIP 317"));
        assert!(fee_rule(&[stats(2, 1, 1, -10_000)])
            .unwrap_err()
            .to_string()
            .contains("instead of paying a fee"));
        // Padding actions to justify a higher fee.
        assert!(fee_rule(&[stats(4, 1, 1, 20_000)])
            .unwrap_err()
            .to_string()
            .contains("4 actions where 2 are enough"));
    }

    #[test]
    fn user_address_label_is_ignored() {
        let honest = check_pczt(FIXTURE, &any()).unwrap().outputs;
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
        let err = check_pczt(&relabeled, &pol(&attacker, 1, None)).unwrap_err().to_string();
        assert!(err.contains("pays 0 zat"), "label must not count as payment: {err}");
        let outs = check_pczt(&relabeled, &pol(PAYEE, PAID, None)).unwrap().outputs;
        assert!(outs.iter().any(|o| o.to_expected && o.value == PAID));
    }

    #[test]
    fn underpayment_or_value_to_anyone_else_is_refused() {
        let err = check_pczt(FIXTURE, &pol(PAYEE, PAID + 1, None)).unwrap_err().to_string();
        assert!(err.contains("pays 99990000 zat"), "{err}");
        let other = other_ua(&check_pczt(FIXTURE, &any()).unwrap().outputs);
        let err = check_pczt(FIXTURE, &pol(&other, 0, None)).unwrap_err().to_string();
        assert!(err.contains("outputs to other addresses"), "{err}");
    }

    #[test]
    fn garbage_is_not_a_pczt() {
        assert!(check_pczt(b"not a pczt", &any()).is_err());
    }

    // ---- sign-pczt: one read, every check, the sighash from the same bytes ----

    #[test]
    fn sign_pczt_signs_an_honest_payout() {
        let r = round(&hex::decode(SIGHASH).unwrap());
        for (id, kp) in &r.keys {
            let (c, _) =
                sign_pczt(FIXTURE, &pol(PAYEE, PAID, Some(MEMO)), &r.pkg, &r.nonces[id], kp, ALPHA)
                    .unwrap();
            assert_eq!(c.sighash, SIGHASH);
        }
    }

    #[test]
    fn sign_pczt_refuses_a_package_for_another_message() {
        let r = round(&[0xaa; 32]);
        let (id, kp) = r.keys.iter().next().unwrap();
        let err =
            sign_pczt(FIXTURE, &any(), &r.pkg, &r.nonces[id], kp, ALPHA).unwrap_err().to_string();
        assert!(err.contains("not the locally derived sighash"), "{err}");
    }

    #[test]
    fn sign_pczt_refuses_a_randomizer_not_in_the_pczt() {
        let r = round(&hex::decode(SIGHASH).unwrap());
        let (id, kp) = r.keys.iter().next().unwrap();
        let alpha = hex::encode(r.randomizer.serialize());
        let err =
            sign_pczt(FIXTURE, &any(), &r.pkg, &r.nonces[id], kp, &alpha).unwrap_err().to_string();
        assert!(err.contains("not the alpha of any spend"), "{err}");
    }

    #[test]
    fn sign_pczt_refuses_before_signing_when_a_check_fails() {
        let r = round(&hex::decode(SIGHASH).unwrap());
        let (id, kp) = r.keys.iter().next().unwrap();
        let err = sign_pczt(
            FIXTURE,
            &pol(PAYEE, PAID, Some("zescrow release other")),
            &r.pkg,
            &r.nonces[id],
            kp,
            ALPHA,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("is not the expected memo"), "{err}");
    }
}

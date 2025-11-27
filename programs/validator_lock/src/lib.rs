//! Validator Lock Program for zkSealevel
//!
//! This program implements the on-chain validator registration, proof anchoring,
//! and token locking mechanisms for the zkSealevel system as specified in the
//! Master Blueprint and POC Execution Plan.

#![forbid(unsafe_code)]
#![deny(
    warnings,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::float_arithmetic,
    clippy::as_conversions
)]
#![deny(
    clippy::else_if_without_else,
    clippy::shadow_reuse,
    clippy::wildcard_enum_match_arm
)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
// Anchor #[program] macro generates items without user-writable docs in 0.32.x
// Allow missing docs only when compiling the actual on-chain program.
#![cfg_attr(not(feature = "skip-anchor-program"), allow(missing_docs))]
#![cfg_attr(
    not(feature = "skip-anchor-program"),
    allow(clippy::missing_docs_in_private_items)
)]
#![allow(unexpected_cfgs)]
#![allow(unused_imports)] // False positives before macro expansion
#![cfg_attr(
    feature = "clippy-skip",
    allow(
        clippy::cargo,
        clippy::multiple_crate_versions,
        clippy::cargo_common_metadata,
        dead_code
    )
)]

use anchor_lang::prelude::*;
use anchor_lang::solana_program::pubkey;
use anchor_lang::solana_program::sysvar::instructions as sysvar_instructions;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};
use blake3::Hasher as Blake3Hasher;

// Program ID (declare_id!) injected at build time from env by build.rs
include!(concat!(env!("OUT_DIR"), "/program_id.rs"));

/// Program entrypoint module for validator_lock per Master_Blueprint.md
#[cfg(not(feature = "skip-anchor-program"))]
#[allow(missing_docs)]
#[allow(clippy::missing_docs_in_private_items)]
#[program]
pub mod validator_lock {
    #![allow(missing_docs)]
    #![allow(clippy::missing_docs_in_private_items)]
    use super::*;

    /// Initialize the on-chain configuration for the validator lock program.
    pub fn initialize(ctx: Context<Initialize>, args: InitializeArgs) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        cfg.zksl_mint = ctx.accounts.zksl_mint.key();
        cfg.admin = ctx.accounts.admin.key();
        cfg.aggregator_pubkey = args.aggregator_pubkey;
        cfg.next_aggregator_pubkey = args.next_aggregator_pubkey;
        cfg.activation_seq = args.activation_seq;
        cfg.chain_id = args.chain_id;
        cfg.paused = 0;
        // minimal state touch to avoid unused warnings on constants/helpers
        let _ = (DS_PREFIX, MAX_SLOTS_PER_ARTIFACT, MAX_CLOCK_SKEW_SECS);
        let _ = allowed_aggregator_key;
        Ok(())
    }

    /// Unlock validator: return exactly 1 token and set status to Unlocked
    /// Unlock a validator by returning exactly 1 token and marking the record unlocked.
    pub fn unlock_validator(ctx: Context<UnlockValidator>) -> Result<()> {
        require!(ctx.accounts.config.paused == 0, ZkError::Paused);
        // Enforce legacy SPL Token program (reject Token-2022)
        require_keys_eq!(
            ctx.accounts.token_program.key(),
            anchor_spl::token::ID,
            ZkError::InvalidMint
        );
        require!(
            ctx.accounts.validator_record.status == 0,
            ZkError::StatusNotActive
        );
        // Ensure escrow holds exactly 1 token (10^decimals base units)
        let decimals = ctx.accounts.zksl_mint.decimals;
        let amount: u64 = 10u64.pow(decimals as u32);
        require!(
            ctx.accounts.validator_escrow.amount == amount,
            ZkError::InvalidLockAmount
        );
        // Transfer back to validator ATA using escrow PDA as signer
        let cpi_accounts = Transfer {
            from: ctx.accounts.validator_escrow.to_account_info(),
            to: ctx.accounts.validator_ata.to_account_info(),
            authority: ctx.accounts.escrow_authority.to_account_info(),
        };
        let validator_key = ctx.accounts.validator.key();
        let seeds = &[b"zksl".as_ref(), b"escrow".as_ref(), validator_key.as_ref()];
        let (_pda, bump) = Pubkey::find_program_address(seeds, ctx.program_id);
        let bump_slice = &[bump];
        let signer_seeds: &[&[u8]] = &[
            b"zksl".as_ref(),
            b"escrow".as_ref(),
            validator_key.as_ref(),
            bump_slice,
        ];
        let signers_seeds = &[signer_seeds];
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
            signers_seeds,
        );
        token::transfer(cpi_ctx, amount)?;
        ctx.accounts.validator_record.status = 1;
        Ok(())
    }

    /// Register a validator by escrow-locking exactly 1 token and creating/updating its record.
    pub fn register_validator(ctx: Context<RegisterValidator>) -> Result<()> {
        require!(ctx.accounts.config.paused == 0, ZkError::Paused);
        // Transfer exactly 1 token of zKSL (10^decimals base units) from validator ATA to escrow
        let mint = ctx.accounts.zksl_mint.key();
        require_keys_eq!(mint, ctx.accounts.config.zksl_mint, ZkError::InvalidMint);
        // Prevent re-registration if a record already exists for this validator
        let rec_existing = &ctx.accounts.validator_record;
        if rec_existing.validator_pubkey != Pubkey::default() {
            return err!(ZkError::AlreadyRegistered);
        }
        // Enforce legacy SPL Token program (reject Token-2022)
        require_keys_eq!(
            ctx.accounts.token_program.key(),
            anchor_spl::token::ID,
            ZkError::InvalidMint
        );
        // Transfer
        let decimals = ctx.accounts.zksl_mint.decimals;
        let amount: u64 = 10u64.pow(decimals as u32);
        let cpi_accounts = Transfer {
            from: ctx.accounts.validator_ata.to_account_info(),
            to: ctx.accounts.validator_escrow.to_account_info(),
            authority: ctx.accounts.validator.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer(cpi_ctx, amount)?;

        let rec = &mut ctx.accounts.validator_record;
        rec.validator_pubkey = ctx.accounts.validator.key();
        rec.lock_token_account = ctx.accounts.validator_escrow.key();
        rec.lock_timestamp = Clock::get()?.unix_timestamp;
        rec.status = 0;
        rec.num_accepts = 0;
        Ok(())
    }

    /// Update the program configuration (admin only).
    pub fn update_config(ctx: Context<UpdateConfig>, args: UpdateConfigArgs) -> Result<()> {
        require_keys_eq!(
            ctx.accounts.admin.key(),
            ctx.accounts.config.admin,
            ZkError::Unauthorized
        );
        let cfg = &mut ctx.accounts.config;
        if let Some(pk) = args.aggregator_pubkey {
            cfg.aggregator_pubkey = pk;
        }
        if let Some(pk) = args.next_aggregator_pubkey {
            cfg.next_aggregator_pubkey = pk;
        }
        if let Some(seq) = args.activation_seq {
            cfg.activation_seq = seq;
        }
        if let Some(p) = args.paused {
            cfg.paused = if p { 1 } else { 0 };
        }
        emit!(ConfigUpdated {
            aggregator_pubkey: args.aggregator_pubkey,
            paused: args.paused,
            timestamp: Clock::get()?.unix_timestamp
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    /// Anchor a proof artifact with strict Ed25519 preflight and domain separation checks.
    pub fn anchor_proof(
        ctx: Context<AnchorProof>,
        artifact_id: [u8; 16],       // arg 0
        proof_hash: [u8; 32],        // arg 1 - moved up for #[instruction]
        seq: u64,                    // arg 2 - moved up for #[instruction]
        start_slot: u64,             // arg 3
        end_slot: u64,               // arg 4
        artifact_len: u32,           // arg 5
        state_root_before: [u8; 32], // arg 6
        state_root_after: [u8; 32],  // arg 7
        aggregator_pubkey: Pubkey,   // arg 8
        timestamp: i64,              // arg 9
        ds_hash: [u8; 32],           // arg 10
    ) -> Result<()> {
        require!(ctx.accounts.config.paused == 0, ZkError::Paused);
        let allowed = allowed_aggregator_key(&ctx.accounts.config, seq);
        require_keys_eq!(aggregator_pubkey, allowed, ZkError::AggregatorMismatch);

        // Strict Ed25519 preflight checks: ensure previous ix is Ed25519 and only one Ed25519 in tx
        let ix_acc = ctx.accounts.sysvar_instructions.to_account_info();
        let mut ed_count: u32 = 0;
        let mut idx: usize = 0;
        let mut has_compute_ok = false;
        loop {
            match sysvar_instructions::load_instruction_at_checked(idx, &ix_acc) {
                Ok(ix) => {
                    if ix.program_id == ED25519_PROGRAM_ID {
                        ed_count += 1;
                    } else if ix.program_id == COMPUTE_BUDGET_PROGRAM_ID {
                        // Require presence of ComputeBudget to force explicit CU/priority-fee planning
                        has_compute_ok = true;
                    }
                    idx += 1;
                }
                Err(_) => break,
            }
        }
        require!(ed_count == 1, ZkError::BadEd25519Order);
        require!(has_compute_ok, ZkError::InsufficientBudget);
        // Use the current instruction index to safely reference the immediately preceding instruction
        let cur_idx = sysvar_instructions::load_current_index_checked(&ix_acc)
            .map_err(|_| error!(ZkError::BadEd25519Order))? as usize;
        require!(cur_idx >= 1, ZkError::BadEd25519Order);
        let prev_ix = sysvar_instructions::load_instruction_at_checked(cur_idx - 1, &ix_acc)
            .map_err(|_| error!(ZkError::BadEd25519Order))?;
        let prev_is_ed25519 = prev_ix.program_id == ED25519_PROGRAM_ID;
        require!(prev_is_ed25519, ZkError::BadEd25519Order);

        // seq monotonic (global, across key rotation)
        if ctx.accounts.aggregator_state.last_seq == 0 {
            require!(seq == 1, ZkError::NonMonotonicSeq);
        } else {
            require!(
                seq == ctx
                    .accounts
                    .aggregator_state
                    .last_seq
                    .checked_add(1)
                    .ok_or(ZkError::MathOverflow)?,
                ZkError::NonMonotonicSeq
            );
        }

        // range monotonic and bounds
        require!(end_slot >= start_slot, ZkError::MathOverflow);
        require!(
            (end_slot - start_slot + 1) <= MAX_SLOTS_PER_ARTIFACT,
            ZkError::MathOverflow
        );
        if ctx.accounts.range_state.last_end_slot != 0 {
            require!(
                start_slot == ctx.accounts.range_state.last_end_slot + 1,
                ZkError::RangeOverlap
            );
        }

        // clock skew
        let now = Clock::get()?.unix_timestamp;
        let skew = now.saturating_sub(timestamp).abs();
        require!(skew <= MAX_CLOCK_SKEW_SECS, ZkError::ClockSkew);

        // Recompute DS and verify ds_hash and Ed25519 message/public key
        let mut ds = Vec::with_capacity(14 + 8 + 32 + 32 + 8 + 8 + 8);
        ds.extend_from_slice(DS_PREFIX);
        ds.extend_from_slice(&ctx.accounts.config.chain_id.to_le_bytes());
        ds.extend_from_slice(ctx.program_id.as_ref());
        ds.extend_from_slice(&proof_hash);
        ds.extend_from_slice(&start_slot.to_le_bytes());
        ds.extend_from_slice(&end_slot.to_le_bytes());
        ds.extend_from_slice(&seq.to_le_bytes());
        let mut hasher = Blake3Hasher::new();
        hasher.update(&ds);
        let expected_ds_hash = *hasher.finalize().as_bytes();
        require!(expected_ds_hash == ds_hash, ZkError::BadDomainSeparation);

        // Parse Ed25519 instruction to ensure it signed the exact DS and with the allowed pubkey
        let data = prev_ix.data.as_slice();
        require!(data.len() >= 16, ZkError::InvalidSignature);
        let num = *data.get(0).ok_or(ZkError::InvalidSignature)?;
        require!(num == 1, ZkError::InvalidSignature);
        let sig_off = u16::from_le_bytes([
            *data.get(2).ok_or(ZkError::InvalidSignature)?,
            *data.get(3).ok_or(ZkError::InvalidSignature)?,
        ]) as usize;
        let sig_ix = u16::from_le_bytes([
            *data.get(4).ok_or(ZkError::InvalidSignature)?,
            *data.get(5).ok_or(ZkError::InvalidSignature)?,
        ]);
        let pk_off = u16::from_le_bytes([
            *data.get(6).ok_or(ZkError::InvalidSignature)?,
            *data.get(7).ok_or(ZkError::InvalidSignature)?,
        ]) as usize;
        let pk_ix = u16::from_le_bytes([
            *data.get(8).ok_or(ZkError::InvalidSignature)?,
            *data.get(9).ok_or(ZkError::InvalidSignature)?,
        ]);
        let msg_off = u16::from_le_bytes([
            *data.get(10).ok_or(ZkError::InvalidSignature)?,
            *data.get(11).ok_or(ZkError::InvalidSignature)?,
        ]) as usize;
        let msg_len = u16::from_le_bytes([
            *data.get(12).ok_or(ZkError::InvalidSignature)?,
            *data.get(13).ok_or(ZkError::InvalidSignature)?,
        ]) as usize;
        let msg_ix = u16::from_le_bytes([
            *data.get(14).ok_or(ZkError::InvalidSignature)?,
            *data.get(15).ok_or(ZkError::InvalidSignature)?,
        ]);
        require!(
            sig_ix == u16::MAX && pk_ix == u16::MAX && msg_ix == u16::MAX,
            ZkError::BadEd25519Order
        );
        // Consolidated bounds checks for Ed25519 instruction slices
        let sig_end = sig_off.saturating_add(64);
        let pk_end = pk_off.saturating_add(32);
        let msg_end = msg_off.saturating_add(msg_len);
        require!(data.len() >= sig_end, ZkError::InvalidSignature);
        require!(data.len() >= pk_end, ZkError::InvalidSignature);
        require!(data.len() >= msg_end, ZkError::InvalidSignature);
        let pk = data
            .get(pk_off..pk_off + 32)
            .ok_or(ZkError::InvalidSignature)?;
        require!(pk == aggregator_pubkey.as_ref(), ZkError::InvalidSignature);
        require!(msg_len == ds.len(), ZkError::BadDomainSeparation);
        let msg = data
            .get(msg_off..(msg_off + msg_len))
            .ok_or(ZkError::InvalidSignature)?;
        require!(msg == ds.as_slice(), ZkError::BadDomainSeparation);

        // Populate ProofRecord
        let pr = &mut ctx.accounts.proof_record;
        require!(pr.seq == 0, ZkError::ProofAlreadyAnchored);
        pr.artifact_id = artifact_id;
        pr.start_slot = start_slot;
        pr.end_slot = end_slot;
        pr.proof_hash = proof_hash;
        // Artifact length bounds guard (defense in depth; also enforced off-chain)
        require!(
            artifact_len <= MAX_ARTIFACT_SIZE_BYTES,
            ZkError::MathOverflow
        );
        pr.artifact_len = artifact_len;
        pr.state_root_before = state_root_before;
        pr.state_root_after = state_root_after;
        pr.submitted_by = ctx.accounts.submitted_by.key();
        pr.aggregator_pubkey = aggregator_pubkey;
        pr.timestamp = timestamp;
        pr.seq = seq;
        pr.ds_hash = ds_hash;
        pr.commitment_level = 0;
        pr.da_params = [0u8; 12];
        pr.reserved = [0u8; 5];

        // Update state
        ctx.accounts.aggregator_state.last_seq = seq;
        ctx.accounts.range_state.last_end_slot = end_slot;

        emit!(ProofAnchored {
            artifact_id,
            proof_hash,
            start_slot,
            end_slot,
            submitted_by: ctx.accounts.submitted_by.key(),
            timestamp,
            seq,
            ds_hash
        });
        Ok(())
    }

    /// Debug instruction to validate account decoding path.
    pub fn ping(ctx: Context<Ping>) -> Result<()> {
        // Minimal instruction to validate account decoding path
        msg!("PING");
        let _ = ctx.accounts.config.chain_id; // touch to avoid unused
        Ok(())
    }

    /// Initialize aggregator and range state PDAs to zero.
    pub fn init_state(ctx: Context<InitState>) -> Result<()> {
        // Initialize aggregator_state and range_state to zero
        ctx.accounts.aggregator_state.last_seq = 0;
        ctx.accounts.range_state.last_end_slot = 0;
        Ok(())
    }

    /// Log resolved account addresses and expected PDA derivations for debugging.
    pub fn echo_accounts(ctx: Context<EchoAccounts>, proof_hash: [u8; 32], seq: u64) -> Result<()> {
        // Log out all resolved accounts in the exact order Anchor expects
        msg!("ECHO start");
        msg!("submitted_by: {}", ctx.accounts.submitted_by.key());
        msg!("config: {}", ctx.accounts.config.key());
        msg!("aggregator_state: {}", ctx.accounts.aggregator_state.key());
        msg!("range_state: {}", ctx.accounts.range_state.key());
        msg!("proof_record: {}", ctx.accounts.proof_record.key());
        // Derive PDAs on-chain and log them for comparison
        let prog_id = ctx.program_id;
        let agg_pda = Pubkey::find_program_address(&[b"zksl", b"aggregator"], prog_id).0;
        let rng_pda = Pubkey::find_program_address(&[b"zksl", b"range"], prog_id).0;
        let pr_pda = Pubkey::find_program_address(
            &[b"zksl", b"proof", &proof_hash, &seq.to_le_bytes()],
            prog_id,
        )
        .0;
        msg!("expected_aggregator_state: {}", agg_pda);
        msg!("expected_range_state: {}", rng_pda);
        msg!("expected_proof_record: {}", pr_pda);
        msg!("ECHO done");
        Ok(())
    }
}

// moved to anchor_items

// moved to anchor_items

// moved to anchor_items

// moved to anchor_items

// moved to anchor_items

/// Initialize arguments
/// Arguments for initialize.
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct InitializeArgs {
    /// Aggregator public key to authorize DS signatures initially.
    pub aggregator_pubkey: Pubkey,
    /// Next aggregator public key for rotation at or after `activation_seq`.
    pub next_aggregator_pubkey: Pubkey,
    /// Sequence number at which `next_aggregator_pubkey` activates.
    pub activation_seq: u64,
    /// Chain identifier bound into domain separation.
    pub chain_id: u64,
}

/// Update config arguments
/// Arguments for `update_config`.
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct UpdateConfigArgs {
    /// Optional replacement for `aggregator_pubkey`.
    pub aggregator_pubkey: Option<Pubkey>,
    /// Optional replacement for `next_aggregator_pubkey`.
    pub next_aggregator_pubkey: Option<Pubkey>,
    /// Optional update for activation sequence.
    pub activation_seq: Option<u64>,
    /// Optional paused flag (true = paused).
    pub paused: Option<bool>,
}

/// Config account
/// Program configuration account.
#[account]
pub struct Config {
    /// Mint for the zKSL token used for escrow.
    pub zksl_mint: Pubkey,
    /// Admin authority allowed to update configuration.
    pub admin: Pubkey,
    /// Current aggregator public key authorized for DS signatures.
    pub aggregator_pubkey: Pubkey,
    /// Next aggregator public key for rotation.
    pub next_aggregator_pubkey: Pubkey,
    /// Activation sequence for aggregator rotation.
    pub activation_seq: u64,
    /// Chain identifier bound into domain separation.
    pub chain_id: u64,
    /// Paused flag (0 = active, 1 = paused).
    pub paused: u8,
    /// PDA bump for `config` account.
    pub bump: u8,
    /// Reserved for future fields; must be zeroed.
    pub reserved: [u8; 22],
}

impl Config {
    /// Packed on-chain size (bytes) of `Config` without the 8-byte Anchor discriminator.
    pub const SIZE: usize = 32 + 32 + 32 + 32 + 8 + 8 + 1 + 1 + 22;
}

/// Validator record
/// Validator record account.
#[account]
pub struct ValidatorRecord {
    /// Validator wallet public key.
    pub validator_pubkey: Pubkey,
    /// Escrow token account holding locked zKSL.
    pub lock_token_account: Pubkey,
    /// Unix timestamp when the lock was created.
    pub lock_timestamp: i64,
    /// Status (0 = Active, 1 = Unlocked).
    pub status: u8,
    /// Number of accepts observed for this validator.
    pub num_accepts: u64,
    /// Reserved for future fields; must be zeroed.
    pub reserved: [u8; 55],
}

impl ValidatorRecord {
    /// Packed on-chain size (bytes) of `ValidatorRecord` without the 8-byte discriminator.
    pub const SIZE: usize = 32 + 32 + 8 + 1 + 8 + 55;
}

// Events
// moved to anchor_items

// Program errors
// moved to anchor_items

// ================= Additional Accounts for Anchoring =================

/// Aggregator state PDA
/// Aggregator state PDA contents.
#[account]
pub struct AggregatorState {
    /// Aggregator public key in effect for the last sequence.
    /// Reserved for future rotation verification or audit trails.
    /// Kept to preserve on-chain layout; not actively read/written today.
    pub aggregator_pubkey: Pubkey,
    /// Last anchored sequence number.
    pub last_seq: u64,
    /// Reserved for future fields; must be zeroed.
    pub reserved: [u8; 86],
}

impl AggregatorState {
    /// Packed size (bytes) without the discriminator.
    pub const SIZE: usize = 32 + 8 + 86;
}

/// Range state PDA
/// Range state PDA contents.
#[account]
pub struct RangeState {
    /// Last end slot anchored by the validator.
    pub last_end_slot: u64,
    /// Reserved for future fields; must be zeroed.
    pub reserved: [u8; 120],
}

impl RangeState {
    /// Packed size (bytes) without the discriminator.
    pub const SIZE: usize = 8 + 120;
}

/// Proof record PDA
/// Proof record PDA contents describing an anchored proof artifact.
#[account]
pub struct ProofRecord {
    /// 16-byte UUID (v4) identifying the artifact.
    pub artifact_id: [u8; 16],
    /// Inclusive start slot of the artifact window.
    pub start_slot: u64,
    /// Inclusive end slot of the artifact window.
    pub end_slot: u64,
    /// 32-byte canonical hash of the artifact JSON.
    pub proof_hash: [u8; 32],
    /// Artifact JSON length in bytes.
    pub artifact_len: u32,
    /// 32-byte state root before the window.
    pub state_root_before: [u8; 32],
    /// 32-byte state root after the window.
    pub state_root_after: [u8; 32],
    /// Submitter public key.
    pub submitted_by: Pubkey,
    /// Aggregator public key in effect for this `seq`.
    pub aggregator_pubkey: Pubkey,
    /// Unix timestamp of submission.
    pub timestamp: i64,
    /// Monotonic sequence number bound to the aggregator state.
    pub seq: u64,
    /// 32-byte domain separation hash bound to DS.
    pub ds_hash: [u8; 32],
    /// Commitment level (0=processed,1=confirmed,2=finalized).
    pub commitment_level: u8,
    /// Data availability parameters (reserved for future use).
    pub da_params: [u8; 12],
    /// Reserved for future fields; must be zeroed.
    pub reserved: [u8; 5],
}

impl ProofRecord {
    /// Packed on-chain size (bytes) of `ProofRecord` without the 8-byte discriminator.
    pub const SIZE: usize = 16 + 8 + 8 + 32 + 4 + 32 + 32 + 32 + 32 + 8 + 8 + 32 + 1 + 12 + 5;
}

// Anchor macro-generated public items are isolated here to allow missing_docs per policy.
/// Anchor macro-generated items (Accounts structs, events, and error codes).
mod anchor_items {
    #![allow(missing_docs)]
    #![allow(clippy::missing_docs_in_private_items)]
    #![allow(clippy::wildcard_imports)]
    #![allow(clippy::shadow_reuse)]
    use super::*;

    #[derive(Accounts)]
    pub struct Initialize<'info> {
        #[account(mut)]
        pub payer: Signer<'info>,
        /// CHECK: admin is recorded only
        pub admin: UncheckedAccount<'info>,
        pub zksl_mint: Account<'info, Mint>,
        #[account(init, payer = payer, seeds = [b"zksl".as_ref(), b"config".as_ref()], bump, space = 8 + Config::SIZE)]
        pub config: Account<'info, Config>,
        pub system_program: Program<'info, System>,
    }

    #[derive(Accounts)]
    pub struct RegisterValidator<'info> {
        #[account(mut)]
        pub validator: Signer<'info>,
        pub zksl_mint: Account<'info, Mint>,
        #[account(mut, has_one = zksl_mint)]
        pub config: Account<'info, Config>,
        #[account(init_if_needed, payer = validator, seeds = [b"zksl".as_ref(), b"validator".as_ref(), validator.key().as_ref()], bump, space = 8 + ValidatorRecord::SIZE)]
        pub validator_record: Account<'info, ValidatorRecord>,
        /// CHECK: PDA authority for escrow
        #[account(seeds = [b"zksl".as_ref(), b"escrow".as_ref(), validator.key().as_ref()], bump)]
        pub escrow_authority: UncheckedAccount<'info>,
        #[account(init_if_needed, payer = validator, associated_token::mint = zksl_mint, associated_token::authority = escrow_authority, associated_token::token_program = token_program)]
        pub validator_escrow: Account<'info, TokenAccount>,
        #[account(mut)]
        pub validator_ata: Account<'info, TokenAccount>,
        pub token_program: Program<'info, Token>,
        pub associated_token_program: Program<'info, AssociatedToken>,
        pub system_program: Program<'info, System>,
    }

    #[derive(Accounts)]
    pub struct UpdateConfig<'info> {
        pub admin: Signer<'info>,
        #[account(mut)]
        pub config: Account<'info, Config>,
    }

    #[derive(Accounts)]
    pub struct InitState<'info> {
        #[account(mut)]
        pub payer: Signer<'info>,
        #[account(init, payer = payer, seeds = [b"zksl".as_ref(), b"aggregator".as_ref()], bump, space = 8 + AggregatorState::SIZE)]
        pub aggregator_state: Account<'info, AggregatorState>,
        #[account(init, payer = payer, seeds = [b"zksl".as_ref(), b"range".as_ref()], bump, space = 8 + RangeState::SIZE)]
        pub range_state: Account<'info, RangeState>,
        pub system_program: Program<'info, System>,
    }

    #[derive(Accounts)]
    pub struct UnlockValidator<'info> {
        #[account(mut)]
        pub validator: Signer<'info>,
        pub zksl_mint: Account<'info, Mint>,
        #[account(mut, has_one = zksl_mint)]
        pub config: Account<'info, Config>,
        #[account(mut, seeds = [b"zksl".as_ref(), b"validator".as_ref(), validator.key().as_ref()], bump)]
        pub validator_record: Account<'info, ValidatorRecord>,
        /// CHECK: PDA authority for escrow
        #[account(seeds = [b"zksl".as_ref(), b"escrow".as_ref(), validator.key().as_ref()], bump)]
        pub escrow_authority: UncheckedAccount<'info>,
        #[account(mut)]
        pub validator_escrow: Account<'info, TokenAccount>,
        #[account(mut)]
        pub validator_ata: Account<'info, TokenAccount>,
        pub token_program: Program<'info, Token>,
    }

    #[derive(Accounts)]
    #[instruction(artifact_id: [u8;16], proof_hash: [u8;32], seq: u64)]
    pub struct AnchorProof<'info> {
        #[account(mut)]
        pub submitted_by: Signer<'info>,
        #[account(mut)]
        pub config: Account<'info, Config>,
        #[account(mut, seeds = [b"zksl".as_ref(), b"aggregator".as_ref()], bump)]
        pub aggregator_state: Account<'info, AggregatorState>,
        #[account(mut, seeds = [b"zksl".as_ref(), b"range".as_ref()], bump)]
        pub range_state: Account<'info, RangeState>,
        #[account(init, payer = submitted_by, seeds = [b"zksl".as_ref(), b"proof".as_ref(), proof_hash.as_ref(), &seq.to_le_bytes()], bump, space = 8 + ProofRecord::SIZE)]
        pub proof_record: Account<'info, ProofRecord>,
        /// CHECK: instructions sysvar
        #[account(address = sysvar_instructions::ID)]
        pub sysvar_instructions: UncheckedAccount<'info>,
        pub system_program: Program<'info, System>,
    }

    #[derive(Accounts)]
    pub struct Ping<'info> {
        #[account(mut)]
        pub submitted_by: Signer<'info>,
        #[account(mut)]
        pub config: Account<'info, Config>,
        /// CHECK: debug only
        pub aggregator_state: UncheckedAccount<'info>,
        /// CHECK: debug only
        pub range_state: UncheckedAccount<'info>,
        /// CHECK: debug only
        pub proof_record: UncheckedAccount<'info>,
        /// CHECK: instructions sysvar (not required, but accepted)
        pub sysvar_instructions: UncheckedAccount<'info>,
        pub system_program: Program<'info, System>,
    }

    #[derive(Accounts)]
    #[instruction(proof_hash: [u8;32], seq: u64)]
    pub struct EchoAccounts<'info> {
        #[account(mut)]
        pub submitted_by: Signer<'info>,
        #[account(mut)]
        pub config: Account<'info, Config>,
        /// CHECK: PDA, observed only
        #[account(seeds = [b"zksl".as_ref(), b"aggregator".as_ref()], bump)]
        pub aggregator_state: UncheckedAccount<'info>,
        /// CHECK: PDA, observed only
        #[account(seeds = [b"zksl".as_ref(), b"range".as_ref()], bump)]
        pub range_state: UncheckedAccount<'info>,
        /// CHECK: PDA, observed only
        #[account(seeds = [b"zksl".as_ref(), b"proof".as_ref(), proof_hash.as_ref(), &seq.to_le_bytes()], bump)]
        pub proof_record: UncheckedAccount<'info>,
        pub system_program: Program<'info, System>,
    }

    #[event]
    pub struct ConfigUpdated {
        pub aggregator_pubkey: Option<Pubkey>,
        pub paused: Option<bool>,
        pub timestamp: i64,
    }

    #[error_code]
    pub enum ZkError {
        #[msg("Invalid mint")]
        InvalidMint = 6000,
        #[msg("Invalid lock amount")]
        InvalidLockAmount = 6001,
        #[msg("Already registered")]
        AlreadyRegistered = 6002,
        #[msg("Not registered")]
        NotRegistered = 6003,
        #[msg("Escrow mismatch")]
        EscrowMismatch = 6004,
        #[msg("Invalid signature")]
        InvalidSignature = 6005,
        #[msg("Aggregator mismatch")]
        AggregatorMismatch = 6006,
        #[msg("Proof already anchored")]
        ProofAlreadyAnchored = 6007,
        #[msg("Status not active")]
        StatusNotActive = 6008,
        #[msg("Math overflow")]
        MathOverflow = 6009,
        #[msg("Paused")]
        Paused = 6010,
        #[msg("Unauthorized")]
        Unauthorized = 6011,
        #[msg("Non monotonic sequence")]
        NonMonotonicSeq = 6012,
        #[msg("Range overlap or gap")]
        RangeOverlap = 6013,
        #[msg("Clock skew too large")]
        ClockSkew = 6014,
        #[msg("Bad Ed25519 instruction order or count")]
        BadEd25519Order = 6015,
        #[msg("Bad domain separation message")]
        BadDomainSeparation = 6016,
        #[msg("Insufficient compute budget")]
        InsufficientBudget = 6017,
    }

    #[event]
    pub struct ProofAnchored {
        pub artifact_id: [u8; 16],
        pub proof_hash: [u8; 32],
        pub start_slot: u64,
        pub end_slot: u64,
        pub submitted_by: Pubkey,
        pub timestamp: i64,
        pub seq: u64,
        pub ds_hash: [u8; 32],
    }
}

pub use anchor_items::*;
// moved to anchor_items

// moved to anchor_items

// moved to anchor_items

/// Domain separation prefix for the anchor DS message.
const DS_PREFIX: &[u8] = b"zKSL/anchor/v1"; // 14 bytes
/// Maximum slot window allowed per artifact.
const MAX_SLOTS_PER_ARTIFACT: u64 = 2048;
/// Maximum acceptable clock skew in seconds.
const MAX_CLOCK_SKEW_SECS: i64 = 120;
/// Maximum allowed artifact size in bytes (defense in depth; mirrored off-chain).
const MAX_ARTIFACT_SIZE_BYTES: u32 = 512 * 1024;
/// Ed25519 program ID (built-in) used to validate preflight signature instruction.
const ED25519_PROGRAM_ID: Pubkey = pubkey!("Ed25519SigVerify111111111111111111111111111");
/// Compute Budget program ID.
/// Presence is required to ensure callers explicitly allocate sufficient compute units
/// and/or priority fees so proof-anchoring succeeds under congestion (defense in depth).
const COMPUTE_BUDGET_PROGRAM_ID: Pubkey =
    pubkey!("ComputeBudget111111111111111111111111111111");

/// Resolve the allowed aggregator key given the current sequence and activation threshold.
fn allowed_aggregator_key(config: &Account<Config>, seq: u64) -> Pubkey {
    if seq >= config.activation_seq {
        config.next_aggregator_pubkey
    } else {
        config.aggregator_pubkey
    }
}

// moved to anchor_items

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_sizes_match_spec() {
        assert_eq!(Config::SIZE, 168, "Config size must be 168 bytes");
        assert_eq!(
            ValidatorRecord::SIZE,
            136,
            "ValidatorRecord size must be 136 bytes"
        );
        assert_eq!(ProofRecord::SIZE, 262, "ProofRecord size must be 262 bytes");
    }

    #[test]
    fn test_ds_prefix_and_length() {
        assert_eq!(DS_PREFIX.len(), 14, "DS prefix must be 14 bytes");
        // DS length = 14 + 8 (chain_id) + 32 (program_id) + 32 (proof_hash) + 8 (start) + 8 (end) + 8 (seq)
        let expected_len = 14 + 8 + 32 + 32 + 8 + 8 + 8;
        assert_eq!(expected_len, 110, "DS length must be 110 bytes");
    }
}

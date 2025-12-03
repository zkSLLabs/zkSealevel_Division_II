#![allow(clippy::missing_errors_doc)]
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use winter_air::{
    Air, AirContext, Assertion, EvaluationFrame, FieldExtension, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};
use winter_crypto::{hashers::Rp64_256, DefaultRandomCoin, MerkleTree};
use winter_math::{fields::f64::BaseElement as Felt, FieldElement, StarkField, ToElements};
use winter_prover::{
    matrix::ColMatrix, DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde,
    Proof, Prover, StarkDomain, TracePolyTable, TraceTable,
};
use winter_verifier::{verify, AcceptableOptions, VerifierError};

const TWO_32: u64 = 4294967296;
const RPO_ALPHA: u64 = 7;
const STATE_WIDTH: usize = 12;
const NUM_ROUNDS: usize = 7;
const ROUNDS_PER_WITNESS: usize = NUM_ROUNDS + 1; // 7 hash rounds + 1 transition row

#[rustfmt::skip]
const MDS: [[u64; 12]; 12] = [
    [7, 23, 8, 26, 13, 10, 9, 4, 5, 2, 3, 1],
    [1, 7, 23, 8, 26, 13, 10, 9, 4, 5, 2, 3],
    [3, 1, 7, 23, 8, 26, 13, 10, 9, 4, 5, 2],
    [2, 3, 1, 7, 23, 8, 26, 13, 10, 9, 4, 5],
    [5, 2, 3, 1, 7, 23, 8, 26, 13, 10, 9, 4],
    [4, 5, 2, 3, 1, 7, 23, 8, 26, 13, 10, 9],
    [9, 4, 5, 2, 3, 1, 7, 23, 8, 26, 13, 10],
    [10, 9, 4, 5, 2, 3, 1, 7, 23, 8, 26, 13],
    [13, 10, 9, 4, 5, 2, 3, 1, 7, 23, 8, 26],
    [26, 13, 10, 9, 4, 5, 2, 3, 1, 7, 23, 8],
    [8, 26, 13, 10, 9, 4, 5, 2, 3, 1, 7, 23],
    [23, 8, 26, 13, 10, 9, 4, 5, 2, 3, 1, 7],
];

#[rustfmt::skip]
const ARK: [[u64; 12]; NUM_ROUNDS] = [
    [0x88c21a6d05a84b28, 0x548196cb68458a88, 0x3e8acfe0c6e89015, 0x95d8d79dc0e5a5a2,
     0x8e6a0fd8c5d0e9eb, 0x82c0a5f37f8e62b8, 0x4e9f17f27c4a3b5c, 0x6b5e6e7a8f6d5a4c,
     0x2c3e5f6a7b8c9d0e, 0x1f2e3d4c5b6a7988, 0x8796a5b4c3d2e1f0, 0xf0e1d2c3b4a59687],
    [0xd16d14d1387ae2fc, 0x6854e56efb8a5819, 0x95176c0e73f14a9e, 0xa687ec279c2e8c8e,
     0xef3e88d6c2b89f6f, 0xb384a6bb7c3e9fa9, 0x7c8e5d4a3b2c1d0e, 0x9f8e7d6c5b4a3928,
     0x1a2b3c4d5e6f7089, 0x89706f5e4d3c2b1a, 0x0f1e2d3c4b5a6978, 0x7869584736251403],
    [0x4a5e3c2d1e0f8796, 0x9687a5b4c3d2e1f0, 0xf0e1d2c3b4a59687, 0x8796a5b4c3d2e1f0,
     0x1f2e3d4c5b6a7988, 0x8897a6b5c4d3e2f1, 0x2d3c4b5a69788796, 0x96877685a49392a1,
     0xa1b2c3d4e5f67890, 0x0f1e2d3c4b5a6978, 0x7869584736251403, 0x0312243546576879],
    [0x5a6b7c8d9e0f1a2b, 0x3c4d5e6f70819283, 0x94a5b6c7d8e9f0a1, 0xb2c3d4e5f6071829,
     0x3a4b5c6d7e8f90a1, 0xb2c3d4e5f6071829, 0x3a4b5c6d7e8f90a1, 0xb2c3d4e5f6071829,
     0x3a4b5c6d7e8f90a1, 0xb2c3d4e5f6071829, 0x3a4b5c6d7e8f90a1, 0xb2c3d4e5f6071829],
    [0x1d2e3f4a5b6c7d8e, 0x9f0a1b2c3d4e5f60, 0x718293a4b5c6d7e8, 0xf90a1b2c3d4e5f60,
     0x718293a4b5c6d7e8, 0xf90a1b2c3d4e5f60, 0x718293a4b5c6d7e8, 0xf90a1b2c3d4e5f60,
     0x718293a4b5c6d7e8, 0xf90a1b2c3d4e5f60, 0x718293a4b5c6d7e8, 0xf90a1b2c3d4e5f60],
    [0x2b3c4d5e6f708192, 0x83940a5b6c7d8e9f, 0x0a1b2c3d4e5f6071, 0x8293a4b5c6d7e8f9,
     0x0a1b2c3d4e5f6071, 0x8293a4b5c6d7e8f9, 0x0a1b2c3d4e5f6071, 0x8293a4b5c6d7e8f9,
     0x0a1b2c3d4e5f6071, 0x8293a4b5c6d7e8f9, 0x0a1b2c3d4e5f6071, 0x8293a4b5c6d7e8f9],
    [0x3e4f5061728394a5, 0xb6c7d8e9f0a1b2c3, 0xd4e5f60718293a4b, 0x5c6d7e8f90a1b2c3,
     0xd4e5f60718293a4b, 0x5c6d7e8f90a1b2c3, 0xd4e5f60718293a4b, 0x5c6d7e8f90a1b2c3,
     0xd4e5f60718293a4b, 0x5c6d7e8f90a1b2c3, 0xd4e5f60718293a4b, 0x5c6d7e8f90a1b2c3],
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicInputs {
    pub start_slot: u64,
    pub end_slot: u64,
    pub initial_state_root: [u8; 32],
    pub final_state_root: [u8; 32],
    pub blockhash: [u8; 32],
}

impl ToElements<Felt> for PublicInputs {
    fn to_elements(&self) -> Vec<Felt> {
        let mut res = Vec::with_capacity(14);
        res.push(Felt::new(self.start_slot));
        res.push(Felt::new(self.end_slot));
        res.extend(bytes_to_felts(&self.initial_state_root));
        res.extend(bytes_to_felts(&self.final_state_root));
        res.extend(bytes_to_felts(&self.blockhash));
        res
    }
}

#[derive(Serialize, Deserialize)]
pub struct StarkProofEnvelope {
    pub proof: String,
    pub public_inputs: PublicInputs,
}

// NUM_COLS without explicit next_root columns (Option A)
const NUM_COLS: usize = 157; // 161 - 4

pub fn build_trace(
    witnesses: &[crate::witness::SlotWitness],
    pub_inputs: &PublicInputs,
) -> Result<TraceTable<Felt>> {
    if witnesses.is_empty() {
        anyhow::bail!("Witnesses cannot be empty");
    }
    if witnesses[0].slot != pub_inputs.start_slot {
        anyhow::bail!("Start slot mismatch");
    }
    if witnesses.last().unwrap().slot != pub_inputs.end_slot {
        anyhow::bail!("End slot mismatch");
    }
    for i in 1..witnesses.len() {
        if witnesses[i].slot <= witnesses[i - 1].slot {
            anyhow::bail!("Slots must be strictly increasing");
        }
    }

    let trace_len = witnesses.len() * ROUNDS_PER_WITNESS;
    let mut trace = vec![Vec::with_capacity(trace_len); NUM_COLS];

    let blockhash_felts = bytes_to_felts(&pub_inputs.blockhash);
    let mut prev_root = bytes_to_felts(&pub_inputs.initial_state_root);

    for (witness_idx, w) in witnesses.iter().enumerate() {
        let is_last_witness = witness_idx == witnesses.len() - 1;

        // Compute stake limbs and delta (used for constraints only)
        let total_stake_u128: u128 = w
            .vote_accounts
            .iter()
            .map(|v| v.activated_stake as u128)
            .sum();
        if total_stake_u128 > u64::MAX as u128 {
            anyhow::bail!("Stake overflow at slot {}", w.slot);
        }
        let total_stake = total_stake_u128 as u64;
        let next_stake = if is_last_witness {
            total_stake
        } else {
            let s: u128 = witnesses[witness_idx + 1]
                .vote_accounts
                .iter()
                .map(|v| v.activated_stake as u128)
                .sum();
            if s > u64::MAX as u128 {
                anyhow::bail!("Stake overflow at next slot {}", witnesses[witness_idx + 1].slot);
            }
            s as u64
        };
        let (delta_abs, sign) = if next_stake >= total_stake {
            (next_stake - total_stake, 0u64)
        } else {
            (total_stake - next_stake, 1u64)
        };
        let stake_lo = total_stake & 0xFFFF_FFFF;
        let stake_hi = total_stake >> 32;
        let delta_lo = delta_abs & 0xFFFF_FFFF;
        let delta_hi = delta_abs >> 32;
        let slot_delta = if is_last_witness { 0 } else { witnesses[witness_idx + 1].slot - w.slot };
        if slot_delta >= 256 {
            anyhow::bail!("Slot delta too large");
        }

        let mut hash_state = [Felt::ZERO; STATE_WIDTH];

        for round in 0..ROUNDS_PER_WITNESS {
            // round counter
            trace[12].push(Felt::new(round as u64));

            if round < NUM_ROUNDS {
                if round == 0 {
                    // Option A: initialize from prev_root only; do not inject message.
                    for i in 0..4 {
                        hash_state[i] = prev_root[i];
                    }
                    for i in 4..STATE_WIDTH {
                        hash_state[i] = Felt::ZERO;
                    }
                }
                // one RPO-like round: (state + ARK)^ALPHA then MDS
                let mut after_sbox = [Felt::ZERO; STATE_WIDTH];
                for i in 0..STATE_WIDTH {
                    let ark = Felt::new(ARK[round][i]);
                    after_sbox[i] = (hash_state[i] + ark).exp(Felt::from(RPO_ALPHA));
                }
                let mut next_state = [Felt::ZERO; STATE_WIDTH];
                for i in 0..STATE_WIDTH {
                    for j in 0..STATE_WIDTH {
                        next_state[i] += after_sbox[j] * Felt::new(MDS[i][j]);
                    }
                }
                hash_state = next_state;
            }

            // push hash_state lanes 0..11
            for i in 0..STATE_WIDTH {
                trace[i].push(hash_state[i]);
            }
            // slot
            trace[13].push(Felt::new(w.slot));
            // slot delta bits
            for b in 0..8 {
                trace[14 + b].push(Felt::new((slot_delta >> b) & 1));
            }
            // arithmetic lanes
            trace[22].push(Felt::new(stake_lo));
            trace[23].push(Felt::new(stake_hi));
            trace[24].push(Felt::new(delta_lo));
            trace[25].push(Felt::new(delta_hi));
            let aux = if sign == 0 { (stake_lo + delta_lo) / TWO_32 } else { if stake_lo < delta_lo { 1 } else { 0 } };
            trace[26].push(Felt::new(aux));
            trace[27].push(Felt::new(sign));
            // bit decompositions for limbs
            push_bits(&mut trace, 28, stake_lo, 32);
            push_bits(&mut trace, 60, stake_hi, 32);
            push_bits(&mut trace, 92, delta_lo, 32);
            push_bits(&mut trace, 124, delta_hi, 32);
            // transition flag
            let is_transition = if round == ROUNDS_PER_WITNESS - 1 { 1u64 } else { 0u64 };
            trace[156].push(Felt::new(is_transition)); // last column index (0-based): 156
        }

        // carry root forward
        prev_root = [hash_state[0], hash_state[1], hash_state[2], hash_state[3]];
    }

    Ok(TraceTable::init(trace))
}

#[derive(Clone)]
pub struct SolanaStateAir {
    context: AirContext<Felt>,
    pub_inputs: PublicInputs,
}

impl Air for SolanaStateAir {
    type BaseField = Felt;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let mut degrees = Vec::new();
        // 0..11: hash constraints
        for _ in 0..12 {
            degrees.push(TransitionConstraintDegree::new(7));
        }
        // 12: round counter
        degrees.push(TransitionConstraintDegree::new(1));
        // 13: slot transition
        degrees.push(TransitionConstraintDegree::new(2));
        // 14..21: slot bits
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(2));
        }
        // 22..27: arithmetic
        for _ in 0..6 {
            degrees.push(TransitionConstraintDegree::new(2));
        }
        // 28..155: bit validity
        for _ in 0..128 {
            degrees.push(TransitionConstraintDegree::new(2));
        }
        // 156: transition_flag constraints will be added inline
        // add a few slots for binary and gating constraints
        degrees.push(TransitionConstraintDegree::new(2)); // transition_flag binary
        degrees.push(TransitionConstraintDegree::new(1)); // round gating
        // plus extra for intra-witness constancy (slot/stake const on hash rows)
        degrees.push(TransitionConstraintDegree::new(1));
        degrees.push(TransitionConstraintDegree::new(1));
        degrees.push(TransitionConstraintDegree::new(1));

        let options = options.with_field_extension(FieldExtension::Quadratic);
        let context = AirContext::new(trace_info, degrees, 10, options);
        Self { context, pub_inputs }
    }

    fn context(&self) -> &AirContext<Felt> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Felt>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let next = frame.next();
        let one = E::ONE;
        let two = E::from(2u32);
        let seven = E::from(7u32);

        let round = cur[12];
        let t = cur[156]; // transition_flag
        let is_hash_round = one - t;
        let is_transition_round = t;

        let mut idx = 0;
        // 1) Hash constraints on hash rows
        let round_idx = (round.as_int() as usize) % NUM_ROUNDS;
        let mut sbox = [E::ZERO; STATE_WIDTH];
        for j in 0..STATE_WIDTH {
            let ark = E::from(ARK[round_idx][j]);
            sbox[j] = (cur[j] + ark).exp(E::PositiveInteger::from(RPO_ALPHA));
        }
        for i in 0..STATE_WIDTH {
            let mut mds_res = E::ZERO;
            for j in 0..STATE_WIDTH {
                mds_res += sbox[j] * E::from(MDS[i][j]);
            }
            result[idx] = (next[i] - mds_res) * is_hash_round;
            idx += 1;
        }

        // 2) Round counter: next = round+1, or reset to 0 on transition (8-cycle)
        let next_round_expected = (round + one) - (t * E::from(8u32));
        result[idx] = next[12] - next_round_expected;
        idx += 1;

        // 3) Slot transition only on transition rows (recompose from bits)
        let mut slot_delta = E::ZERO;
        let mut p2 = E::ONE;
        for i in 0..8 {
            slot_delta += cur[14 + i] * p2;
            p2 *= two;
        }
        result[idx] = (next[13] - (cur[13] + slot_delta)) * is_transition_round;
        idx += 1;

        // 4) Slot bits binary
        for i in 0..8 {
            let bit = cur[14 + i];
            result[idx] = bit * (bit - one);
            idx += 1;
        }

        // 5) Arithmetic lane on transition rows (stake +/- delta with aux)
        let stake_lo = cur[22];
        let stake_hi = cur[23];
        let delta_lo = cur[24];
        let delta_hi = cur[25];
        let aux = cur[26];
        let sign = cur[27];
        let stake_lo_next = next[22];
        let stake_hi_next = next[23];
        let is_add = one - sign;
        let is_sub = sign;
        let two32 = E::from(TWO_32);
        let add_lo = (stake_lo + delta_lo) - (stake_lo_next + aux * two32);
        let sub_lo = (stake_lo - delta_lo + aux * two32) - stake_lo_next;
        result[idx] = (is_add * add_lo + is_sub * sub_lo) * is_transition_round;
        idx += 1;
        let add_hi = (stake_hi + delta_hi + aux) - stake_hi_next;
        let sub_hi = (stake_hi - delta_hi - aux) - stake_hi_next;
        result[idx] = (is_add * add_hi + is_sub * sub_hi) * is_transition_round;
        idx += 1;
        // aux binary
        result[idx] = aux * (aux - one);
        idx += 1;
        // sign binary
        result[idx] = sign * (sign - one);
        idx += 1;
        // delta const on hash rows
        result[idx] = (next[24] - delta_lo) * is_hash_round;
        idx += 1;
        result[idx] = (next[25] - delta_hi) * is_hash_round;
        idx += 1;

        // 6) Bit validity 0/1
        for i in 0..128 {
            let bit = cur[28 + i];
            result[idx] = bit * (bit - one);
            idx += 1;
        }

        // 7) Bit recomposition for 4 limbs
        for (limb_col, bit_start) in [(22usize, 28usize), (23, 60), (24, 92), (25, 124)] {
            let mut reconstructed = E::ZERO;
            let mut p = E::ONE;
            for i in 0..32 {
                reconstructed += cur[bit_start + i] * p;
                p *= two;
            }
            result[idx] = cur[limb_col] - reconstructed;
            idx += 1;
        }

        // 8) Root carry at transition: next state lanes == current state lanes
        for i in 0..4 {
            result[idx] = (next[i] - cur[i]) * is_transition_round;
            idx += 1;
        }

        // 9) Intra-witness constancy on hash rows: slot and stake are constant
        result[idx] = (next[13] - cur[13]) * is_hash_round;
        idx += 1;
        result[idx] = (next[22] - cur[22]) * is_hash_round;
        idx += 1;
        result[idx] = (next[23] - cur[23]) * is_hash_round;
        idx += 1;

        // 10) transition_flag binary and round gating (only when round==7)
        result[idx] = t * (t - one);
        idx += 1;
        result[idx] = (round - seven) * t;
        idx += 1;
    }

    fn get_assertions(&self) -> Vec<Assertion<Felt>> {
        let last_step = self.trace_length() - 1;
        let mut assertions = Vec::new();
        // Bind endpoints: slots and roots
        assertions.push(Assertion::single(13, 0, Felt::new(self.pub_inputs.start_slot)));
        assertions.push(Assertion::single(13, last_step, Felt::new(self.pub_inputs.end_slot)));
        // Initial root lanes 0..3
        let init = bytes_to_felts(&self.pub_inputs.initial_state_root);
        for i in 0..4 {
            assertions.push(Assertion::single(i, 0, init[i]));
        }
        // Final root lanes 0..3
        let fin = bytes_to_felts(&self.pub_inputs.final_state_root);
        for i in 0..4 {
            assertions.push(Assertion::single(i, last_step, fin[i]));
        }
        assertions
    }
}

struct SolanaProver {
    options: ProofOptions,
    pub_inputs: PublicInputs,
}

impl Prover for SolanaProver {
    type BaseField = Felt;
    type Air = SolanaStateAir;
    type Trace = TraceTable<Felt>;
    type HashFn = Rp64_256;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Felt>> =
        DefaultTraceLde<E, Self::HashFn, MerkleTree<Self::HashFn>>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Felt>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;
    type ConstraintCommitment<E: FieldElement<BaseField = Felt>> =
        DefaultConstraintCommitment<E, Self::HashFn, MerkleTree<Self::HashFn>>;
    type VC = MerkleTree<Self::HashFn>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> PublicInputs {
        self.pub_inputs.clone()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Felt>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Felt>,
        domain: &StarkDomain<Felt>,
        partition_options: winter_prover::PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_options)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Felt>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<winter_air::AuxRandElements<E>>,
        composition_coefficients: winter_air::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

pub fn generate_proof(
    pub_inputs: PublicInputs,
    witnesses: &[crate::witness::SlotWitness],
) -> Result<StarkProofEnvelope> {
    let trace = build_trace(witnesses, &pub_inputs)?;
    let options = ProofOptions::new(64, 16, 20, FieldExtension::Quadratic, 8, 31);
    let prover = SolanaProver { options, pub_inputs: pub_inputs.clone() };
    let proof = prover
        .prove(trace)
        .map_err(|e| anyhow::anyhow!("Proof generation failed: {}", e))?;
    Ok(StarkProofEnvelope {
        proof: B64.encode(proof.to_bytes()),
        public_inputs: pub_inputs,
    })
}

pub fn verify_proof(envelope: StarkProofEnvelope) -> Result<bool> {
    let proof_bytes = B64
        .decode(envelope.proof)
        .context("Failed to decode base64 proof")?;
    let proof = Proof::from_bytes(&proof_bytes).context("Failed to deserialize proof")?;
    let options = ProofOptions::new(64, 16, 20, FieldExtension::Quadratic, 8, 31);
    let acceptable = AcceptableOptions::Option(options);
    match verify::<SolanaStateAir, Rp64_256, DefaultRandomCoin<Rp64_256>, MerkleTree<Rp64_256>>(
        proof,
        envelope.public_inputs,
        &acceptable,
    ) {
        Ok(_) => Ok(true),
        Err(VerifierError::ProofVerificationError(_)) => Ok(false),
        Err(e) => Err(anyhow::anyhow!("Verification system error: {}", e)),
    }
}

fn bytes_to_felts(bytes: &[u8; 32]) -> Vec<Felt> {
    (0..4)
        .map(|i| {
            let start = i * 8;
            let chunk = &bytes[start..start + 8];
            Felt::new(u64::from_le_bytes(chunk.try_into().unwrap()))
        })
        .collect()
}


use std::marker::PhantomData;

use crate::{
  errors::{ProofVerifyError, R1CSError},
  ComputationCommitment, ComputationDecommitment, InputsAssignment, Instance, SNARKGens,
  VarsAssignment, SNARK as SpartanSNARK,
};
use ark_crypto_primitives::snark::*;
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_relations::r1cs::{
  ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, Matrix, OptimizationGoal,
  SynthesisMode,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{CryptoRng, RngCore};
use merlin::Transcript;
use std::iter;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SpartanProof<G: CurveGroup>(SpartanSNARK<G>);

impl<G: CurveGroup> SpartanProof<G> {
  pub fn verify(
    &self,
    comm: &ComputationCommitment<G>,
    input: &InputsAssignment<G::ScalarField>,
    gens: &SNARKGens<G>,
  ) -> Result<(), ProofVerifyError> {
    let mut transcript = Transcript::new(b"Spartan");
    self.0.verify(comm, input, &mut transcript, gens)
  }
}

pub struct Spartan<G: CurveGroup> {
  _p: PhantomData<G>,
}

impl<G: CurveGroup> Spartan<G> {
  fn matrix_to_triplets(
    matrix: Matrix<G::ScalarField>,
    num_vars: usize,
    num_inputs: usize,
  ) -> Vec<(usize, usize, G::ScalarField)> {
    // A ark_relations::r1cs::Matrix is a constraint matrix, represented as a Vec of constraints.
    // A constraint is a vec of pairs, containing the value of the cell and
    // the index of the cell in the row.
    // Constraints columns are ordered as 1, i0, i1, ..., w0, w1, ...
    //
    // A ark-spartan Matrix is a Vec of triplets containing (row, column, value)
    // of each chell.
    // Columns are ordered as w0, w1, ..., 1, i0, i1, ...
    //
    // To convert, we take the last `num_vars` columns and move them to the front
    let num_cols = num_vars + num_inputs + 1;
    matrix
      .into_iter()
      .enumerate()
      .flat_map(|(r, constraint)| {
        constraint.into_iter().map(move |(coeff, idx)| {
          let idx = (idx + num_vars) % num_cols; // Move columns
          (r, idx, coeff)
        })
      })
      .collect()
  }
}

impl<G: CurveGroup> SNARK<G::ScalarField> for Spartan<G> {
  type ProvingKey = (
    ComputationCommitment<G>,
    ComputationDecommitment<G::ScalarField>,
  );
  type VerifyingKey = ComputationCommitment<G>;
  type Proof = SpartanProof<G>;
  type ProcessedVerifyingKey = ();
  type Error = R1CSError;

  fn circuit_specific_setup<C: ConstraintSynthesizer<G::ScalarField>, R: RngCore>(
    _circuit: C,
    _rng: &mut R,
  ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error> {
    panic!("Spartan uses a universal setup. Use `UniversalSetupSNARK::universal_setup` instead");
  }

  fn prove<C: ConstraintSynthesizer<G::ScalarField>, R: RngCore>(
    (comm, decomm): &Self::ProvingKey,
    circuit: C,
    _rng: &mut R,
  ) -> Result<Self::Proof, Self::Error> {
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Prove {
      construct_matrices: true,
    });
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    assert!(cs.is_satisfied().unwrap_or(true));
    let cb = ComputationBound::from_cs(&cs);
    let gens = SNARKGens::<G>::new(cb.num_cons, cb.num_vars, cb.num_inputs, cb.num_non_zero);
    let matrices = cs.to_matrices().unwrap();
    let inst = Instance::new(
      cb.num_cons,
      cb.num_vars,
      cb.num_inputs,
      &Self::matrix_to_triplets(matrices.a, cb.num_vars, cb.num_inputs),
      &Self::matrix_to_triplets(matrices.b, cb.num_vars, cb.num_inputs),
      &Self::matrix_to_triplets(matrices.c, cb.num_vars, cb.num_inputs),
    )?;
    let assignment_vars = VarsAssignment::new(&cs.borrow().unwrap().witness_assignment).unwrap();
    let assignment_inputs =
      InputsAssignment::new(&cs.borrow().unwrap().instance_assignment[1..]).unwrap();

    let mut prover_transcript = Transcript::new(b"Spartan");
    Ok(SpartanProof(SpartanSNARK::prove(
      &inst,
      comm,
      decomm,
      assignment_vars,
      &assignment_inputs,
      &gens,
      &mut prover_transcript,
    )))
  }

  fn process_vk(
    _circuit_vk: &Self::VerifyingKey,
  ) -> Result<Self::ProcessedVerifyingKey, Self::Error> {
    unimplemented!();
  }

  fn verify_with_processed_vk(
    _circuit_pvk: &Self::ProcessedVerifyingKey,
    _x: &[G::ScalarField],
    _proof: &Self::Proof,
  ) -> Result<bool, Self::Error> {
    unimplemented!();
  }
}

#[derive(Clone, Default, Debug)]
pub struct ComputationBound {
  num_cons: usize,
  num_vars: usize,
  num_inputs: usize,
  num_non_zero: usize,
}

impl ComputationBound {
  fn from_cs<F: Field>(cs: &ConstraintSystemRef<F>) -> Self {
    let matrices = cs.to_matrices().unwrap();
    let num_cons = cs.num_constraints();
    let num_vars = cs.num_witness_variables();
    let num_inputs = cs.num_instance_variables() - 1;
    let num_non_zero = iter::once(matrices.a_num_non_zero)
      .chain([matrices.b_num_non_zero])
      .chain([matrices.a_num_non_zero])
      .max()
      .unwrap();
    ComputationBound {
      num_cons,
      num_vars,
      num_inputs,
      num_non_zero,
    }
  }
}

impl<G: CurveGroup> Spartan<G> {
  pub fn generate_computation_bound<C: ConstraintSynthesizer<G::ScalarField>>(
    circuit: C,
  ) -> ComputationBound {
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    ComputationBound::from_cs(&cs)
  }
}
impl<G: CurveGroup> UniversalSetupSNARK<G::ScalarField> for Spartan<G> {
  type ComputationBound = ComputationBound;
  type PublicParameters = SNARKGens<G>;

  fn universal_setup<R>(
    compute_bound: &Self::ComputationBound,
    _rng: &mut R,
  ) -> Result<Self::PublicParameters, Self::Error>
  where
    R: RngCore + CryptoRng,
  {
    Ok(SNARKGens::<G>::new(
      compute_bound.num_cons,
      compute_bound.num_vars,
      compute_bound.num_inputs,
      compute_bound.num_non_zero,
    ))
  }

  fn index<C, R>(
    pp: &Self::PublicParameters,
    circuit: C,
    _rng: &mut R,
  ) -> Result<
    (Self::ProvingKey, Self::VerifyingKey),
    UniversalSetupIndexError<Self::ComputationBound, Self::Error>,
  >
  where
    C: ConstraintSynthesizer<G::ScalarField>,
    R: RngCore + CryptoRng,
  {
    // Create constraint system
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    assert!(cs.is_satisfied().unwrap_or(true));
    // Create parameters
    let cb = ComputationBound::from_cs(&cs);
    let matrices = cs.to_matrices().unwrap();
    let inst = Instance::new(
      cb.num_cons,
      cb.num_vars,
      cb.num_inputs,
      &Self::matrix_to_triplets(matrices.a, cb.num_vars, cb.num_inputs),
      &Self::matrix_to_triplets(matrices.b, cb.num_vars, cb.num_inputs),
      &Self::matrix_to_triplets(matrices.c, cb.num_vars, cb.num_inputs),
    )
    .map_err(UniversalSetupIndexError::Other)?;
    // Index
    let (comm, decomm) = SpartanSNARK::encode(&inst, pp);
    Ok(((comm.clone(), decomm), comm))
  }
}

use ark_ec::CurveGroup;

use crate::{snark::Spartan, InputsAssignment};
use ark_crypto_primitives::snark::{UniversalSetupSNARK, SNARK};
use ark_ff::Field;
use ark_relations::{
  lc,
  r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::{
  rand::{RngCore, SeedableRng},
  test_rng, UniformRand,
};
use std::iter;

trait TestCircuit<G: CurveGroup> {
  fn test_prove_and_verify(n_iters: usize);
}

// CubicEx example
#[derive(Clone)]
struct CubicExCircuit<F: Field> {
  z_0: Option<F>,
  z_1: Option<F>,
  z_2: Option<F>,
  z_3: Option<F>,
  i0: F,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for CubicExCircuit<ConstraintF> {
  fn generate_constraints(
    self,
    cs: ConstraintSystemRef<ConstraintF>,
  ) -> Result<(), SynthesisError> {
    let z_0 = cs.new_witness_variable(|| self.z_0.ok_or(SynthesisError::AssignmentMissing))?;
    let z_1 = cs.new_witness_variable(|| self.z_1.ok_or(SynthesisError::AssignmentMissing))?;
    let z_2 = cs.new_witness_variable(|| self.z_2.ok_or(SynthesisError::AssignmentMissing))?;
    let z_3 = cs.new_witness_variable(|| self.z_3.ok_or(SynthesisError::AssignmentMissing))?;
    let io = cs.new_input_variable(|| Ok(self.i0))?;
    let one = ark_relations::r1cs::Variable::One;
    // constraint 0 entries in (A,B,C)
    // constraint 0 is Z0 * Z0 - Z1 = 0.
    cs.enforce_constraint(lc!() + z_0, lc!() + z_0, lc!() + z_1)?;
    // constraint 1 entries in (A,B,C)
    // constraint 1 is Z1 * Z0 - Z2 = 0.
    cs.enforce_constraint(lc!() + z_1, lc!() + z_0, lc!() + z_2)?;
    // constraint 2 entries in (A,B,C)
    // constraint 2 is (Z2 + Z0) * 1 - Z3 = 0.
    cs.enforce_constraint(lc!() + z_2 + z_0, lc!() + one, lc!() + z_3)?;
    // constraint 3 entries in (A,B,C)
    // constraint 3 is (Z3 + 5) * 1 - I0 = 0.
    cs.enforce_constraint(
      lc!() + z_3 + (ConstraintF::from(5u32), one),
      lc!() + one,
      lc!() + io,
    )?;
    Ok(())
  }
}

impl<G: CurveGroup> TestCircuit<G> for CubicExCircuit<G::ScalarField> {
  fn test_prove_and_verify(_foo: usize) {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let z0 = G::ScalarField::rand(&mut rng);
    let z1 = z0 * z0; // constraint 0
    let z2 = z1 * z0; // constraint 1
    let z3 = z2 + z0; // constraint 2
    let i0 = z3 + G::ScalarField::from(5u32); // constraint 3
    let circuit = Self {
      z_0: Some(z0),
      z_1: Some(z1),
      z_2: Some(z2),
      z_3: Some(z3),
      i0,
    };
    let cb = Spartan::<G>::generate_computation_bound(circuit.clone());
    let gens = Spartan::universal_setup(&cb, &mut rng).unwrap();
    let (pk, vk) =
      Spartan::index(&gens, circuit.clone(), &mut rng).unwrap_or_else(|_| panic!("Error indexing"));
    let proof = Spartan::<G>::prove(&pk, circuit, &mut rng).unwrap();
    assert!(proof
      .verify(&vk, &InputsAssignment::new(&[i0]).unwrap(), &gens)
      .is_ok());
  }
}

// Circuit with only witnesses
#[derive(Clone)]
struct WitnessAllocCircuit<F: Field> {
  vals: Option<Vec<F>>,
  len: usize,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for WitnessAllocCircuit<ConstraintF> {
  fn generate_constraints(
    self,
    cs: ConstraintSystemRef<ConstraintF>,
  ) -> Result<(), SynthesisError> {
    let (sq, vals): (_, Vec<Option<ConstraintF>>) = if let Some(vals) = self.vals {
      assert_eq!(self.len, vals.len());
      (
        Some(vals[0] * vals[0]),
        vals.into_iter().map(|a| Some(a)).collect(),
      )
    } else {
      (None, iter::repeat(None).take(self.len).collect())
    };
    let vars = vals
      .iter()
      .map(|v| cs.new_witness_variable(|| v.ok_or(SynthesisError::AssignmentMissing)))
      .collect::<Result<Vec<_>, _>>()?;
    // Need at least 2 constraints for Spartan (probably a bug)
    let sq_var = cs.new_witness_variable(|| sq.ok_or(SynthesisError::AssignmentMissing))?;
    cs.enforce_constraint(lc!() + vars[0], lc!() + vars[0], lc!() + sq_var)?;
    cs.enforce_constraint(lc!() + vars[0], lc!() + vars[0], lc!() + sq_var)?;
    Ok(())
  }
}

impl<G: CurveGroup> TestCircuit<G> for WitnessAllocCircuit<G::ScalarField> {
  fn test_prove_and_verify(n_allocs: usize) {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let vals = (0..n_allocs)
      .map(|_| G::ScalarField::rand(&mut rng))
      .collect::<Vec<_>>();
    let len = vals.len();
    let circuit = Self {
      vals: Some(vals),
      len,
    };
    let cb = Spartan::<G>::generate_computation_bound(circuit.clone());
    let gens = Spartan::universal_setup(&cb, &mut rng).unwrap();
    let (pk, vk) =
      Spartan::index(&gens, circuit.clone(), &mut rng).unwrap_or_else(|_| panic!("Error indexing"));
    let proof = Spartan::<G>::prove(&pk, circuit, &mut rng).unwrap();
    assert!(proof
      .verify(&vk, &InputsAssignment::new(&[]).unwrap(), &gens)
      .is_ok());
  }
}

// Circuit with only inputs
#[derive(Clone)]
struct InputAllocCircuit<F: Field> {
  vals: Vec<F>,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for InputAllocCircuit<ConstraintF> {
  fn generate_constraints(
    self,
    cs: ConstraintSystemRef<ConstraintF>,
  ) -> Result<(), SynthesisError> {
    let sq = self.vals[0] * self.vals[0];
    let vars = self
      .vals
      .into_iter()
      .map(|v| cs.new_input_variable(|| Ok(v)))
      .collect::<Result<Vec<_>, _>>()?;
    // Need at least 2 constraints for Spartan (probably a bug)
    let sq_var = cs.new_witness_variable(|| Ok(sq))?;
    cs.enforce_constraint(lc!() + vars[0], lc!() + vars[0], lc!() + sq_var)?;
    cs.enforce_constraint(lc!() + vars[0], lc!() + vars[0], lc!() + sq_var)?;
    Ok(())
  }
}

impl<G: CurveGroup> TestCircuit<G> for InputAllocCircuit<G::ScalarField> {
  fn test_prove_and_verify(n_allocs: usize) {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let vals = (0..n_allocs)
      .map(|_| G::ScalarField::rand(&mut rng))
      .collect::<Vec<_>>();
    let circuit = Self { vals: vals.clone() };
    let cb = Spartan::<G>::generate_computation_bound(circuit.clone());
    let gens = Spartan::universal_setup(&cb, &mut rng).unwrap();
    let (pk, vk) =
      Spartan::index(&gens, circuit.clone(), &mut rng).unwrap_or_else(|_| panic!("Error indexing"));
    let proof = Spartan::<G>::prove(&pk, circuit, &mut rng).unwrap();
    assert!(proof
      .verify(&vk, &InputsAssignment::new(&vals).unwrap(), &gens)
      .is_ok());
  }
}

// Test taken from ark_groth16
#[derive(Clone)]
struct MySillyCircuit<F: Field> {
  a: Option<F>,
  b: Option<F>,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MySillyCircuit<ConstraintF> {
  fn generate_constraints(
    self,
    cs: ConstraintSystemRef<ConstraintF>,
  ) -> Result<(), SynthesisError> {
    let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
    let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
    let c = cs.new_input_variable(|| {
      let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
      let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

      a *= &b;
      Ok(a)
    })?;

    cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
    cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
    cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
    cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
    cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
    cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;

    Ok(())
  }
}

impl<G: CurveGroup> TestCircuit<G> for MySillyCircuit<G::ScalarField> {
  fn test_prove_and_verify(n_iters: usize) {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    for _ in 0..n_iters {
      let a = G::ScalarField::rand(&mut rng);
      let b = G::ScalarField::rand(&mut rng);
      let mut c = a;
      c *= b;

      let circuit = Self {
        a: Some(a),
        b: Some(b),
      };
      let cb = Spartan::<G>::generate_computation_bound(circuit.clone());
      let gens = Spartan::universal_setup(&cb, &mut rng).unwrap();
      let (pk, vk) = Spartan::index(&gens, circuit.clone(), &mut rng)
        .unwrap_or_else(|_| panic!("Error indexing"));
      let proof = Spartan::<G>::prove(&pk, circuit, &mut rng).unwrap();
      assert!(proof
        .verify(&vk, &InputsAssignment::new(&[c]).unwrap(), &gens)
        .is_ok());
      assert!(!proof
        .verify(&vk, &InputsAssignment::new(&[a]).unwrap(), &gens)
        .is_ok());
    }
  }
}

mod bls12_381 {
  use super::*;
  use ark_bls12_381::G1Projective;

  #[test]
  fn prove_and_verify() {
    <MySillyCircuit<_> as TestCircuit<G1Projective>>::test_prove_and_verify(1);
    <WitnessAllocCircuit<_> as TestCircuit<G1Projective>>::test_prove_and_verify(5);
    <InputAllocCircuit<_> as TestCircuit<G1Projective>>::test_prove_and_verify(5);
    <CubicExCircuit<_> as TestCircuit<G1Projective>>::test_prove_and_verify(0);
  }
}

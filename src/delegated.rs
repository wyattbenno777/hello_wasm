use std::marker::PhantomData;

use ff::Field;
use ff::{PrimeField, PrimeFieldBits};
use nova_snark::frontend::{AllocatedBit, LinearCombination};
use nova_snark::traits::{RO2ConstantsCircuit, ROCircuitTrait};
use nova_snark::{
    frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError},
    traits::{circuit::StepCircuit, Engine},
};

/// Size of the address in bytes
const ADDRESS_SIZE: usize = 10;
/// Number of public addresses in the circuit
const NUM_ADDRESSES: usize = 5;
/// Number of bits in the challenge
const NUM_CHALLENGE_BITS: usize = 250;
/// Public list of addresses
///
/// # Note
///
/// * The `*` operator dereferences the byte slice literal into an array.
/// * We pad addresses with zeros since we need a fixed length of the addresses in the circuit
const ADDRESSES: [[u8; ADDRESS_SIZE]; NUM_ADDRESSES] = [
    *b"192.168.01",
    *b"10.0.0.1\0\0",
    *b"127.0.0.1\0",
    *b"8.8.8.8\0\0\0",
    *b"172.16.0.1",
];

/// A circuit that enforces an address is not in a list of public addresses
#[derive(Clone, Debug)]
pub struct ExclusionCircuit<E> {
    address: [u8; ADDRESS_SIZE],
    _engine: PhantomData<E>,
}

impl<E> StepCircuit<E::Scalar> for ExclusionCircuit<E>
where
    E: Engine,
{
    fn arity(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<E::Scalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<E::Scalar>],
    ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
        let (address, pub_addresses) = self.alloc_witness(cs.namespace(|| "alloc witness"))?;

        // Get challenge & use it to hash addresses
        let mut ro = E::RO2Circuit::new(RO2ConstantsCircuit::<E>::default());
        address.absorb_in_ro::<E>(&mut ro);
        let r_bits = ro.squeeze(cs.namespace(|| "squeeze"), NUM_CHALLENGE_BITS)?;
        let r = le_bits_to_num(cs.namespace(|| "bits to hash"), &r_bits)?;
        let basis = pow_vec::<_, _, ADDRESS_SIZE>(cs.namespace(|| "pow_vec"), &r)?;
        let address_hash = address.hash(cs.namespace(|| "address_hash"), &basis)?;
        let public_hashes = pub_addresses
            .iter()
            .enumerate()
            .map(|(i, pub_address)| {
                pub_address.hash(cs.namespace(|| format!("pub_address_hash_{i}")), &basis)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // --- enforce address_hash != public_hashes[i] for all i ---
        for (i, pub_address_hash) in public_hashes.iter().enumerate() {
            // We know that `a != b` iff `a-b` has an inverse, i.e. that there exists
            // `c` such that `c * (a-b) = 1`.
            let inverse = cs.alloc(
                || format!("q_{i}"),
                || {
                    let a = address_hash
                        .get_value()
                        .ok_or(SynthesisError::AssignmentMissing)?;
                    let b = pub_address_hash
                        .get_value()
                        .ok_or(SynthesisError::AssignmentMissing)?;
                    let inv = (a - b).invert();
                    if inv.is_some().into() {
                        Ok(inv.unwrap())
                    } else {
                        Ok(E::Scalar::ZERO)
                    }
                },
            )?;
            cs.enforce(
                || format!("enforce address_hash != public_hashes[{}]", i),
                |lc| lc + inverse,
                |lc| lc + address_hash.get_variable() - pub_address_hash.get_variable(),
                |lc| lc + CS::one(),
            );
        }
        Ok(z.to_owned())
    }
}

/// Computes the powers of a field element and returns them in a vector
fn pow_vec<CS, F, const SIZE: usize>(
    mut cs: CS,
    r: &AllocatedNum<F>,
) -> Result<[AllocatedNum<F>; SIZE], SynthesisError>
where
    CS: ConstraintSystem<F>,
    F: PrimeField,
{
    let mut result = Vec::with_capacity(SIZE);
    let mut current = AllocatedNum::alloc_infallible(cs.namespace(|| "one"), || F::ONE);
    result.push(current.clone());
    for i in 1..SIZE {
        let next = current.mul(cs.namespace(|| format!("mul_{i}")), r)?;
        result.push(next.clone());
        current = next;
    }
    result
        .try_into()
        .map_err(|_| SynthesisError::UnconstrainedVariable)
}

impl<E> ExclusionCircuit<E>
where
    E: Engine,
{
    /// Creates an instance of [`ExclusionCircuit`]
    pub fn new(address: [u8; ADDRESS_SIZE]) -> Self {
        Self {
            address,
            _engine: PhantomData,
        }
    }

    /// Allocates the address and public addresses in the circuit
    pub fn alloc_witness<CS, F>(
        &self,
        mut cs: CS,
    ) -> Result<(AllocatedAddress<F>, Vec<AllocatedAddress<F>>), SynthesisError>
    where
        CS: ConstraintSystem<F>,
        F: PrimeField,
    {
        let address = AllocatedAddress::alloc(cs.namespace(|| "address"), &self.address)?;
        let public_addresses = ADDRESSES
            .iter()
            .enumerate()
            .map(|(i, address)| {
                AllocatedAddress::alloc(cs.namespace(|| format!("pub_addresses_{i}")), address)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((address, public_addresses))
    }
}

/// A type that represents an address in the constraint system
pub struct AllocatedAddress<F>
where
    F: PrimeField,
{
    value: [AllocatedNum<F>; ADDRESS_SIZE],
}

impl<F> AllocatedAddress<F>
where
    F: PrimeField,
{
    fn alloc<CS>(mut cs: CS, address: &[u8; ADDRESS_SIZE]) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        let mut value = Vec::with_capacity(ADDRESS_SIZE);
        for (i, c) in address.iter().enumerate() {
            let char = AllocatedNum::alloc(cs.namespace(|| format!("char_{i}")), || {
                Ok(F::from(*c as u64))
            })?;
            value.push(char)
        }
        Ok(Self {
            value: value
                .try_into()
                .map_err(|_| SynthesisError::UnconstrainedVariable)?,
        })
    }

    /// Hashes the address using the basis
    fn hash<CS>(
        &self,
        mut cs: CS,
        basis: &[AllocatedNum<F>],
    ) -> Result<AllocatedNum<F>, SynthesisError>
    where
        CS: ConstraintSystem<F>,
        F: PrimeField,
    {
        let mut result = AllocatedNum::alloc_infallible(cs.namespace(|| "res"), || F::ZERO);
        for (i, (b, c)) in basis.iter().zip(self.value.iter()).enumerate() {
            let term = b.mul(cs.namespace(|| format!("mul_{i}")), c)?;
            result = result.add(cs.namespace(|| format!("add_{i}")), &term)?;
        }
        Ok(result)
    }

    /// Absorbs the address in the provided RO
    fn absorb_in_ro<E>(&self, ro: &mut E::RO2Circuit)
    where
        E: Engine<Scalar = F>,
    {
        for c in self.value.iter() {
            ro.absorb(c);
        }
    }
}

/// Gets as input the little indian representation of a number and spits out the number
pub fn le_bits_to_num<Scalar, CS>(
    mut cs: CS,
    bits: &[AllocatedBit],
) -> Result<AllocatedNum<Scalar>, SynthesisError>
where
    Scalar: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<Scalar>,
{
    // We loop over the input bits and construct the constraint
    // and the field element that corresponds to the result
    let mut lc = LinearCombination::zero();
    let mut coeff = Scalar::ONE;
    let mut fe = Some(Scalar::ZERO);
    for bit in bits.iter() {
        lc = lc + (coeff, bit.get_variable());
        fe = bit.get_value().map(|val| {
            if val {
                fe.unwrap() + coeff
            } else {
                fe.unwrap()
            }
        });
        coeff = coeff.double();
    }
    let num = AllocatedNum::alloc(cs.namespace(|| "Field element"), || {
        fe.ok_or(SynthesisError::AssignmentMissing)
    })?;
    lc = lc - num.get_variable();
    cs.enforce(|| "compute number from bits", |lc| lc, |lc| lc, |_| lc);
    Ok(num)
}

#[cfg(test)]
mod test {
    use std::time::Instant;

    use super::ExclusionCircuit;
    use nova_snark::traits::circuit::StepCircuit;
    use nova_snark::traits::Engine;
    use nova_snark::{
        frontend::test_cs::TestConstraintSystem,
        provider::{ipa_pc, Bn256EngineIPA},
        spartan::{direct::DirectSNARK, snark::RelaxedR1CSSNARK},
    };

    type E = Bn256EngineIPA;
    type F = <E as Engine>::Scalar;
    type EE = ipa_pc::EvaluationEngine<E>;
    type S = RelaxedR1CSSNARK<E, EE>;

    const TEST_ADDRESS: [u8; 10] = *b"192.168.02";

    #[test]
    fn test_circuit() {
        let circuit = ExclusionCircuit::<E>::new(TEST_ADDRESS);
        let mut cs = TestConstraintSystem::<F>::new();
        circuit
            .synthesize(&mut cs, &[])
            .expect("circuit should synthesize");
        assert!(cs.is_satisfied());
    }

    #[test]
    fn test_delegated_spartan() {
        let circuit = ExclusionCircuit::<E>::new(TEST_ADDRESS);
        let time = Instant::now();
        let (pk, vk) =
            DirectSNARK::<E, S, _>::setup(circuit.clone()).expect("pk, vk should be constructed");
        println!("Setup time: {:?}", time.elapsed());
        let time = Instant::now();
        let proof =
            DirectSNARK::<E, S, _>::prove(&pk, circuit, &[]).expect("proof should be valid");
        println!("Proving time: {:?}", time.elapsed());
        let time = Instant::now();
        proof.verify(&vk, &[]).expect("proof should be verified");
        println!("Verification time: {:?}", time.elapsed());
    }
}

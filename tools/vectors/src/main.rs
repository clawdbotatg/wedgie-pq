// Prints Plonky3's KoalaBear Poseidon2 (width 16) constants and test permutations as JSON,
// so the Python and wedgie versions can be checked against the real thing.
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::{
    default_koalabear_poseidon2_16, KoalaBear, KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL, KOALABEAR_POSEIDON2_RC_16_INTERNAL,
};
use p3_symmetric::Permutation;

fn v(a: &[KoalaBear]) -> Vec<u32> {
    a.iter().map(|x| x.as_canonical_u32()).collect()
}

fn main() {
    let p = default_koalabear_poseidon2_16();
    let mut tests = vec![];
    for seed in 0u32..4 {
        let input: [KoalaBear; 16] =
            core::array::from_fn(|i| KoalaBear::from_u32((i as u32 + 1) * 0x0101_0101u32.wrapping_mul(seed + 1) % 0x7f00_0001));
        let out = p.permute(input);
        tests.push(format!("{{\"in\":{:?},\"out\":{:?}}}", v(&input), v(&out)));
    }
    let ei: Vec<Vec<u32>> = KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL.iter().map(|r| v(r)).collect();
    let ef: Vec<Vec<u32>> = KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL.iter().map(|r| v(r)).collect();
    println!(
        "{{\"p\":{},\"external_initial\":{:?},\"external_final\":{:?},\"internal\":{:?},\"tests\":[{}]}}",
        0x7f00_0001u32, ei, ef, v(&KOALABEAR_POSEIDON2_RC_16_INTERNAL), tests.join(",")
    );
}

use halo2_base::{self, utils::BigPrimeField, Context};
use halo2_ecc::{ecc::EccChip, fields::FieldChip};

pub struct PublicKeyChip<'chip, F: BigPrimeField, FC: FieldChip<F>> {
    ecc_chip: EccChip<'chip, F, FC>,
}

impl<'chip, F: BigPrimeField, FC: FieldChip<F>> PublicKeyChip<'chip, F, FC> {
    pub fn new(ecc_chip: EccChip<'chip, F, FC>) -> Self {
        Self { ecc_chip }
    }

    pub fn load_secret_key(&self, ctx: &mut Context<F>, value: FC::FieldType) -> FC::FieldPoint {
        let fc = self.ecc_chip.field_chip();
        fc.load_private(ctx, value)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use blake2::{digest::consts::U32, Blake2b, Digest};
    use secp256k1::{
        hashes::hex::{Case, DisplayHex},
        Secp256k1, SecretKey,
    };

    #[test]
    fn ecdsa() {
        let secp = Secp256k1::new();

        let sk_hex = "dee4c34e8d700eb78345e5fc77b8a010c229684bf38b43884481558e5474d990";
        let sk_secp = SecretKey::from_str(sk_hex).unwrap();
        let pk_secp = secp256k1::PublicKey::from_secret_key(&secp, &sk_secp);

        let mut hasher = Blake2b::<U32>::new();
        hasher.update(pk_secp.serialize());
        let hash = hasher.finalize();

        println!("Secret key: 0x{}", sk_secp.display_secret());
        println!("Public key: 0x{}", pk_secp);
        println!("Account id: 0x{}", hash.to_hex_string(Case::Lower));
    }
}

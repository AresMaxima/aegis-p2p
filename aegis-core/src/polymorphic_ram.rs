use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

pub struct PolymorphicBuffer {
    data: Vec<u8>,
    mask: Vec<u8>,
}

impl PolymorphicBuffer {
    /// Crée un tampon polymorphe masqué dès l'instanciation
    pub fn new(input: &[u8]) -> Self {
        let mut mask = vec![0u8; input.len()];
        rand::thread_rng().fill_bytes(&mut mask);

        let data = input
            .iter()
            .zip(mask.iter())
            .map(|(&b, &m)| b ^ m)
            .collect();

        Self { data, mask }
    }

    /// Déchiffre temporairement, re-masque sur place avec une nouvelle entropie et détruit l'ancien masque
    pub fn read_and_mutate(&mut self) -> Zeroizing<Vec<u8>> {
        let mut new_mask = vec![0u8; self.mask.len()];
        rand::thread_rng().fill_bytes(&mut new_mask);

        let mut plaintext = Vec::with_capacity(self.data.len());

        // Pass unique : déchiffrement, stockage en clair et re-masquage sur place
        for i in 0..self.data.len() {
            let p = self.data[i] ^ self.mask[i];
            plaintext.push(p);
            self.data[i] = p ^ new_mask[i];
        }

        self.mask.zeroize();
        self.mask = new_mask;

        Zeroizing::new(plaintext)
    }
}

impl Drop for PolymorphicBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
        self.mask.zeroize();
    }
}
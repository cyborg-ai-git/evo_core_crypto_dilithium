use crate::{K, SEEDBYTES};
use crate::packing::{pack_pk, unpack_sk};
use crate::params::{PUBLICKEYBYTES, SECRETKEYBYTES, SIGNBYTES};
use crate::polyvec::{polyvec_matrix_expand, polyvec_matrix_pointwise_montgomery, polyveck_add, polyveck_caddq, polyveck_invntt_tomont, polyveck_power2round, polyveck_reduce, polyvecl_ntt, Polyveck, Polyvecl};
use crate::sign::*;

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Keypair {
  pub public: [u8; PUBLICKEYBYTES],
  secret: [u8; SECRETKEYBYTES],
}

/// Secret key elided
impl std::fmt::Debug for Keypair {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "public: {:?}\nsecret: <elided>", self.public)
  }
}

pub enum SignError {
  Input,
  Verify,
}



#[derive(Debug)]
pub enum KeyError {
  Pk,
  Sk,
}


impl Keypair {
  /// Explicitly expose secret key
  /// ```
  /// # use pqc_dilithium::*;
  /// let keys = Keypair::generate();
  /// let secret_key = keys.expose_secret();
  /// assert!(secret_key.len() == SECRETKEYBYTES);
  /// ```
  pub fn expose_secret(&self) -> &[u8] {
    &self.secret
  }

  /// Generates a keypair for signing and verification
  ///
  /// Example:
  /// ```
  /// # use pqc_dilithium::*;
  /// let keys = Keypair::generate();
  /// assert!(keys.public.len() == PUBLICKEYBYTES);
  /// assert!(keys.expose_secret().len() == SECRETKEYBYTES);
  /// ```
  pub fn generate() -> Keypair {
    let mut public = [0u8; PUBLICKEYBYTES];
    let mut secret = [0u8; SECRETKEYBYTES];
    crypto_sign_keypair(&mut public, &mut secret, None);
    Keypair { public, secret }
  }

  /// Generates a signature for the given message using a keypair
  ///
  /// Example:
  /// ```
  /// # use pqc_dilithium::*;
  /// # let keys = Keypair::generate();
  /// let msg = "Hello".as_bytes();
  /// let sig = keys.sign(&msg);
  /// assert!(sig.len() == SIGNBYTES);
  /// ```  
  pub fn sign(&self, msg: &[u8]) -> [u8; SIGNBYTES] {
    let mut sig = [0u8; SIGNBYTES];
    crypto_sign_signature(&mut sig, msg, &self.secret);
    sig
  }
}

/// Verify signature using keypair
///
/// Example:
/// ```
/// # use pqc_dilithium::*;
/// # let keys = Keypair::generate();
/// # let msg = [0u8; 32];
/// # let sig = keys.sign(&msg);
/// let sig_verify = verify(&sig, &msg, &keys.public);
/// assert!(sig_verify.is_ok());
pub fn verify(
  sig: &[u8],
  msg: &[u8],
  public_key: &[u8],
) -> Result<(), SignError> {
  if sig.len() != SIGNBYTES {
    return Err(SignError::Input);
  }
  crypto_sign_verify(&sig, &msg, public_key)
}

pub fn get_pk_from_sk(sk: &[u8]) -> Result<Vec<u8>, KeyError> {
  // Verify secret key length
  if sk.len() != SECRETKEYBYTES {
    return Err(KeyError::Sk);
  }

  let mut pk = vec![0u8; PUBLICKEYBYTES];
  let mut mat = [Polyvecl::default(); K];
  let mut s1 = Polyvecl::default();
  let (mut s2, mut t1, mut t0) = (
    Polyveck::default(),
    Polyveck::default(),
    Polyveck::default(),
  );
  let mut rho = [0u8; SEEDBYTES];
  let mut tr = [0u8; SEEDBYTES];
  let mut key = [0u8; SEEDBYTES];

  // Unpack the secret key to extract rho, s1, s2, t0
  unpack_sk(&mut rho, &mut tr, &mut key, &mut t0, &mut s1, &mut s2, sk);

  // Expand the matrix A from rho
  polyvec_matrix_expand(&mut mat, &rho);

  // Compute t1 = A * s1 + s2 (reconstructing the public key components)
  let mut s1hat = s1;
  polyvecl_ntt(&mut s1hat);

  // Matrix-vector multiplication: t1 = A * s1
  polyvec_matrix_pointwise_montgomery(&mut t1, &mat, &s1hat);
  polyveck_reduce(&mut t1);
  polyveck_invntt_tomont(&mut t1);

  // Add error vector s2: t1 = A * s1 + s2
  polyveck_add(&mut t1, &s2);

  // Extract high bits for public key
  polyveck_caddq(&mut t1);
  polyveck_power2round(&mut t1, &mut t0);

  // Pack the public key (rho, t1)
  pack_pk(&mut pk, &rho, &t1);

  Ok(pk)
}
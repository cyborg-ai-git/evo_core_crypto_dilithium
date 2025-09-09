use env_logger::Builder;
use std::{env, sync::Once};
use faster_hex::{hex_decode, hex_string};
//--------------------------------------------------------------------------------------------------
static INIT_LOGGER: Once = Once::new();

pub fn do_init_logger() {
    INIT_LOGGER.call_once(|| {
        if env::var("RUST_LOG").is_err() {
            unsafe {
                env::set_var("RUST_LOG", "debug");
            }
        }
        Builder::from_default_env().init();
    });
}

#[cfg(test)]
mod tests {
    use evo_core_crypto_dilithium::{get_pk_from_sk, Keypair};
    use super::*;
    use log::debug;

    #[test]
    fn test_get_pk_from_sk() {
        do_init_logger();

        let keys = Keypair::generate();

        let pk = keys.public.to_vec();
        let sk = keys.expose_secret();

        let pk_1 = get_pk_from_sk(&sk).unwrap();


        debug!("{} == {}",  hex_string(&pk),  hex_string(&pk_1));

        assert_eq!(pk, pk_1);




    }

}

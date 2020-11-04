// Implementation of Zcash ZIP-313 that changes the default network fee with the Canopy Upgrade.
// See https://github.com/zcash/zips/blob/2719212839358a342d5c23b4063b6bd4b5223690/zip-reduce-shielded_tx_fee.rst

use zcash_primitives::consensus::{MAIN_NETWORK, NetworkUpgrade, Parameters};

const PRE_CANOPY_DEFAULT_FEE: u64 = 10_000;
const POST_CANOPY_DEFAULT_FEE: u64 = 1_000;
const ZIP313_GRACE_PERIOD_BLOCKS:u64 = 33_600;

// Return the default network fee at a given height. 
pub fn get_default_fee(height: i32) -> u64 {
  let canopy_height: u64 = MAIN_NETWORK.activation_height(NetworkUpgrade::Canopy).unwrap().into();
  if height as u64 >= ZIP313_GRACE_PERIOD_BLOCKS + canopy_height {
    POST_CANOPY_DEFAULT_FEE
  } else {
    PRE_CANOPY_DEFAULT_FEE
  }
}

#[cfg(test)]
pub mod tests {
  use zcash_primitives::consensus::{MAIN_NETWORK, NetworkUpgrade, Parameters};
  use super::{POST_CANOPY_DEFAULT_FEE, PRE_CANOPY_DEFAULT_FEE, ZIP313_GRACE_PERIOD_BLOCKS, get_default_fee};

  #[test]
  pub fn test_fees() {
    assert_eq!(get_default_fee(1_000_000), PRE_CANOPY_DEFAULT_FEE);

    let canopy_height: u64 = MAIN_NETWORK.activation_height(NetworkUpgrade::Canopy).unwrap().into();
    assert_eq!(get_default_fee(canopy_height as i32), PRE_CANOPY_DEFAULT_FEE);
    
    let grace_height: u64 = canopy_height + ZIP313_GRACE_PERIOD_BLOCKS;
    assert_eq!(get_default_fee(grace_height as i32), POST_CANOPY_DEFAULT_FEE);

    assert_eq!(get_default_fee(1_046_400), PRE_CANOPY_DEFAULT_FEE);  // Canopy activation height
    assert_eq!(get_default_fee(1_080_000), POST_CANOPY_DEFAULT_FEE);  // Grace perioud height
    assert_eq!(get_default_fee(1_090_000), POST_CANOPY_DEFAULT_FEE);  // Grace perioud height
  }
}
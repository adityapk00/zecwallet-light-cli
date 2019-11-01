pub fn get_closest_checkpoint(chain_name: &str, height: u64) ->  Option<(u64, &'static str, &'static str)> {
    match chain_name {
        "test" => get_test_checkpoint(height),
        "main" => get_main_checkpoint(height),
        _      => None
    }
}

fn get_test_checkpoint(height: u64) ->  Option<(u64, &'static str, &'static str)> {
    let checkpoints: Vec<(u64, &str, &str)> = vec![
        (600000, "0107385846c7451480912c294b6ce1ee1feba6c2619079fd9104f6e71e4d8fe7",
                 "01690698411e3f8badea7da885e556d7aba365a797e9b20b44ac0946dced14b23c001001ab2a18a5a86aa5d77e43b69071b21770b6fe6b3c26304dcaf7f96c0bb3fed74d000186482712fa0f2e5aa2f2700c4ed49ef360820f323d34e2b447b78df5ec4dfa0401a332e89a21afb073cb1db7d6f07396b56a95e97454b9bca5a63d0ebc575d3a33000000000001c9d3564eff54ebc328eab2e4f1150c3637f4f47516f879a0cfebdf49fe7b1d5201c104705fac60a85596010e41260d07f3a64f38f37a112eaef41cd9d736edc5270145e3d4899fcd7f0f1236ae31eafb3f4b65ad6b11a17eae1729cec09bd3afa01a000000011f8322ef806eb2430dc4a7a41c1b344bea5be946efc7b4349c1c9edb14ff9d39"
        ),
        (650000, "003f7e09a357a75c3742af1b7e1189a9038a360cebb9d55e158af94a1c5aa682",
                 "010113f257f93a40e25cfc8161022f21c06fa2bc7fb03ee9f9399b3b30c636715301ef5b99706e40a19596d758bf7f4fd1b83c3054557bf7fab4801985642c317d41100001b2ad599fd7062af72bea99438dc5d8c3aa66ab52ed7dee3e066c4e762bd4e42b0001599dd114ec6c4c5774929a342d530bf109b131b48db2d20855afa9d37c92d6390000019159393c84b1bf439d142ed2c54ee8d5f7599a8b8f95e4035a75c30b0ec0fa4c0128e3a018bd08b2a98ed8b6995826f5857a9dc2777ce6af86db1ae68b01c3c53d0000000001e3ec5d790cc9acc2586fc6e9ce5aae5f5aba32d33e386165c248c4a03ec8ed670000011f8322ef806eb2430dc4a7a41c1b344bea5be946efc7b4349c1c9edb14ff9d39"
        )
    ];

    find_checkpoint(height, checkpoints)
}


fn get_main_checkpoint(height: u64) ->  Option<(u64, &'static str, &'static str)> {
    let checkpoints: Vec<(u64, &str, &str)> = vec![
        (610000, "000000000218882f481e3b49ca3df819734b8d74aac91f69e848d7499b34b472",
                 "0192943f1eca6525cea7ea8e26b37c792593ed50cfe2be7a1ff551a08dc64b812f001000000001deef7ae5162a9942b4b9aa797137c5bdf60750e9548664127df99d1981dda66901747ad24d5daf294ce2a27aba923e16e52e7348eea3048c5b5654b99ab0a371200149d8aff830305beb3887529f6deb150ab012916c3ce88a6b47b78228f8bfeb3f01ff84a89890cfae65e0852bc44d9aa82be2c5d204f5aebf681c9e966aa46f540e000001d58f1dfaa9db0996996129f8c474acb813bfed452d347fb17ebac2e775e209120000000001319312241b0031e3a255b0d708750b4cb3f3fe79e3503fe488cc8db1dd00753801754bb593ea42d231a7ddf367640f09bbf59dc00f2c1d2003cc340e0c016b5b13"
        ),
        (630000, "00000000015493abba3e3bb384562f09141548f60581e06d4056993388d2ea2f",
                 "019b01066bae720ce88b4252c3852b0160ec4c4dcd6110df92e76de5cb23ab2f540109c3001b823fc745328a89a47fc5ace701bbd4dc1e9692e918a125ca48960545100001b2ba91c0f96777e735ded1ba9671003a399d435db3a0746bef3b2c83ba4d953f01d4c31130d2013fb57440d21fba0a8af65e61cd1405a8e2d9b987c02df8fc6514011c44ba36710e293ddf95e6715594daa927883d48cda6a3a5ee4aa3ef141ec55b0001cd9540592d39094703664771e61ce69d5b08539812886e0b9df509c80f938f6601178b3d8f9e7f7af7a1f4a049289195001abd96bb41e15b4010cecc1468af4e4b01ffe988e63aba31819640175d3fbb8c91b3c42d2f5074b4c075411d3a5c28e62801cb2e8d7f7387a9d31ba38697a9564808c9aff7d018a4cbdcd1c635edc3ab3014000001060f0c26ee205d7344bda85024a9f9a3c3022d52ea30dfb6770f4acbe168406d0103a7a58b1d7caef1531d521cc85de6fcb18d3590f31ad4486ca1252dac2c96020001319312241b0031e3a255b0d708750b4cb3f3fe79e3503fe488cc8db1dd00753801754bb593ea42d231a7ddf367640f09bbf59dc00f2c1d2003cc340e0c016b5b13"
        ),
    ];

    find_checkpoint(height, checkpoints)
}

fn find_checkpoint(height: u64, chkpts: Vec<(u64, &'static str, &'static str)>) -> Option<(u64, &'static str, &'static str)> {
    // Find the closest checkpoint
    let mut heights = chkpts.iter().map(|(h, _, _)| *h as u64).collect::<Vec<_>>();
    heights.sort();

    match get_first_lower_than(height, heights) {
        Some(closest_height) => {
            chkpts.iter().find(|(h, _, _)| *h ==  closest_height).map(|t| *t)
        },
        None    => None
    }
}

fn get_first_lower_than(height: u64, heights: Vec<u64>) -> Option<u64> {
    // If it's before the first checkpoint, return None. 
    if heights.len() == 0 || height < heights[0] {
        return None;
    }

    for (i, h) in heights.iter().enumerate() {
        if height < *h {
            return Some(heights[i-1]);
        }
    }

    return Some(*heights.last().unwrap());
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_lower_than() {
        assert_eq!(get_first_lower_than( 9, vec![10, 30, 40]), None);
        assert_eq!(get_first_lower_than(10, vec![10, 30, 40]).unwrap(), 10);
        assert_eq!(get_first_lower_than(11, vec![10, 30, 40]).unwrap(), 10);
        assert_eq!(get_first_lower_than(29, vec![10, 30, 40]).unwrap(), 10);
        assert_eq!(get_first_lower_than(30, vec![10, 30, 40]).unwrap(), 30);
        assert_eq!(get_first_lower_than(40, vec![10, 30, 40]).unwrap(), 40);
        assert_eq!(get_first_lower_than(41, vec![10, 30, 40]).unwrap(), 40);
        assert_eq!(get_first_lower_than(99, vec![10, 30, 40]).unwrap(), 40);
    }

    #[test]
    fn test_checkpoints() {
        assert_eq!(get_test_checkpoint(500000), None);
        assert_eq!(get_test_checkpoint(600000).unwrap().0, 600000);
        assert_eq!(get_test_checkpoint(625000).unwrap().0, 600000);
        assert_eq!(get_test_checkpoint(650000).unwrap().0, 650000);
        assert_eq!(get_test_checkpoint(655000).unwrap().0, 650000);

        assert_eq!(get_main_checkpoint(500000), None);
        assert_eq!(get_main_checkpoint(610000).unwrap().0, 610000);
        assert_eq!(get_main_checkpoint(625000).unwrap().0, 610000);
    }

}
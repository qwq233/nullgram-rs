#[allow(unused_variables)]
pub fn get_v2signature(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 8 {
        return None;
        
    }

    let mut offset = 0 as usize;
    while offset < data.len() {
        // we might use it later so keep it
        let signer_sequence_size = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        // println!("signer_size: {}", signer_sequence_size);
        offset += 4;

        let signer_size = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        // println!("signer_size: {}", signer_size);
        if data.len() < offset + 4 + signer_size as usize {
            return None;
        }
        offset += 4;
        
        let signed_data_size = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        // println!("signed_data_size: {}", signed_data_size);
        offset += 4;

        // skip digest
        let digests_size = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        offset += 4 + digests_size as usize;
        // println!("digests_size: {}", digests_size);

        // now we are at the certificates
        let certificates_size = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        // println!("certificates_size: {}", certificates_size);
        let mut certificates = vec![0u8; (certificates_size - 4) as usize];
        certificates.copy_from_slice(
            data[offset + 8..offset + 4 + certificates_size as usize]
                .try_into()
                .unwrap(),
        );

        return Some(certificates);
    }
    None
}

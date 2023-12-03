use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
};

#[derive(Debug)]
#[allow(dead_code)]
pub struct SignatureBlock {
    pub id_pairs: Vec<IdPairs>,
    size: u64,       // same as above, including the magic (16 bytes)
    magic: [u8; 16], // b"APK Sig Block 42" (16 bytes) Placeholder for future-proofing
}

pub fn parse_signature_block(file: &mut File, start: u64) -> std::io::Result<SignatureBlock> {
    let file_size = file.seek(SeekFrom::End(0)).unwrap() as i128;

    let magic_offset = find_magic_offset(file, start);
    if magic_offset.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Signature record not found",
        ));
    }
    let magic_offset = magic_offset.unwrap();

    let mut size = [0u8; 8];
    file.seek(SeekFrom::Start(magic_offset - 8)).unwrap();
    match file.read_exact(&mut size) {
        Ok(_) => (),
        Err(e) => return Err(e),
    }
    let size = u64::from_le_bytes(size);

    if size - 16 > file_size as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid signature block: size is too big",
        ));
    }

    let mut id_pairs_raw = vec![0u8; (size - 20) as usize];
    file.seek(SeekFrom::Start(magic_offset + 16 - size)).unwrap();
    match file.read_exact(&mut id_pairs_raw) {
        Ok(_) => (),
        Err(e) => return Err(e),
    }

    match parse_id_pairs(id_pairs_raw) {
        Ok(id_pairs) => {
            return Ok(SignatureBlock {
                id_pairs,
                size,
                magic: *b"APK Sig Block 42", // Placeholder
            });
        },
        Err(e) => return Err(e),
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct IdPairs {
    len: u64,
    pub id: u32,
    pub value: Vec<u8>, // size = len - 4
}

fn parse_id_pairs(raw_data: Vec<u8>) -> std::io::Result<Vec<IdPairs>> {
    let mut id_pairs: Vec<IdPairs> = Vec::new();
    let mut current_pos: usize = 0;

    loop {
        let size = u64::from_le_bytes([
            raw_data[current_pos],
            raw_data[current_pos + 1],
            raw_data[current_pos + 2],
            raw_data[current_pos + 3],
            raw_data[current_pos + 4],
            raw_data[current_pos + 5],
            raw_data[current_pos + 6],
            raw_data[current_pos + 7],
        ]) - 4;

        println!("size: {}", size);

        let id = u32::from_le_bytes([
            raw_data[current_pos + 8],
            raw_data[current_pos + 9],
            raw_data[current_pos + 10],
            raw_data[current_pos + 11],
        ]);

        current_pos += 12;

        if current_pos + size as usize >= raw_data.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid signature block: size is too big",
            ));
        }

        let mut value = vec![0u8; size as usize];
        value.copy_from_slice(&raw_data[current_pos..current_pos + size as usize]);

        id_pairs.push(IdPairs {
            len: size + 4,
            id,
            value,
        });

        current_pos += size as usize;
        if current_pos + 8 >= raw_data.len() {
            break;
        }
    }

    Ok(id_pairs)
}

// it's said that the signature block is just next to the EOCD but i am not sure so i just search for it
pub fn find_magic_offset(file: &mut File, cd_offset: u64) -> Option<u64> {
    const SIGNATURE: &[u8; 16] = b"APK Sig Block 42";

    let mut buf = [0u8; 128 as usize];

    let mut offset = file.seek(SeekFrom::Start(cd_offset - 128)).unwrap() as i64;
    while offset > 0 {
        file.seek(SeekFrom::Start(offset as u64)).unwrap();
        file.read_exact(&mut buf).unwrap();

        for i in 0..=(buf.len() - 16) {
            let mut magic = [0u8; 16];
            magic.copy_from_slice(&buf[i..i + 16]);

            if magic == *SIGNATURE {
                return Some(offset as u64 + i as u64);
            }
        }

        offset -= 128;
    }

    None
}

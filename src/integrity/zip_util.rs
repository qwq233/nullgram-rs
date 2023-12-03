use std::fs::File;
use std::io::{Read, Seek, SeekFrom};


// End of Central Directory Record
#[derive(Debug)]
pub struct Ecod {
    pub magic: u32, // 0x06054b50
    pub disk_num: u16,
    pub disk_num_start: u16,
    pub num_entries_disk: u16,
    pub num_entries: u16,
    pub cd_size: u32,
    pub cd_offset: u32,
    pub comment_len: u16,
    pub comment: Vec<u8>
}

pub fn parse_eocd(file: &mut File)-> std::io::Result<Ecod> {
    let eocd_offset = find_eocd_offset(file).unwrap();
    file.seek(SeekFrom::Start(eocd_offset)).unwrap();

    let mut buf = [0u8; 22];
    file.read_exact(&mut buf).unwrap();

    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let disk_num = u16::from_le_bytes([buf[4], buf[5]]);
    let disk_num_start = u16::from_le_bytes([buf[6], buf[7]]);
    let num_entries_disk = u16::from_le_bytes([buf[8], buf[9]]);
    let num_entries = u16::from_le_bytes([buf[10], buf[11]]);
    let cd_size = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
    let cd_offset = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
    let comment_len = u16::from_le_bytes([buf[20], buf[21]]);

    let mut comment = vec![0u8; comment_len as usize];
    file.read_exact(&mut comment).unwrap();

    let eocd = Ecod {
        magic,
        disk_num,
        disk_num_start,
        num_entries_disk,
        num_entries,
        cd_size,
        cd_offset,
        comment_len,
        comment,
    };

    return Ok(eocd);
}

fn find_eocd_offset(file: &mut File) -> std::io::Result<u64> {
    const SEARCH_CHUNK_SIZE: i64 = 4096;

    let mut buf = [0u8; SEARCH_CHUNK_SIZE as usize];
    let mut offset = file.seek(SeekFrom::End(-SEARCH_CHUNK_SIZE))? as i64;

    while offset > 0 {
        file.seek(SeekFrom::Start(offset as u64))?;
        file.read_exact(&mut buf)?;

        if let Some(eocd_offset) = find_eocd_in_buffer(&buf) {
            return Ok(offset as u64 + eocd_offset as u64);
        }

        offset -= SEARCH_CHUNK_SIZE;
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "EOCD record not found",
    ))
}

fn find_eocd_in_buffer(buf: &[u8; 4096]) -> Option<u64> {
    const SIGNATURE: u32 = 0x06054b50;

    for i in 0..=(buf.len() - 4) {
        let signature = u32::from_le_bytes([
            buf[i],
            buf[i + 1],
            buf[i + 2], 
            buf[i + 3]
        ]);

        if signature == SIGNATURE {
            return Some(i as u64);
        }
    }

    None
}

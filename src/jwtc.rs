use std::io::Write;

use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use flate2::{
    write::{ZlibDecoder, ZlibEncoder},
    Compression,
};

pub fn compress(jwt: &str) -> Result<String> {
    let components = jwt
        .trim()
        .split('.')
        .map(|x| Ok(general_purpose::URL_SAFE_NO_PAD.decode(x)?))
        .collect::<Result<Vec<_>>>()?;
    let body = components.join(&b"\n"[..]);
    let mut encoder = ZlibEncoder::new(vec![], Compression::best());
    encoder.write_all(&body)?;
    let compressed_bytes = encoder.finish()?;

    Ok(general_purpose::URL_SAFE_NO_PAD.encode(&compressed_bytes))
}

pub fn decompress(jwt: &str) -> Result<String> {
    let compressed = general_purpose::URL_SAFE_NO_PAD.decode(jwt.trim())?;
    let mut decoder = ZlibDecoder::new(vec![]);
    decoder.write_all(&compressed)?;
    let decompressed = decoder.finish()?;
    Ok(decompressed
        .splitn(3, |x| *x == b'\n')
        .map(|x| general_purpose::URL_SAFE_NO_PAD.encode(&x))
        .collect::<Vec<_>>()
        .join("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    const TEST_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    #[test]
    fn test_jwtc() {
        let compressed = compress(TEST_TOKEN).unwrap();
        println!("token size = {}", compressed.len());
        assert_eq!(TEST_TOKEN, decompress(&compressed).unwrap());
    }
}

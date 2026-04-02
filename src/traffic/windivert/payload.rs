/// Extract HTTP Host header from payload
pub fn extract_http_host(payload: &[u8]) -> Option<String> {
    let start = payload
        .windows(6)
        .position(|w| w.eq_ignore_ascii_case(b"Host: "))?
        + 6;
    let end = payload[start..]
        .iter()
        .position(|&c| c == b'\r' || c == b'\n')
        .map_or(payload.len(), |pos| start + pos);
    String::from_utf8(payload[start..end].to_vec()).ok()
}

/// Extract TLS SNI (Server Name Indication) from ClientHello
pub fn extract_tls_sni(payload: &[u8]) -> Option<String> {
    if payload.len() <= 43 || payload[0] != 0x16 || payload[1] != 0x03 || payload[5] != 0x01 {
        return None;
    }

    let mut offset = 43;

    let session_id_len = *payload.get(offset)? as usize;
    offset += 1 + session_id_len;

    let cipher_len = ((*payload.get(offset)? as usize) << 8) | (*payload.get(offset + 1)? as usize);
    offset += 2 + cipher_len;

    let comp_len = *payload.get(offset)? as usize;
    offset += 1 + comp_len;

    let ext_len = ((*payload.get(offset)? as usize) << 8) | (*payload.get(offset + 1)? as usize);
    offset += 2;

    let ext_end = offset + ext_len;

    while offset + 3 < ext_end {
        let ext_type = ((*payload.get(offset)? as u16) << 8) | (*payload.get(offset + 1)? as u16);
        let ext_data_len =
            ((*payload.get(offset + 2)? as usize) << 8) | (*payload.get(offset + 3)? as usize);
        offset += 4;

        if ext_type == 0x0000 {
            let mut sni_offset = offset;
            sni_offset += 2; // skip list len

            let name_type = *payload.get(sni_offset)?;
            if name_type == 0 {
                // 0 = host_name
                sni_offset += 1;
                let name_len = ((*payload.get(sni_offset)? as usize) << 8)
                    | (*payload.get(sni_offset + 1)? as usize);
                sni_offset += 2;

                let name_bytes = payload.get(sni_offset..sni_offset + name_len)?;
                return String::from_utf8(name_bytes.to_vec()).ok();
            }
        }
        offset += ext_data_len;
    }

    None
}

/// Extract host from payload (tries HTTP Host header first, then TLS SNI)
pub fn extract_host(payload: &[u8]) -> Option<String> {
    extract_http_host(payload).or_else(|| extract_tls_sni(payload))
}

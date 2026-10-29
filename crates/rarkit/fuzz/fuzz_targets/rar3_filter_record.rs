//! SPEC-J section 6.3: arbitrary bytes as a RAR 3 filter record stream
//! against a synthetic member of arbitrary length. No panic; bounded queue
//! (asserted inside the driver); a success delivers exactly the member.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((len, records)) = data.split_first_chunk::<3>() else {
        return;
    };
    let member_len = u32::from_le_bytes([len[0], len[1], len[2], 0]) as u64;
    if let Ok((delivered, _)) = rarkit::internals::rar3::rar3_record_stream(records, member_len) {
        assert_eq!(delivered, member_len);
    }
});

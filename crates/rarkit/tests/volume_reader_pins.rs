//! A volume set whose members arrive as READERS is the archive it was
//! before a volume set batched them (spec G 3.9 and 3.10;
//! 1 Oct 2026).
//!
//! **The digests below were printed by this file built against the
//! PARENT of that change** (an earlier revision; the level 5 rows again from a later one, whose level 5 by class moved them; every other row unchanged there), whose writer took every
//! reader member of a volume set a member at a time: a solid run through
//! the windowed walk, a non-solid set through the writing thread alone.
//! The change lets a solid batch and the worker team take those members,
//! and its claim is that this is a WIDTH and never a byte: no split
//! point, header or packed byte of any volume moves. A digest here that
//! stops matching says a volume moved.
//!
//! The rows are `support/volumereaders.rs`'s: one set at both families and
//! levels 1 to 5, solid and not, at a cap smaller than a batch and at one
//! of several, and at level 3 a password, encrypted headers, BLAKE2sp, a
//! payload bound and a ceiling the caller names; and a second set built
//! so that a solid batch's tail lands past a boundary and is encoded
//! again.
//!
//! To pin again from a new parent: build this file there, run it, and
//! copy the `PIN` lines it prints for every row it has no digest for.
//!
//! **Pinned again on 11 Oct 2026, over new test data.** The members here
//! are made by the shared test data makers now, so every digest below
//! was taken again, from that day's build, whose engine was byte for byte
//! the one that passed the pins before them. They record the same
//! behaviour on new data and guard it from here on; they no longer prove
//! equality with the older build this header names.

#[path = "support/volumereaders.rs"]
mod volumereaders;

use volumereaders::{options_of, set_digest, sets, write, Hand};

/// `(row, volumes, sha256 over every volume's length and bytes)`.
const PINS: &[(&str, usize, &str)] = &[
    (
        "r5/m1/solid/40000",
        52,
        "7b957f60626d42a60f5bfcb437bef61bb06c0208fd4598ab53b1229836d1d921",
    ),
    (
        "r5/m1/solid/400000",
        6,
        "2976ac913ccb8ff431de1f9a202e33fd1c8817463df04e5e62e98559c401272e",
    ),
    (
        "r5/m1/plain/40000",
        52,
        "9608649d47e42f01a3052536d53d006b784ad3491bb2f6e65f23ab65edc176d9",
    ),
    (
        "r5/m1/plain/400000",
        6,
        "8186a1a1899dfa5e233d2548e4f3a3b9fc367934e6bff56ffd46e3f488d86925",
    ),
    (
        "r5/m2/solid/40000",
        51,
        "25c0fa6db6ee73e68c0fada87b006060aedf27fcfdaca962a779ee9408d34383",
    ),
    (
        "r5/m2/solid/400000",
        6,
        "c7668c036efac44e1f8390ed9bd691a333a015e44c96c74622c553ecf4e9b6de",
    ),
    (
        "r5/m2/plain/40000",
        51,
        "b82f6daa036ea037b825b79eb9ebf931d9aa78c592010452d8ec7519b48b4fbf",
    ),
    (
        "r5/m2/plain/400000",
        6,
        "705b5638794e971f5156fc7e9cf6267e28059f9b1c42e4acc4ebff4020333aaf",
    ),
    (
        "r5/m3/solid/40000",
        49,
        "d5ec5a8840e7cb608a4ae50bb6bf53cb413664c4d96991a051275c59e7f3f790",
    ),
    (
        "r5/m3/solid/400000",
        5,
        "dc125e32225da6df222e45fbbee0a9342bd6797cc40ee6949e4dd62130405188",
    ),
    (
        "r5/m3/plain/40000",
        49,
        "f02d7af6b2c0ab39609773418638ff817b8402431243687f76f085a351cfebe4",
    ),
    (
        "r5/m3/plain/400000",
        5,
        "e3db81318de88fcff3201c86ae2cdc4be4222220c977e3a48a2bba007c31c24a",
    ),
    (
        "r5/m4/solid/40000",
        48,
        "2396e4cae5cce57f71e7719cf7fce180ac441a452a1fab3426a5175e985a24b9",
    ),
    (
        "r5/m4/solid/400000",
        5,
        "77fd40bd983f7efddad69afcc8824743d028be9c5d34081fda2f8c0aa3ea739b",
    ),
    (
        "r5/m4/plain/40000",
        49,
        "00700dddc01cf2b88653bb678834b46837ec26fe9b790b0254536e2e4aac7cfd",
    ),
    (
        "r5/m4/plain/400000",
        5,
        "ab415fc29fd7afeef791bf4741c12186f345c19abd6bd660a93ffb807910db15",
    ),
    (
        "r5/m5/solid/40000",
        48,
        "040ff936604114c3e99b702404132a75c9b240cf86e30fe3c5e36f7cabe2bdf6",
    ),
    (
        "r5/m5/solid/400000",
        5,
        "bf7a956e440e5249880c47acfb828aaa42180852da69e20e8d6303cacca8e824",
    ),
    (
        "r5/m5/plain/40000",
        48,
        "b51b8b40e6e150bb75bfcea35b617acdd1e75cabcd053ae526dc94abc0df09e1",
    ),
    (
        "r5/m5/plain/400000",
        5,
        "3d2fa8d437d9988a038d754b43cdf35cc0bb2094240551ac5435ac948ae5b895",
    ),
    (
        "r4/m1/solid/40000",
        52,
        "d20b0844ce4fd82bdf06f8e3468f3d5b6493c816e924b14fcf612368ed7d1770",
    ),
    (
        "r4/m1/solid/400000",
        6,
        "27869406679a366237c95e2831f069a804a4ca9e3ce7177e8e2904a18e19185c",
    ),
    (
        "r4/m1/plain/40000",
        52,
        "e5cf2d3ce57bf5df3ba55290ea57bd0d7a7294ac3abefed0c3cb6b06a110a2eb",
    ),
    (
        "r4/m1/plain/400000",
        6,
        "820b354cfb92458f192b67c71a776271588168226ea14b0503716cdea99d819f",
    ),
    (
        "r4/m2/solid/40000",
        51,
        "564ef53f0bc7bc12705ee6fbcbdc546462fa0336a1b4bf9d37d08e6414382c27",
    ),
    (
        "r4/m2/solid/400000",
        6,
        "6fbf40b22fc77132a9668122cef6943302a2fdb3c2d339a2462c773a0e010719",
    ),
    (
        "r4/m2/plain/40000",
        51,
        "b151bf7c4e8df44b1f4e81c34221c0e20fb3540a38ba7f3abd1a9316404c0842",
    ),
    (
        "r4/m2/plain/400000",
        6,
        "db1493ec9e2a68c1bb458ca3b439bdd1fd22429f9c5cba1ca08c922a98a7bbb5",
    ),
    (
        "r4/m3/solid/40000",
        49,
        "765a0c7a99ffcf1865a6793548a13f5d135f9cb2ae4b3de7da81162eda67d0b9",
    ),
    (
        "r4/m3/solid/400000",
        5,
        "220bd527b793e71eac01e6e986554de8d6ee1847a2bff0fc7fca6d5c70431123",
    ),
    (
        "r4/m3/plain/40000",
        49,
        "78a33b476430b50a3098224b587ad36d4d52151efc515b5faf93225a7aa9f9d0",
    ),
    (
        "r4/m3/plain/400000",
        5,
        "05b461879070bb31690d913bbaaba150d06929cdaa238c36c9d530c8862ac802",
    ),
    (
        "r4/m4/solid/40000",
        48,
        "00658e256c27c78c504188d3935c99f100a1d18ea266781725967ef20fd0ff7d",
    ),
    (
        "r4/m4/solid/400000",
        5,
        "063b26e24858fd2ade98b35c2ef2d51d2fdfcb4979bf60bb8449d1000c3521a9",
    ),
    (
        "r4/m4/plain/40000",
        49,
        "5f158535c13047b3ff015b3362061185290a40d66c2273b0a6aa74c2ffecd35f",
    ),
    (
        "r4/m4/plain/400000",
        5,
        "e74eee2ed2ad681a1e7d4cd9c3e4bb894d4ef46c1fdf7b83fdb859ed29ac9c64",
    ),
    (
        "r4/m5/solid/40000",
        48,
        "4353416426d1a900b56761bdfbe8e6e1abb6da65bc3f42c17afc127c5a279268",
    ),
    (
        "r4/m5/solid/400000",
        5,
        "47af16d97cbacf513b1b40c3e37dd19a446349ba3c6786145c4fd47e10831958",
    ),
    (
        "r4/m5/plain/40000",
        48,
        "4a6e93fca00843b6dbf3cd0ad7ce42aeea5dc6037b0e45e54a4b7afb7e0d46c5",
    ),
    (
        "r4/m5/plain/400000",
        5,
        "23f36d0ea26c8da161ae4d4cfd78f573024f22f57aa34274cc825b72d8c69ba2",
    ),
    (
        "r5/m3/solid/40000+pw",
        49,
        "cc0a85efb7209c3dddbded3188874c36787a60a362110cd011e676f3bb8566d0",
    ),
    (
        "r5/m3/solid/40000+hp",
        49,
        "1a8d7f808fc381ef5fb04a8769c66fdcee218562a3f0842243479ce9579b4618",
    ),
    (
        "r4/m3/solid/40000+pw",
        49,
        "4c663a417a531679c42399e6516f01a6625856288cdf3c453fa49c1cdde6637c",
    ),
    (
        "r4/m3/solid/40000+hp",
        49,
        "9f46b02eb02e25053acd030f36e51a3dfc7d7afc5045cf22f13cde7fbac10d9e",
    ),
    (
        "r5/m3/solid/40000+blake2",
        49,
        "d6e14a363cd9819878d5492e4a0fd2b09c4758584eb503dabfe664741c3cf936",
    ),
    (
        "r5/m3/solid/30000+payload-bound",
        65,
        "ffcd3b40970990b9c3282cc10c4023be4926d503cdc7d362f2f3f522dfff1464",
    ),
    (
        "r5/m3/solid/40000+mm512",
        49,
        "d5ec5a8840e7cb608a4ae50bb6bf53cb413664c4d96991a051275c59e7f3f790",
    ),
    (
        "r5/m5/solid/40000+mm96",
        48,
        "040ff936604114c3e99b702404132a75c9b240cf86e30fe3c5e36f7cabe2bdf6",
    ),
    (
        "r5/m3/plain/40000+pw",
        49,
        "be5f0bdf9e2610a64bcaf0aa30d12ec6caa2816e2b2fd954d82fa3d45129b90f",
    ),
    (
        "r5/m3/plain/40000+hp",
        50,
        "b2a53f6fad017cd62bcd9974655bfa92d39398d700a4a3a0b9cf0dd3c1462120",
    ),
    (
        "r4/m3/plain/40000+pw",
        49,
        "acf092fea2f4a3ebc4407d65bafc574139e72dcff403c20277643e2293dd30f7",
    ),
    (
        "r4/m3/plain/40000+hp",
        49,
        "4ed96d6fce774f6b1893b2c6e5c92fd17807b6e4385957b0646d7002eb246a11",
    ),
    (
        "r5/m3/plain/40000+blake2",
        49,
        "154f16a73d6975577ed19e8840497ae9e1ec0929335f0bd98f2a7aed6b87953a",
    ),
    (
        "r5/m3/plain/30000+payload-bound",
        65,
        "725e004f0bd9800ce4305ab58ccc53b511b086d0d5b0e89a0ac034cfdbb73810",
    ),
    (
        "r5/m3/plain/40000+mm512",
        49,
        "f02d7af6b2c0ab39609773418638ff817b8402431243687f76f085a351cfebe4",
    ),
    (
        "r5/m5/plain/40000+mm96",
        48,
        "b51b8b40e6e150bb75bfcea35b617acdd1e75cabcd053ae526dc94abc0df09e1",
    ),
    (
        "ragged-r5/m1/solid/40000",
        10,
        "6b8da967efdde45ba6eab3716ed289f472ad4ee2509fef9eca456edd6edc3734",
    ),
    (
        "ragged-r5/m3/solid/40000",
        10,
        "4b26fbd0dd42d34b3429441951d40c83e963bc31d802078f615c0b80a8d11c48",
    ),
    (
        "ragged-r5/m5/solid/40000",
        10,
        "c940361838d075e23f81091ea200f3d3f942dbccfc412d6018315f5aee751d96",
    ),
    (
        "ragged-r5/m3/solid/40000+pw",
        10,
        "bb7623124e0b586b803e3ea4eee1f105d072f340f36abc46620814b0bbcf789b",
    ),
    (
        "ragged-r5/m3/plain/40000",
        10,
        "21eaedd00ca86b7fe5fbd44d80f9ed30946b0a7aba1fa6474cd4714868203351",
    ),
    (
        "ragged-r4/m1/solid/40000",
        10,
        "a960d35e849f9d3017a2fa9e07709adceea3d50d74d18c514ea4392496b652c2",
    ),
    (
        "ragged-r4/m3/solid/40000",
        10,
        "37ee6599c356209167d6350b0c7b6118079277e1ca917cb21d51fe720c600d67",
    ),
    (
        "ragged-r4/m5/solid/40000",
        10,
        "8d005766876c9b3ffc352e14c66f226030ac50898b626bfef13bc062a75d4764",
    ),
    (
        "ragged-r4/m3/solid/40000+pw",
        10,
        "5d106209ef40d564f66a27b6e05946ee9a1dc970f19bb627ba183dd974e4a7c4",
    ),
    (
        "ragged-r4/m3/plain/40000",
        10,
        "8b911600014fff8871367ae134cee42b82f849bc2f16ed3fdb5bd9a33807a2d8",
    ),
];

#[test]
fn a_volume_set_of_readers_is_the_archive_it_was_a_member_at_a_time() {
    let mut wrong = Vec::new();
    for (members, rows, as_added) in sets() {
        for row in rows {
            let options = options_of(&row, as_added);
            let (volumes, _) = write(options, &members, Hand::Reader, &mut ());
            let digest = set_digest(&volumes);
            let pinned = PINS.iter().find(|(label, ..)| *label == row.label);
            if pinned != Some(&(row.label.as_str(), volumes.len(), digest.as_str())) {
                eprintln!("PIN (\"{}\", {}, \"{digest}\"),", row.label, volumes.len());
                wrong.push(row.label.clone());
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} row(s) are not the archive the member-at-a-time writer gave: {wrong:?}",
        wrong.len()
    );
}

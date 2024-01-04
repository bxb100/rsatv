//! Parser and data extractor for raw DMAP data.
//!
//! DMAP is basically TLV (see Wikipedia) where the key is a 4 byte ASCII value,
//! a four byte big endian unsigned int as length and the data as data. So:
//!
//! ```plain
//!   +---------------+------------------+--------------------+
//!   | Key (4 bytes) | Length (4 bytes) | Data (Length bytes |
//!   +---------------+------------------+--------------------+
//!```
//!
#![allow(dead_code)]
#![allow(unused_variables)]
use crate::dmap::parser::DmapType::*;
use anyhow::{anyhow, Result};
use bytes::Buf;
use phf::phf_map;
use std::io::Cursor;

#[derive(PartialEq)]
enum DmapType {
    Unknown,
    Uint,
    Int,
    Str,
    Data,
    Date,
    Vers,
    Dict,
    Item,
}

struct DmapField {
    code: &'static str,
    item_type: DmapType,
    list_item_type: Option<DmapType>,
    name: &'static str,
}

macro_rules! dmap_field {
    ($code:expr, $item_type:expr, $list_item_type:expr, $name:expr) => {
        DmapField {
            code: $code,
            item_type: $item_type,
            list_item_type: $list_item_type,
            name: $name,
        }
    };
    ($code:expr, $item_type:expr, $name:expr) => {
        DmapField {
            code: $code,
            item_type: $item_type,
            list_item_type: None,
            name: $name,
        }
    };
}

/// Mapping from https://github.com/postlund/pyatv/blob/master/pyatv/protocols/dmap/tag_definitions.py
static DMAP_MAP: phf::Map<&'static str, DmapField> = phf_map! {
    "aelb" => dmap_field!("aelb", Uint, None, "com.apple.itunes.like-button"),
    "aels" => dmap_field!("aels", Uint, "com.apple.itunes.liked-state"),
    "aeFP" => dmap_field!("aeFP", Uint, "com.apple.itunes.req-fplay"),
    "aeGs" => dmap_field!("aeGs", Uint, "com.apple.itunes.can-be-genius-seed"),
    "aeSV" => dmap_field!("aeSV", Uint, "com.apple.itunes.music-sharing-version"),
    "apro" => dmap_field!("apro", Uint, "daap.protocolversion"),
    "asai" => dmap_field!("asai", Uint, "daap.songalbumid"),
    "asal" => dmap_field!("asal", Str, "daap.songalbum"),
    "asar" => dmap_field!("asar", Str, "daap.songartist"),
    "asgr" => dmap_field!("asgr", Uint, "com.apple.itunes.gapless-resy"),
    "astm" => dmap_field!("astm", Uint, "daap.songtime"),
    "ated" => dmap_field!("ated", Uint, "daap.supportsextradata"),
    "caar" => dmap_field!("caar", Uint, "dacp.albumrepeat"),
    "caas" => dmap_field!("caas", Uint, "dacp.albumshuffle"),
    "caci" => dmap_field!("caci", Dict, "dacp.controlint"),
    "cafe" => dmap_field!("cafe", Uint, "dacp.fullscreenenabled"),
    "cafs" => dmap_field!("cafs", Uint, "dacp.fullscreen"),
    "cana" => dmap_field!("cana", Str, "daap.nowplayingartist"),
    "cang" => dmap_field!("cang", Str, "dacp.nowplayinggenre"),
    "canl" => dmap_field!("canl", Str, "daap.nowplayingalbum"),
    "cann" => dmap_field!("cann", Str, "daap.nowplayingtrack"),
    "canp" => dmap_field!("canp", Uint, "daap.nowplayingid"),
    "cant" => dmap_field!("cant", Uint, "dacp.remainingtime"),
    "capr" => dmap_field!("capr", Uint, "dacp.protocolversion"),
    "caps" => dmap_field!("caps", Uint, "dacp.playstatus"),
    "carp" => dmap_field!("carp", Uint, "dacp.repeatstate"),
    "cash" => dmap_field!("cash", Uint, "dacp.shufflestate"),
    "cast" => dmap_field!("cast", Uint, "dacp.tracklength"),
    "casu" => dmap_field!("casu", Uint, "dacp.su"),
    "cavc" => dmap_field!("cavc", Uint, "dacp.volumecontrollable"),
    "cave" => dmap_field!("cave", Uint, "dacp.dacpvisualizerenabled"),
    "cavs" => dmap_field!("cavs", Uint, "dacp.visualizer"),
    "ceGS" => dmap_field!("ceGS", Str, "com.apple.itunes.genius-selectable"),
    "ceQR" => dmap_field!("ceQR", Dict, "com.apple.itunes.playqueue-contents-response"),
    "ceSD" => dmap_field!("ceSD", Dict, "playing metadata"),
    "cmcp" => dmap_field!("cmcp", Dict, "dmcp.controlprompt"),
    "cmmk" => dmap_field!("cmmk", Uint, "dmcp.mediakind"),
    "cmnm" => dmap_field!("cmnm", Str, "dacp.devicename"),
    "cmpa" => dmap_field!("cmpa", Dict, "dacp.pairinganswer"),
    "cmpg" => dmap_field!("cmpg", Uint, "dacp.pairingguid"),
    "cmpr" => dmap_field!("cmpr", Uint, "dmcp.protocolversion"),
    "cmsr" => dmap_field!("cmsr", Uint, "dmcp.serverrevision"),
    "cmst" => dmap_field!("cmst", Dict, "dmcp.playstatus"),
    "cmty" => dmap_field!("cmty", Str, "dacp.devicetype"),
    "mdcl" => dmap_field!("mdcl", Dict, "dmap.dictionary"),
    "miid" => dmap_field!("miid", Uint, "dmap.itemid"),
    "minm" => dmap_field!("minm", Str, "dmap.itemname"),
    "mlcl" => dmap_field!("mlcl", Dict, Some(Dict), "dmap.listing"),
    "mlid" => dmap_field!("mlid", Uint, "dmap.sessionid"),
    "mlit" => dmap_field!("mlit", Item, "dmap.listingitem"),
    "mlog" => dmap_field!("mlog", Dict, "dmap.loginresponse"),
    "mpro" => dmap_field!("mpro", Uint, "dmap.protocolversion"),
    "mrco" => dmap_field!("mrco", Uint, "dmap.returnedcount"),
    "msal" => dmap_field!("msal", Uint, "dmap.supportsautologout"),
    "msbr" => dmap_field!("msbr", Uint, "dmap.supportsbrowse"),
    "msdc" => dmap_field!("msdc", Uint, "dmap.databasescount"),
    "msed" => dmap_field!("msed", Uint, "dmap.supportsedit"),
    "msex" => dmap_field!("msex", Uint, "dmap.supportsextensions"),
    "msix" => dmap_field!("msix", Uint, "dmap.supportsindex"),
    "mslr" => dmap_field!("mslr", Uint, "dmap.loginrequired"),
    "mspi" => dmap_field!("mspi", Uint, "dmap.supportspersistentids"),
    "msqy" => dmap_field!("msqy", Uint, "dmap.supportsquery"),
    "msrv" => dmap_field!("msrv", Dict, "dmap.serverinforesponse"),
    "mstc" => dmap_field!("mstc", Uint, "dmap.utctime"),
    "mstm" => dmap_field!("mstm", Uint, "dmap.timeoutinterval"),
    "msto" => dmap_field!("msto", Uint, "dmap.utcoffset"),
    "mstt" => dmap_field!("mstt", Uint, "dmap.status"),
    "msup" => dmap_field!("msup", Uint, "dmap.supportsupdate"),
    "mtco" => dmap_field!("mtco", Uint, "dmap.containercount"),
    // Tags with (yet) unknown purpose
    "aead" => dmap_field!("aead", Uint, "unknown tag"),
    "aeFR" => dmap_field!("aeFR", Uint, "unknown tag"),
    "aeSX" => dmap_field!("aeSX", Uint, "unknown tag"),
    "asse" => dmap_field!("asse", Uint, "unknown tag"),
    "atCV" => dmap_field!("atCV", Uint, "unknown tag"),
    "atSV" => dmap_field!("atSV", Uint, "unknown tag"),
    "caks" => dmap_field!("caks", Uint, "unknown tag"),
    "caov" => dmap_field!("caov", Uint, "unknown tag"),
    "capl" => dmap_field!("capl", Uint, "unknown tag"),
    "casa" => dmap_field!("casa", Uint, "unknown tag"),
    "casc" => dmap_field!("casc", Uint, "unknown tag"),
    "cass" => dmap_field!("cass", Uint, "unknown tag"),
    "ceQA" => dmap_field!("ceQA", Uint, "unknown tag"),
    "ceQU" => dmap_field!("ceQU", Uint, "unknown tag"),
    "ceMQ" => dmap_field!("ceMQ", Uint, "unknown tag"),
    "ceNQ" => dmap_field!("ceNQ", Uint, "unknown tag"),
    "ceNR" => dmap_field!("ceNR", Uint, "unknown tag"),
    "ceQu" => dmap_field!("ceQu", Uint, "unknown tag"),
    "cmbe" => dmap_field!("cmbe", Str, "unknown tag"),
    "cmcc" => dmap_field!("cmcc", Str, "unknown tag"),
    "cmce" => dmap_field!("cmce", Str, "unknown tag"),
    "cmcv" => dmap_field!("cmcv", Data, "unknown tag"),
    "cmik" => dmap_field!("cmik", Uint, "unknown tag"),
    "cmsb" => dmap_field!("cmsb", Uint, "unknown tag"),
    "cmsc" => dmap_field!("cmsc", Uint, "unknown tag"),
    "cmsp" => dmap_field!("cmsp", Uint, "unknown tag"),
    "cmsv" => dmap_field!("cmsv", Uint, "unknown tag"),
    "cmte" => dmap_field!("cmte", Str, "unknown tag"),
    "mscu" => dmap_field!("mscu", Uint, "unknown tag"),
};

trait Handler {
    fn on_u32(&mut self, code: &str, field_name: &str, value: u32);
    fn on_i32(&mut self, code: &str, field_name: &str, value: i32);
    fn on_u64(&mut self, code: &str, field_name: &str, value: u64);
    fn on_i64(&mut self, code: &str, field_name: &str, value: i64);
    fn on_data(&mut self, code: &str, field_name: &str, value: &[u8]);
    fn on_string(&mut self, code: &str, field_name: &str, value: &str);
    fn on_date(&mut self, code: &str, field_name: &str, value: u32);
    fn on_dict_start(&mut self, code: &str, field_name: &str);
    fn on_dict_end(&mut self, code: &str, field_name: &str);
}

/// Code: https://github.com/mattstevens/dmap-parser
fn _dmap_parse<T: Handler>(
    setting: &mut T,
    buf: &mut Cursor<&[u8]>,
    len: usize,
    parent: Option<&DmapField>,
) -> Result<()> {
    let end = buf.position() as usize + len;

    // key 4 bytes + length 4 bytes
    while end - buf.position() as usize >= 8 {
        // `get_u32()` will advance the cursor 4 bytes
        // and we know the key is 4 bytes, and length is same
        let code_bytes = buf.get_u32().to_be_bytes();
        let code = unsafe { std::str::from_utf8_unchecked(&code_bytes) };
        let field = DMAP_MAP.get(code);
        let field_len = buf.get_u32() as usize;

        let start = buf.position() as usize;

        if start + field_len > end {
            return Err(anyhow!("Invalid length"));
        }
        let field_name: &str;
        let mut field_type: &DmapType;

        let p = buf.get_ref();

        if field.is_some() {
            field_name = field.unwrap().name;
            field_type = &field.unwrap().item_type;

            if *field_type == Item {
                if parent.is_some() && parent.unwrap().list_item_type.is_some() {
                    field_type = parent.unwrap().list_item_type.as_ref().unwrap();
                } else {
                    field_type = &Dict;
                }
            }
        } else {
            // Guess type
            // I don't know the real situation, so this is the copy from `mattstevens/dmap-parser`
            field_type = &Unknown;
            field_name = code;

            if field_len >= 8 {
                // check if the data is the valid DMAP type
                if p[start].is_ascii_alphabetic()
                    && p[start + 1].is_ascii_alphabetic()
                    && p[start + 2].is_ascii_alphabetic()
                    && p[start + 3].is_ascii_alphabetic()
                {
                    let may_len_arr = &p[start + 4..start + 8];
                    // the remaining length may be contained other Dict
                    if dmap_read_u32(may_len_arr) < field_len as u32 {
                        field_type = &Dict;
                    }
                }
            }

            if *field_type == Unknown {
                let mut is_str = true;
                for i in start..end {
                    // if it is not printable
                    if p[i] <= 0x20 || p[i] > 0x7e {
                        is_str = false;
                        break;
                    }
                }
                field_type = if is_str { &Str } else { &Uint };
            }
        }

        // do
        match *field_type {
            Uint => match field_len {
                1 | 2 | 4 => {
                    setting.on_u32(
                        code,
                        field_name,
                        dmap_read_u32(&p[start..start + field_len]),
                    );
                }
                8 => {
                    setting.on_u64(
                        code,
                        field_name,
                        dmap_read_u64(&p[start..start + field_len]),
                    );
                }
                _ => setting.on_data(code, field_name, &p[start..start + field_len]),
            },
            Int => match field_len {
                1 | 2 | 4 => {
                    setting.on_i32(
                        code,
                        field_name,
                        dmap_read_u32(&p[start..start + field_len]) as i32,
                    );
                }
                8 => {
                    setting.on_i64(
                        code,
                        field_name,
                        dmap_read_u64(&p[start..start + field_len]) as i64,
                    );
                }
                _ => setting.on_data(code, field_name, &p[start..start + field_len]),
            },

            Str => unsafe {
                setting.on_string(
                    code,
                    field_name,
                    std::str::from_utf8_unchecked(&p[start..start + field_len]),
                );
            },

            Data => {
                setting.on_data(code, field_name, &p[start..start + field_len]);
            }

            Date => {
                setting.on_date(
                    code,
                    field_name,
                    dmap_read_u32(&p[start..start + field_len]),
                );
            }

            Vers => {
                if field_len >= 4 {
                    let version = format!(
                        "{}.{}",
                        dmap_read_u16(&p[start + field_len - 4..start + field_len - 2]),
                        dmap_read_u16(&p[start + field_len - 2..start + field_len])
                    );
                    setting.on_string(code, field_name, &version);
                }
            }

            Dict => {
                setting.on_dict_start(code, field_name);
                _dmap_parse(setting, buf, field_len, field)?;
                setting.on_dict_end(code, field_name);
                continue;
            }
            Item => {
                panic!("Item should not be here");
            }
            Unknown => {}
        }

        buf.advance(field_len);
    }

    if buf.position() as usize != end {
        Err(anyhow!("Invalid length"))
    } else {
        Ok(())
    }
}

fn dmap_read_u16(arr: &[u8]) -> u16 {
    let len = arr.len();
    ((arr[len - 2] as u16 * 0xff) << 8) + arr[len - 1] as u16
}
fn dmap_read_u32(arr: &[u8]) -> u32 {
    let len = arr.len();
    ((arr[len - 4] as u32 * 0xff) << 24)
        + ((arr[len - 3] as u32 * 0xff) << 16)
        + ((arr[len - 2] as u32 * 0xff) << 8)
        + arr[len - 1] as u32
}

fn dmap_read_u64(arr: &[u8]) -> u64 {
    let len = arr.len();
    ((arr[len - 8] as u64 * 0xff) << 56)
        + ((arr[len - 7] as u64 * 0xff) << 48)
        + ((arr[len - 6] as u64 * 0xff) << 40)
        + ((arr[len - 5] as u64 * 0xff) << 32)
        + ((arr[len - 4] as u64 * 0xff) << 24)
        + ((arr[len - 3] as u64 * 0xff) << 16)
        + ((arr[len - 2] as u64 * 0xff) << 8)
        + arr[len - 1] as u64
}

#[cfg(test)]
mod test {
    use crate::dmap::parser::Handler;
    use serde::Deserialize;
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::rc::Rc;

    #[derive(Debug, Deserialize)]
    struct Response {
        cmst: Status,
    }

    #[derive(Debug, Deserialize)]
    struct Status {
        mstt: String,
        cmsr: String,
    }

    /// There are two pattern to assemble in this test:
    /// 1. Map with others
    /// 2. String with others
    ///
    /// I don't know how to add a right local variable in the Handler implementation,
    /// so I'm using a `serde_json` to achieve the goal.
    struct TestHandler(u8, Rc<RefCell<String>>);

    impl TestHandler {
        fn insert_str(&mut self, code: &str, value: String) {
            let mut ref_mut = self.1.borrow_mut();

            if !ref_mut.ends_with('{') {
                ref_mut.push(',')
            }

            ref_mut.push_str(format!("\"{}\": \"{}\"", code, value).as_str());
        }
    }
    impl Handler for TestHandler {
        fn on_u32(&mut self, code: &str, field_name: &str, value: u32) {
            let width = self.0 as usize;
            println!("{:>width$}", "|");
            println!("{:>width$} - {}: {}", "+", code, value);
            self.insert_str(code, value.to_string());
        }

        fn on_i32(&mut self, code: &str, field_name: &str, value: i32) {
            let width = self.0 as usize;
            println!("{:>width$}", "|");
            println!("{:>width$} - {}: {}", "+", code, value);
            self.insert_str(code, value.to_string());
        }

        fn on_u64(&mut self, code: &str, field_name: &str, value: u64) {
            let width = self.0 as usize;
            println!("{:>width$}", "|");
            println!("{:>width$} - {}: {}", "+", code, value);
            self.insert_str(code, value.to_string());
        }

        fn on_i64(&mut self, code: &str, field_name: &str, value: i64) {
            let width = self.0 as usize;
            println!("{:>width$}", "|");
            println!("{:>width$} - {}: {}", "+", code, value);
            self.insert_str(code, value.to_string());
        }

        fn on_data(&mut self, code: &str, field_name: &str, value: &[u8]) {
            let width = self.0 as usize;
            println!("{:>width$}", "|");
            println!("{:>width$} - {}: {:?}", "+", code, value);
            self.insert_str(code, format!("{:?}", value));
        }

        fn on_string(&mut self, code: &str, field_name: &str, value: &str) {
            let width = self.0 as usize;
            println!("{:>width$}", "|");
            println!("{:>width$} - {}: {}", "+", code, value);
            self.insert_str(code, value.to_string());
        }

        fn on_date(&mut self, code: &str, field_name: &str, value: u32) {
            let width = self.0 as usize;
            println!("{:>width$}", "|");
            println!("{:>width$} - {}: {}", "+", code, value);
            self.insert_str(code, value.to_string());
        }

        fn on_dict_start(&mut self, code: &str, field_name: &str) {
            let width = self.0 as usize;
            self.0 += 3;
            println!("{:>width$} {}: ", "+", code);

            let mut ref_mut = self.1.borrow_mut();
            // get last char
            if ref_mut.ends_with('}') {
                ref_mut.push(',')
            }

            ref_mut.push_str(format!("\"{}\": {{", code).as_str());
        }

        fn on_dict_end(&mut self, code: &str, field_name: &str) {
            self.0 -= 3;

            self.1.borrow_mut().push('}');
        }
    }

    #[test]
    fn test_parse() {
        let data = b"\x63\x6d\x73\x74\x00\x00\x00\x18\x6d\x73\x74\x74\x00\x00\x00\x04\x00\x00\x00\xc8\x63\x6d\x73\x72\x00\x00\x00\x04\x00\x00\x00\x19";

        let mut buf = Cursor::new(&data[..]);

        let s = Rc::new(RefCell::new("{".to_string()));
        let mut handler = TestHandler(0, s.clone());
        super::_dmap_parse(&mut handler, &mut buf, data.len(), None).unwrap();
        s.borrow_mut().push_str("}\n");

        let json = s.take();

        let res = serde_json::from_str::<Response>(&json).unwrap();
        assert_eq!(res.cmst.mstt, "200");
        assert_eq!(res.cmst.cmsr, "25");
    }
}

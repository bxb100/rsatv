//! https://pyatv.dev/documentation/protocols/#opack

use std::ops::Index;

use nom::{AsBytes, InputTakeAtPosition, IResult};
use nom::bytes::complete::take;
use nom::combinator::{map, map_res};
use nom::number::complete::{be_u8, le_f32, le_f64, le_u128, le_u16, le_u32, le_u8};
use nom::number::streaming::le_u64;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub enum TypeData<'a> {
    Bool(bool),
    None,
    NegativeOne,
    Uuid(Uuid),
    Num(u8),
    NumU8(u8),
    NumU16(u16),
    NumU32(u32),
    NumU64(u64),
    NumU128(u128),
    Float(f32),
    Double(f64),
    Str(&'a str),
    Raw(&'a [u8]),
    Array(Vec<TypeData<'a>>),
    Dict(Vec<(TypeData<'a>, TypeData<'a>)>),
}

fn read_index(input: &[u8]) -> usize {
    // maximum 4 bytes, so we can safely cast to usize(32/64 bits)
    let mut res = 0usize;
    let bound = input.len();

    for i in 0..bound {
        res = (res << 8) + input[bound - i - 1] as usize;
    }
    res
}

pub fn deserializer(input: &[u8]) -> IResult<&[u8], TypeData> {
    _deserializer(input, &mut Vec::new())
}

fn _deserializer<'a>(
    input: &'a [u8], object_list: &mut Vec<TypeData<'a>>,
) -> IResult<&'a [u8], TypeData<'a>> {
    let mut add_to_object_list = true;

    let (input, tag) = be_u8(input)?;

    let data = match tag {
        0x01 => {
            add_to_object_list = false;
            Ok((input, TypeData::Bool(true)))
        }
        0x02 => {
            add_to_object_list = false;
            Ok((input, TypeData::Bool(false)))
        }
        0x04 => {
            add_to_object_list = false;
            Ok((input, TypeData::None))
        }
        0x05 => {
            map_res(take(16usize), |slice| {
                Uuid::from_slice(slice).map(TypeData::Uuid)
            })(input)
        }
        0x06 => {
            // TODO: source code logical only parse as integer
            map(le_u64, TypeData::NumU64)(input)
        }
        0x07 => {
            add_to_object_list = false;
            Ok((input, TypeData::NegativeOne))
        }
        data @ 0x08..=0x2F => {
            add_to_object_list = false;
            Ok((input, TypeData::Num(data - 0x08)))
        }
        // 0x30 0x31 0x32 0x33 0x34
        data if data & 0xF0 == 0x30 => {
            let no_of_bytes = 2u8.pow((data & 0xF) as u32);
            match no_of_bytes {
                1 => map(le_u8, TypeData::NumU8)(input),
                2 => map(le_u16, TypeData::NumU16)(input),
                4 => map(le_u32, TypeData::NumU32)(input),
                8 => map(le_u64, TypeData::NumU64)(input),
                16 => map(le_u128, TypeData::NumU128)(input),
                _ => {
                    return Err(nom::Err::Error(nom::error::Error::new(
                        input,
                        nom::error::ErrorKind::TooLarge,
                    )));
                }
            }
        }
        0x35 => {
            map(le_f32, TypeData::Float)(input)
        }
        0x36 => {
            map(le_f64, TypeData::Double)(input)
        }
        data @ 0x40..=0x60 => {
            let len = data - 0x40;
            map_res(take(len as usize), |slice| {
                std::str::from_utf8(slice).map(TypeData::Str)
            })(input)
        }
        data @ 0x61..=0x64 => {
            let no_of_bytes: usize = (data & 0xF) as usize;
            let len = read_index(&input[..no_of_bytes]);

            map_res(take(len), |slice| {
                std::str::from_utf8(slice).map(TypeData::Str)
            })(&input[no_of_bytes..])
        }
        // null terminated string
        0x6F => {
            let (remaining, data) = input.split_at_position(|item| item == 0x00)?;
            Ok((
                // remove `0x00`
                &remaining[1..],
                TypeData::Str(std::str::from_utf8(data).unwrap()),
            ))
        }
        data @ 0x70..=0x90 => {
            let len = data - 0x70;
            map(take(len as usize), TypeData::Raw)(input)
        }
        data @ 0x91..=0x94 => {
            let no_of_bytes = (data & 0xF) as usize;
            let len = read_index(&input[..no_of_bytes]);
            let (raw, remaining) = input[no_of_bytes..].split_at(len);
            Ok((remaining, TypeData::Raw(raw)))
        }
        // array with v elements
        data if data & 0xD0 == 0xD0 => {
            let v = data & 0x0F;
            let mut ptr = input;
            let mut output: Vec<TypeData> = Vec::new();
            if v == 0xF {
                // endless list
                while ptr[0] != 0x03 {
                    let (remaining, data) = _deserializer(ptr, object_list)?;
                    output.push(data);
                    ptr = remaining;
                }
                // remove `0x03`
                ptr = &ptr[1..];
            } else {
                for _ in 0..v {
                    let (remaining, data) = _deserializer(ptr, object_list)?;
                    output.push(data);
                    ptr = remaining;
                }
            }
            add_to_object_list = false;
            Ok((ptr, TypeData::Array(output)))
        }
        // dict with v elements
        data if data & 0xE0 == 0xE0 => {
            let v = data & 0xF;
            let mut output: Vec<(TypeData, TypeData)> = Vec::new();
            let mut ptr = input;
            if v == 0xF {
                // endless list
                while ptr[0] != 0x03 {
                    let (remaining, key) = _deserializer(ptr, object_list)?;
                    let (remaining, value) = _deserializer(remaining, object_list)?;
                    output.push((key, value));
                    ptr = remaining;
                }
                // remove `0x03`
                ptr = &ptr[1..];
            } else {
                for _ in 0..v {
                    let (remaining, key) = _deserializer(ptr, object_list)?;
                    let (remaining, value) = _deserializer(remaining, object_list)?;
                    output.push((key, value));
                    ptr = remaining;
                }
            }
            add_to_object_list = false;
            Ok((ptr, TypeData::Dict(output)))
        }
        // pointer
        data @ 0xA0..=0xC0 => Ok((input, object_list[(data & 0x1F) as usize].clone())),
        data @ 0xC1..=0xC4 => {
            let len = (data - 0xC0) as usize;
            let uid = read_index(&input[..len]);
            Ok((input, object_list[uid].clone()))
        }
        _ => {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Fail,
            )));
        }
    };

    if let Ok((_, value)) = &data {
        if add_to_object_list && !object_list.contains(value) {
            object_list.push(value.clone());
        }
    }

    data
}

trait ConvertToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

macro_rules! impl_convert_to_bytes {
    ($type:ident, $header:literal) => {
        impl ConvertToBytes for $type {
            fn to_bytes(&self) -> Vec<u8> {
                let mut bytes = vec![$header];
                bytes.extend_from_slice(&self.to_le_bytes());
                bytes
            }
        }
    };

    ($($type:ident, $header:literal),*) => {
        $(
        impl_convert_to_bytes!($type, $header);
        )*
    };
}

impl_convert_to_bytes!(u8, 0x30, u16, 0x31, u32, 0x32, u64, 0x33, u128, 0x34, f32, 0x35, f64, 0x36);

fn _serializer<'a>(data: TypeData<'a>, object_list: &mut Vec<Vec<u8>>) -> anyhow::Result<Vec<u8>> {
    let mut bytes: Vec<u8> = match data {
        TypeData::Bool(data) => {
            if data {
                vec![0x01]
            } else {
                vec![0x02]
            }
        }
        TypeData::None => vec![0x04],
        TypeData::NegativeOne => vec![0x07],
        TypeData::Uuid(data) => {
            let mut bytes = vec![0x05];
            bytes.extend_from_slice(data.as_bytes());
            bytes
        }
        TypeData::Num(data) => {
            vec![data + 0x08]
        }
        TypeData::NumU8(data) => data.to_bytes(),
        TypeData::NumU16(data) => data.to_bytes(),
        TypeData::NumU32(data) => data.to_bytes(),
        TypeData::NumU64(data) => data.to_bytes(),
        TypeData::NumU128(data) => data.to_bytes(),
        TypeData::Float(data) => data.to_bytes(),
        TypeData::Double(data) => data.to_bytes(),
        TypeData::Str(data) => {
            let str_bytes = data.as_bytes();
            let len = str_bytes.len();
            let mut bytes: Vec<u8> = Vec::new();
            if len <= 0x20 {
                bytes.push(0x40 + len as u8);
            } else if len <= 0xFF {
                bytes.push(0x61);
                // 1 byte
                bytes.extend_from_slice(&(len as u8).to_le_bytes());
            } else if len <= 0xFFFF {
                bytes.push(0x62);
                // 2 bytes
                bytes.extend_from_slice(&(len as u16).to_le_bytes());
            } else if len <= 0xFFFFFF {
                bytes.push(0x63);
                // 3 bytes
                bytes.extend_from_slice(&(len as u32).to_le_bytes()[..3]);
            } else if len <= 0xFFFFFFFF {
                bytes.push(0x64);
                // 4 bytes
                bytes.extend_from_slice(&(len as u32).to_le_bytes());
            } else {
                return Err(anyhow::anyhow!("String too long"));
            }
            bytes.extend_from_slice(str_bytes);
            bytes
        }
        TypeData::Raw(data) => {
            let mut bytes: Vec<u8> = Vec::new();
            let len = data.len();
            if len <= 0x20 {
                bytes.push(0x70 + len as u8);
            } else if len <= 0xFF {
                bytes.push(0x91);
                // 1 byte
                bytes.extend_from_slice(&(len as u8).to_le_bytes());
            } else if len <= 0xFFFF {
                bytes.push(0x92);
                // 2 bytes
                bytes.extend_from_slice(&(len as u16).to_le_bytes());
            } else if len <= 0xFFFFFF {
                bytes.push(0x93);
                // 3 bytes
                bytes.extend_from_slice(&(len as u32).to_le_bytes()[..3]);
            } else if len <= 0xFFFFFFFF {
                bytes.push(0x94);
                // 4 bytes
                bytes.extend_from_slice(&(len as u32).to_le_bytes());
            } else {
                return Err(anyhow::anyhow!("Bytes too long"));
            }
            bytes.extend_from_slice(data);
            bytes
        }
        TypeData::Array(data) => {
            let data_len = data.len();
            let len = data_len.min(0xF);
            let mut bytes: Vec<u8> = vec![0xD0 + len as u8];
            for item in data {
                bytes.extend(_serializer(item, object_list)?);
            }
            if data_len >= 0xF {
                bytes.push(0x03);
            }
            bytes
        }
        TypeData::Dict(data) => {
            let data_len = data.len();
            let len = data_len.min(0xF);
            let mut bytes = vec![0xE0 + len as u8];
            for (key, value) in data {
                bytes.extend(_serializer(key, object_list)?);
                bytes.extend(_serializer(value, object_list)?);
            }
            if data_len >= 0xF {
                bytes.push(0x03);
            }
            bytes
        }
    };

    // reuse if in object list, otherwise add it to object list
    if let Some(index) = object_list.iter().position(|item| item == &bytes) {
        if index <= 0x20 {
            bytes = vec![0xA0 + index as u8];
        } else if index <= 0xFF {
            bytes = vec![0xC1, index as u8];
        } else if index <= 0xFFFF {
            bytes = vec![0xC2];
            bytes.extend_from_slice(&(index as u16).to_le_bytes());
            // fixme: it different from python implementation
        } else if index <= 0xFFFFFF {
            bytes = vec![0xC3];
            bytes.extend_from_slice(&(index as u32).to_le_bytes()[..3]);
        } else if index <= 0xFFFFFFFF {
            bytes = vec![0xC4];
            bytes.extend_from_slice(&(index as u32).to_le_bytes());
        } else {
            return Err(anyhow::anyhow!("Object list too long"));
        }
    } else if bytes.len() > 1 {
        object_list.push(bytes.clone());
    }

    Ok(bytes)
}

pub fn serializer(data: TypeData) -> anyhow::Result<Vec<u8>> {
    _serializer(data, &mut Vec::new())
}

#[cfg(test)]
mod deserialize_test {
    use uuid::Uuid;

    use super::{_deserializer, deserializer, TypeData};

    /// ```plain
    /// EF    : Endless dict
    /// 41 61 : "a"
    /// 41 62 : "b"
    /// 03    : Terminates previous dict
    /// ```
    #[test]
    fn test_termination() {
        let input = b"\xEF\x41\x61\x41\x62\x03";

        let (_, data) = deserializer(input).unwrap();

        if let TypeData::Dict(data) = data {
            assert_eq!(data.len(), 1);
            assert_eq!(data[0].0, TypeData::Str("a"));
            assert_eq!(data[0].1, TypeData::Str("b"));
        } else {
            panic!("Expected dict");
        }
    }

    /// ```plain
    /// 05                                                 : UUID
    /// 12 34 56 78 12 12 34 56 78 12 34 56 78 12 34 56 78 : 12345678-1234-5678-1234-567812345678
    /// ```
    ///
    /// don't know `<CFUUID 0x600002af2e80>` yet
    #[test]
    fn test_uuid() {
        // 05 : UUID
        let input = b"\x05\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78";

        let (_, data) = deserializer(input).unwrap();

        assert_eq!(
            data,
            TypeData::Uuid(Uuid::parse_str("12345678-1234-5678-1234-567812345678").unwrap())
        );
    }

    ///```plain
    /// 07                         : -1
    /// 17                         : 15
    /// 30 20                      : 32
    /// 31 20 00                   : 32
    /// 32 20 00 00 00             : 32
    /// 33 20 00 00 00 00 00 00 00 : 32
    /// ```
    #[test]
    fn test_num() {
        let input = b"\x07\x17\x30\x20\x31\x20\x00\x32\x20\x00\x00\x00\x33\x20\x00\x00\x00\x00\x00\x00\x00";
        let mut vec: Vec<TypeData> = Vec::new();

        let (remaining, data) = _deserializer(input, &mut vec).unwrap();
        matches!(data, TypeData::NegativeOne);

        let (remaining, data) = _deserializer(remaining, &mut vec).unwrap();
        if let TypeData::Num(data) = data {
            assert_eq!(data, 15);
        } else {
            panic!("Expected Num");
        }

        let (remaining, data) = _deserializer(remaining, &mut vec).unwrap();
        if let TypeData::NumU8(data) = data {
            assert_eq!(data, 32);
        } else {
            panic!("Expected NumU8");
        }

        let (remaining, data) = _deserializer(remaining, &mut vec).unwrap();
        if let TypeData::NumU16(data) = data {
            assert_eq!(data, 32);
        } else {
            panic!("Expected NumU16");
        }

        let (remaining, data) = _deserializer(remaining, &mut vec).unwrap();
        if let TypeData::NumU32(data) = data {
            assert_eq!(data, 32);
        } else {
            panic!("Expected NumU32");
        }

        let (_, data) = _deserializer(remaining, &mut vec).unwrap();
        if let TypeData::NumU64(data) = data {
            assert_eq!(data, 32);
        } else {
            panic!("Expected NumU64");
        }
    }

    /// ```plain
    /// 72             : AA BB
    /// 91 02          : AA BB
    /// 92 02 00       : AA BB
    /// 93 02 00 00    : AA BB
    /// 94 02 00 00 00 : AA BB
    /// ```
    #[test]
    fn test_raw() {
        let input = b"\x72\xAA\xBB\x91\x02\xAA\xBB\x92\x02\x00\xAA\xBB\x93\x02\x00\x00\xAA\xBB\x94\x02\x00\x00\x00\xAA\xBB";

        let mut vec: Vec<TypeData> = Vec::new();

        let (remaining, data) = _deserializer(input, &mut vec).unwrap();
        if let TypeData::Raw(data) = data {
            assert_eq!(data, &[0xAA, 0xBB]);
        } else {
            panic!("Expected raw");
        }

        let (remaining, data) = _deserializer(remaining, &mut vec).unwrap();
        if let TypeData::Raw(data) = data {
            assert_eq!(data, &[0xAA, 0xBB]);
        } else {
            panic!("Expected raw");
        }

        let (remaining, data) = _deserializer(remaining, &mut vec).unwrap();
        if let TypeData::Raw(data) = data {
            assert_eq!(data, &[0xAA, 0xBB]);
        } else {
            panic!("Expected raw");
        }

        let (remaining, data) = _deserializer(remaining, &mut vec).unwrap();
        if let TypeData::Raw(data) = data {
            assert_eq!(data, &[0xAA, 0xBB]);
        } else {
            panic!("Expected raw");
        }

        let (_, data) = _deserializer(remaining, &mut vec).unwrap();
        if let TypeData::Raw(data) = data {
            assert_eq!(data, &[0xAA, 0xBB]);
        } else {
            panic!("Expected raw");
        }
    }

    /// ```plain
    /// DF    : Endless list
    /// 41 61 : "a"
    /// 03    : Terminates previous list (or dict)
    /// ```
    #[test]
    fn test_endless_collections() {
        let input = b"\xDF\x41\x61\x03";

        let (_, data) = deserializer(input).unwrap();
        assert_eq!(data, TypeData::Array(vec![TypeData::Str("a")]));
    }

    /// ```plain
    /// E3          : Dictionary with three items
    /// 41 61       : "a"
    /// 02          : False
    /// 41 62       : "b"
    /// 44 74657374 : "test"
    /// 41 63       : "c"
    /// A2          : Pointer, index=2
    /// ```
    #[test]
    fn test_pointer() {
        let input = b"\xE3\x41\x61\x02\x41\x62\x44\x74\x65\x73\x74\x41\x63\xA2";

        let (_, data) = deserializer(input).unwrap();

        assert_eq!(
            data,
            TypeData::Dict(vec![
                (TypeData::Str("a"), TypeData::Bool(false)),
                (TypeData::Str("b"), TypeData::Str("test")),
                (TypeData::Str("c"), TypeData::Str("test")),
            ])
        )
    }
}

#[cfg(test)]
mod serialize_test {
    use super::{serializer, TypeData};

    #[test]
    fn test_string() {
        let input = "test";
        let bytes = serializer(TypeData::Str(input)).unwrap();
        assert_eq!(bytes, b"\x44\x74\x65\x73\x74");
    }

    #[test]
    fn test_dict_and_pointer() {
        let input = TypeData::Dict(vec![
            (TypeData::Str("a"), TypeData::Bool(false)),
            (TypeData::Str("b"), TypeData::Str("tes2")),
            (TypeData::Str("c"), TypeData::Str("tes2")),
        ]);
        let bytes = serializer(input).unwrap();
        assert_eq!(bytes, b"\xE3\x41\x61\x02\x41\x62\x44\x74\x65\x73\x32\x41\x63\xA2");
    }
}

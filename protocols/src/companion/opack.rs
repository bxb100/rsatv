//! https://pyatv.dev/documentation/protocols/#opack

use nom::{InputTakeAtPosition, IResult};
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
    Num(u32),
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
            Ok((input, TypeData::Num((data - 0x08) as u32)))
        }
        // 0x30 0x31 0x32 0x33 0x34
        data if data & 0xF0 == 0x30 => {
            let no_of_bytes = 2u8.pow((data & 0xF) as u32);
            match no_of_bytes {
                1 => map(le_u8, |num| TypeData::Num(num as u32))(input),
                2 => map(le_u16, |num| TypeData::Num(num as u32))(input),
                4 => map(le_u32, TypeData::Num)(input),
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

#[cfg(test)]
mod serialize_test {
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
        if let TypeData::Num(data) = data {
            assert_eq!(data, 32);
        } else {
            panic!("Expected Num");
        }

        let (remaining, data) = _deserializer(remaining, &mut vec).unwrap();
        if let TypeData::Num(data) = data {
            assert_eq!(data, 32);
        } else {
            panic!("Expected Num");
        }

        let (remaining, data) = _deserializer(remaining, &mut vec).unwrap();
        if let TypeData::Num(data) = data {
            assert_eq!(data, 32);
        } else {
            panic!("Expected Num");
        }

        let (_, data) = _deserializer(remaining, &mut vec).unwrap();
        if let TypeData::NumU64(data) = data {
            assert_eq!(data, 32);
        } else {
            panic!("Expected Num");
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
use super::tag_definition::Tag::*;
use super::tag_definition::DMAP_MAP;
use nom::bytes::complete::take;
use nom::combinator::{flat_map, map, map_parser, map_res};
use nom::multi::many0;
use nom::sequence::pair;
use nom::{IResult, Needed};
use std::collections::HashMap;
use std::str::from_utf8;

fn key_data(input: &[u8]) -> IResult<&[u8], &str> {
    map_res(take(4usize), from_utf8)(input)
}

fn read_usize(arr: &[u8]) -> usize {
    let mut sum = 0usize;

    for i in 0..arr.len() {
        sum += (arr[i] as usize) << (8 * (arr.len() - i - 1));
    }

    sum
}

fn len_data(input: &[u8]) -> IResult<&[u8], usize> {
    map(take(4usize), read_usize)(input)
}

#[derive(Debug, PartialEq)]
pub enum TagType {
    Container(HashMap<String, TagType>),
    String(String),
    Uint(usize),
    Bool(bool),
    Bytes(Vec<u8>),
}

fn container_data(tag_name: String, input: &[u8], len: usize) -> IResult<&[u8], (String, TagType)> {
    if input.len() < len {
        return Err(nom::Err::Incomplete(Needed::new(len)));
    }

    if len < 1 {
        return Err(nom::Err::Incomplete(Needed::new(1)));
    }

    let inner_content_parser = map_parser(take(len), many0(parser));

    map(inner_content_parser, |tags| {
        (
            tag_name.clone(),
            TagType::Container(tags.into_iter().collect()),
        )
    })(input)
}

fn uint_data(tag_name: String, input: &[u8], len: usize) -> IResult<&[u8], (String, TagType)> {
    if input.len() < len {
        return Err(nom::Err::Incomplete(Needed::new(len)));
    }

    if len < 1 {
        return Err(nom::Err::Incomplete(Needed::new(1)));
    }

    map(take(len), |bytes| {
        (tag_name.clone(), TagType::Uint(read_usize(bytes)))
    })(input)
}

fn string_data(tag_name: String, input: &[u8], len: usize) -> IResult<&[u8], (String, TagType)> {
    if input.len() < len {
        return Err(nom::Err::Incomplete(Needed::new(len)));
    }

    if len < 1 {
        return Err(nom::Err::Incomplete(Needed::new(1)));
    }

    map_res(take(len), |bytes: &[u8]| {
        let mut trim_data = bytes;

        while trim_data.first() == Some(&0u8) {
            trim_data = &trim_data[1..];
        }

        match String::from_utf8(trim_data.to_vec()) {
            Ok(s) => Ok((tag_name.clone(), TagType::String(s))),
            Err(e) => Err(nom::Err::Failure(e)),
        }
    })(input)
}

fn bool_data(tag_name: String, input: &[u8], len: usize) -> IResult<&[u8], (String, TagType)> {
    if input.len() < len {
        return Err(nom::Err::Incomplete(Needed::new(len)));
    }

    if len < 1 {
        return Err(nom::Err::Incomplete(Needed::new(1)));
    }

    map(take(len), |bytes: &[u8]| {
        (tag_name.clone(), TagType::Bool(bytes.last() == Some(&1u8)))
    })(input)
}

fn bytes_data(tag_name: String, input: &[u8], len: usize) -> IResult<&[u8], (String, TagType)> {
    if input.len() < len {
        return Err(nom::Err::Incomplete(Needed::new(len)));
    }

    if len < 1 {
        return Err(nom::Err::Incomplete(Needed::new(1)));
    }

    map(take(len), |bytes: &[u8]| {
        (tag_name.clone(), TagType::Bytes(bytes.to_vec()))
    })(input)
}

fn map_tag_type(tag: String, size: usize) -> impl Fn(&[u8]) -> IResult<&[u8], (String, TagType)> {
    let opt_tag_type = DMAP_MAP.get(tag.as_str());

    move | input | match opt_tag_type {
        Some(Uint) => uint_data,
        Some(Str) => string_data,
        Some(Dict) => container_data,
        Some(Data) => bytes_data,
        Some(Bool) => bool_data,
        None => panic!("Unknown tag: {}", tag),
    }(tag.clone(), input, size)
}

pub fn parser(input: &[u8]) -> IResult<&[u8], (String, TagType)> {
    flat_map(pair(key_data, len_data), |(key, len)| {
        map_tag_type(key.to_string(), len)
    })(input)
}

#[cfg(test)]
mod test {
    use super::*;
    use nom::sequence::pair;

    const DATA: &[u8; 32] = b"\x63\x6d\x73\x74\x00\x00\x00\x18\x6d\x73\x74\x74\x00\x00\x00\x04\x00\x00\x00\xc8\x63\x6d\x73\x72\x00\x00\x00\x04\x00\x00\x00\x19";

    #[test]
    fn test_tl_data() {
        let (remaining, key) = key_data(DATA).unwrap();
        assert_eq!(key, "cmst");
        let (_, len) = len_data(remaining).unwrap();
        assert_eq!(len, 24);
    }

    #[test]
    fn simple_test_raw_data() {
        let (remaining, (key, len)) = pair(key_data, len_data)(DATA).unwrap();
        assert_eq!(key, "cmst");
        assert_eq!(len, 24);
    }

    #[test]
    fn test_parse() {
        let (remaining, (tag_name, tag_type)) = parser(DATA).unwrap();

        assert_eq!(tag_name, "cmst");

        assert_eq!(
            TagType::Container(
                vec![
                    ("mstt".to_string(), TagType::Uint(200)),
                    ("cmsr".to_string(), TagType::Uint(25)),
                ]
                .into_iter()
                .collect()
            ),
            tag_type
        );

        assert!(remaining.is_empty());
    }

    #[test]
    fn test_string_data() {
        let data: &[u8] = b"\x00\x00\x00\x63\x6d\x73\x74";
        let (r, (_, t)) = string_data("_".to_string(), data, data.len()).unwrap();
        assert_eq!(t, TagType::String("cmst".to_string()));
        assert!(r.is_empty());
    }
}

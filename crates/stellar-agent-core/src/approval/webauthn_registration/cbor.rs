//! A bounded decoder for the CBOR subset a WebAuthn attestation object uses.
//!
//! The decoder accepts only definite-length items with minimal-length
//! arguments, no tags, no floating-point or undefined values, no duplicate
//! map keys, a bounded nesting depth and item count, and no trailing bytes.
//! It imposes no order on map keys.

/// Deepest CBOR nesting the decoder accepts. The attestation object nests
/// two levels, an extension map at most three.
const CBOR_MAX_DEPTH: usize = 4;

/// Most CBOR items one decode accepts.
const CBOR_MAX_ITEMS: usize = 64;

/// A decoded CBOR item of the subset the attestation object uses.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Cbor<'a> {
    /// Major type 0.
    Unsigned(u64),
    /// Major type 1: the value is `-1 - n`.
    Negative(u64),
    /// Major type 2.
    Bytes(&'a [u8]),
    /// Major type 3, valid UTF-8.
    Text(&'a str),
    /// Major type 4.
    Array(Vec<Cbor<'a>>),
    /// Major type 5, keys unique.
    Map(Vec<(Cbor<'a>, Cbor<'a>)>),
    /// Simple values 20 and 21.
    Bool(bool),
    /// Simple value 22.
    Null,
}

impl Cbor<'_> {
    /// The item as an integer, when it is one that fits `i64`.
    pub(super) fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Unsigned(n) => i64::try_from(*n).ok(),
            Self::Negative(n) => i64::try_from(*n).ok().map(|n| -1 - n),
            _ => None,
        }
    }
}

/// Why the CBOR decoder refused its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Malformed;

/// Decodes exactly one item that spans all of `input`.
pub(super) fn decode_complete(input: &[u8]) -> Result<Cbor<'_>, Malformed> {
    let (value, used) = decode_prefix(input)?;
    if used == input.len() {
        Ok(value)
    } else {
        Err(Malformed)
    }
}

/// Decodes one item from the start of `input` and returns it with the
/// number of bytes it spans.
pub(super) fn decode_prefix(input: &[u8]) -> Result<(Cbor<'_>, usize), Malformed> {
    let mut decoder = Decoder {
        input,
        pos: 0,
        items: 0,
    };
    let value = decoder.item(0)?;
    Ok((value, decoder.pos))
}

struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
    items: usize,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], Malformed> {
        let end = self.pos.checked_add(len).ok_or(Malformed)?;
        let bytes = self.input.get(self.pos..end).ok_or(Malformed)?;
        self.pos = end;
        Ok(bytes)
    }

    fn remaining(&self) -> usize {
        self.input.len() - self.pos
    }

    /// Reads the argument of an item head, refusing indefinite lengths,
    /// reserved encodings, and any argument not in its shortest form.
    fn argument(&mut self, info: u8) -> Result<u64, Malformed> {
        let (value, minimum) = match info {
            0..=23 => return Ok(u64::from(info)),
            24 => (u64::from(self.take(1)?[0]), 24),
            25 => {
                let b = self.take(2)?;
                (u64::from(u16::from_be_bytes([b[0], b[1]])), 0x100)
            }
            26 => {
                let b = self.take(4)?;
                (
                    u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
                    0x1_0000,
                )
            }
            27 => {
                let b = self.take(8)?;
                (
                    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
                    0x1_0000_0000,
                )
            }
            _ => return Err(Malformed),
        };
        if value < minimum {
            return Err(Malformed);
        }
        Ok(value)
    }

    fn length(&mut self, info: u8) -> Result<usize, Malformed> {
        usize::try_from(self.argument(info)?).map_err(|_| Malformed)
    }

    fn item(&mut self, depth: usize) -> Result<Cbor<'a>, Malformed> {
        self.items += 1;
        if self.items > CBOR_MAX_ITEMS || depth > CBOR_MAX_DEPTH {
            return Err(Malformed);
        }
        let head = self.take(1)?[0];
        let info = head & 0x1f;
        match head >> 5 {
            0 => Ok(Cbor::Unsigned(self.argument(info)?)),
            1 => Ok(Cbor::Negative(self.argument(info)?)),
            2 => {
                let len = self.length(info)?;
                Ok(Cbor::Bytes(self.take(len)?))
            }
            3 => {
                let len = self.length(info)?;
                let text = std::str::from_utf8(self.take(len)?).map_err(|_| Malformed)?;
                Ok(Cbor::Text(text))
            }
            4 => {
                let len = self.length(info)?;
                if len > self.remaining() {
                    return Err(Malformed);
                }
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(self.item(depth + 1)?);
                }
                Ok(Cbor::Array(items))
            }
            5 => {
                let len = self.length(info)?;
                if len > self.remaining() / 2 {
                    return Err(Malformed);
                }
                let mut entries = Vec::with_capacity(len);
                let mut keys: Vec<&'a [u8]> = Vec::with_capacity(len);
                for _ in 0..len {
                    let start = self.pos;
                    let key = self.item(depth + 1)?;
                    let encoded = &self.input[start..self.pos];
                    if keys.contains(&encoded) {
                        return Err(Malformed);
                    }
                    keys.push(encoded);
                    let value = self.item(depth + 1)?;
                    entries.push((key, value));
                }
                Ok(Cbor::Map(entries))
            }
            7 => match info {
                20 => Ok(Cbor::Bool(false)),
                21 => Ok(Cbor::Bool(true)),
                22 => Ok(Cbor::Null),
                _ => Err(Malformed),
            },
            _ => Err(Malformed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbor_decoder_refuses_what_it_does_not_accept() {
        for input in [
            &[0x18, 0x05][..],
            &[0x19, 0x00, 0x10],
            &[0x1a, 0x00, 0x00, 0x01, 0x00],
            &[0x1b, 0, 0, 0, 0, 0, 0, 0xff, 0xff],
            &[0x1c],
            &[0x5f, 0xff],
            &[0x62, 0xff, 0xfe],
            &[0xf9, 0x00, 0x00],
            &[0xf7],
            &[0xc1, 0x00],
            &[0xa2, 0x01, 0x02, 0x01, 0x03],
            &[0x81, 0x81, 0x81, 0x81, 0x81, 0x00],
            &[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ] {
            assert_eq!(decode_complete(input), Err(Malformed), "{input:02x?}");
        }
        let many: Vec<u8> = std::iter::once(0x98)
            .chain(std::iter::once(CBOR_MAX_ITEMS as u8))
            .chain(std::iter::repeat_n(0x00, CBOR_MAX_ITEMS))
            .collect();
        assert_eq!(decode_complete(&many), Err(Malformed));
        assert_eq!(
            decode_complete(&[0x82, 0x20, 0xf5]),
            Ok(Cbor::Array(vec![Cbor::Negative(0), Cbor::Bool(true)]))
        );
        assert_eq!(decode_complete(&[0x18, 0x18]), Ok(Cbor::Unsigned(24)));
    }
}

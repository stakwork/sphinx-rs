use std::io::Read;
use std::io::Result;

pub(crate) struct VvCursor {
    pos: usize,
    index: usize,
    bytes: Vec<Vec<u8>>,
}

impl VvCursor {
    pub(crate) fn new(bytes: Vec<Vec<u8>>) -> Self {
        VvCursor {
            pos: 0usize,
            index: 0usize,
            bytes,
        }
    }
    pub(crate) fn _get_caps(&self) -> Vec<usize> {
        self.bytes.iter().map(|vector| vector.capacity()).collect()
    }
}

impl Read for VvCursor {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.bytes.is_empty() {
            return Ok(0);
        }
        let mut total = 0usize;
        loop {
            let n = (&(self.bytes[self.index])[self.pos..]).read(&mut buf[total..])?;
            total += n;
            if self.pos + n == self.bytes[self.index].len() {
                self.bytes[self.index].clear();
                self.bytes[self.index].shrink_to(0usize);
                self.pos = 0;
                self.index += 1;
            } else {
                self.pos += n;
                return Ok(total);
            }
            if self.index == self.bytes.len() {
                return Ok(total);
            }
        }
    }
}

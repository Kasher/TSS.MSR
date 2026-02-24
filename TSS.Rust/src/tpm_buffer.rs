// Since all of the functions here are called from auto-generated code that expects a specific names,
// we have to use those names and not the Rust convention of snake_case
#![allow(non_snake_case)]

use crate::error::TpmError;
use crate::tpm_structure::TpmEnum;

pub struct SizedStructInfo {
    pub start_pos: usize,
    pub size: usize,
}

pub trait TpmMarshaller {
    /** Convert this object to its TPM representation and store it in the given marshaling buffer */
    fn toTpm(&self, buf: &mut TpmBuffer) -> Result<(), TpmError>;

    /** Populate this object from the TPM representation in the given marshaling buffer */
    fn initFromTpm(&mut self, buf: &mut TpmBuffer) -> Result<(), TpmError>;
}

pub struct TpmBuffer {
    buf: Vec<u8>,
    pos: usize,
    out_of_bounds: bool,
    sized_struct_sizes: Vec<SizedStructInfo>,
}

impl TpmBuffer {
    /** Constructs output (default) or input marshaling buffer depending on the parameter. */
    pub fn new(capacity_or_src_buf: Option<&TpmBuffer>) -> Self {
        match capacity_or_src_buf {
            Some(src_buf) => TpmBuffer {
                buf: src_buf.buf.clone(),
                pos: src_buf.pos,
                out_of_bounds: false,
                sized_struct_sizes: Vec::new(),
            },
            None => TpmBuffer {
                buf: Vec::with_capacity(4096),
                pos: 0,
                out_of_bounds: false,
                sized_struct_sizes: Vec::new(),
            },
        }
    }

    pub fn from(src_buf: &[u8]) -> Self {
        TpmBuffer {
            buf: src_buf.to_vec(),
            pos: 0,
            out_of_bounds: false,
            sized_struct_sizes: Vec::new(),
        }
    }

    /** @return Reference to the backing byte buffer */
    pub fn buffer(&self) -> &Vec<u8> {
        &self.buf
    }

    /** @return Size of the backing byte buffer. */
    pub fn size(&self) -> usize {
        self.buf.len()
    }

    /** @return Current read/write position in the backing byte buffer. */
    pub fn current_pos(&self) -> usize {
        self.pos
    }

    /** Sets the current read/write position in the backing byte buffer. */
    pub fn set_current_pos(&mut self, new_pos: usize) {
        self.pos = new_pos;
        self.out_of_bounds = self.size() < new_pos;
    }

    /** @return True unless a previous read/write operation caused under/overflow correspondingly. */
    pub fn isOk(&self) -> bool {
        !self.out_of_bounds
    }

    /** Shrinks the backing byte buffer so that it ends at the current position */
    pub fn trim(&mut self) -> &Vec<u8> {
        self.buf.truncate(self.pos);
        &self.buf
    }

    pub fn getCurStuctRemainingSize(&self) -> usize {
        if let Some(ssi) = self.sized_struct_sizes.last() {
            return ssi.size - (self.pos - ssi.start_pos);
        }
        0
    }

    fn check_len(&mut self, len: usize) -> bool {
        if self.buf.len() < self.pos + len {
            // Grow the buffer if needed on write operations
            self.buf.resize(self.pos + len, 0);
        }
        true
    }

    pub fn write_num(&mut self, val: u64, len: usize) {
        if !self.check_len(len) {
            return;
        }

        if len == 8 {
            self.buf[self.pos] = ((val >> 56) & 0xFF) as u8;
            self.pos += 1;
            self.buf[self.pos] = ((val >> 48) & 0xFF) as u8;
            self.pos += 1;
            self.buf[self.pos] = ((val >> 40) & 0xFF) as u8;
            self.pos += 1;
            self.buf[self.pos] = ((val >> 32) & 0xFF) as u8;
            self.pos += 1;
        }
        if len >= 4 {
            self.buf[self.pos] = ((val >> 24) & 0xFF) as u8;
            self.pos += 1;
            self.buf[self.pos] = ((val >> 16) & 0xFF) as u8;
            self.pos += 1;
        }
        if len >= 2 {
            self.buf[self.pos] = ((val >> 8) & 0xFF) as u8;
            self.pos += 1;
        }
        self.buf[self.pos] = (val & 0xFF) as u8;
        self.pos += 1;
    }

    pub fn read_num(&mut self, len: usize) -> u64 {
        if !self.check_len(len) {
            return 0;
        }

        let mut res: u64 = 0;
        if len == 8 {
            res += (self.buf[self.pos] as u64) << 56;
            self.pos += 1;
            res += (self.buf[self.pos] as u64) << 48;
            self.pos += 1;
            res += (self.buf[self.pos] as u64) << 40;
            self.pos += 1;
            res += (self.buf[self.pos] as u64) << 32;
            self.pos += 1;
        }
        if len >= 4 {
            res += (self.buf[self.pos] as u64) << 24;
            self.pos += 1;
            res += (self.buf[self.pos] as u64) << 16;
            self.pos += 1;
        }
        if len >= 2 {
            res += (self.buf[self.pos] as u64) << 8;
            self.pos += 1;
        }
        res += (self.buf[self.pos] as u8) as u64;
        self.pos += 1;
        res
    }

    pub fn write_num_at_pos(&mut self, val: u64, pos: usize, len: usize) {
        let cur_pos = self.pos;
        self.pos = pos;
        self.write_num(val, len);
        self.pos = cur_pos;
    }

    /** Writes the given 8-bit integer to this buffer */
    pub fn writeByte(&mut self, val: u8) {
        if self.check_len(1) {
            self.buf[self.pos] = val;
            self.pos += 1;
        }
    }

    /** Marshals the given 16-bit integer to this buffer. */
    pub fn writeShort(&mut self, val: u16) {
        self.write_num(val as u64, 2);
    }

    /** Marshals the given 32-bit integer to this buffer. */
    pub fn writeInt(&mut self, val: u32) {
        self.write_num(val as u64, 4);
    }

    /** Marshals the given 64-bit integer to this buffer. */
    pub fn writeInt64(&mut self, val: u64) {
        self.write_num(val, 8);
    }

    /** Reads a byte from this buffer. */
    pub fn readByte(&mut self) -> u8 {
        if self.check_len(1) {
            let val = self.buf[self.pos];
            self.pos += 1;
            return val;
        }
        0
    }

    /** Unmarshals a 16-bit integer from this buffer. */
    pub fn readShort(&mut self) -> u16 {
        self.read_num(2) as u16
    }

    /** Unmarshals a 32-bit integer from this buffer. */
    pub fn readInt(&mut self) -> u32 {
        self.read_num(4) as u32
    }

    /** Unmarshals a 64-bit integer from this buffer. */
    pub fn readInt64(&mut self) -> u64 {
        self.read_num(8)
    }

    /** Marshalls the given byte buffer with no length prefix. */
    pub fn writeByteBuf(&mut self, data: &Vec<u8>) {
        let data_size = data.len();
        if data_size == 0 || !self.check_len(data_size) {
            return;
        }
        for i in 0..data_size {
            self.buf[self.pos + i] = data[i];
        }
        self.pos += data_size;
    }

    /** Unmarshalls a byte buffer of the given size (no marshaled length prefix). */
    pub fn readByteBuf(&mut self, size: usize) -> Vec<u8> {
        if !self.check_len(size) {
            return Vec::new().into();
        }
        let mut new_buf = Vec::with_capacity(size);
        for i in 0..size {
            new_buf.push(self.buf[self.pos + i]);
        }
        self.pos += size;
        new_buf
    }

    /** Marshalls the given byte buffer with a length prefix. */
    pub fn writeSizedByteBuf(&mut self, data: &Vec<u8>, size_len: usize) {
        self.write_num(data.len() as u64, size_len);
        self.writeByteBuf(data);
    }

    /** Unmarshals a byte buffer from its size-prefixed representation in the TPM wire format. */
    pub fn readSizedByteBuf(&mut self, size_len: usize) -> Vec<u8> {
        let size = self.read_num(size_len) as usize;
        self.readByteBuf(size)
    }

    pub fn createObj<T: TpmMarshaller + Default>(&mut self) -> Result<T, TpmError> {
        let mut new_obj = T::default();
        new_obj.initFromTpm(self)?;
        Ok(new_obj)
    }

    pub fn writeSizedObj<T: TpmMarshaller>(&mut self, obj: &T) -> Result<(), TpmError> {
        const LEN_SIZE: usize = 2; // Length of the object size is always 2 bytes
        if !self.check_len(LEN_SIZE) {
            return Ok(());
        }

        // Remember position to marshal the size of the data structure
        let size_pos = self.pos;
        // Account for the reserved size area
        self.pos += LEN_SIZE;
        // Marshal the object
        obj.toTpm(self)?;
        // Calc marshaled object len
        let obj_size = self.pos - (size_pos + LEN_SIZE);
        // Marshal it in the appropriate position
        self.pos = size_pos;
        self.writeShort(obj_size as u16);
        self.pos += obj_size;

        Ok(())
    }

    pub fn readSizedObj<T: TpmMarshaller + Default>(
        &mut self,
        obj: &mut T,
    ) -> Result<(), TpmError> {
        let size = self.readShort();
        if size == 0 {
            return Ok(());
        }

        self.sized_struct_sizes.push(SizedStructInfo {
            start_pos: self.pos,
            size: size as usize,
        });

        obj.initFromTpm(self)?;

        self.sized_struct_sizes.pop();
        Ok(())
    }

    pub fn writeObjArr<T: TpmMarshaller>(&mut self, arr: &[T]) -> Result<(), TpmError> {
        self.writeInt(arr.len() as u32);
        for elt in arr {
            if !self.isOk() {
                break;
            }
            elt.toTpm(self)?;
        }

        Ok(())
    }

    pub fn readObjArr<T: TpmMarshaller + Default>(
        &mut self,
        arr: &mut Vec<T>,
    ) -> Result<(), TpmError> {
        let len = self.readInt();
        if len == 0 {
            return Ok(arr.clear());
        }

        arr.resize_with(len as usize, T::default);
        for elt in arr {
            if !self.isOk() {
                break;
            }
            elt.initFromTpm(self)?;
        }

        Ok(())
    }

    pub fn writeValArr<T, U>(&mut self, arr: &[T], val_size: usize)
    where
        T: TpmEnum<U> + Default,
        U: Into<u64>,
    {
        // Length of the array size is always 4 bytes
        self.writeInt(arr.len() as u32);
        for val in arr {
            if !self.isOk() {
                break;
            }
            self.write_num(val.get_value().into(), val_size);
        }
    }

    pub fn readValArr<T, U>(&mut self, arr: &mut Vec<T>, val_size: usize) -> Result<(), TpmError>
    where
        T: TpmEnum<U> + Default,
        U: Into<u64>,
    {
        // Length of the array size is always 4 bytes
        let len = self.readInt();
        if len == 0 {
            return Ok(arr.clear());
        }

        arr.resize_with(len as usize, Default::default);

        for elt in arr {
            if !self.isOk() {
                break;
            }

            *elt = T::new_from_trait((self.read_num(val_size) as u32).into())?;
        }

        Ok(())
    }
}

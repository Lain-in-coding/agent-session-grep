//! Incremental typed commitment over the fixed old-catalog row projection.
//! The caller supplies rows from one separately admitted snapshot. A completed
//! digest proves those supplied bytes only, not a live database or lock.

#[path = "managed_schema_transition_projection.rs"]
mod projection;
pub use projection::{TABLES, TableProjection};
use std::{cmp::Ordering, fmt};

const DOMAIN: &[u8] = b"asg.transition.catalog-preserved-rows/v1\0";

/// No row count cap: lengths/counts are checked against their wire widths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentError {
    Invalid,
    Overflow,
    Allocation,
    Unordered,
}

impl fmt::Display for CommitmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid catalog commitment input",
            Self::Overflow => "catalog commitment framing overflow",
            Self::Allocation => "catalog commitment scratch unavailable",
            Self::Unordered => "catalog commitment rows out of order",
        })
    }
}
impl std::error::Error for CommitmentError {}
type Result<T> = std::result::Result<T, CommitmentError>;

#[derive(Clone, Copy, Debug)]
pub enum Cell<'a> {
    Null,
    Integer(i64),
    Text(&'a [u8]),
    Blob(&'a [u8]),
    Real(f64),
}

fn scalar_len(cell: Cell<'_>) -> Result<usize> {
    match cell {
        Cell::Null => Ok(1),
        Cell::Integer(_) => Ok(9),
        Cell::Real(value) => {
            if value.is_nan() {
                Err(CommitmentError::Invalid)
            } else {
                Ok(9)
            }
        }
        Cell::Text(bytes) | Cell::Blob(bytes) => {
            u32::try_from(bytes.len()).map_err(|_| CommitmentError::Overflow)?;
            if matches!(cell, Cell::Text(_)) && std::str::from_utf8(bytes).is_err() {
                return Err(CommitmentError::Invalid);
            }
            bytes.len().checked_add(5).ok_or(CommitmentError::Overflow)
        }
    }
}

fn append_cell(output: &mut Vec<u8>, cell: Cell<'_>) {
    match cell {
        Cell::Null => output.push(0),
        Cell::Integer(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_le_bytes());
        }
        Cell::Text(bytes) | Cell::Blob(bytes) => {
            output.push(if matches!(cell, Cell::Text(_)) { 2 } else { 3 });
            // Width was checked before any output mutation.
            output.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            output.extend_from_slice(bytes);
        }
        Cell::Real(value) => {
            output.push(4);
            output.extend_from_slice(&value.to_bits().to_le_bytes());
        }
    }
}

/// Exact final BLOB tie-break key for optional statistics. No hash, rowid or
/// string coercion substitutes for the typed bytes.
pub fn encode_row(cells: &[Cell<'_>], output: &mut Vec<u8>) -> Result<()> {
    let length = cells.iter().try_fold(0_usize, |length, cell| {
        length
            .checked_add(scalar_len(*cell)?)
            .ok_or(CommitmentError::Overflow)
    })?;
    output.clear();
    output
        .try_reserve(length)
        .map_err(|_| CommitmentError::Allocation)?;
    for cell in cells {
        append_cell(output, *cell);
    }
    Ok(())
}

fn decode_cells(bytes: &[u8], column_count: usize) -> Result<Vec<Cell<'_>>> {
    let mut cells = Vec::new();
    cells
        .try_reserve_exact(column_count)
        .map_err(|_| CommitmentError::Allocation)?;
    let mut rest = bytes;
    while let Some((&tag, tail)) = rest.split_first() {
        if cells.len() == column_count {
            return Err(CommitmentError::Invalid);
        }
        rest = tail;
        let cell = match tag {
            0 => Cell::Null,
            1 | 4 => {
                let encoded = rest.get(..8).ok_or(CommitmentError::Invalid)?;
                let value: [u8; 8] = encoded.try_into().map_err(|_| CommitmentError::Invalid)?;
                rest = &rest[8..];
                if tag == 1 {
                    Cell::Integer(i64::from_le_bytes(value))
                } else {
                    Cell::Real(f64::from_bits(u64::from_le_bytes(value)))
                }
            }
            2 | 3 => {
                let encoded: [u8; 4] = rest
                    .get(..4)
                    .ok_or(CommitmentError::Invalid)?
                    .try_into()
                    .map_err(|_| CommitmentError::Invalid)?;
                let length = u32::from_le_bytes(encoded) as usize;
                rest = &rest[4..];
                let value = rest.get(..length).ok_or(CommitmentError::Invalid)?;
                rest = &rest[length..];
                if tag == 2 {
                    Cell::Text(value)
                } else {
                    Cell::Blob(value)
                }
            }
            _ => return Err(CommitmentError::Invalid),
        };
        scalar_len(cell)?;
        cells.push(cell);
    }
    Ok(cells)
}

fn class(cell: Cell<'_>) -> u8 {
    match cell {
        Cell::Null => 0,
        Cell::Integer(_) | Cell::Real(_) => 1,
        Cell::Text(_) => 2,
        Cell::Blob(_) => 3,
    }
}

// Same boundary handling as SQLite's sqlite3IntFloatCompare. Casting the i64 to
// f64 first loses ordering above 2^53; compare the integral part before that cast.
fn integer_real(integer: i64, real: f64) -> Ordering {
    if real < -9_223_372_036_854_775_808.0 {
        return Ordering::Greater;
    }
    if real >= 9_223_372_036_854_775_808.0 {
        return Ordering::Less;
    }
    match integer.cmp(&(real as i64)) {
        Ordering::Equal => (integer as f64)
            .partial_cmp(&real)
            .unwrap_or(Ordering::Equal),
        result => result,
    }
}

fn compare_cell(left: Cell<'_>, right: Cell<'_>) -> Ordering {
    match (left, right) {
        (Cell::Integer(a), Cell::Integer(b)) => a.cmp(&b),
        (Cell::Real(a), Cell::Real(b)) => a.partial_cmp(&b).unwrap_or(Ordering::Equal),
        (Cell::Integer(a), Cell::Real(b)) => integer_real(a, b),
        (Cell::Real(a), Cell::Integer(b)) => integer_real(b, a).reverse(),
        (Cell::Text(a), Cell::Text(b)) | (Cell::Blob(a), Cell::Blob(b)) => a.cmp(b),
        _ => class(left).cmp(&class(right)),
    }
}

/// Compare fixed SQL keys then, for stats, full typed row bytes. This pure
/// comparator also makes INTEGER/REAL ties testable without a native query.
pub fn compare_rows(ordinal: u16, left: &[u8], right: &[u8]) -> Result<Ordering> {
    let table = TABLES
        .get(
            usize::from(ordinal)
                .checked_sub(1)
                .ok_or(CommitmentError::Invalid)?,
        )
        .ok_or(CommitmentError::Invalid)?;
    let a = decode_cells(left, table.columns.len())?;
    let b = decode_cells(right, table.columns.len())?;
    validate_cells(table, &a)?;
    validate_cells(table, &b)?;
    for index in table.order {
        let comparison = compare_cell(a[*index], b[*index]);
        if comparison != Ordering::Equal {
            return Ok(comparison);
        }
    }
    Ok(if table.optional {
        left.cmp(right)
    } else {
        Ordering::Equal
    })
}

fn validate_cells(table: &TableProjection, cells: &[Cell<'_>]) -> Result<()> {
    if cells.len() != table.columns.len()
        || (!table.allows_real && cells.iter().any(|cell| matches!(cell, Cell::Real(_))))
        || (!table.optional
            && table
                .order
                .iter()
                .any(|index| matches!(cells[*index], Cell::Null)))
    {
        return Err(CommitmentError::Invalid);
    }
    for (cell, storage) in cells.iter().zip(table.storage.bytes()) {
        let valid = match cell {
            Cell::Null => storage.is_ascii_lowercase() || storage == b'A',
            Cell::Integer(_) => matches!(storage, b'I' | b'i' | b'A'),
            Cell::Text(_) => matches!(storage, b'T' | b't' | b'A'),
            Cell::Blob(_) => matches!(storage, b'B' | b'b' | b'A'),
            Cell::Real(_) => storage == b'A',
        };
        if !valid {
            return Err(CommitmentError::Invalid);
        }
        scalar_len(*cell)?;
    }
    Ok(())
}

/// Only a streaming observation accumulator. One previous/current row of scratch
/// is retained to reject unordered input; no history or equal-key group is kept.
pub struct CatalogCommitment {
    hash: blake3::Hasher,
    next: usize,
    active: Option<(usize, u64, u64)>,
    previous: Vec<u8>,
    scratch: Vec<u8>,
    failed: bool,
}

impl Default for CatalogCommitment {
    fn default() -> Self {
        Self::new()
    }
}

impl CatalogCommitment {
    pub fn new() -> Self {
        let mut hash = blake3::Hasher::new();
        hash.update(DOMAIN);
        Self {
            hash,
            next: 0,
            active: None,
            previous: Vec::new(),
            scratch: Vec::new(),
            failed: false,
        }
    }

    fn reject<T>(&mut self, error: CommitmentError) -> Result<T> {
        self.failed = true;
        Err(error)
    }

    pub fn begin_table(&mut self, ordinal: u16, present: bool, row_count: u64) -> Result<()> {
        let Some(table) = TABLES.get(self.next) else {
            return self.reject(CommitmentError::Invalid);
        };
        if self.failed
            || self.active.is_some()
            || ordinal != table.ordinal
            || (!present && (!table.optional || row_count != 0))
        {
            return self.reject(CommitmentError::Invalid);
        }
        self.hash.update(&ordinal.to_le_bytes());
        self.hash.update(&[u8::from(present)]);
        self.hash.update(&row_count.to_le_bytes());
        self.active = Some((self.next, row_count, 0));
        self.previous.clear();
        Ok(())
    }

    pub fn push_row(&mut self, cells: &[Cell<'_>]) -> Result<()> {
        if self.failed {
            return Err(CommitmentError::Invalid);
        }
        let Some((index, expected, seen)) = self.active else {
            return self.reject(CommitmentError::Invalid);
        };
        if seen >= expected {
            return self.reject(CommitmentError::Invalid);
        }
        if let Err(error) = validate_cells(&TABLES[index], cells)
            .and_then(|()| encode_row(cells, &mut self.scratch))
        {
            return self.reject(error);
        }
        if seen != 0 {
            match compare_rows(TABLES[index].ordinal, &self.previous, &self.scratch) {
                Ok(Ordering::Less) => {}
                Ok(Ordering::Equal) if TABLES[index].optional => {}
                Ok(_) => return self.reject(CommitmentError::Unordered),
                Err(error) => return self.reject(error),
            }
        }
        self.hash.update(&self.scratch);
        std::mem::swap(&mut self.previous, &mut self.scratch);
        self.active = Some((
            index,
            expected,
            seen.checked_add(1).ok_or(CommitmentError::Overflow)?,
        ));
        Ok(())
    }

    pub fn end_table(&mut self) -> Result<()> {
        if self.failed {
            return Err(CommitmentError::Invalid);
        }
        let Some((_, expected, seen)) = self.active else {
            return self.reject(CommitmentError::Invalid);
        };
        if expected != seen {
            return self.reject(CommitmentError::Invalid);
        }
        self.active = None;
        self.next += 1;
        self.previous.clear();
        self.scratch.clear();
        Ok(())
    }

    pub fn finish(self) -> Result<[u8; 32]> {
        if self.failed || self.active.is_some() || self.next != TABLES.len() {
            return Err(CommitmentError::Invalid);
        }
        Ok(*self.hash.finalize().as_bytes())
    }
}

#[cfg(test)]
#[path = "managed_schema_transition_tests.rs"]
mod tests;

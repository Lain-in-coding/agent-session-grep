//! TOML syntax is owned by toml_edit; only validated source spans are spliced here.
use super::{ErrorCode, Host, KEY, MAX_BYTES, Result, Value, toml_item, without_node};
use std::{collections::BTreeMap, ops::Range};
use toml_edit::{InlineTable, Item, Table};

type KeyPath = Vec<String>;

pub(super) struct Document {
    parsed: toml_edit::Document<String>,
    pub value: Value,
    records: Vec<Record>,
}

struct Record {
    path: KeyPath,
    scope: KeyPath,
    expression: Range<usize>,
    line: Range<usize>,
    leading: usize,
    header: bool,
    comment: bool,
}

struct Change {
    path: KeyPath,
    after: Option<Value>,
}

struct Patch {
    range: Range<usize>,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct StatementGroup {
    relative: Vec<u8>,
    sections: Vec<u8>,
}

struct Planner<'a> {
    base: &'a Document,
    donors: &'a [&'a Document],
    patches: Vec<Patch>,
    statement_groups: BTreeMap<usize, StatementGroup>,
}

impl Document {
    pub fn parse(raw: &str) -> Result<Self> {
        let parsed =
            toml_edit::Document::parse(raw.to_owned()).map_err(|_| ErrorCode::Malformed)?;
        let value = toml_edit::de::from_document::<Value>(parsed.clone())
            .map_err(|_| ErrorCode::Malformed)?;
        let mut records = Vec::new();
        collect_records(parsed.as_table(), &[], &[], parsed.raw(), &mut records)?;
        let mut document = Self {
            parsed,
            value,
            records,
        };
        document
            .records
            .sort_by_key(|record| record.expression.start);
        if document
            .records
            .windows(2)
            .any(|pair| pair[0].line.end > pair[1].line.start)
        {
            return Err(ErrorCode::Unsupported.into());
        }
        Ok(document)
    }

    fn raw(&self) -> &str {
        self.parsed.raw()
    }

    pub fn has_explicit_parent(&self) -> bool {
        self.item(&["mcp_servers".into()]).is_some_and(|item| {
            item.is_inline_table()
                || item
                    .as_table()
                    .is_some_and(|table| !table.is_implicit() && !table.is_dotted())
        })
    }

    fn item(&self, path: &[String]) -> Option<&Item> {
        path.iter().try_fold(self.parsed.as_item(), |item, key| {
            item.as_table_like()?.get(key)
        })
    }

    fn inline_parent(&self, path: &[String]) -> Option<KeyPath> {
        (1..path.len()).find_map(|length| {
            let table = self.item(&path[..length])?.as_inline_table()?;
            (!table.is_dotted()).then(|| path[..length].to_vec())
        })
    }

    pub fn render(&self, after: &Value, donors: &[&Self]) -> Result<Vec<u8>> {
        let mut changes = Vec::new();
        differences(&self.value, after, &mut Vec::new(), &mut changes);
        // An absent parent is not an owned inline wrapper. Author the actual
        // registration as a dotted assignment so removal needs no extra authority.
        if self.value.get("mcp_servers").is_none() {
            for change in &mut changes {
                if change.path == ["mcp_servers"]
                    && let Some(object) = change.after.as_ref().and_then(Value::as_object)
                    && object.len() == 1
                    && let Some(owned) = object.get(KEY)
                {
                    change.path.push(KEY.into());
                    change.after = Some(owned.clone());
                }
            }
        }
        let mut planner = Planner {
            base: self,
            donors,
            patches: Vec::new(),
            statement_groups: BTreeMap::new(),
        };
        let mut inline = BTreeMap::new();
        for change in changes {
            if let Some(path) = self.inline_parent(&change.path) {
                inline.insert(path, ());
            } else {
                planner.change(&change)?;
            }
        }
        for (path, ()) in inline {
            let table = self
                .item(&path)
                .and_then(Item::as_inline_table)
                .ok_or(ErrorCode::Unsupported)?;
            let empty = Value::Object(Default::default());
            let target = at(after, &path).unwrap_or(&empty);
            planner.inline(table, &path, target)?;
        }
        let bytes = planner.finish()?;
        let parsed = Self::parse(std::str::from_utf8(&bytes).map_err(|_| ErrorCode::Malformed)?)?;
        if without_node(parsed.value.clone(), Host::Codex)
            != without_node(after.clone(), Host::Codex)
            || at(&parsed.value, &["mcp_servers".into(), KEY.into()])
                != at(after, &["mcp_servers".into(), KEY.into()])
        {
            return Err(ErrorCode::Unsupported.into());
        }
        Ok(bytes)
    }

    // An old pending intended image is not proof merely because its digest
    // matches the journal. Rebuild its allowed delta, then compare protected bytes.
    pub fn verify_intended(&self, intended: &Self) -> Result<bool> {
        if without_node(self.value.clone(), Host::Codex)
            != without_node(intended.value.clone(), Host::Codex)
        {
            return Err(ErrorCode::Unsupported.into());
        }
        let rebuilt = self.render(&intended.value, &[intended])?;
        let rebuilt =
            Self::parse(std::str::from_utf8(&rebuilt).map_err(|_| ErrorCode::Malformed)?)?;
        let introduced_parent = self.value.get("mcp_servers").is_none();
        if rebuilt.protected(introduced_parent)? != intended.protected(introduced_parent)? {
            return Err(ErrorCode::Unsupported.into());
        }
        // The rebuilt plan already includes the requested value changes.
        // After protected-byte equality, any remaining byte difference is
        // owned formatting, including same-shape whitespace or quoting edits.
        Ok(
            (self.owned_shape() != intended.owned_shape() || rebuilt.raw() != intended.raw())
                && at(&self.value, &["mcp_servers".into(), KEY.into()]).is_some()
                && at(&intended.value, &["mcp_servers".into(), KEY.into()]).is_some(),
        )
    }

    fn owned_shape(&self) -> Vec<(KeyPath, bool)> {
        self.records
            .iter()
            .filter(|record| record.path.starts_with(&["mcp_servers".into(), KEY.into()]))
            .map(|record| (record.path.clone(), record.header))
            .collect()
    }

    fn protected(&self, introduced_parent: bool) -> Result<Vec<u8>> {
        let mut target = self.value.clone();
        if let Some(parent) = target.get_mut("mcp_servers").and_then(Value::as_object_mut) {
            parent.remove(KEY);
            if introduced_parent && parent.is_empty() {
                target
                    .as_object_mut()
                    .ok_or(ErrorCode::Malformed)?
                    .remove("mcp_servers");
            }
        }
        self.render(&target, &[])
    }
}

fn at<'a>(value: &'a Value, path: &[String]) -> Option<&'a Value> {
    path.iter().try_fold(value, |value, key| value.get(key))
}

fn differences(before: &Value, after: &Value, path: &mut KeyPath, out: &mut Vec<Change>) {
    if before == after {
        return;
    }
    if let (Some(before), Some(after)) = (before.as_object(), after.as_object()) {
        for key in before
            .keys()
            .chain(after.keys().filter(|key| !before.contains_key(*key)))
        {
            path.push(key.clone());
            match (before.get(key), after.get(key)) {
                (Some(old), Some(new)) => differences(old, new, path, out),
                (_, new) => out.push(Change {
                    path: path.clone(),
                    after: new.cloned(),
                }),
            }
            path.pop();
        }
    } else {
        out.push(Change {
            path: path.clone(),
            after: Some(after.clone()),
        });
    }
}

fn checked<'a>(raw: &'a str, range: &Range<usize>) -> Result<&'a str> {
    raw.get(range.clone())
        .ok_or_else(|| ErrorCode::Unsupported.into())
}

fn line_record(
    raw: &str,
    path: KeyPath,
    scope: KeyPath,
    expression: Range<usize>,
    leading: Option<usize>,
    header: bool,
) -> Result<Record> {
    checked(raw, &expression)?;
    let start = raw[..expression.start].rfind('\n').map_or(0, |n| n + 1);
    if !raw[start..expression.start]
        .bytes()
        .all(|b| b == b' ' || b == b'\t')
    {
        return Err(ErrorCode::Unsupported.into());
    }
    let end = raw[expression.end..]
        .find('\n')
        .map_or(raw.len(), |n| expression.end + n + 1);
    let tail = raw[expression.end..end].trim_end_matches(['\r', '\n']);
    let tail = tail.trim_start_matches([' ', '\t']);
    if !tail.is_empty() && !tail.starts_with('#') {
        return Err(ErrorCode::Unsupported.into());
    }
    let leading = leading.filter(|n| *n <= start).unwrap_or(start);
    if leading != 0 && !raw[..leading].ends_with('\n') {
        return Err(ErrorCode::Unsupported.into());
    }
    Ok(Record {
        path,
        scope,
        expression,
        line: start..end,
        leading,
        header,
        comment: !tail.is_empty(),
    })
}

fn collect_records(
    table: &Table,
    path: &[String],
    parent_scope: &[String],
    raw: &str,
    records: &mut Vec<Record>,
) -> Result<()> {
    let explicit = !path.is_empty() && !table.is_implicit() && !table.is_dotted();
    let scope = if explicit { path } else { parent_scope };
    if explicit {
        let span = table.span().ok_or(ErrorCode::Unsupported)?;
        if !checked(raw, &span)?.starts_with('[') {
            return Err(ErrorCode::Unsupported.into());
        }
        let leading = table
            .decor()
            .prefix()
            .and_then(|s| s.span())
            .map(|r| r.start);
        records.push(line_record(
            raw,
            path.to_vec(),
            scope.to_vec(),
            span,
            leading,
            true,
        )?);
    }
    if !table.is_dotted() {
        for (keys, value) in table.get_values() {
            let last = keys.last().ok_or(ErrorCode::Unsupported)?;
            let leaf = last.span().ok_or(ErrorCode::Unsupported)?;
            let start = raw[..leaf.start].rfind('\n').map_or(0, |n| n + 1);
            let expression_start = start
                + raw[start..]
                    .bytes()
                    .take_while(|b| *b == b' ' || *b == b'\t')
                    .count();
            let value_span = value.span().ok_or(ErrorCode::Unsupported)?;
            let leading = last
                .leaf_decor()
                .prefix()
                .and_then(|raw| raw.span())
                .map(|span| span.start);
            let full_path = path
                .iter()
                .cloned()
                .chain(keys.iter().map(|key| key.get().to_owned()))
                .collect();
            records.push(line_record(
                raw,
                full_path,
                scope.to_vec(),
                expression_start..value_span.end,
                leading,
                false,
            )?);
        }
    }
    for (key, item) in table.iter() {
        let child: Vec<_> = path.iter().cloned().chain([key.to_owned()]).collect();
        match item {
            Item::Table(nested) => collect_records(nested, &child, scope, raw, records)?,
            Item::ArrayOfTables(array) => {
                for nested in array.iter() {
                    collect_records(nested, &child, scope, raw, records)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn key_path(path: &[String]) -> String {
    path.iter()
        .map(|key| toml_edit::Key::new(key).to_string())
        .collect::<Vec<_>>()
        .join(".")
}

fn authored(value: &Value) -> Result<String> {
    let item = toml_item(value)?;
    let mut value = item.into_value().map_err(|_| ErrorCode::Unsupported)?;
    value.decor_mut().clear();
    Ok(value.to_string())
}

impl Planner<'_> {
    fn patch(&mut self, range: Range<usize>, bytes: Vec<u8>) -> Result<()> {
        checked(self.base.raw(), &range)?;
        if bytes.len() as u64 > MAX_BYTES || self.patches.len() > self.base.raw().len() + 1 {
            return Err(ErrorCode::Malformed.into());
        }
        self.patches.push(Patch { range, bytes });
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<u8>> {
        for (anchor, group) in std::mem::take(&mut self.statement_groups) {
            let mut bytes = Vec::new();
            if anchor > 0 && !self.base.raw()[..anchor].ends_with('\n') {
                bytes.extend_from_slice(self.eol(anchor).as_bytes());
            }
            bytes.extend_from_slice(&group.relative);
            bytes.extend_from_slice(&group.sections);
            self.patch(anchor..anchor, bytes)?;
        }
        self.patches
            .sort_by_key(|patch| (patch.range.start, patch.range.end));
        let mut end = 0;
        let mut length = self.base.raw().len();
        for patch in &self.patches {
            if patch.range.start < end {
                return Err(ErrorCode::Unsupported.into());
            }
            end = patch.range.end;
            length = length
                .checked_sub(patch.range.len())
                .and_then(|n| n.checked_add(patch.bytes.len()))
                .ok_or(ErrorCode::Malformed)?;
            if length as u64 > MAX_BYTES {
                return Err(ErrorCode::Malformed.into());
            }
        }
        let mut output = Vec::with_capacity(length);
        let mut copied = 0;
        for patch in self.patches {
            output.extend_from_slice(&self.base.raw().as_bytes()[copied..patch.range.start]);
            output.extend_from_slice(&patch.bytes);
            copied = patch.range.end;
        }
        output.extend_from_slice(&self.base.raw().as_bytes()[copied..]);
        Ok(output)
    }

    fn donor(&self, path: &[String], value: &Value) -> Result<Option<&Document>> {
        let mut selected: Option<(&Document, Vec<u8>)> = None;
        for donor in self.donors {
            if at(&donor.value, path) != Some(value) {
                continue;
            }
            let image = donor.fragment(path)?;
            if let Some((_, previous)) = &selected {
                if *previous != image {
                    return Err(ErrorCode::Conflict.into());
                }
            } else {
                selected = Some((donor, image));
            }
        }
        Ok(selected.map(|(document, _)| document))
    }

    fn token(&self, path: &[String], value: &Value) -> Result<Vec<u8>> {
        if path.starts_with(&["mcp_servers".into(), KEY.into()]) {
            return Ok(authored(value)?.into_bytes());
        }
        if !path.starts_with(&["mcp_servers".into(), KEY.into()])
            && let Some(donor) = self.donor(path, value)?
            && let Some(item) = donor.item(path)
        {
            return donor.inline_item(item);
        }
        Err(ErrorCode::Conflict.into())
    }

    fn change(&mut self, change: &Change) -> Result<()> {
        if let Some(item) = self.base.item(&change.path) {
            if let (Some(value), Some(after)) = (item.as_value(), change.after.as_ref()) {
                let bytes = self.token(&change.path, after)?;
                return self.patch(value.span().ok_or(ErrorCode::Unsupported)?, bytes);
            }
            self.remove(&change.path)?;
        }
        if let Some(value) = &change.after {
            self.insert(&change.path, value)?;
        }
        Ok(())
    }

    fn remove(&mut self, path: &[String]) -> Result<()> {
        let records: Vec<_> = self
            .base
            .records
            .iter()
            .filter(|record| record.path.starts_with(path))
            .collect();
        if records.is_empty() {
            return Err(ErrorCode::Unsupported.into());
        }
        for record in records {
            let range = if record.comment {
                record.line.start..record.expression.end
            } else {
                record.line.clone()
            };
            self.patch(range, Vec::new())?;
        }
        Ok(())
    }

    fn eol(&self, offset: usize) -> &'static str {
        let raw = self.base.raw();
        let newline = raw[..offset]
            .rfind('\n')
            .or_else(|| raw[offset..].find('\n').map(|n| offset + n));
        if newline.is_some_and(|n| n > 0 && raw.as_bytes()[n - 1] == b'\r') {
            "\r\n"
        } else {
            "\n"
        }
    }

    fn sections(&mut self, fragment: Vec<u8>) -> Result<()> {
        let anchor = self
            .base
            .records
            .iter()
            .filter(|record| record.header)
            .map(|record| record.leading)
            .min()
            .unwrap_or(self.base.raw().len());
        self.statements(anchor, fragment, true)
    }

    fn statements(&mut self, anchor: usize, mut fragment: Vec<u8>, section: bool) -> Result<()> {
        checked(self.base.raw(), &(anchor..anchor))?;
        if !fragment.ends_with(b"\n") {
            fragment.extend_from_slice(self.eol(anchor).as_bytes());
        }
        let group = self.statement_groups.entry(anchor).or_default();
        let length = group
            .relative
            .len()
            .checked_add(group.sections.len())
            .and_then(|length| length.checked_add(fragment.len()))
            .ok_or(ErrorCode::Malformed)?;
        if length as u64 > MAX_BYTES {
            return Err(ErrorCode::Malformed.into());
        }
        if section {
            group.sections.extend_from_slice(&fragment);
        } else {
            group.relative.extend_from_slice(&fragment);
        }
        Ok(())
    }

    fn insert(&mut self, path: &[String], value: &Value) -> Result<()> {
        if !path.starts_with(&["mcp_servers".into(), KEY.into()])
            && let Some(donor) = self.donor(path, value)?
            && donor
                .item(path)
                .is_some_and(|item| item.is_table() || item.is_array_of_tables())
        {
            let records: Vec<_> = donor
                .records
                .iter()
                .enumerate()
                .filter(|(_, record)| record.path.starts_with(path))
                .collect();
            let first_header = records
                .iter()
                .position(|(_, record)| record.header)
                .unwrap_or(records.len());
            if first_header == 0 {
                return self.sections(donor.fragment(path)?);
            }
            let scope = &records.first().ok_or(ErrorCode::Unsupported)?.1.scope;
            let same_scope = records[..first_header]
                .iter()
                .all(|(_, record)| &record.scope == scope);
            let has_explicit_ancestor = self
                .base
                .records
                .iter()
                .any(|record| record.header && path.starts_with(&record.path));
            let anchors = if scope.is_empty() && !has_explicit_ancestor {
                Some((
                    0,
                    self.base
                        .records
                        .iter()
                        .find(|record| record.header)
                        .map_or(self.base.raw().len(), |record| record.leading),
                ))
            } else {
                self.base
                    .records
                    .iter()
                    .find(|record| record.header && &record.path == scope)
                    .map(|header| {
                        let section_anchor = self
                            .base
                            .records
                            .iter()
                            .find(|record| {
                                record.header && record.expression.start > header.expression.start
                            })
                            .map_or(self.base.raw().len(), |record| record.leading);
                        (header.line.end, section_anchor)
                    })
            };
            if same_scope && let Some((anchor, section_anchor)) = anchors {
                let relative = donor.record_fragment(records[..first_header].iter().copied())?;
                let sections = if first_header < records.len() {
                    Some(donor.record_fragment(records[first_header..].iter().copied())?)
                } else {
                    None
                };
                if let Some(sections) = sections {
                    self.statements(section_anchor, sections, true)?;
                }
                return self.statements(anchor, relative, false);
            }
        }
        if path == ["mcp_servers", KEY]
            && let Some(table) = self
                .base
                .item(&["mcp_servers".into()])
                .and_then(Item::as_table)
            && !table.is_dotted()
        {
            let eol = self.eol(0);
            let mut section = format!("[{}]{eol}", key_path(path));
            for (key, value) in value.as_object().ok_or(ErrorCode::Malformed)? {
                section.push_str(&format!(
                    "{} = {}{eol}",
                    key_path(std::slice::from_ref(key)),
                    authored(value)?
                ));
            }
            return self.sections(section.into_bytes());
        }
        let mut scope = Vec::new();
        let mut anchor = 0;
        for length in (1..path.len()).rev() {
            if let Some(record) = self
                .base
                .records
                .iter()
                .find(|r| r.header && r.path == path[..length])
            {
                scope = path[..length].to_vec();
                anchor = record.line.end;
                break;
            }
        }
        let token = self.token(path, value)?;
        let mut bytes = Vec::new();
        if anchor > 0 && !self.base.raw()[..anchor].ends_with('\n') {
            bytes.extend_from_slice(self.eol(anchor).as_bytes());
        }
        bytes.extend_from_slice(format!("{} = ", key_path(&path[scope.len()..])).as_bytes());
        bytes.extend_from_slice(&token);
        bytes.extend_from_slice(self.eol(anchor).as_bytes());
        self.patch(anchor..anchor, bytes)
    }

    fn inline(&mut self, table: &InlineTable, path: &[String], target: &Value) -> Result<()> {
        let span = table.span().ok_or(ErrorCode::Unsupported)?;
        let raw = self.base.raw();
        let text = checked(raw, &span)?;
        if !text.starts_with('{') || !text.ends_with('}') {
            return Err(ErrorCode::Unsupported.into());
        }
        let mut entries = Vec::new();
        for (keys, value) in table.get_values() {
            let last = keys.last().ok_or(ErrorCode::Unsupported)?;
            let leaf = last.span().ok_or(ErrorCode::Unsupported)?;
            let start = last
                .leaf_decor()
                .prefix()
                .and_then(|s| s.span())
                .map(|r| r.end)
                .or_else(|| {
                    keys.first()
                        .and_then(|key| key.span())
                        .map(|range| range.start)
                })
                .unwrap_or(leaf.start);
            let range = value.span().ok_or(ErrorCode::Unsupported)?;
            if start < span.start + 1 || start >= range.start || range.end >= span.end {
                return Err(ErrorCode::Unsupported.into());
            }
            let relative: Vec<_> = keys.iter().map(|key| key.get().to_owned()).collect();
            entries.push((start, range, relative, value));
        }
        entries.sort_by_key(|entry| entry.0);
        let kept: Vec<_> = entries
            .iter()
            .map(|entry| at(target, &entry.2).is_some())
            .collect();
        let trailing_comma = match entries.last() {
            Some((_, range, _, _)) => punctuation(raw, range.end..span.end - 1, b',')?,
            None => None,
        };
        for (index, (start, range, relative, value)) in entries.iter().enumerate() {
            let full: Vec<_> = path
                .iter()
                .cloned()
                .chain(relative.iter().cloned())
                .collect();
            match at(target, relative) {
                None => self.patch(*start..range.end, Vec::new())?,
                Some(after) if at(&self.base.value, &full) != Some(after) => {
                    if let Some(nested) = value.as_inline_table() {
                        if after.is_object() {
                            self.inline(nested, &full, after)?;
                        } else {
                            self.patch(range.clone(), self.token(&full, after)?)?;
                        }
                    } else {
                        self.patch(range.clone(), self.token(&full, after)?)?;
                    }
                }
                _ => {}
            }
            if index + 1 < entries.len() {
                let gap = range.end..entries[index + 1].0;
                let comma = punctuation(raw, gap, b',')?.ok_or(ErrorCode::Unsupported)?;
                // When the original table had a trailing comma, retain the
                // surviving member's comma even if later members are removed.
                if !kept[index]
                    || (trailing_comma.is_none() && !kept[index + 1..].iter().any(|keep| *keep))
                {
                    self.patch(comma..comma + 1, Vec::new())?;
                }
            }
        }
        if kept.last() == Some(&false)
            && let Some(comma) = trailing_comma
        {
            self.patch(comma..comma + 1, Vec::new())?;
        }
        let before = at(&self.base.value, path).ok_or(ErrorCode::Unsupported)?;
        let mut changes = Vec::new();
        differences(before, target, &mut Vec::new(), &mut changes);
        let mut additions = Vec::new();
        for change in changes {
            if at(before, &change.path).is_none()
                && let Some(value) = change.after
            {
                let full: Vec<_> = path
                    .iter()
                    .cloned()
                    .chain(change.path.iter().cloned())
                    .collect();
                if entries.iter().any(|entry| {
                    change.path.starts_with(&entry.2)
                        && entry.3.as_inline_table().is_some()
                        && change.path.len() > entry.2.len()
                }) {
                    continue;
                }
                let token = self.token(&full, &value)?;
                let mut member = format!("{} = ", key_path(&change.path)).into_bytes();
                member.extend_from_slice(&token);
                additions.push(member);
            }
        }
        if !additions.is_empty() {
            let mut bytes = Vec::new();
            for (index, member) in additions.iter().enumerate() {
                if index > 0 {
                    bytes.push(b',');
                }
                bytes.extend_from_slice(member);
            }
            if kept.iter().any(|keep| *keep) {
                bytes.push(b',');
            }
            self.patch(span.start + 1..span.start + 1, bytes)?;
        }
        Ok(())
    }
}

// Only parser-delimited trivia gaps are scanned, never values or quoted keys.
fn punctuation(raw: &str, range: Range<usize>, expected: u8) -> Result<Option<usize>> {
    let mut found = None;
    let mut comment = false;
    for (offset, byte) in checked(raw, &range)?.bytes().enumerate() {
        if comment {
            if byte == b'\n' {
                comment = false;
            }
        } else if byte == b'#' {
            comment = true;
        } else if byte == expected && found.is_none() {
            found = Some(range.start + offset);
        } else if !byte.is_ascii_whitespace() {
            return Err(ErrorCode::Unsupported.into());
        }
    }
    Ok(found)
}

impl Document {
    fn fragment(&self, path: &[String]) -> Result<Vec<u8>> {
        if let Some(value) = self.item(path).and_then(Item::as_value) {
            return Ok(
                checked(self.raw(), &value.span().ok_or(ErrorCode::Unsupported)?)?
                    .as_bytes()
                    .to_vec(),
            );
        }
        self.record_fragment(
            self.records
                .iter()
                .enumerate()
                .filter(|(_, record)| record.path.starts_with(path)),
        )
    }

    fn record_fragment<'a>(
        &'a self,
        records: impl Iterator<Item = (usize, &'a Record)>,
    ) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut copied = 0;
        for (index, record) in records {
            let start = record.leading.max(copied);
            let end = if index + 1 == self.records.len() {
                self.raw().len()
            } else {
                record.line.end
            };
            bytes.extend_from_slice(checked(self.raw(), &(start..end))?.as_bytes());
            if !bytes.ends_with(b"\n") {
                bytes.push(b'\n');
            }
            copied = end;
        }
        if bytes.is_empty() {
            return Err(ErrorCode::Unsupported.into());
        }
        Ok(bytes)
    }

    // Selected donor structures may need inline syntax at their destination.
    // Keep original value tokens and trivia; only author the container syntax.
    fn inline_item(&self, item: &Item) -> Result<Vec<u8>> {
        match item {
            Item::Value(value) => Ok(checked(
                self.raw(),
                &value.span().ok_or(ErrorCode::Unsupported)?,
            )?
            .as_bytes()
            .to_vec()),
            Item::Table(table) => self.inline_table(table),
            Item::ArrayOfTables(array) => {
                let mut bytes = b"[\n".to_vec();
                for table in array.iter() {
                    bytes.extend_from_slice(&self.inline_table(table)?);
                    bytes.extend_from_slice(b",\n");
                }
                bytes.push(b']');
                Ok(bytes)
            }
            Item::None => Err(ErrorCode::Unsupported.into()),
        }
    }

    fn inline_table(&self, table: &Table) -> Result<Vec<u8>> {
        let mut bytes = b"{\n".to_vec();
        let members: Vec<_> = table.iter().collect();
        let mut last_end = table.span().map_or(0, |span| span.end);
        for (index, (name, item)) in members.iter().enumerate() {
            let key = table.key(name).ok_or(ErrorCode::Unsupported)?;
            let span = key.span().ok_or(ErrorCode::Unsupported)?;
            let prefix = match item {
                Item::Table(child) => child.decor().prefix(),
                _ => key.leaf_decor().prefix(),
            }
            .and_then(|raw| raw.span());
            if let Some(prefix) = prefix {
                bytes.extend_from_slice(checked(self.raw(), &prefix)?.as_bytes());
            }
            bytes.extend_from_slice(checked(self.raw(), &span)?.as_bytes());
            bytes.extend_from_slice(b" = ");
            bytes.extend_from_slice(&self.inline_item(item)?);
            if index + 1 < members.len() {
                bytes.push(b',');
            }
            let token_end = item
                .span()
                .map(|span| span.end)
                .ok_or(ErrorCode::Unsupported)?;
            if let Some(record) = self
                .records
                .iter()
                .find(|record| record.expression.end == token_end)
            {
                bytes.extend_from_slice(
                    checked(self.raw(), &(token_end..record.line.end))?.as_bytes(),
                );
                last_end = last_end.max(record.line.end);
            }
            if !bytes.ends_with(b"\n") {
                bytes.push(b'\n');
            }
        }
        if self
            .records
            .last()
            .is_some_and(|record| record.line.end == last_end)
        {
            bytes.extend_from_slice(&self.raw().as_bytes()[last_end..]);
        }
        bytes.push(b'}');
        if bytes.len() as u64 > MAX_BYTES {
            return Err(ErrorCode::Malformed.into());
        }
        Ok(bytes)
    }
}

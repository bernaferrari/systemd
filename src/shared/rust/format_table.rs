// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/shared/format-table.c

use std::cmp::Ordering;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

const DEFAULT_WEIGHT: u32 = 100;
const ELLIPSIS: char = '…';

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableDataType {
    Empty,
    String,
    StringWithAnsi,
    Header,
    Field,
    Strv,
    StrvWrapped,
    Path,
    PathBasename,
    Version,
    Boolean,
    BooleanCheckmark,
    Tristate,
    Timestamp,
    TimestampUtc,
    TimestampRelative,
    TimestampRelativeMonotonic,
    TimestampLeft,
    TimestampDate,
    Timespan,
    TimespanMsec,
    TimespanDay,
    Size,
    Bps,
    Int,
    Int8,
    Int16,
    Int32,
    Int64,
    Uint,
    Uint8,
    Uint16,
    Uint32,
    Uint32Hex,
    Uint32Hex0x,
    Uint64,
    Uint64Hex,
    Uint64Hex0x,
    Percent,
    IfIndex,
    InAddr,
    In6Addr,
    Id128,
    Uuid,
    Uid,
    Gid,
    Pid,
    Signal,
    Mode,
    ModeInodeType,
    Devnum,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableErsatz {
    Empty,
    Dash,
    Unset,
    NotApplicable,
}

impl TableErsatz {
    fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "",
            Self::Dash => "-",
            Self::Unset => "(unset)",
            Self::NotApplicable => "n/a",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableCellId(pub usize);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableValue {
    Empty,
    Text(String),
    Strv(Vec<String>),
    Bool(bool),
    Usec(u64),
    U64(u64),
    I64(i64),
    Percent(i32),
    IfIndex(i32),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Id128([u8; 16]),
    Uid(u32),
    Gid(u32),
    Pid(i32),
    Mode(u32),
    Devnum { major: u32, minor: u32 },
    Json(String),
}

impl From<&str> for TableValue {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl From<String> for TableValue {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<bool> for TableValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<Vec<String>> for TableValue {
    fn from(value: Vec<String>) -> Self {
        Self::Strv(value)
    }
}

impl From<Vec<&str>> for TableValue {
    fn from(value: Vec<&str>) -> Self {
        Self::Strv(value.into_iter().map(str::to_owned).collect())
    }
}

impl From<u64> for TableValue {
    fn from(value: u64) -> Self {
        Self::U64(value)
    }
}

impl From<i64> for TableValue {
    fn from(value: i64) -> Self {
        Self::I64(value)
    }
}

impl From<i32> for TableValue {
    fn from(value: i32) -> Self {
        Self::I64(i64::from(value))
    }
}

impl From<Ipv4Addr> for TableValue {
    fn from(value: Ipv4Addr) -> Self {
        Self::Ipv4(value)
    }
}

impl From<Ipv6Addr> for TableValue {
    fn from(value: Ipv6Addr) -> Self {
        Self::Ipv6(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableCell {
    pub data_type: TableDataType,
    pub value: TableValue,
    pub minimum_width: usize,
    pub maximum_width: Option<usize>,
    pub weight: u32,
    pub align_percent: u32,
    pub ellipsize_percent: u32,
    pub uppercase: bool,
    pub underline: bool,
    pub rgap_underline: bool,
    pub color: Option<String>,
    pub rgap_color: Option<String>,
    pub url: Option<String>,
}

impl TableCell {
    fn new(data_type: TableDataType, value: TableValue) -> Self {
        Self {
            data_type,
            value,
            minimum_width: 1,
            maximum_width: None,
            weight: DEFAULT_WEIGHT,
            align_percent: 0,
            ellipsize_percent: 100,
            uppercase: data_type == TableDataType::Header,
            underline: false,
            rgap_underline: false,
            color: None,
            rgap_color: None,
            url: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableItem {
    Cell(TableDataType, TableValue),
    SetMinimumWidth(usize),
    SetMaximumWidth(Option<usize>),
    SetWeight(u32),
    SetAlignPercent(u32),
    SetEllipsizePercent(u32),
    SetColor(Option<String>),
    SetRgapColor(Option<String>),
    SetBothColors(Option<String>),
    SetUnderline(bool),
    SetRgapUnderline(bool),
    SetBothUnderlines(bool),
    SetUrl(Option<String>),
    SetUppercase(bool),
    SetJsonFieldName(Option<String>),
}

#[derive(Debug, Clone)]
pub struct Table {
    n_columns: usize,
    cells: Vec<TableCell>,
    header: bool,
    vertical: bool,
    ersatz: TableErsatz,
    width: Option<usize>,
    cell_height_max: Option<usize>,
    display_map: Option<Vec<usize>>,
    sort_map: Vec<usize>,
    json_fields: Vec<Option<String>>,
    reverse_map: Vec<bool>,
}

impl Table {
    pub fn new_raw(n_columns: usize) -> Self {
        assert!(n_columns > 0);
        Self {
            n_columns,
            cells: Vec::new(),
            header: true,
            vertical: false,
            ersatz: TableErsatz::Empty,
            width: None,
            cell_height_max: None,
            display_map: None,
            sort_map: Vec::new(),
            json_fields: Vec::new(),
            reverse_map: vec![false; n_columns],
        }
    }

    pub fn new<I, S>(headers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let headers: Vec<String> = headers.into_iter().map(|s| s.as_ref().to_owned()).collect();
        assert!(!headers.is_empty());
        let mut table = Self::new_raw(headers.len());
        for header in headers {
            let _ = table.add_cell(TableDataType::Header, header);
        }
        table
    }

    pub fn new_vertical() -> Self {
        let mut table = Self::new(["key", "value"]);
        table.vertical = true;
        table.header = false;
        let _ = table.set_align_percent(TableCellId(0), 100);
        let _ = table.set_align_percent(TableCellId(1), 0);
        table
    }

    pub fn add_cell(
        &mut self,
        data_type: TableDataType,
        value: impl Into<TableValue>,
    ) -> TableCellId {
        self.add_cell_full(data_type, Some(value.into()), None, None, None, None, None)
    }

    pub fn add_cell_full(
        &mut self,
        data_type: TableDataType,
        value: Option<TableValue>,
        minimum_width: Option<usize>,
        maximum_width: Option<Option<usize>>,
        weight: Option<u32>,
        align_percent: Option<u32>,
        ellipsize_percent: Option<u32>,
    ) -> TableCellId {
        let column = self.get_current_column();
        let previous = self
            .cells
            .len()
            .checked_sub(self.n_columns)
            .and_then(|index| self.cells.get(index))
            .cloned();
        let effective_type = if value.is_none() {
            TableDataType::Empty
        } else {
            data_type
        };
        let mut cell = TableCell::new(effective_type, value.unwrap_or(TableValue::Empty));
        if let Some(prev) = previous {
            cell.minimum_width = minimum_width.unwrap_or(prev.minimum_width);
            cell.maximum_width = maximum_width.unwrap_or(prev.maximum_width);
            cell.weight = weight.unwrap_or(prev.weight);
            cell.align_percent = align_percent.unwrap_or(prev.align_percent);
            cell.ellipsize_percent = ellipsize_percent.unwrap_or(prev.ellipsize_percent);
        } else {
            cell.minimum_width = minimum_width.unwrap_or(1);
            cell.maximum_width = maximum_width.unwrap_or(None);
            cell.weight = weight.unwrap_or(DEFAULT_WEIGHT);
            cell.align_percent = align_percent.unwrap_or(0);
            cell.ellipsize_percent = ellipsize_percent.unwrap_or(100);
        }
        assert!(cell.align_percent <= 100);
        assert!(cell.ellipsize_percent <= 100);
        if effective_type == TableDataType::Header {
            cell.uppercase = true;
        }
        let id = TableCellId(self.cells.len());
        let _ = column;
        self.cells.push(cell);
        id
    }

    pub fn add_cell_stringf_full(
        &mut self,
        data_type: TableDataType,
        value: impl fmt::Display,
    ) -> TableCellId {
        self.add_cell(data_type, value.to_string())
    }

    pub fn fill_empty(&mut self, until_column: usize) {
        assert!(until_column < self.n_columns);
        loop {
            let _ = self.add_cell_full(TableDataType::Empty, None, None, None, None, None, None);
            if self.get_current_column() == until_column {
                break;
            }
        }
    }

    pub fn dup_cell(&mut self, cell: TableCellId) -> Option<TableCellId> {
        let cloned = self.cells.get(cell.0)?.clone();
        let id = TableCellId(self.cells.len());
        self.cells.push(cloned);
        Some(id)
    }

    pub fn update(
        &mut self,
        cell: TableCellId,
        data_type: TableDataType,
        value: impl Into<TableValue>,
    ) -> bool {
        let current = match self.cells.get(cell.0).cloned() {
            Some(current) => current,
            None => return false,
        };
        self.cells[cell.0] = TableCell {
            data_type,
            value: value.into(),
            minimum_width: current.minimum_width,
            maximum_width: current.maximum_width,
            weight: current.weight,
            align_percent: current.align_percent,
            ellipsize_percent: current.ellipsize_percent,
            uppercase: current.uppercase,
            underline: current.underline,
            rgap_underline: current.rgap_underline,
            color: current.color,
            rgap_color: current.rgap_color,
            url: current.url,
        };
        true
    }

    pub fn add_many(&mut self, items: impl IntoIterator<Item = TableItem>) {
        let mut last = None;
        for item in items {
            match item {
                TableItem::Cell(data_type, value) => last = Some(self.add_cell(data_type, value)),
                TableItem::SetMinimumWidth(width) => {
                    let _ = last.and_then(|id| self.set_minimum_width(id, width));
                }
                TableItem::SetMaximumWidth(width) => {
                    let _ = last.and_then(|id| self.set_maximum_width(id, width));
                }
                TableItem::SetWeight(weight) => {
                    let _ = last.and_then(|id| self.set_weight(id, weight));
                }
                TableItem::SetAlignPercent(percent) => {
                    let _ = last.and_then(|id| self.set_align_percent(id, percent));
                }
                TableItem::SetEllipsizePercent(percent) => {
                    let _ = last.and_then(|id| self.set_ellipsize_percent(id, percent));
                }
                TableItem::SetColor(color) => {
                    let _ = last.and_then(|id| self.set_color(id, color));
                }
                TableItem::SetRgapColor(color) => {
                    let _ = last.and_then(|id| self.set_rgap_color(id, color));
                }
                TableItem::SetBothColors(color) => {
                    let _ = last.and_then(|id| self.set_color(id, color.clone()));
                    let _ = last.and_then(|id| self.set_rgap_color(id, color));
                }
                TableItem::SetUnderline(value) => {
                    let _ = last.and_then(|id| self.set_underline(id, value));
                }
                TableItem::SetRgapUnderline(value) => {
                    let _ = last.and_then(|id| self.set_rgap_underline(id, value));
                }
                TableItem::SetBothUnderlines(value) => {
                    let _ = last.and_then(|id| self.set_underline(id, value));
                    let _ = last.and_then(|id| self.set_rgap_underline(id, value));
                }
                TableItem::SetUrl(url) => {
                    let _ = last.and_then(|id| self.set_url(id, url));
                }
                TableItem::SetUppercase(value) => {
                    let _ = last.and_then(|id| self.set_uppercase(id, value));
                }
                TableItem::SetJsonFieldName(name) => {
                    if let Some(id) = last {
                        let idx = if self.vertical {
                            id.0 / self.n_columns - 1
                        } else {
                            id.0 % self.n_columns
                        };
                        let _ = self.set_json_field_name(idx, name);
                    }
                }
            }
        }
    }

    pub fn set_header(&mut self, value: bool) {
        self.header = value;
    }

    pub fn set_width(&mut self, width: usize) {
        self.width = if width == 0 || width == usize::MAX {
            None
        } else {
            Some(width)
        };
    }

    pub fn set_cell_height_max(&mut self, height: usize) {
        assert!(height >= 1 || height == usize::MAX);
        self.cell_height_max = if height == usize::MAX {
            None
        } else {
            Some(height)
        };
    }

    pub fn set_ersatz_string(&mut self, ersatz: TableErsatz) {
        self.ersatz = ersatz;
    }

    pub fn set_display(&mut self, columns: impl IntoIterator<Item = usize>) {
        let columns: Vec<usize> = columns.into_iter().collect();
        assert!(columns.iter().all(|&column| column < self.n_columns));
        self.display_map = Some(columns);
    }

    pub fn set_sort(&mut self, columns: impl IntoIterator<Item = usize>) {
        let columns: Vec<usize> = columns.into_iter().collect();
        assert!(columns.iter().all(|&column| column < self.n_columns));
        self.sort_map = columns;
    }

    pub fn hide_columns_from_display(&mut self, columns: impl IntoIterator<Item = usize>) {
        let hidden: Vec<usize> = columns.into_iter().collect();
        let mut shown = self
            .display_map
            .clone()
            .unwrap_or_else(|| (0..self.n_columns).collect());
        shown.retain(|column| !hidden.contains(column));
        self.display_map = Some(shown);
    }

    pub fn set_reverse(&mut self, column: usize, reverse: bool) -> Option<bool> {
        let slot = self.reverse_map.get_mut(column)?;
        let old = *slot;
        *slot = reverse;
        Some(old)
    }

    pub fn data_requested_width(&self, column: usize) -> Option<usize> {
        if column >= self.n_columns {
            return None;
        }
        let mut width = 0;
        for row in 0..self.get_rows() {
            let cell = self.get_at_cell(row, column)?;
            width = width.max(self.requested_width_height(cell, usize::MAX).0);
        }
        Some(width)
    }

    pub fn set_column_width(&mut self, column: usize, width: usize) -> bool {
        if column >= self.n_columns {
            return false;
        }
        let mut changed = false;
        for row in 0..self.get_rows() {
            if let Some(id) = self.get_cell(row, column) {
                changed |= self.set_minimum_width(id, width).is_some();
            }
        }
        changed
    }

    pub fn sync_column_width(
        &mut self,
        column_a: usize,
        other: &mut Table,
        column_b: usize,
    ) -> bool {
        let width = self
            .data_requested_width(column_a)
            .zip(other.data_requested_width(column_b))
            .map(|(a, b)| a.max(b));
        match width {
            Some(width) => {
                self.set_column_width(column_a, width) | other.set_column_width(column_b, width)
            }
            None => false,
        }
    }

    pub fn format(&self) -> String {
        if self.cells.is_empty() {
            return String::new();
        }
        assert_eq!(self.cells.len() % self.n_columns, 0);
        let columns = self.visible_columns();
        let widths = self.compute_column_widths(&columns);
        let mut out = String::new();
        for row_index in self.sorted_row_indices() {
            if !self.header && row_index == 0 {
                continue;
            }
            let rendered: Vec<RenderedCell> = columns
                .iter()
                .enumerate()
                .filter_map(|(display_index, &column)| {
                    self.get_at_cell(row_index, column)
                        .map(|cell| self.render_cell(cell, widths[display_index]))
                })
                .collect();
            let height = rendered
                .iter()
                .map(|cell| cell.lines.len())
                .max()
                .unwrap_or(1);
            for subline in 0..height {
                for (index, cell) in rendered.iter().enumerate() {
                    if index > 0 {
                        out.push(' ');
                    }
                    let text = cell.lines.get(subline).cloned().unwrap_or_default();
                    out.push_str(&align_string(&text, cell.width, cell.align_percent));
                }
                while out.ends_with(' ') {
                    out.pop();
                }
                out.push('\n');
            }
        }
        out
    }

    pub fn to_json(&self) -> String {
        if self.vertical {
            self.to_json_vertical()
        } else {
            self.to_json_regular()
        }
    }

    pub fn print_json(&self) -> String {
        self.to_json()
    }

    pub fn get_rows(&self) -> usize {
        self.cells.len() / self.n_columns
    }

    pub fn get_columns(&self) -> usize {
        self.n_columns
    }

    pub fn get_current_column(&self) -> usize {
        self.cells.len() % self.n_columns
    }

    pub fn get_cell(&self, row: usize, column: usize) -> Option<TableCellId> {
        if column >= self.n_columns {
            return None;
        }
        let index = row.checked_mul(self.n_columns)?.checked_add(column)?;
        self.cells.get(index)?;
        Some(TableCellId(index))
    }

    pub fn get(&self, cell: TableCellId) -> Option<&TableValue> {
        self.cells.get(cell.0).map(|cell| &cell.value)
    }

    pub fn get_at(&self, row: usize, column: usize) -> Option<&TableValue> {
        self.get_cell(row, column).and_then(|cell| self.get(cell))
    }

    pub fn set_json_field_name(
        &mut self,
        idx: usize,
        name: Option<String>,
    ) -> Option<Option<String>> {
        if name.is_some() && self.json_fields.len() <= idx {
            self.json_fields.resize(idx + 1, None);
        }
        let slot = self.json_fields.get_mut(idx)?;
        Some(std::mem::replace(slot, name))
    }

    pub fn mangle_to_json_field_name(input: &str) -> String {
        mangle_to_json_field_name(input)
    }

    fn set_minimum_width(&mut self, cell: TableCellId, width: usize) -> Option<usize> {
        let cell = self.cells.get_mut(cell.0)?;
        let old = cell.minimum_width;
        cell.minimum_width = width.max(1);
        Some(old)
    }

    fn set_maximum_width(
        &mut self,
        cell: TableCellId,
        width: Option<usize>,
    ) -> Option<Option<usize>> {
        let cell = self.cells.get_mut(cell.0)?;
        let old = cell.maximum_width;
        cell.maximum_width = width;
        Some(old)
    }

    fn set_weight(&mut self, cell: TableCellId, weight: u32) -> Option<u32> {
        let cell = self.cells.get_mut(cell.0)?;
        let old = cell.weight;
        cell.weight = weight;
        Some(old)
    }

    fn set_align_percent(&mut self, cell: TableCellId, percent: u32) -> Option<u32> {
        assert!(percent <= 100);
        let cell = self.cells.get_mut(cell.0)?;
        let old = cell.align_percent;
        cell.align_percent = percent;
        Some(old)
    }

    fn set_ellipsize_percent(&mut self, cell: TableCellId, percent: u32) -> Option<u32> {
        assert!(percent <= 100);
        let cell = self.cells.get_mut(cell.0)?;
        let old = cell.ellipsize_percent;
        cell.ellipsize_percent = percent;
        Some(old)
    }

    fn set_color(&mut self, cell: TableCellId, color: Option<String>) -> Option<Option<String>> {
        let cell = self.cells.get_mut(cell.0)?;
        Some(std::mem::replace(
            &mut cell.color,
            color.filter(|s| !s.is_empty()),
        ))
    }

    fn set_rgap_color(
        &mut self,
        cell: TableCellId,
        color: Option<String>,
    ) -> Option<Option<String>> {
        let cell = self.cells.get_mut(cell.0)?;
        Some(std::mem::replace(
            &mut cell.rgap_color,
            color.filter(|s| !s.is_empty()),
        ))
    }

    fn set_underline(&mut self, cell: TableCellId, value: bool) -> Option<bool> {
        let cell = self.cells.get_mut(cell.0)?;
        let old = cell.underline;
        cell.underline = value;
        Some(old)
    }

    fn set_rgap_underline(&mut self, cell: TableCellId, value: bool) -> Option<bool> {
        let cell = self.cells.get_mut(cell.0)?;
        let old = cell.rgap_underline;
        cell.rgap_underline = value;
        Some(old)
    }

    fn set_url(&mut self, cell: TableCellId, url: Option<String>) -> Option<Option<String>> {
        let cell = self.cells.get_mut(cell.0)?;
        Some(std::mem::replace(&mut cell.url, url))
    }

    fn set_uppercase(&mut self, cell: TableCellId, value: bool) -> Option<bool> {
        let cell = self.cells.get_mut(cell.0)?;
        let old = cell.uppercase;
        cell.uppercase = value;
        Some(old)
    }

    fn visible_columns(&self) -> Vec<usize> {
        self.display_map
            .clone()
            .unwrap_or_else(|| (0..self.n_columns).collect())
    }

    fn get_at_cell(&self, row: usize, column: usize) -> Option<&TableCell> {
        self.get_cell(row, column)
            .and_then(|cell| self.cells.get(cell.0))
    }

    fn sorted_row_indices(&self) -> Vec<usize> {
        let mut rows: Vec<usize> = (0..self.get_rows()).collect();
        if self.sort_map.is_empty() || rows.len() <= 2 {
            return rows;
        }
        rows[1..].sort_by(|a, b| self.compare_rows(*a, *b));
        rows
    }

    fn compare_rows(&self, a: usize, b: usize) -> Ordering {
        for &column in &self.sort_map {
            let left = match self.get_at_cell(a, column) {
                Some(cell) => cell,
                None => continue,
            };
            let right = match self.get_at_cell(b, column) {
                Some(cell) => cell,
                None => continue,
            };
            let ordering = compare_cell_values(left, right);
            if ordering != Ordering::Equal {
                return if self.reverse_map.get(column).copied().unwrap_or(false) {
                    ordering.reverse()
                } else {
                    ordering
                };
            }
        }
        a.cmp(&b)
    }

    fn requested_width_height(&self, cell: &TableCell, available_width: usize) -> (usize, usize) {
        let formatted = self.format_cell_text(cell, false, available_width);
        let lines = apply_height_limit(lines(&formatted), self.cell_height_max);
        let mut width = lines
            .iter()
            .map(|line| display_width(line))
            .max()
            .unwrap_or(0);
        if let Some(maximum_width) = cell.maximum_width {
            width = width.min(maximum_width);
        }
        width = width.max(cell.minimum_width);
        (width, lines.len().max(1))
    }

    fn compute_column_widths(&self, columns: &[usize]) -> Vec<usize> {
        let mut minimum = vec![1; columns.len()];
        let mut requested = vec![1; columns.len()];
        let mut weight = vec![0u64; columns.len()];
        let start_row = if self.header {
            0
        } else {
            1.min(self.get_rows())
        };
        for row in start_row..self.get_rows() {
            for (display_index, &column) in columns.iter().enumerate() {
                if let Some(cell) = self.get_at_cell(row, column) {
                    let (need, _) = self.requested_width_height(cell, usize::MAX);
                    requested[display_index] = requested[display_index].max(need);
                    minimum[display_index] = minimum[display_index].max(cell.minimum_width);
                    weight[display_index] += u64::from(cell.weight);
                }
            }
        }
        let spacing = columns.len().saturating_sub(1);
        let requested_total = requested.iter().sum::<usize>() + spacing;
        let target = self.width.unwrap_or(requested_total);
        if requested_total <= target {
            return requested;
        }
        let mut widths = requested.clone();
        let mut excess = requested_total - target;
        while excess > 0 {
            let mut changed = false;
            for index in 0..widths.len() {
                if widths[index] > minimum[index] {
                    widths[index] -= 1;
                    excess -= 1;
                    changed = true;
                    if excess == 0 {
                        break;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        widths
    }

    fn format_cell_text(
        &self,
        cell: &TableCell,
        avoid_uppercasing: bool,
        available_width: usize,
    ) -> String {
        let ersatz = self.ersatz.as_str();
        match cell.data_type {
            TableDataType::Empty => ersatz.to_owned(),
            TableDataType::String
            | TableDataType::StringWithAnsi
            | TableDataType::Path
            | TableDataType::Version
            | TableDataType::Header => match &cell.value {
                TableValue::Text(text) => {
                    maybe_uppercase(text, cell.uppercase && !avoid_uppercasing)
                }
                _ => ersatz.to_owned(),
            },
            TableDataType::Field => match &cell.value {
                TableValue::Text(text) => {
                    let mut text = maybe_uppercase(text, cell.uppercase && !avoid_uppercasing);
                    text.push(':');
                    text
                }
                _ => format!("{ersatz}:"),
            },
            TableDataType::PathBasename => match &cell.value {
                TableValue::Text(text) => basename(text).to_owned(),
                _ => ersatz.to_owned(),
            },
            TableDataType::Strv => match &cell.value {
                TableValue::Strv(items) if !items.is_empty() => items.join("\n"),
                _ => ersatz.to_owned(),
            },
            TableDataType::StrvWrapped => match &cell.value {
                TableValue::Strv(items) if !items.is_empty() => wrap_strv(items, available_width),
                _ => ersatz.to_owned(),
            },
            TableDataType::Boolean => match &cell.value {
                TableValue::Bool(value) => if *value { "yes" } else { "no" }.to_owned(),
                _ => ersatz.to_owned(),
            },
            TableDataType::BooleanCheckmark => match &cell.value {
                TableValue::Bool(value) => if *value { "✓" } else { "✗" }.to_owned(),
                _ => ersatz.to_owned(),
            },
            TableDataType::Tristate => match &cell.value {
                TableValue::I64(value) if *value < 0 => ersatz.to_owned(),
                TableValue::I64(value) => if *value == 0 { "no" } else { "yes" }.to_owned(),
                _ => ersatz.to_owned(),
            },
            TableDataType::Timestamp
            | TableDataType::TimestampUtc
            | TableDataType::TimestampRelative
            | TableDataType::TimestampRelativeMonotonic
            | TableDataType::TimestampLeft
            | TableDataType::TimestampDate => match &cell.value {
                TableValue::Usec(value) => format_timestamp(cell.data_type, *value),
                TableValue::U64(value) => format_timestamp(cell.data_type, *value),
                _ => ersatz.to_owned(),
            },
            TableDataType::Timespan | TableDataType::TimespanMsec | TableDataType::TimespanDay => {
                match &cell.value {
                    TableValue::Usec(value) => format_timespan(cell.data_type, *value),
                    TableValue::U64(value) => format_timespan(cell.data_type, *value),
                    _ => ersatz.to_owned(),
                }
            }
            TableDataType::Size => match &cell.value {
                TableValue::U64(value) => format_bytes(*value),
                _ => ersatz.to_owned(),
            },
            TableDataType::Bps => match &cell.value {
                TableValue::U64(value) => format!("{}bps", format_bytes(*value)),
                _ => ersatz.to_owned(),
            },
            TableDataType::Int
            | TableDataType::Int8
            | TableDataType::Int16
            | TableDataType::Int32
            | TableDataType::Int64 => match &cell.value {
                TableValue::I64(value) => value.to_string(),
                _ => ersatz.to_owned(),
            },
            TableDataType::Uint
            | TableDataType::Uint8
            | TableDataType::Uint16
            | TableDataType::Uint32
            | TableDataType::Uint64 => match &cell.value {
                TableValue::U64(value) => value.to_string(),
                _ => ersatz.to_owned(),
            },
            TableDataType::Uint32Hex | TableDataType::Uint64Hex => match &cell.value {
                TableValue::U64(value) => format!("{value:x}"),
                _ => ersatz.to_owned(),
            },
            TableDataType::Uint32Hex0x | TableDataType::Uint64Hex0x => match &cell.value {
                TableValue::U64(value) => format!("0x{value:x}"),
                _ => ersatz.to_owned(),
            },
            TableDataType::Percent => match &cell.value {
                TableValue::Percent(value) => format!("{value}%"),
                TableValue::I64(value) => format!("{value}%"),
                _ => ersatz.to_owned(),
            },
            TableDataType::IfIndex => match &cell.value {
                TableValue::IfIndex(value) if *value > 0 => format!("if{value}"),
                _ => ersatz.to_owned(),
            },
            TableDataType::InAddr => match &cell.value {
                TableValue::Ipv4(value) => value.to_string(),
                _ => ersatz.to_owned(),
            },
            TableDataType::In6Addr => match &cell.value {
                TableValue::Ipv6(value) => value.to_string(),
                _ => ersatz.to_owned(),
            },
            TableDataType::Id128 => match &cell.value {
                TableValue::Id128(value) => hex_lower(value),
                _ => ersatz.to_owned(),
            },
            TableDataType::Uuid => match &cell.value {
                TableValue::Id128(value) => format_uuid(value),
                _ => ersatz.to_owned(),
            },
            TableDataType::Uid => match &cell.value {
                TableValue::Uid(value) => value.to_string(),
                _ => ersatz.to_owned(),
            },
            TableDataType::Gid => match &cell.value {
                TableValue::Gid(value) => value.to_string(),
                _ => ersatz.to_owned(),
            },
            TableDataType::Pid => match &cell.value {
                TableValue::Pid(value) if *value > 0 => value.to_string(),
                _ => ersatz.to_owned(),
            },
            TableDataType::Signal => match &cell.value {
                TableValue::I64(value) => signal_name(*value as i32).unwrap_or(ersatz).to_owned(),
                _ => ersatz.to_owned(),
            },
            TableDataType::Mode => match &cell.value {
                TableValue::Mode(value) => format!("{:04o}", value & 0o7777),
                _ => ersatz.to_owned(),
            },
            TableDataType::ModeInodeType => match &cell.value {
                TableValue::Mode(value) => inode_type(*value).unwrap_or(ersatz).to_owned(),
                _ => ersatz.to_owned(),
            },
            TableDataType::Devnum => match &cell.value {
                TableValue::Devnum { major, minor } => format!("{major}:{minor}"),
                _ => ersatz.to_owned(),
            },
            TableDataType::Json => match &cell.value {
                TableValue::Json(value) => value.clone(),
                _ => ersatz.to_owned(),
            },
        }
    }

    fn render_cell(&self, cell: &TableCell, width: usize) -> RenderedCell {
        let text = self.format_cell_text(cell, false, width);
        let mut cell_lines = apply_height_limit(lines(&text), self.cell_height_max);
        let height_limit_hit = self
            .cell_height_max
            .map(|max| lines(&text).len() > max)
            .unwrap_or(false);
        if height_limit_hit && !cell_lines.is_empty() {
            let last = cell_lines.len() - 1;
            cell_lines[last] = ellipsize(
                &(cell_lines[last].clone() + &ELLIPSIS.to_string()),
                width,
                100,
            );
        }
        for line in &mut cell_lines {
            if display_width(line) > width {
                *line = ellipsize(line, width, cell.ellipsize_percent);
            }
        }
        if cell_lines.is_empty() {
            cell_lines.push(String::new());
        }
        RenderedCell {
            lines: cell_lines,
            width,
            align_percent: cell.align_percent,
        }
    }

    fn to_json_regular(&self) -> String {
        let columns = self.visible_columns();
        let rows: Vec<String> = self
            .sorted_row_indices()
            .into_iter()
            .skip(1)
            .map(|row_index| {
                let fields: Vec<String> = columns
                    .iter()
                    .enumerate()
                    .filter_map(|(display_index, &column)| {
                        let cell = self.get_at_cell(row_index, column)?;
                        let name = self
                            .json_fields
                            .get(column)
                            .and_then(|name| name.clone())
                            .unwrap_or_else(|| {
                                self.get_at_cell(0, column)
                                    .map(|header| {
                                        mangle_to_json_field_name(&self.format_cell_text(
                                            header,
                                            true,
                                            usize::MAX,
                                        ))
                                    })
                                    .unwrap_or_else(|| format!("column_{display_index}"))
                            });
                        Some(format!("{}:{}", json_string(&name), self.cell_json(cell)))
                    })
                    .collect();
                format!("{{{}}}", fields.join(","))
            })
            .collect();
        format!("[{}]", rows.join(","))
    }

    fn to_json_vertical(&self) -> String {
        let mut fields = Vec::new();
        for row in 1..self.get_rows() {
            let key_index = row - 1;
            let key = self
                .json_fields
                .get(key_index)
                .and_then(|name| name.clone())
                .or_else(|| {
                    self.get_at_cell(row, 0).map(|cell| {
                        let text = self.format_cell_text(cell, true, usize::MAX);
                        let trimmed = text.trim_end_matches(':');
                        mangle_to_json_field_name(trimmed)
                    })
                })
                .unwrap_or_else(|| format!("field_{key_index}"));
            if let Some(value) = self.get_at_cell(row, 1) {
                fields.push(format!("{}:{}", json_string(&key), self.cell_json(value)));
            }
        }
        format!("{{{}}}", fields.join(","))
    }

    fn cell_json(&self, cell: &TableCell) -> String {
        match cell.data_type {
            TableDataType::Empty => "null".to_owned(),
            TableDataType::String
            | TableDataType::Path
            | TableDataType::PathBasename
            | TableDataType::Field
            | TableDataType::Header
            | TableDataType::Version => match &cell.value {
                TableValue::Text(value) => json_string(value),
                _ => "null".to_owned(),
            },
            TableDataType::StringWithAnsi => match &cell.value {
                TableValue::Text(value) => json_string(&strip_ansi(value)),
                _ => "null".to_owned(),
            },
            TableDataType::Strv | TableDataType::StrvWrapped => match &cell.value {
                TableValue::Strv(values) => format!(
                    "[{}]",
                    values
                        .iter()
                        .map(|value| json_string(value))
                        .collect::<Vec<_>>()
                        .join(",")
                ),
                _ => "null".to_owned(),
            },
            TableDataType::Boolean | TableDataType::BooleanCheckmark => match &cell.value {
                TableValue::Bool(value) => value.to_string(),
                _ => "null".to_owned(),
            },
            TableDataType::Tristate => match &cell.value {
                TableValue::I64(value) if *value < 0 => "null".to_owned(),
                TableValue::I64(value) => (*value > 0).to_string(),
                _ => "null".to_owned(),
            },
            TableDataType::Timestamp
            | TableDataType::TimestampUtc
            | TableDataType::TimestampRelative
            | TableDataType::TimestampRelativeMonotonic
            | TableDataType::TimestampLeft
            | TableDataType::TimestampDate
            | TableDataType::Timespan
            | TableDataType::TimespanMsec
            | TableDataType::TimespanDay
            | TableDataType::Size
            | TableDataType::Bps
            | TableDataType::Uint
            | TableDataType::Uint8
            | TableDataType::Uint16
            | TableDataType::Uint32
            | TableDataType::Uint32Hex
            | TableDataType::Uint32Hex0x
            | TableDataType::Uint64
            | TableDataType::Uint64Hex
            | TableDataType::Uint64Hex0x => match &cell.value {
                TableValue::Usec(value) | TableValue::U64(value) => value.to_string(),
                _ => "null".to_owned(),
            },
            TableDataType::Int
            | TableDataType::Int8
            | TableDataType::Int16
            | TableDataType::Int32
            | TableDataType::Int64
            | TableDataType::Percent
            | TableDataType::IfIndex
            | TableDataType::Uid
            | TableDataType::Gid
            | TableDataType::Pid
            | TableDataType::Signal => match &cell.value {
                TableValue::I64(value) => value.to_string(),
                TableValue::Percent(value) => value.to_string(),
                TableValue::IfIndex(value) => value.to_string(),
                TableValue::Uid(value) | TableValue::Gid(value) => value.to_string(),
                TableValue::Pid(value) => value.to_string(),
                _ => "null".to_owned(),
            },
            TableDataType::InAddr => match &cell.value {
                TableValue::Ipv4(value) => json_string(&value.to_string()),
                _ => "null".to_owned(),
            },
            TableDataType::In6Addr => match &cell.value {
                TableValue::Ipv6(value) => json_string(&value.to_string()),
                _ => "null".to_owned(),
            },
            TableDataType::Id128 => match &cell.value {
                TableValue::Id128(value) => json_string(&hex_lower(value)),
                _ => "null".to_owned(),
            },
            TableDataType::Uuid => match &cell.value {
                TableValue::Id128(value) => json_string(&format_uuid(value)),
                _ => "null".to_owned(),
            },
            TableDataType::Mode | TableDataType::ModeInodeType => match &cell.value {
                TableValue::Mode(value) => value.to_string(),
                _ => "null".to_owned(),
            },
            TableDataType::Devnum => match &cell.value {
                TableValue::Devnum { major, minor } => format!("[{},{}]", major, minor),
                _ => "null".to_owned(),
            },
            TableDataType::Json => match &cell.value {
                TableValue::Json(value) => value.clone(),
                _ => "null".to_owned(),
            },
        }
    }
}

#[derive(Debug, Clone)]
struct RenderedCell {
    lines: Vec<String>,
    width: usize,
    align_percent: u32,
}

impl fmt::Display for Table {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.format())
    }
}

fn compare_cell_values(left: &TableCell, right: &TableCell) -> Ordering {
    if left.data_type != right.data_type {
        return Ordering::Equal;
    }
    match (&left.value, &right.value, left.data_type) {
        (TableValue::I64(a), TableValue::I64(b), TableDataType::Tristate) => {
            let bucket = |value: i64| value.signum();
            bucket(*a).cmp(&bucket(*b))
        }
        (TableValue::Text(a), TableValue::Text(b), TableDataType::Version) => version_cmp(a, b),
        (TableValue::Text(a), TableValue::Text(b), _) => a.cmp(b),
        (TableValue::Strv(a), TableValue::Strv(b), _) => a.cmp(b),
        (TableValue::Bool(a), TableValue::Bool(b), _) => a.cmp(b),
        (TableValue::Usec(a), TableValue::Usec(b), _)
        | (TableValue::U64(a), TableValue::U64(b), _) => a.cmp(b),
        (TableValue::I64(a), TableValue::I64(b), _) => a.cmp(b),
        (TableValue::Percent(a), TableValue::Percent(b), _) => a.cmp(b),
        (TableValue::IfIndex(a), TableValue::IfIndex(b), _) => a.cmp(b),
        (TableValue::Ipv4(a), TableValue::Ipv4(b), _) => a.octets().cmp(&b.octets()),
        (TableValue::Ipv6(a), TableValue::Ipv6(b), _) => a.octets().cmp(&b.octets()),
        (TableValue::Id128(a), TableValue::Id128(b), _) => a.cmp(b),
        (TableValue::Uid(a), TableValue::Uid(b), _)
        | (TableValue::Gid(a), TableValue::Gid(b), _) => a.cmp(b),
        (TableValue::Pid(a), TableValue::Pid(b), _) => a.cmp(b),
        (TableValue::Mode(a), TableValue::Mode(b), _) => a.cmp(b),
        (
            TableValue::Devnum {
                major: am,
                minor: an,
            },
            TableValue::Devnum {
                major: bm,
                minor: bn,
            },
            _,
        ) => am.cmp(bm).then(an.cmp(bn)),
        (TableValue::Json(a), TableValue::Json(b), _) => a.cmp(b),
        _ => Ordering::Equal,
    }
}

fn maybe_uppercase(text: &str, uppercase: bool) -> String {
    if uppercase {
        text.to_ascii_uppercase()
    } else {
        text.to_owned()
    }
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn display_width(text: &str) -> usize {
    text.chars().count()
}

fn lines(text: &str) -> Vec<String> {
    let lines: Vec<String> = text.split('\n').map(str::to_owned).collect();
    if lines.is_empty() {
        vec![String::new()]
    } else {
        lines
    }
}

fn apply_height_limit(mut lines: Vec<String>, limit: Option<usize>) -> Vec<String> {
    if let Some(limit) = limit {
        lines.truncate(limit);
    }
    lines
}

fn wrap_strv(items: &[String], width: usize) -> String {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut current = String::new();
    for item in items {
        if current.is_empty() {
            current = item.clone();
        } else if display_width(&current) + 1 + display_width(item) <= width {
            current.push(' ');
            current.push_str(item);
        } else {
            lines.push(current);
            current = item.clone();
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines.join("\n")
}

fn align_string(text: &str, width: usize, percent: u32) -> String {
    let actual = display_width(text);
    if actual >= width {
        return text.to_owned();
    }
    let padding = width - actual;
    let left = padding * percent as usize / 100;
    let right = padding - left;
    format!("{}{}{}", " ".repeat(left), text, " ".repeat(right))
}

fn ellipsize(text: &str, width: usize, percent: u32) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= width {
        return text.to_owned();
    }
    if width == 0 {
        return String::new();
    }
    if width == 1 {
        return ELLIPSIS.to_string();
    }
    let keep = width - 1;
    let left = keep * percent as usize / 100;
    let left = left.min(keep);
    let right = keep - left;
    let mut out = String::new();
    out.extend(chars.iter().take(left));
    out.push(ELLIPSIS);
    if right > 0 {
        out.extend(chars.iter().skip(chars.len() - right));
    }
    out
}

fn format_timestamp(kind: TableDataType, usec: u64) -> String {
    match kind {
        TableDataType::TimestampRelative
        | TableDataType::TimestampRelativeMonotonic
        | TableDataType::TimestampLeft => format_timespan(TableDataType::Timespan, usec),
        TableDataType::TimestampDate => format!("date:{usec}"),
        TableDataType::TimestampUtc => format!("utc:{usec}"),
        _ => format!("ts:{usec}"),
    }
}

fn format_timespan(kind: TableDataType, usec: u64) -> String {
    match kind {
        TableDataType::TimespanDay => format!("{}d", usec / 86_400_000_000),
        TableDataType::TimespanMsec => format!("{}ms", usec / 1_000),
        _ => {
            if usec >= 1_000_000 {
                format!("{}.{:03}s", usec / 1_000_000, (usec % 1_000_000) / 1_000)
            } else if usec >= 1_000 {
                format!("{}ms", usec / 1_000)
            } else {
                format!("{usec}us")
            }
        }
    }
}

fn format_bytes(value: u64) -> String {
    const UNITS: [&str; 6] = ["B", "K", "M", "G", "T", "P"];
    let mut size = value as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{}{}", value, UNITS[unit])
    } else {
        format!("{size:.1}{}", UNITS[unit])
    }
}

fn hex_lower(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn format_uuid(bytes: &[u8; 16]) -> String {
    let hex = hex_lower(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn inode_type(mode: u32) -> Option<&'static str> {
    match mode & 0o170000 {
        0o040000 => Some("directory"),
        0o100000 => Some("regular"),
        0o120000 => Some("symlink"),
        0o060000 => Some("blockdev"),
        0o020000 => Some("chardev"),
        0o010000 => Some("fifo"),
        0o140000 => Some("socket"),
        _ => None,
    }
}

fn signal_name(signal: i32) -> Option<&'static str> {
    match signal {
        1 => Some("SIGHUP"),
        2 => Some("SIGINT"),
        9 => Some("SIGKILL"),
        15 => Some("SIGTERM"),
        _ => None,
    }
}

fn version_cmp(left: &str, right: &str) -> Ordering {
    let mut l = left.chars().peekable();
    let mut r = right.chars().peekable();
    loop {
        match (l.peek(), r.peek()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(lc), Some(rc)) if lc.is_ascii_digit() && rc.is_ascii_digit() => {
                let ln = take_number(&mut l);
                let rn = take_number(&mut r);
                match ln.cmp(&rn) {
                    Ordering::Equal => continue,
                    ordering => return ordering,
                }
            }
            (Some(_), Some(_)) => {
                let lc = l.next().unwrap_or_default();
                let rc = r.next().unwrap_or_default();
                match lc.cmp(&rc) {
                    Ordering::Equal => continue,
                    ordering => return ordering,
                }
            }
        }
    }
}

fn take_number(iter: &mut std::iter::Peekable<std::str::Chars<'_>>) -> u64 {
    let mut value = 0u64;
    while let Some(ch) = iter.peek() {
        if !ch.is_ascii_digit() {
            break;
        }
        value = value
            .saturating_mul(10)
            .saturating_add(u64::from(ch.to_digit(10).unwrap_or(0)));
        iter.next();
    }
    value
}

fn strip_ansi(input: &str) -> String {
    let mut out = String::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            while let Some(next) = chars.next() {
                if ('@'..='~').contains(&next) {
                    break;
                }
            }
            continue;
        }
        if ch != '\t' {
            out.push(ch);
        }
    }
    out
}

fn mangle_to_json_field_name(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(chars.len());
    let mut new_word = true;
    for (index, ch) in chars.iter().copied().enumerate() {
        if !ch.is_ascii_alphanumeric() {
            out.push('_');
            new_word = true;
            continue;
        }
        if new_word
            && chars
                .get(index + 1)
                .is_some_and(|next| next.is_ascii_lowercase())
        {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
        new_word = false;
    }
    out
}

fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_basic_table() {
        let mut table = Table::new(["name", "value"]);
        table.add_cell(TableDataType::String, "alpha");
        table.add_cell(TableDataType::Uint64, 42_u64);
        table.add_cell(TableDataType::String, "beta");
        table.add_cell(TableDataType::Uint64, 7_u64);
        assert_eq!(table.format(), "NAME  VALUE\nalpha 42\nbeta  7\n");
    }

    #[test]
    fn sorts_versions_and_reverses() {
        let mut table = Table::new(["name", "version"]);
        table.add_cell(TableDataType::String, "pkg");
        table.add_cell(TableDataType::Version, "1.9");
        table.add_cell(TableDataType::String, "pkg");
        table.add_cell(TableDataType::Version, "1.10");
        table.set_sort([1]);
        assert!(table.format().contains("1.9\npkg  1.10\n"));
        let _ = table.set_reverse(1, true);
        assert!(table.format().contains("1.10\npkg  1.9\n"));
    }

    #[test]
    fn wraps_and_truncates_multiline_cells() {
        let mut table = Table::new(["items"]);
        table.add_cell(
            TableDataType::StrvWrapped,
            vec!["one", "two", "three", "four"],
        );
        table.set_width(6);
        table.set_cell_height_max(2);
        assert_eq!(table.format(), "ITEMS\none\ntwo…\n");
    }

    #[test]
    fn fill_empty_and_duplicate_work() {
        let mut table = Table::new(["a", "b", "c"]);
        let first = table.add_cell(TableDataType::String, "x");
        table.fill_empty(0);
        let _ = table.dup_cell(first);
        table.add_cell(TableDataType::String, "y");
        assert_eq!(table.get_rows(), 2);
        assert_eq!(table.get_at(1, 0), Some(&TableValue::Text("x".into())));
    }

    #[test]
    fn add_many_applies_follow_up_modifiers() {
        let mut table = Table::new(["path"]);
        table.add_many([
            TableItem::Cell(
                TableDataType::PathBasename,
                TableValue::from("/tmp/demo.txt"),
            ),
            TableItem::SetMinimumWidth(12),
            TableItem::SetAlignPercent(100),
            TableItem::SetJsonFieldName(Some("file".into())),
        ]);
        assert_eq!(table.format(), "PATH\n    demo.txt\n");
        assert_eq!(table.to_json(), "[{\"file\":\"/tmp/demo.txt\"}]");
    }

    #[test]
    fn hides_columns_and_syncs_widths() {
        let mut left = Table::new(["name", "value"]);
        left.add_cell(TableDataType::String, "longer-name");
        left.add_cell(TableDataType::String, "x");

        let mut right = Table::new(["name", "value"]);
        right.add_cell(TableDataType::String, "id");
        right.add_cell(TableDataType::String, "y");

        assert!(left.sync_column_width(0, &mut right, 0));
        right.hide_columns_from_display([1]);
        assert_eq!(left.data_requested_width(0), right.data_requested_width(0));
        assert_eq!(right.format(), "NAME\nid\n");
    }

    #[test]
    fn vertical_json_uses_field_names() {
        let mut table = Table::new_vertical();
        table.add_cell(TableDataType::Field, "User Name");
        table.add_cell(TableDataType::String, "alice");
        table.add_cell(TableDataType::Field, "UID");
        table.add_cell(TableDataType::Uid, TableValue::Uid(1000));
        assert_eq!(table.to_json(), "{\"user_name\":\"alice\",\"UID\":1000}");
    }

    #[test]
    fn json_strips_ansi_sequences() {
        let mut table = Table::new(["colored"]);
        table.add_cell(TableDataType::StringWithAnsi, "\u{1b}[31mred\u{1b}[0m");
        assert_eq!(table.to_json(), "[{\"colored\":\"red\"}]");
    }

    #[test]
    fn renders_special_types() {
        let mut table = Table::new(["mode", "dev", "signal", "uuid"]);
        table.add_cell(TableDataType::Mode, TableValue::Mode(0o100644));
        table.add_cell(
            TableDataType::Devnum,
            TableValue::Devnum { major: 8, minor: 1 },
        );
        table.add_cell(TableDataType::Signal, TableValue::I64(15));
        table.add_cell(TableDataType::Uuid, TableValue::Id128([0x12; 16]));
        let output = table.format();
        assert!(output.contains("0644"));
        assert!(output.contains("8:1"));
        assert!(output.contains("SIGTERM"));
        assert!(output.contains("12121212-1212-1212-1212-121212121212"));
    }

    #[test]
    fn mangles_json_field_names_like_c_style() {
        assert_eq!(Table::mangle_to_json_field_name("User Name"), "user_name");
        assert_eq!(
            Table::mangle_to_json_field_name("CPU Usage %"),
            "CPU_usage__"
        );
    }
}

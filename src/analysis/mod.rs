pub mod branches;
pub mod compare;
pub mod hotpaths;
pub mod page;
pub mod source;
pub mod timeline;

pub use compare::{CompareReport, compare_hotpaths};
pub use hotpaths::{HotpathOptions, child_index, hotpaths, hotpaths_with, inline_rows};
pub use page::{fit_json, paginate, parse_offset_cursor};
pub use source::{InlineFrame, SourceInfo, dwarf_frames, resolve_source};
pub use timeline::{TimelineOptions, self_elapsed, timeline_rows, timeline_rows_with};

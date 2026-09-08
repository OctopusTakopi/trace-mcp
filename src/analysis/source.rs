use std::path::Path;

use crate::model::{
    Address, CodeLocation, FlowEvent, FunctionSpan, IdKind, InstructionRecord, LocalId,
    parse_namespaced,
};

/// One DWARF inline frame, innermost first in [`SourceInfo::inlined`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InlineFrame {
    pub function: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
}

/// Source evidence for one code location. `file`/`line` describe the
/// innermost inlined frame at that address; `function` is the containing
/// ELF symbol. Source lines refer to the build that was archived, which may
/// differ from today's checkout.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SourceInfo {
    pub image_path: String,
    pub image_id: String,
    pub image_offset: Address,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virt_ip: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    pub inlined: Vec<InlineFrame>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Fill file/line and the inline chain from the archived image's DWARF.
pub fn dwarf_frames(
    archive_path: &Path,
    addr: u64,
) -> (
    Option<String>,
    Option<u32>,
    Vec<InlineFrame>,
    Option<String>,
) {
    let loader = match addr2line::Loader::new(archive_path) {
        Ok(l) => l,
        Err(e) => {
            return (
                None,
                None,
                Vec::new(),
                Some(format!("no DWARF loader: {e}")),
            );
        }
    };
    let mut inlined = Vec::new();
    match loader.find_frames(addr) {
        Ok(mut frames) => {
            while let Ok(Some(f)) = frames.next() {
                inlined.push(InlineFrame {
                    function: f
                        .function
                        .as_ref()
                        .and_then(|n| n.demangle().ok().map(|s| s.into_owned())),
                    file: f.location.as_ref().and_then(|l| l.file.map(str::to_string)),
                    line: f.location.as_ref().and_then(|l| l.line),
                });
            }
        }
        Err(e) => {
            return (
                None,
                None,
                Vec::new(),
                Some(format!("DWARF lookup failed: {e}")),
            );
        }
    }
    let (file, line) = inlined
        .first()
        .map(|f| (f.file.clone(), f.line))
        .unwrap_or((None, None));
    let note = if inlined.is_empty() {
        Some("no DWARF line information at this address (build with debug=2, no strip)".into())
    } else {
        None
    };
    (file, line, inlined, note)
}

pub fn resolve_source(
    locs: &[CodeLocation],
    events: &[FlowEvent],
    instructions: &[InstructionRecord],
    spans: &[FunctionSpan],
    location_id: Option<&str>,
    function_id: Option<&str>,
    evidence_id: Option<&str>,
) -> Option<CodeLocation> {
    if let Some(id) = location_id
        && let Some(loc) = loc_by_ref(locs, id)
    {
        return Some(loc);
    }
    if let Some(id) = function_id
        && let Some(loc) = loc_by_function_ref(locs, id)
    {
        return Some(loc);
    }
    if let Some(id) = evidence_id {
        return loc_by_evidence(locs, events, instructions, spans, id);
    }
    None
}

fn loc_by_id(locs: &[CodeLocation], id: LocalId) -> Option<CodeLocation> {
    locs.iter().find(|l| l.id == id).cloned()
}

fn loc_by_function(locs: &[CodeLocation], id: LocalId) -> Option<CodeLocation> {
    locs.iter().find(|l| l.function == Some(id)).cloned()
}

fn loc_by_ref(locs: &[CodeLocation], raw: &str) -> Option<CodeLocation> {
    let ns = parse_namespaced(raw).ok()?;
    if ns.kind == IdKind::Location {
        loc_by_id(locs, ns.local)
    } else {
        None
    }
}

fn loc_by_function_ref(locs: &[CodeLocation], raw: &str) -> Option<CodeLocation> {
    let ns = parse_namespaced(raw).ok()?;
    if ns.kind == IdKind::Function {
        loc_by_function(locs, ns.local)
    } else {
        None
    }
}

fn loc_from_event(locs: &[CodeLocation], event: &FlowEvent) -> Option<CodeLocation> {
    event.from.or(event.to).and_then(|id| loc_by_id(locs, id))
}

fn loc_by_evidence(
    locs: &[CodeLocation],
    events: &[FlowEvent],
    instructions: &[InstructionRecord],
    spans: &[FunctionSpan],
    raw: &str,
) -> Option<CodeLocation> {
    if let Some((start, end)) = parse_event_range(raw) {
        return events
            .iter()
            .filter(|e| e.id.0 >= start.0 && e.id.0 <= end.0)
            .find_map(|e| loc_from_event(locs, e));
    }
    let ns = parse_namespaced(raw).ok()?;
    match ns.kind {
        IdKind::Location => loc_by_id(locs, ns.local),
        IdKind::Function => loc_by_function(locs, ns.local),
        IdKind::Event => events
            .iter()
            .find(|e| e.id == ns.local)
            .and_then(|e| loc_from_event(locs, e)),
        IdKind::Span => spans.iter().find(|s| s.id == ns.local).and_then(|sp| {
            loc_by_function(locs, sp.function?).or_else(|| {
                events
                    .iter()
                    .find(|e| e.id == sp.evidence.start_id)
                    .and_then(|e| loc_from_event(locs, e))
            })
        }),
        IdKind::Gap => None,
    }
    .or_else(|| {
        instructions
            .iter()
            .find(|i| i.id == ns.local)
            .and_then(|i| i.location.and_then(|id| loc_by_id(locs, id)))
    })
}

fn parse_event_range(raw: &str) -> Option<(LocalId, LocalId)> {
    let (left, right) = raw.split_once("-e")?;
    let start = parse_namespaced(left).ok()?;
    if start.kind != IdKind::Event {
        return None;
    }
    let end = right.parse::<u32>().ok()?;
    Some((start.local, LocalId(end)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Address, BoundaryFlags, EventTime, FlowKind};

    fn loc(id: u32, func: Option<u32>) -> CodeLocation {
        CodeLocation {
            id: LocalId(id),
            image_id: "img".into(),
            image_offset: Address(0),
            virt_ip: None,
            function: func.map(LocalId),
            file: Some("src/lib.rs".into()),
            line: Some(10),
            inlined: None,
        }
    }

    fn event(id: u32, from: u32) -> FlowEvent {
        FlowEvent {
            id: LocalId(id),
            thread: crate::model::ThreadId::from_raw("t_0").unwrap(),
            sequence: id as u64,
            time: EventTime::unknown(),
            from: Some(LocalId(from)),
            to: None,
            kind: FlowKind::Call,
            boundary: BoundaryFlags::default(),
            virt_from: None,
            virt_to: None,
        }
    }

    #[test]
    fn evidence_id_is_not_the_first_location() {
        let locs = vec![loc(0, Some(1)), loc(1, Some(2))];
        let events = vec![event(4, 1)];
        let found = resolve_source(&locs, &events, &[], &[], None, None, Some("a_1:e4")).unwrap();
        assert_eq!(found.id, LocalId(1));
        assert!(resolve_source(&locs, &events, &[], &[], None, None, Some("a_1:e99")).is_none());
    }

    #[test]
    fn event_range_and_location_refs() {
        let locs = vec![loc(0, Some(1)), loc(3, Some(2))];
        let events = vec![event(0, 0), event(2, 3)];
        let range =
            resolve_source(&locs, &events, &[], &[], None, None, Some("a_1:e1-e2")).unwrap();
        assert_eq!(range.id, LocalId(3));
        let by_loc = resolve_source(&locs, &[], &[], &[], Some("a_1:l3"), None, None).unwrap();
        assert_eq!(by_loc.id, LocalId(3));
        let by_fn = resolve_source(&locs, &[], &[], &[], None, Some("a_1:f2"), None).unwrap();
        assert_eq!(by_fn.id, LocalId(3));
    }

    #[test]
    fn unknown_evidence_does_not_fall_back() {
        let locs = vec![loc(0, None)];
        assert!(resolve_source(&locs, &[], &[], &[], None, None, Some("a_1:e0")).is_none());
    }
}

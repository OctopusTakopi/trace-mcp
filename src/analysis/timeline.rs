use crate::model::{EventTime, FunctionSpan, Selection, SpanCompleteness, ThreadId};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TimelineRow {
    pub span_id: String,
    pub thread_id: ThreadId,
    pub function: Option<String>,
    pub parent: Option<String>,
    pub start_ns: Option<u64>,
    pub end_ns: Option<u64>,
    pub completeness: SpanCompleteness,
    pub clipped: bool,
    pub evidence: String,
    /// Address of the call that opened the span, when observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_site: Option<crate::model::Address>,
    /// Innermost inlined function at the call site (filled by the service
    /// from DWARF when the image is archived).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_site_inline: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct TimelineOptions {
    pub function_contains: Option<String>,
    pub min_duration_ns: Option<u64>,
}

pub fn timeline_rows(
    analysis: &str,
    spans: &[FunctionSpan],
    names: &std::collections::HashMap<u32, String>,
    selection: &Selection,
) -> Vec<TimelineRow> {
    timeline_rows_with(
        analysis,
        spans,
        names,
        selection,
        &TimelineOptions::default(),
    )
}

pub fn timeline_rows_with(
    analysis: &str,
    spans: &[FunctionSpan],
    names: &std::collections::HashMap<u32, String>,
    selection: &Selection,
    opts: &TimelineOptions,
) -> Vec<TimelineRow> {
    let mut rows = Vec::new();
    for sp in spans {
        if let Some(ref want) = selection.thread_id
            && &sp.thread != want
        {
            continue;
        }
        let start = sp.start.relative_ns;
        let end = sp.end.relative_ns;
        if !selection.intersects(start, end) {
            continue;
        }
        let name = sp.function.and_then(|id| names.get(&id.0));
        if let Some(f) = &opts.function_contains
            && !name.is_some_and(|n| n.contains(f.as_str()))
        {
            continue;
        }
        if let Some(min) = opts.min_duration_ns {
            match (start, end) {
                (Some(s), Some(e)) if e.saturating_sub(s) >= min => {}
                _ => continue,
            }
        }
        let clipped = match (selection.start_ns, selection.end_ns, start, end) {
            (Some(s), _, Some(st), _) if st < s => true,
            (_, Some(e), _, Some(en)) if en > e => true,
            _ => false,
        };
        rows.push(TimelineRow {
            span_id: format!("{analysis}:sp{}", sp.id.0),
            thread_id: sp.thread.clone(),
            function: sp.function.and_then(|id| names.get(&id.0).cloned()),
            parent: sp.parent.map(|p| format!("{analysis}:sp{}", p.0)),
            start_ns: start,
            end_ns: end,
            completeness: sp.completeness,
            clipped,
            evidence: format!(
                "{analysis}:e{}-e{}",
                sp.evidence.start_id.0, sp.evidence.end_id.0
            ),
            call_site: sp.call_site,
            call_site_inline: None,
        });
    }
    rows.sort_by(|a, b| a.start_ns.cmp(&b.start_ns).then(a.span_id.cmp(&b.span_id)));
    rows
}

pub fn inclusive_elapsed(
    start: &EventTime,
    end: &EventTime,
    complete: SpanCompleteness,
) -> Option<u64> {
    if complete != SpanCompleteness::Complete {
        return None;
    }
    Some(end.relative_ns?.saturating_sub(start.relative_ns?))
}

/// Self time = parent interval minus the union of eligible immediate-child intervals.
pub fn self_elapsed(
    parent_start: u64,
    parent_end: u64,
    children: &[(u64, u64)],
    children_certain: bool,
) -> Option<u64> {
    if !children_certain || parent_end < parent_start {
        return None;
    }
    let mut iv: Vec<(u64, u64)> = children
        .iter()
        .filter_map(|&(s, e)| {
            let s = s.max(parent_start);
            let e = e.min(parent_end);
            (e > s).then_some((s, e))
        })
        .collect();
    iv.sort_unstable();
    let mut union = 0u64;
    let mut cur = parent_start;
    for (s, e) in iv {
        let s = s.max(cur);
        if e > s {
            union = union.saturating_add(e - s);
            cur = e;
        }
    }
    (parent_end - parent_start).checked_sub(union)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_union() {
        assert_eq!(
            self_elapsed(0, 100, &[(10, 20), (15, 30), (50, 60)], true),
            Some(70)
        );
        assert_eq!(self_elapsed(0, 100, &[], true), Some(100));
        assert_eq!(self_elapsed(0, 100, &[(0, 100)], true), Some(0));
        assert!(self_elapsed(0, 100, &[(1, 2)], false).is_none());
    }
}

use std::collections::HashMap;

use crate::analysis::timeline::{inclusive_elapsed, self_elapsed};
use crate::model::{
    Count, FunctionSpan, HotpathGroup, HotpathSort, P99_MIN_SAMPLES, Selection, SpanCompleteness,
    nearest_rank,
};

#[derive(Debug, Clone, Default)]
pub struct HotpathOptions {
    pub function_contains: Option<String>,
    pub group: HotpathGroup,
    pub sort: HotpathSort,
    pub max_depth: Option<usize>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HotpathRow {
    pub path: String,
    pub complete_calls: Count,
    pub observed_entries: Count,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inclusive_sum_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_sum_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p50_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p95_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p99_ns: Option<u64>,
    pub excluded_incomplete: Count,
    pub n_eligible: Count,
    /// `group: inline` only: executed instructions in this inline chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<Count>,
}

pub fn hotpaths(
    spans: &[FunctionSpan],
    names: &HashMap<u32, String>,
    selection: &Selection,
    children: &HashMap<u32, Vec<u32>>,
) -> Vec<HotpathRow> {
    hotpaths_with(
        spans,
        names,
        selection,
        children,
        &HotpathOptions::default(),
    )
}

pub fn hotpaths_with(
    spans: &[FunctionSpan],
    names: &HashMap<u32, String>,
    selection: &Selection,
    children: &HashMap<u32, Vec<u32>>,
    opts: &HotpathOptions,
) -> Vec<HotpathRow> {
    let by_id: HashMap<u32, usize> = spans.iter().enumerate().map(|(i, s)| (s.id.0, i)).collect();
    let mut path_cache: HashMap<u32, String> = HashMap::new();
    let mut by_path: HashMap<String, Agg> = HashMap::new();
    for sp in spans {
        if let Some(ref t) = selection.thread_id
            && &sp.thread != t
        {
            continue;
        }
        let path = match opts.group {
            HotpathGroup::Path => {
                let full = path_of(sp, spans, &by_id, names, &mut path_cache);
                match opts.max_depth {
                    Some(d) if d > 0 => truncate_depth(&full, d),
                    _ => full,
                }
            }
            HotpathGroup::Function | HotpathGroup::Inline => sp
                .function
                .and_then(|id| names.get(&id.0).cloned())
                .unwrap_or_else(|| "<unknown>".into()),
        };
        if let Some(f) = &opts.function_contains
            && !path.contains(f.as_str())
        {
            continue;
        }
        let e = by_path.entry(path).or_default();
        e.observed += 1;
        let contained = match (
            selection.start_ns,
            selection.end_ns,
            sp.start.relative_ns,
            sp.end.relative_ns,
        ) {
            (Some(a), Some(b), Some(s), Some(e)) => s >= a && e <= b,
            (None, None, _, _) => true,
            (Some(a), None, Some(s), _) => s >= a,
            (None, Some(b), _, Some(e)) => e <= b,
            _ => false,
        };
        if sp.completeness != SpanCompleteness::Complete || !contained {
            e.excluded += 1;
            continue;
        }
        e.complete += 1;
        if let Some(inc) = inclusive_elapsed(&sp.start, &sp.end, sp.completeness) {
            e.inclusives.push(inc);
        }
        if let (Some(ps), Some(pe)) = (sp.start.relative_ns, sp.end.relative_ns) {
            let kids = children.get(&sp.id.0).cloned().unwrap_or_default();
            let mut civ = Vec::new();
            let mut certain = true;
            for kid in kids {
                if let Some(ch) = by_id.get(&kid).map(|&i| &spans[i]) {
                    if ch.completeness != SpanCompleteness::Complete {
                        certain = false;
                        break;
                    }
                    if let (Some(s), Some(e)) = (ch.start.relative_ns, ch.end.relative_ns) {
                        civ.push((s, e));
                    } else {
                        certain = false;
                        break;
                    }
                }
            }
            if let Some(slf) = self_elapsed(ps, pe, &civ, certain) {
                e.selfs.push(slf);
            }
        }
    }

    let mut rows: Vec<_> = by_path
        .into_iter()
        .map(|(path, mut agg)| {
            agg.inclusives.sort_unstable();
            let n = agg.inclusives.len();
            HotpathRow {
                path,
                complete_calls: Count(agg.complete),
                observed_entries: Count(agg.observed),
                inclusive_sum_ns: if agg.inclusives.is_empty() {
                    None
                } else {
                    Some(agg.inclusives.iter().copied().sum())
                },
                self_sum_ns: if agg.selfs.is_empty() {
                    None
                } else {
                    Some(agg.selfs.iter().copied().sum())
                },
                p50_ns: nearest_rank(&agg.inclusives, 50),
                p95_ns: nearest_rank(&agg.inclusives, 95),
                p99_ns: if n >= P99_MIN_SAMPLES {
                    nearest_rank(&agg.inclusives, 99)
                } else {
                    None
                },
                excluded_incomplete: Count(agg.excluded),
                n_eligible: Count(n as u64),
                instructions: None,
            }
        })
        .collect();
    match opts.sort {
        HotpathSort::Inclusive => rows.sort_by(|a, b| {
            b.inclusive_sum_ns
                .cmp(&a.inclusive_sum_ns)
                .then(a.path.cmp(&b.path))
        }),
        HotpathSort::SelfTime => rows.sort_by(|a, b| {
            b.self_sum_ns
                .cmp(&a.self_sum_ns)
                .then(b.inclusive_sum_ns.cmp(&a.inclusive_sum_ns))
                .then(a.path.cmp(&b.path))
        }),
        HotpathSort::Calls => rows.sort_by(|a, b| {
            b.observed_entries
                .cmp(&a.observed_entries)
                .then(a.path.cmp(&b.path))
        }),
    }
    rows
}

/// `group: inline` rows from the reconstructor's block attribution.
pub fn inline_rows(
    rows: &[crate::model::InlineRow],
    names: &HashMap<u32, String>,
    selection: &Selection,
    opts: &HotpathOptions,
) -> Vec<HotpathRow> {
    let mut by_path: HashMap<String, (u64, u64, u64)> = HashMap::new();
    for r in rows {
        if let Some(ref t) = selection.thread_id
            && &r.thread != t
        {
            continue;
        }
        let mut path = r
            .function
            .and_then(|id| names.get(&id.0).cloned())
            .unwrap_or_else(|| "<unknown>".into());
        for c in r.chain.iter().rev() {
            path.push_str(" > ");
            path.push_str(c);
        }
        if let Some(f) = &opts.function_contains
            && !path.contains(f.as_str())
        {
            continue;
        }
        let e = by_path.entry(path).or_default();
        e.0 += r.instructions.0;
        e.1 += r.blocks.0;
        e.2 += r.elapsed_ns.0;
    }
    let mut out: Vec<HotpathRow> = by_path
        .into_iter()
        .map(|(path, (insns, blocks, elapsed))| HotpathRow {
            path,
            complete_calls: Count(0),
            observed_entries: Count(blocks),
            inclusive_sum_ns: None,
            self_sum_ns: Some(elapsed),
            p50_ns: None,
            p95_ns: None,
            p99_ns: None,
            excluded_incomplete: Count(0),
            n_eligible: Count(blocks),
            instructions: Some(Count(insns)),
        })
        .collect();
    match opts.sort {
        HotpathSort::SelfTime => {
            out.sort_by(|a, b| b.self_sum_ns.cmp(&a.self_sum_ns).then(a.path.cmp(&b.path)))
        }
        _ => out.sort_by(|a, b| {
            b.instructions
                .cmp(&a.instructions)
                .then(a.path.cmp(&b.path))
        }),
    }
    out
}

/// Keep the innermost `depth` frames of a `/`-joined path.
fn truncate_depth(path: &str, depth: usize) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() <= depth {
        return path.to_string();
    }
    format!(".../{}", parts[parts.len() - depth..].join("/"))
}

#[derive(Default)]
struct Agg {
    complete: u64,
    observed: u64,
    excluded: u64,
    inclusives: Vec<u64>,
    selfs: Vec<u64>,
}

fn path_of(
    sp: &FunctionSpan,
    spans: &[FunctionSpan],
    by_id: &HashMap<u32, usize>,
    names: &HashMap<u32, String>,
    cache: &mut HashMap<u32, String>,
) -> String {
    if let Some(p) = cache.get(&sp.id.0) {
        return p.clone();
    }
    const MAX_DEPTH: usize = 64;
    // Walk up without recursion (a deep recursive workload has parent
    // chains far longer than a blocking thread's stack), stopping at a
    // cached ancestor or after MAX_DEPTH frames.
    let mut chain: Vec<&FunctionSpan> = vec![sp];
    let mut prefix: Option<String> = None;
    let mut cur = sp;
    while let Some(parent) = cur.parent.and_then(|p| by_id.get(&p.0)).map(|&i| &spans[i]) {
        if parent.id == cur.id {
            break;
        }
        if let Some(p) = cache.get(&parent.id.0) {
            prefix = Some(p.clone());
            break;
        }
        if chain.len() >= MAX_DEPTH {
            prefix = Some("...".to_string());
            break;
        }
        chain.push(parent);
        cur = parent;
    }
    let mut path = prefix.unwrap_or_default();
    for node in chain.iter().rev() {
        let name = node
            .function
            .and_then(|id| names.get(&id.0).cloned())
            .unwrap_or_else(|| "<unknown>".into());
        path = if path.is_empty() {
            name
        } else if path.matches('/').count() >= MAX_DEPTH {
            format!("{path}/...")
        } else {
            format!("{path}/{name}")
        };
        cache.insert(node.id.0, path.clone());
    }
    path
}

pub fn child_index(spans: &[FunctionSpan]) -> HashMap<u32, Vec<u32>> {
    let mut m: HashMap<u32, Vec<u32>> = HashMap::new();
    for sp in spans {
        if let Some(p) = sp.parent {
            m.entry(p.0).or_default().push(sp.id.0);
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EventRange, EventTime, LocalId, ThreadId};

    fn span(id: u32, parent: Option<u32>, start: u64, end: u64, complete: bool) -> FunctionSpan {
        FunctionSpan {
            id: LocalId(id),
            thread: ThreadId::from_raw("t_0").unwrap(),
            function: Some(LocalId(id)),
            parent: parent.map(LocalId),
            start: EventTime::estimate(start),
            end: EventTime::estimate(end),
            completeness: if complete {
                SpanCompleteness::Complete
            } else {
                SpanCompleteness::OpenEnd
            },
            evidence: EventRange {
                start_id: LocalId(0),
                end_id: LocalId(0),
            },
            call_site: None,
        }
    }

    #[test]
    fn excludes_incomplete() {
        let spans = [span(1, None, 0, 10, true), span(2, Some(1), 1, 2, false)];
        let mut names = HashMap::new();
        names.insert(1, "root".into());
        names.insert(2, "child".into());
        let rows = hotpaths(
            &spans,
            &names,
            &Selection {
                thread_id: None,
                start_ns: None,
                end_ns: None,
            },
            &child_index(&spans),
        );
        let root = rows.iter().find(|r| r.path == "root").unwrap();
        assert_eq!(root.complete_calls.0, 1);
        let child = rows.iter().find(|r| r.path.ends_with("child"));
        if let Some(c) = child {
            assert_eq!(c.complete_calls.0, 0);
        }
    }
}

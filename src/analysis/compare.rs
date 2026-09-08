use crate::model::{
    AnalysisManifest, ComparabilityCheck, CompareMode, CompareRequest, CompareRow, Count,
    MetricValue, SnapshotManifest, relative_delta,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CompareReport {
    pub checks: Vec<ComparabilityCheck>,
    pub comparable: bool,
    pub mode: CompareMode,
    pub rows: Vec<CompareRow>,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_analysis_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_analysis_id: Option<String>,
}

pub fn compare_hotpaths(
    req: &CompareRequest,
    baseline: &[crate::analysis::hotpaths::HotpathRow],
    candidate: &[crate::analysis::hotpaths::HotpathRow],
    same_workload: bool,
    cpu_ok: bool,
    pt_ok: bool,
    decoder_ok: bool,
) -> CompareReport {
    let mut checks = vec![
        ComparabilityCheck {
            name: "workload".into(),
            ok: same_workload,
            detail: if same_workload {
                "caller-supplied workload/input fingerprints match".into()
            } else {
                "workload/input fingerprint missing or differs".into()
            },
        },
        ComparabilityCheck {
            name: "cpu_pt".into(),
            ok: cpu_ok && pt_ok,
            detail: format!("cpu_ok={cpu_ok} pt_ok={pt_ok}"),
        },
        ComparabilityCheck {
            name: "decoder".into(),
            ok: decoder_ok,
            detail: "decoder version/schema".into(),
        },
    ];
    let mut warnings = Vec::new();
    let strict_ok = same_workload && cpu_ok && pt_ok && decoder_ok;
    if req.mode == CompareMode::StrictPerformance && !strict_ok {
        return CompareReport {
            checks,
            comparable: false,
            mode: req.mode,
            rows: Vec::new(),
            warnings: vec!["INCOMPARABLE: strict_performance requirements unmet".into()],
            baseline_analysis_id: None,
            candidate_analysis_id: None,
        };
    }
    if !same_workload {
        warnings.push(
            "exploratory structural comparison; performance deltas withheld when units are incomparable"
                .into(),
        );
    }

    let allow_perf = same_workload && cpu_ok && pt_ok && decoder_ok;
    let rows = pair_rows(req, baseline, candidate, allow_perf);
    let ambiguous_ok =
        rows.iter().all(|r| r.match_kind != "ambiguous") || !req.function_pairs.is_empty();
    checks.push(ComparabilityCheck {
        name: "explicit_pairs".into(),
        ok: ambiguous_ok,
        detail: format!("{} caller function pairs", req.function_pairs.len()),
    });
    CompareReport {
        checks,
        comparable: true,
        mode: req.mode,
        rows,
        warnings,
        baseline_analysis_id: None,
        candidate_analysis_id: None,
    }
}

pub fn cpu_pt_compat(baseline: &SnapshotManifest, candidate: &SnapshotManifest) -> (bool, bool) {
    let cpu_ok = !baseline.cpu_vendor.is_empty()
        && baseline.cpu_vendor == candidate.cpu_vendor
        && baseline.cpu_model == candidate.cpu_model;
    let pt_ok = !baseline.effective_event.is_empty()
        && baseline.effective_event == candidate.effective_event
        && baseline.requested_config.timing == candidate.requested_config.timing;
    (cpu_ok, pt_ok)
}

pub fn decoder_compat(baseline: &AnalysisManifest, candidate: &AnalysisManifest) -> bool {
    !baseline.dialect.is_empty()
        && baseline.dialect == candidate.dialect
        && baseline.decoder_version == candidate.decoder_version
        && baseline.decode_mode == candidate.decode_mode
        && baseline.ir_version == candidate.ir_version
        && baseline.schema_version == candidate.schema_version
}

fn pair_rows(
    req: &CompareRequest,
    baseline: &[crate::analysis::hotpaths::HotpathRow],
    candidate: &[crate::analysis::hotpaths::HotpathRow],
    allow_perf: bool,
) -> Vec<CompareRow> {
    let mut rows = Vec::new();
    let mut used_b = vec![false; baseline.len()];
    let mut used_c = vec![false; candidate.len()];

    for pair in &req.function_pairs {
        let bi = baseline
            .iter()
            .position(|r| matches_id(&r.path, &pair.baseline_function_id));
        let ci = candidate
            .iter()
            .position(|r| matches_id(&r.path, &pair.candidate_function_id));
        match (bi, ci) {
            (Some(bi), Some(ci)) => {
                used_b[bi] = true;
                used_c[ci] = true;
                rows.push(delta_row(
                    &baseline[bi].path,
                    Some(&baseline[bi]),
                    Some(&candidate[ci]),
                    allow_perf,
                    "explicit_pair",
                ));
            }
            (Some(bi), None) => {
                used_b[bi] = true;
                rows.push(delta_row(
                    &baseline[bi].path,
                    Some(&baseline[bi]),
                    None,
                    false,
                    "unmatched",
                ));
            }
            (None, Some(ci)) => {
                used_c[ci] = true;
                rows.push(delta_row(
                    &candidate[ci].path,
                    None,
                    Some(&candidate[ci]),
                    false,
                    "unmatched",
                ));
            }
            _ => {}
        }
    }

    let b_stem_counts = stem_counts(baseline);
    let c_stem_counts = stem_counts(candidate);

    for (i, b) in baseline.iter().enumerate() {
        if used_b[i] {
            continue;
        }
        let stem = linkage_stem(leaf(&b.path));
        let b_n = *b_stem_counts.get(stem).unwrap_or(&0);
        let c_n = *c_stem_counts.get(stem).unwrap_or(&0);
        if b_n > 1 || c_n > 1 {
            rows.push(delta_row(&b.path, Some(b), None, false, "ambiguous"));
            used_b[i] = true;
            continue;
        }
        let cj = candidate.iter().enumerate().find(|(j, c)| {
            !used_c[*j]
                && (c.path == b.path
                    || leaf(&c.path) == leaf(&b.path)
                    || linkage_stem(leaf(&c.path)) == stem)
        });
        if let Some((j, c)) = cj {
            used_b[i] = true;
            used_c[j] = true;
            let kind = if c.path == b.path {
                "path"
            } else {
                "demangled_path"
            };
            rows.push(delta_row(&b.path, Some(b), Some(c), allow_perf, kind));
        } else {
            used_b[i] = true;
            rows.push(delta_row(&b.path, Some(b), None, false, "unmatched"));
        }
    }
    for (j, c) in candidate.iter().enumerate() {
        if used_c[j] {
            continue;
        }
        let stem = linkage_stem(leaf(&c.path));
        let kind = if *c_stem_counts.get(stem).unwrap_or(&0) > 1 {
            "ambiguous"
        } else {
            "unmatched"
        };
        rows.push(delta_row(&c.path, None, Some(c), false, kind));
    }
    rows
}

fn stem_counts(
    rows: &[crate::analysis::hotpaths::HotpathRow],
) -> std::collections::HashMap<String, usize> {
    let mut m = std::collections::HashMap::new();
    for r in rows {
        *m.entry(linkage_stem(leaf(&r.path)).to_string())
            .or_insert(0) += 1;
    }
    m
}

fn leaf(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Strip a Rust hex linkage disambiguator (`::h` + hex) so two builds of the
/// same function can be paired explicitly. Ambiguous stems stay unmatched.
pub fn linkage_stem(name: &str) -> &str {
    if let Some(i) = name.rfind("::h") {
        let rest = &name[i + 3..];
        if rest.len() >= 8 && rest.chars().all(|c| c.is_ascii_hexdigit()) {
            return &name[..i];
        }
    }
    name
}

fn matches_id(path: &str, id: &str) -> bool {
    path == id || leaf(path) == id || path.ends_with(id) || leaf(path).ends_with(id)
}

fn delta_row(
    path: &str,
    b: Option<&crate::analysis::hotpaths::HotpathRow>,
    c: Option<&crate::analysis::hotpaths::HotpathRow>,
    allow_perf: bool,
    match_kind: &str,
) -> CompareRow {
    let bv = b.and_then(|r| r.inclusive_sum_ns).map(|v| v as i128);
    let cv = c.and_then(|r| r.inclusive_sum_ns).map(|v| v as i128);
    let (abs, rel) = if allow_perf && match_kind != "ambiguous" && match_kind != "unmatched" {
        match (bv, cv) {
            (Some(b), Some(c)) => {
                let abs = c - b;
                (Some(abs), relative_delta(abs, b))
            }
            _ => (None, None),
        }
    } else {
        (None, None)
    };
    CompareRow {
        path: path.to_string(),
        baseline: b.map(|r| MetricValue {
            value: r.inclusive_sum_ns.unwrap_or(0) as i128,
            n: r.complete_calls,
            exclusions: Some(r.excluded_incomplete),
        }),
        candidate: c.map(|r| MetricValue {
            value: r.inclusive_sum_ns.unwrap_or(0) as i128,
            n: r.complete_calls,
            exclusions: Some(r.excluded_incomplete),
        }),
        absolute_delta: abs,
        relative_delta: rel,
        unit: "ns_decoder_estimate".into(),
        normalization: if allow_perf
            && matches!(match_kind, "path" | "demangled_path" | "explicit_pair")
        {
            "per_matched_path".into()
        } else {
            "raw_selected_region".into()
        },
        match_kind: match_kind.into(),
        baseline_evidence: Vec::new(),
        candidate_evidence: Vec::new(),
    }
}

pub fn match_functions(baseline_name: &str, candidate_name: &str, explicit: bool) -> &'static str {
    if explicit {
        "explicit_pair"
    } else if baseline_name == candidate_name
        || linkage_stem(baseline_name) == linkage_stem(candidate_name)
    {
        "demangled_path"
    } else {
        "unmatched"
    }
}

fn _count_placeholder() -> Count {
    Count(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::hotpaths::HotpathRow;
    use crate::model::{CompareMode, CompareSide, FunctionPair, SnapshotId};

    fn row(path: &str, ns: u64) -> HotpathRow {
        HotpathRow {
            path: path.into(),
            complete_calls: Count(10),
            observed_entries: Count(10),
            inclusive_sum_ns: Some(ns),
            self_sum_ns: Some(ns),
            p50_ns: Some(ns),
            p95_ns: Some(ns),
            p99_ns: None,
            excluded_incomplete: Count(0),
            n_eligible: Count(10),
            instructions: None,
        }
    }

    fn req(pairs: Vec<FunctionPair>) -> CompareRequest {
        CompareRequest {
            baseline: CompareSide {
                snapshot_id: SnapshotId::from_raw("s_b").unwrap(),
                analysis_id: None,
                selection: None,
                workload: None,
            },
            candidate: CompareSide {
                snapshot_id: SnapshotId::from_raw("s_c").unwrap(),
                analysis_id: None,
                selection: None,
                workload: None,
            },
            mode: CompareMode::Exploratory,
            function_pairs: pairs,
            group: Default::default(),
            function_contains: None,
        }
    }

    #[test]
    fn explicit_pairs_match_cross_build_hashes() {
        let b = [row("root/foo::bar::h11111111", 100)];
        let c = [row("root/foo::bar::h22222222", 140)];
        let auto = compare_hotpaths(&req(Vec::new()), &b, &c, true, true, true, true);
        assert_eq!(auto.rows[0].match_kind, "demangled_path");
        let paired = compare_hotpaths(
            &req(vec![FunctionPair {
                baseline_function_id: "foo::bar::h11111111".into(),
                candidate_function_id: "foo::bar::h22222222".into(),
            }]),
            &b,
            &c,
            true,
            true,
            true,
            true,
        );
        assert_eq!(paired.rows[0].match_kind, "explicit_pair");
        assert_eq!(paired.rows[0].absolute_delta, Some(40));
    }

    #[test]
    fn ambiguous_monomorphizations_stay_unmatched() {
        let b = [row("root/foo::bar::h11111111", 100)];
        let c = [
            row("root/foo::bar::h22222222", 140),
            row("root/foo::bar::h33333333", 90),
        ];
        let report = compare_hotpaths(&req(Vec::new()), &b, &c, true, true, true, true);
        assert!(
            report.rows.iter().any(|r| r.match_kind == "ambiguous"),
            "expected ambiguous rows, got {:?}",
            report
                .rows
                .iter()
                .map(|r| &r.match_kind)
                .collect::<Vec<_>>()
        );
        assert!(report.rows.iter().all(|r| r.absolute_delta.is_none()));
    }

    #[test]
    fn linkage_stem_strips_rust_hash() {
        assert_eq!(linkage_stem("foo::bar::hdeadbeef"), "foo::bar");
        assert_eq!(linkage_stem("foo::bar"), "foo::bar");
    }

    #[test]
    fn placeholder_count() {
        assert_eq!(_count_placeholder().0, 0);
    }

    #[test]
    fn strict_mode_rejects_incompatible_cpu_pt() {
        let b = [row("foo", 100)];
        let c = [row("foo", 80)];
        let mut r = req(Vec::new());
        r.mode = CompareMode::StrictPerformance;
        let report = compare_hotpaths(&r, &b, &c, true, false, true, true);
        assert!(!report.comparable);
        assert!(report.rows.is_empty());
        let ok = compare_hotpaths(&r, &b, &c, true, true, true, true);
        assert!(ok.comparable);
        assert_eq!(ok.rows[0].absolute_delta, Some(-20));
    }
}

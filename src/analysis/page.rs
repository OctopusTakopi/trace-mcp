use serde_json::Value;

use crate::error::{Error, Result};

/// Deterministic offset cursor: decimal index into the sorted result set.
pub fn parse_offset_cursor(cursor: Option<&str>) -> Result<usize> {
    match cursor {
        None => Ok(0),
        Some(c) => c.parse::<usize>().map_err(|_| {
            Error::invalid_argument(format!("cursor must be a decimal offset, got {c}"))
        }),
    }
}

pub fn paginate<T: Clone>(items: &[T], offset: usize, limit: usize) -> (Vec<T>, Option<String>) {
    let page: Vec<T> = items.iter().skip(offset).take(limit).cloned().collect();
    let next = if offset.saturating_add(page.len()) < items.len() {
        Some(offset.saturating_add(page.len()).to_string())
    } else {
        None
    };
    (page, next)
}

/// Shrink an evidence envelope until its serialized size fits `budget`.
/// Full rows remain in the store; the page records `truncated` and a resume cursor.
pub fn fit_json(mut envelope: Value, budget: usize, offset: usize) -> Value {
    let over = |v: &Value| {
        serde_json::to_vec(v)
            .map(|b| b.len() > budget)
            .unwrap_or(true)
    };
    if !over(&envelope) {
        return envelope;
    }
    envelope["truncated"] = Value::Bool(true);
    loop {
        if !over(&envelope) {
            break;
        }
        match envelope.get_mut("data") {
            Some(Value::Array(arr)) if arr.len() > 1 => {
                arr.pop();
                envelope["next_cursor"] =
                    Value::String(offset.saturating_add(arr.len()).to_string());
            }
            Some(Value::Array(arr)) if arr.len() == 1 => {
                if shrink_row(&mut arr[0]) {
                    continue;
                }
                arr.clear();
                envelope["data"] = serde_json::json!([{
                    "omitted": "row exceeded MCP result budget; full data remains in the store"
                }]);
                envelope["next_cursor"] = Value::String(offset.to_string());
                break;
            }
            _ => break,
        }
    }
    envelope
}

/// Halve the largest array or string field of one row (recursively into
/// nested objects) and record what was cut in `truncated_fields`. Returns
/// false when nothing shrinkable is left.
fn shrink_row(row: &mut Value) -> bool {
    fn largest(v: &mut Value, path: &mut Vec<String>, best: &mut Option<(Vec<String>, usize)>) {
        if let Value::Object(map) = v {
            for (k, child) in map.iter_mut() {
                if k == "truncated_fields" {
                    continue;
                }
                path.push(k.clone());
                let size = match child {
                    Value::Array(a) if a.len() > 1 => {
                        serde_json::to_vec(a).map(|b| b.len()).unwrap_or(0)
                    }
                    Value::String(s) if s.len() > 256 => s.len(),
                    _ => 0,
                };
                if size > 0 && best.as_ref().is_none_or(|b| size > b.1) {
                    *best = Some((path.clone(), size));
                }
                largest(child, path, best);
                path.pop();
            }
        }
    }
    let mut best = None;
    largest(row, &mut Vec::new(), &mut best);
    let Some((path, _)) = best else { return false };
    let mut cur = &mut *row;
    for k in &path {
        cur = &mut cur[k.as_str()];
    }
    match cur {
        Value::Array(a) => {
            let keep = a.len() / 2;
            a.truncate(keep);
        }
        Value::String(s) => {
            let keep = s.len() / 2;
            let mut cut = keep;
            while !s.is_char_boundary(cut) {
                cut -= 1;
            }
            s.truncate(cut);
            s.push_str("...");
        }
        _ => return false,
    }
    if let Value::Object(map) = row {
        let entry = map
            .entry("truncated_fields")
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Value::Array(list) = entry {
            let name = Value::String(path.join("."));
            if !list.contains(&name) {
                list.push(name);
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_row_shrinks_arrays_before_omitting() {
        let big: Vec<Value> = (0..400)
            .map(|i| serde_json::json!({"tid": i, "comm": "x"}))
            .collect();
        let env = serde_json::json!({
            "data": [{"count": 400, "threads": big, "notes": ["a"]}],
            "next_cursor": null,
            "truncated": false
        });
        let fitted = fit_json(env, 2000, 0);
        let row = &fitted["data"][0];
        assert_eq!(row["count"], 400);
        assert!(row["threads"].as_array().unwrap().len() < 400);
        assert!(!row["threads"].as_array().unwrap().is_empty());
        assert_eq!(row["truncated_fields"][0], "threads");
        assert!(serde_json::to_vec(&fitted).unwrap().len() <= 2000);
    }

    #[test]
    fn paginate_two_pages() {
        let items: Vec<u32> = (0..5).collect();
        let (p1, c1) = paginate(&items, 0, 2);
        assert_eq!(p1, vec![0, 1]);
        assert_eq!(c1.as_deref(), Some("2"));
        let (p2, c2) = paginate(&items, 2, 2);
        assert_eq!(p2, vec![2, 3]);
        assert_eq!(c2.as_deref(), Some("4"));
        let (p3, c3) = paginate(&items, 4, 2);
        assert_eq!(p3, vec![4]);
        assert!(c3.is_none());
    }

    #[test]
    fn fit_json_shrinks_data() {
        let env = serde_json::json!({
            "data": [{"x": "aaaaaaaaaaaaaaaaaaaaaaaa"}, {"x": "bbbbbbbbbbbbbbbbbbbbbbbb"}],
            "next_cursor": null,
            "truncated": false
        });
        let fitted = fit_json(env, 80, 0);
        assert_eq!(fitted["truncated"], true);
        assert!(fitted["data"].as_array().unwrap().len() <= 1);
    }
}

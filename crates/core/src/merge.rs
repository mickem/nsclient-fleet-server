//! JSON Merge Patch (RFC 7396) with deterministic output for stable hashing.

use serde_json::{Map, Value};

/// Apply a JSON Merge Patch in place. Per RFC 7396:
/// - If `patch` is not an object, replace `target` wholesale.
/// - Otherwise, for each key in `patch`:
///   - If the value is `null`, remove that key from `target`.
///   - Else if both target[k] and patch[k] are objects, merge recursively.
///   - Else replace target[k] with patch[k].
pub fn merge_patch(target: &mut Value, patch: &Value) {
    match patch {
        Value::Object(patch_map) => {
            // Promote target to object if it isn't already
            if !target.is_object() {
                *target = Value::Object(Map::new());
            }
            let target_map = target.as_object_mut().expect("just promoted");
            for (k, v) in patch_map {
                if v.is_null() {
                    target_map.remove(k);
                } else if let Some(existing) = target_map.get_mut(k) {
                    merge_patch(existing, v);
                } else {
                    target_map.insert(k.clone(), strip_nulls(v.clone()));
                }
            }
        }
        other => {
            *target = other.clone();
        }
    }
}

/// When inserting a fresh value (not merging into existing), strip `null` leaves per RFC 7396 §1
/// — the patch document `{"a": null}` is equivalent to deleting key `a`, not inserting `null`.
fn strip_nulls(v: Value) -> Value {
    match v {
        Value::Object(map) => {
            let cleaned: Map<String, Value> = map
                .into_iter()
                .filter_map(|(k, vv)| {
                    if vv.is_null() {
                        None
                    } else {
                        Some((k, strip_nulls(vv)))
                    }
                })
                .collect();
            Value::Object(cleaned)
        }
        other => other,
    }
}

/// Canonicalize a JSON value to a deterministic string by sorting object keys lexicographically.
/// Used for stable hashing.
pub fn canonical_string(v: &Value) -> String {
    let mut buf = String::new();
    write_canonical(&mut buf, v);
    buf
}

fn write_canonical(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            // Use serde's escaping for safety
            out.push_str(&serde_json::to_string(s).expect("string encode"));
        }
        Value::Array(a) => {
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).expect("key encode"));
                out.push(':');
                write_canonical(out, &map[*k]);
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rfc7396_basic_examples() {
        // RFC 7396 Section 3 examples
        let cases: Vec<(Value, Value, Value)> = vec![
            (json!({"a":"b"}), json!({"a":"c"}), json!({"a":"c"})),
            (json!({"a":"b"}), json!({"b":"c"}), json!({"a":"b","b":"c"})),
            (json!({"a":"b"}), json!({"a":null}), json!({})),
            (
                json!({"a":"b","b":"c"}),
                json!({"a":null}),
                json!({"b":"c"}),
            ),
            (json!({"a":["b"]}), json!({"a":"c"}), json!({"a":"c"})),
            (json!({"a":"c"}), json!({"a":["b"]}), json!({"a":["b"]})),
            (
                json!({"a":{"b":"c"}}),
                json!({"a":{"b":"d","c":null}}),
                json!({"a":{"b":"d"}}),
            ),
            (json!({"a":[{"b":"c"}]}), json!({"a":[1]}), json!({"a":[1]})),
            (json!(["a", "b"]), json!(["c", "d"]), json!(["c", "d"])),
            (json!({"a":"b"}), json!(["c"]), json!(["c"])),
            (json!({"a":"foo"}), json!(null), json!(null)),
            (json!({"a":"foo"}), json!("bar"), json!("bar")),
            (json!({"e":null}), json!({"a":1}), json!({"e":null,"a":1})),
            (json!([1, 2]), json!({"a":"b","c":null}), json!({"a":"b"})),
            (
                json!({}),
                json!({"a":{"bb":{"ccc":null}}}),
                json!({"a":{"bb":{}}}),
            ),
        ];
        for (i, (mut target, patch, expected)) in cases.into_iter().enumerate() {
            merge_patch(&mut target, &patch);
            assert_eq!(target, expected, "case {i}");
        }
    }

    #[test]
    fn null_in_fresh_insert_is_stripped() {
        let mut t = json!({});
        merge_patch(&mut t, &json!({"keep": 1, "drop": null}));
        assert_eq!(t, json!({"keep": 1}));
    }

    #[test]
    fn canonical_is_deterministic_across_key_orders() {
        let a = json!({"z": 1, "a": 2, "m": {"y": [1,2], "x": null}});
        let b = json!({"a": 2, "m": {"x": null, "y": [1,2]}, "z": 1});
        assert_eq!(canonical_string(&a), canonical_string(&b));
    }

    #[test]
    fn empty_target_starts_from_object() {
        let mut t = json!(null);
        merge_patch(&mut t, &json!({"a": {"b": 1}}));
        assert_eq!(t, json!({"a": {"b": 1}}));
    }
}

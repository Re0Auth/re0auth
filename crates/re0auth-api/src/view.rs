//! 声明式视图：把上游 JSON 映射成我们声明的字段（ADR-0049）。
//!
//! 解析器只支持够用的子集：`$` 根、`.key` 字段、`[n]` 数组下标。
//! 不支持通配符、过滤与函数——需要更复杂的形态时先评估成熟库，不要在这里长语法。

use serde_json::Value;

/// 路径解析失败。配置错误，启动时就该拒绝。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathError {
    message: &'static str,
}

impl PathError {
    #[must_use]
    pub fn message(&self) -> &'static str {
        self.message
    }
}

impl std::fmt::Display for PathError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Segment {
    Key(String),
    Index(usize),
}

/// 一条已校验的 JSON 路径。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonPath {
    segments: Vec<Segment>,
}

impl JsonPath {
    /// 解析 `$`、`$.a.b`、`$.a[0].b` 这类路径。
    pub fn parse(raw: &str) -> Result<Self, PathError> {
        let Some(rest) = raw.strip_prefix('$') else {
            return Err(PathError {
                message: "path must start with $",
            });
        };
        let bytes = rest.as_bytes();
        let mut segments = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b'.' => {
                    index += 1;
                    let start = index;
                    while index < bytes.len()
                        && (bytes[index].is_ascii_alphanumeric()
                            || bytes[index] == b'_'
                            || bytes[index] == b'-')
                    {
                        index += 1;
                    }
                    if start == index {
                        return Err(PathError {
                            message: "empty field name after '.'",
                        });
                    }
                    segments.push(Segment::Key(rest[start..index].to_string()));
                }
                b'[' => {
                    index += 1;
                    let start = index;
                    while index < bytes.len() && bytes[index].is_ascii_digit() {
                        index += 1;
                    }
                    if start == index || index >= bytes.len() || bytes[index] != b']' {
                        return Err(PathError {
                            message: "index must be digits inside [ ]",
                        });
                    }
                    let parsed = rest[start..index].parse::<usize>().map_err(|_| PathError {
                        message: "index is too large",
                    })?;
                    index += 1;
                    segments.push(Segment::Index(parsed));
                }
                _ => {
                    return Err(PathError {
                        message: "unexpected character in path",
                    });
                }
            }
        }
        Ok(Self { segments })
    }

    /// 取路径指向的值；任一段缺失都返回 `None`。
    #[must_use]
    pub fn get<'a>(&self, value: &'a Value) -> Option<&'a Value> {
        let mut current = value;
        for segment in &self.segments {
            current = match segment {
                Segment::Key(key) => current.get(key)?,
                Segment::Index(index) => current.get(*index)?,
            };
        }
        Some(current)
    }
}

/// 一个输出字段：我们的字段名，以及相对元素/数据根的取值路径。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldMapping {
    pub name: String,
    pub path: JsonPath,
}

/// 资源声明的视图。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViewSpec {
    /// 非列表资源的数据根；默认 `$`。
    pub data_path: JsonPath,
    /// 列表资源的数组位置；与 `data_path` 互斥。
    pub items_path: Option<JsonPath>,
    /// 输出字段映射；为空时原样透出。
    pub fields: Vec<FieldMapping>,
}

/// 视图求值的输出。
#[derive(Clone, Debug, PartialEq)]
pub enum ViewOutput {
    Single(Value),
    Items(Vec<Value>),
}

/// 上游响应不满足声明。由网关翻译成 `upstream_contract_changed`。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ViewError {
    /// 声明的路径在上游响应里不存在。
    MissingPath,
    /// 期望对象，实际不是。
    NotAnObject,
    /// 期望数组，实际不是。
    NotAnArray,
    /// 某个字段路径取不到值。
    MissingField(String),
}

impl ViewSpec {
    /// 按声明求值。任一路径缺失都失败——不能拿 null 冒充成功。
    pub fn apply(&self, body: &Value) -> Result<ViewOutput, ViewError> {
        match &self.items_path {
            Some(path) => {
                let array = path
                    .get(body)
                    .ok_or(ViewError::MissingPath)?
                    .as_array()
                    .ok_or(ViewError::NotAnArray)?;
                let mut items = Vec::with_capacity(array.len());
                for item in array {
                    items.push(self.map(item)?);
                }
                Ok(ViewOutput::Items(items))
            }
            None => {
                let base = self.data_path.get(body).ok_or(ViewError::MissingPath)?;
                Ok(ViewOutput::Single(self.map(base)?))
            }
        }
    }

    fn map(&self, item: &Value) -> Result<Value, ViewError> {
        if self.fields.is_empty() {
            return Ok(item.clone());
        }
        item.as_object().ok_or(ViewError::NotAnObject)?;
        let mut mapped = serde_json::Map::with_capacity(self.fields.len());
        for field in &self.fields {
            let value = field
                .path
                .get(item)
                .ok_or_else(|| ViewError::MissingField(field.name.clone()))?;
            mapped.insert(field.name.clone(), value.clone());
        }
        Ok(Value::Object(mapped))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn root() -> JsonPath {
        JsonPath::parse("$").expect("root path")
    }

    #[test]
    fn paths_parse_the_documented_subset() {
        for raw in ["$", "$.a", "$.a.b", "$.a[0].b", "$.a-b_c"] {
            assert!(JsonPath::parse(raw).is_ok(), "{raw} must parse");
        }
        for raw in ["", "a", "$.", "$..a", "$[a]", "$[-1]", "$.a."] {
            assert!(JsonPath::parse(raw).is_err(), "{raw} must be rejected");
        }
    }

    #[test]
    fn get_walks_objects_and_arrays() {
        let value = json!({"a": {"b": [{"c": 1}]}});
        let path = JsonPath::parse("$.a.b[0].c").expect("path");
        assert_eq!(path.get(&value), Some(&json!(1)));
        assert_eq!(JsonPath::parse("$.a.x").expect("path").get(&value), None);
        assert_eq!(root().get(&value), Some(&value));
    }

    #[test]
    fn a_single_view_maps_declared_fields() {
        let spec = ViewSpec {
            data_path: JsonPath::parse("$.data").expect("path"),
            items_path: None,
            fields: vec![
                FieldMapping {
                    name: "player_id".to_string(),
                    path: JsonPath::parse("$.user.id").expect("path"),
                },
                FieldMapping {
                    name: "score".to_string(),
                    path: JsonPath::parse("$.score").expect("path"),
                },
            ],
        };
        let body = json!({"data": {"user": {"id": "42"}, "score": 7, "extra": true}});
        let output = spec.apply(&body).expect("view applies");
        assert_eq!(
            output,
            ViewOutput::Single(json!({"player_id": "42", "score": 7}))
        );
    }

    #[test]
    fn a_view_fails_instead_of_mapping_null() {
        let spec = ViewSpec {
            data_path: JsonPath::parse("$.data").expect("path"),
            items_path: None,
            fields: vec![FieldMapping {
                name: "missing".to_string(),
                path: JsonPath::parse("$.nope").expect("path"),
            }],
        };
        let body = json!({"data": {"user": {"id": "42"}}});
        assert_eq!(
            spec.apply(&body),
            Err(ViewError::MissingField("missing".to_string()))
        );

        let empty = ViewSpec {
            data_path: JsonPath::parse("$.absent").expect("path"),
            items_path: None,
            fields: Vec::new(),
        };
        assert_eq!(empty.apply(&body), Err(ViewError::MissingPath));
    }

    #[test]
    fn a_list_view_maps_each_item_and_rejects_non_arrays() {
        let spec = ViewSpec {
            data_path: root(),
            items_path: Some(JsonPath::parse("$.data.items").expect("path")),
            fields: vec![FieldMapping {
                name: "id".to_string(),
                path: JsonPath::parse("$.id").expect("path"),
            }],
        };
        let body = json!({"data": {"items": [{"id": "a", "x": 1}, {"id": "b"}]}});
        assert_eq!(
            spec.apply(&body),
            Ok(ViewOutput::Items(vec![
                json!({"id": "a"}),
                json!({"id": "b"})
            ]))
        );

        let object = json!({"data": {"items": {}}});
        assert_eq!(spec.apply(&object), Err(ViewError::NotAnArray));
    }

    #[test]
    fn an_empty_mapping_passes_the_subtree_through() {
        let spec = ViewSpec {
            data_path: JsonPath::parse("$.data").expect("path"),
            items_path: None,
            fields: Vec::new(),
        };
        let body = json!({"data": {"a": 1}});
        assert_eq!(spec.apply(&body), Ok(ViewOutput::Single(json!({"a": 1}))));
    }
}

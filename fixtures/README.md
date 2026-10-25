# `fixtures/` — 测试输入

存放 Oracle 测试与契约测试的**输入样本**（例如某个上游的真实响应，用来喂给解析/归一化代码）。

## 铁律（ADR-0035）

- **字段名保留，敏感值必须是占位符 `"<redacted>"`**。字段名是我们要断言的形状；真实值不是。
- **绝不提交未经脱敏的真实响应。** 上游 token、`sessionToken`、cookie、`api_user_id`、昵称、头像 URL 等一律替换。
- 脱敏用 `node ../../tools/sanitize-golden.mjs <raw.json> > <file>.json`（工具是辅助；**权威闸门**是
  `re0auth-archtest` 的 `fixtures_and_golden_carry_no_live_secrets`，它会扫描本目录与 `golden/`）。

## 会被闸门拦下的东西

- JWT（`eyJ...` 三段式）、LeanCloud 会话令牌（`r:...`）、长十六进制串（≥ 32 位）；
- 任何敏感字段名（见闸门里的 `SENSITIVE_KEYS`）对应的值不是 `"<redacted>"`。

目录为空时闸门通过；第一份真实录制在提交前就会被挡住。

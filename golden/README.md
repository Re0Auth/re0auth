# `golden/` — 期望输出

存放 Oracle 测试的**期望结果**（把已脱敏的 `fixtures/` 输入喂进去，应当得到的东西），用于比对
「我们以为解析出的形状」与「上游实际响应的形状」。

## 铁律（ADR-0035）

- **字段名保留，敏感值必须是占位符 `"<redacted>"`。**
- **绝不提交未经脱敏的真实响应。** 与 `fixtures/` 同一套规则。
- 脱敏用 `node tools/sanitize-golden.mjs <raw.json> > golden/<name>.json`。
- 权威闸门：`re0auth-archtest` 的 `fixtures_and_golden_carry_no_live_secrets`。

> 说明：目录目前为空是**正常的**——真实 golden 要等上游适配器（A1）落地、有了脱敏样本再录。
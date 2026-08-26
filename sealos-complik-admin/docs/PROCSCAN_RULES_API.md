# Procscan 高风险规则 API

这组接口供 Procscan 节点和规则管理前端使用。规则配置由专用 API 管理，通用 `/api/configs` 不允许修改或删除 `procscan_rules` 与 `procscan_rules_v2`。

## 鉴权

- Admin 凭据：可读取、验证和更新规则。
- Procscan 凭据：仅可读取规则、读取运行时通知配置、上报违规事件。
- Procscan 凭据不能调用 `PUT /api/procscan/rules`、`POST /api/procscan/rules/validate` 或其他管理接口。
- 两套凭据必须不同；相同凭据会导致 Admin 拒绝启动。

## 规则接口

### `GET /api/procscan/rules`

返回当前 V2 规则集，并在 `ETag` 响应头中返回 revision，例如 `ETag: "12"`。

请求携带相同的 `If-None-Match` 时返回 `304 Not Modified`。

```json
{
  "schema_version": 2,
  "ruleset_revision": 12,
  "rules": [
    {
      "id": "miner-xmrig",
      "name": "XMRig",
      "description": "Known cryptocurrency miner",
      "enabled": true,
      "match_type": "process_name",
      "pattern": "(?i)^xmrig$",
      "severity": "critical",
      "action": "ban"
    }
  ],
  "exemptions": {
    "processes": [],
    "commands": [],
    "namespaces": [],
    "pod_names": []
  }
}
```

约束：

- `match_type`：`process_name`、`command_keyword`。
- `severity`：`low`、`medium`、`high`、`critical`。
- `action`：`alert`、`ban`。
- 只有 `process_name + high/critical` 可使用 `ban`。
- `id` 在规则集内唯一，正则最长 1024 字节，规则集任一字段非法则拒绝整个更新。

### `PUT /api/procscan/rules`

更新规则前必须携带从 GET 得到的 `If-Match`：

```http
If-Match: "12"
```

请求体不包含 revision：

```json
{
  "schema_version": 2,
  "rules": [],
  "exemptions": {
    "processes": [],
    "commands": [],
    "namespaces": [],
    "pod_names": []
  }
}
```

结果：

- `200`：保存成功，响应包含新 revision 和新 ETag。
- `409`：revision 冲突，前端应重新读取，不要覆盖服务器版本。
- `423`：`PROCSCAN_RULES_V2_WRITES_ENABLED=false`，迁移期只读。
- `428`：缺少或非法 `If-Match`。

### `POST /api/procscan/rules/validate`

请求体与 PUT 相同。只验证，不保存。合法返回：

```json
{ "valid": true }
```

### `GET /api/procscan/rules/status`

供管理前端判断迁移期是否允许保存：

```json
{ "v2_writes_enabled": false }
```

### `GET /api/procscan/rules/legacy`

返回 V1 兼容投影，只供旧 Procscan 回退读取。V2 保存时后端同步更新该投影。

## Procscan 运行接口

### `GET /api/procscan/runtime-config`

只返回 Procscan 运行所需通知字段，不暴露其他项目配置：

```json
{
  "region": "cn",
  "webhook": "https://example.test/hook"
}
```

### `POST /api/procscan-violations`

新版 Procscan 上报结构化规则结果：

```json
{
  "namespace": "demo",
  "pod_name": "miner-0",
  "process_name": "xmrig",
  "process_command": "xmrig --url pool",
  "ruleset_revision": 12,
  "primary_rule_id": "miner-xmrig",
  "matched_rule_ids": ["miner-xmrig"],
  "match_type": "process_name",
  "match_rule": "(?i)^xmrig$",
  "severity": "critical",
  "rule_action": "ban",
  "attribution_status": "resolved",
  "message": "process matched rule miner-xmrig",
  "is_illegal": true,
  "pid": 42,
  "detected_at": "2026-08-13T10:00:00Z"
}
```

归属失败时使用：

```json
{
  "namespace": null,
  "attribution_status": "unresolved",
  "attribution_reason": "cri_lookup_failed"
}
```

这类事件仍会入库和告警，但不会进入自动封禁。Admin 还会使用当前规则重新匹配；缺少 revision、revision 过期、主规则不一致、命中豁免或规则不具备 `ban` 资格时都只记录原因，不调用 002。

违规查询响应新增：

- `ruleset_revision`
- `primary_rule_id`
- `matched_rule_ids`
- `severity`
- `rule_action`
- `attribution_status` / `attribution_reason`
- `autoban_status` / `autoban_reason`

`autoban_status` 仅有：`not_triggered`、`dry_run`、`submitted`、`failed`。其中 `submitted` 只表示同步封禁调用已成功返回，不代表 NetworkPolicy 或 ResourceQuota 已完成。

`kube-system`、`kube-public`、`kube-node-lease`、`sealos`、`block-system` 是后端硬保护命名空间，不能通过自动封禁策略移除。

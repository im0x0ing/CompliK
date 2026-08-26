import { useEffect, useMemo, useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import {
  Button,
  EmptyState,
  Field,
  Input,
  Modal,
  PageHeader,
  Select,
  StatusPill,
} from "../components/ui";
import {
  ApiRequestError,
  defaultAutobanPolicy,
  loadAutobanPolicy,
  loadProcscanRuleSet,
  loadProcscanRulesStatus,
  saveAutobanPolicy,
  saveProcscanRuleSet,
  validateProcscanRuleSet,
} from "../lib/api";
import type { AutobanPolicy, ProcscanRule, ProcscanRuleSet } from "../types";

type ManagedRule = {
  id: string;
  pattern: string;
  severity: "high" | "critical";
};

type ScopeMode = "cluster" | "namespaces";
type ExecutionMode = "off" | "observe" | "execute";

function isManagedRule(rule: ProcscanRule): rule is ProcscanRule & { severity: ManagedRule["severity"] } {
  return rule.enabled && rule.match_type === "process_name" && rule.action === "ban" &&
    (rule.severity === "high" || rule.severity === "critical");
}

function normalizeValues(values: string[]) {
  return Array.from(new Set(values.map((value) => value.trim()).filter(Boolean)));
}

function clonePolicy(policy: AutobanPolicy): AutobanPolicy {
  return {
    ...policy,
    sources: {
      complik: { ...policy.sources.complik },
      procscan: { ...policy.sources.procscan },
    },
    processNameAllowlist: [...policy.processNameAllowlist],
    processNameDenylist: [...policy.processNameDenylist],
    namespaceAllowlist: [...policy.namespaceAllowlist],
    namespaceDenylist: [...policy.namespaceDenylist],
  };
}

function normalizePolicy(policy: AutobanPolicy): AutobanPolicy {
  const next = clonePolicy(policy);
  next.sources.complik.enabled = false;
  next.sources.procscan.enabled = true;
  next.processNameAllowlist = normalizeValues(next.processNameAllowlist);
  next.processNameDenylist = [];
  next.namespaceAllowlist = normalizeValues(next.namespaceAllowlist);
  next.namespaceDenylist = normalizeValues(next.namespaceDenylist);
  return next;
}

function getManagedRules(ruleSet: ProcscanRuleSet | null): ManagedRule[] {
  if (!ruleSet) {
    return [];
  }

  return ruleSet.rules
    .filter(isManagedRule)
    .map((rule) => ({ id: rule.id, pattern: rule.pattern, severity: rule.severity }));
}

function createRule(pattern: string): ProcscanRule {
  const normalizedPattern = pattern.trim();
  const idPart = normalizedPattern.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "process";
  return {
    id: `autoban-${idPart}-${Date.now().toString(36)}`,
    name: `Auto-ban: ${normalizedPattern}`,
    description: "Managed by the automatic ban policy page.",
    enabled: true,
    match_type: "process_name",
    pattern: normalizedPattern ? `^${normalizedPattern}$` : "",
    severity: "high",
    action: "ban",
  };
}

function toExactProcessName(pattern: string) {
  const exact = pattern.match(/^\^(.+)\$$/);
  return exact?.[1] ?? pattern;
}

function isExactProcessNamePattern(pattern: string) {
  const processName = toExactProcessName(pattern).trim();
  return /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(processName) && pattern === `^${processName}$`;
}

function isValidNamespace(value: string) {
  return value.length <= 63 && /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(value);
}

function fallbackRuleSet(processNames: string[]): ProcscanRuleSet {
  return {
    schema_version: 2,
    ruleset_revision: 1,
    rules: normalizeValues(processNames).map((processName) => createRule(processName)),
    exemptions: { processes: [], commands: [], namespaces: [], pod_names: [] },
  };
}

function NamespacePicker({
  values,
  onChange,
  onError,
}: {
  values: string[];
  onChange: (values: string[]) => void;
  onError: (message: string | null) => void;
}) {
  const [draft, setDraft] = useState("");

  const addValue = () => {
    const namespace = draft.trim();
    if (!isValidNamespace(namespace)) {
      onError("Namespace 必须符合 Kubernetes 命名格式：小写字母、数字或连字符。");
      return;
    }
    onChange(normalizeValues([...values, namespace]));
    setDraft("");
    onError(null);
  };

  return (
    <div className="scope-input-row">
      <Input
        aria-label="放开 Namespace"
        onChange={(event) => setDraft(event.target.value)}
        placeholder="选择或输入 Namespace"
        value={draft}
      />
      <button aria-label="放开 Namespace" className="icon-btn" onClick={addValue} type="button">
        <Plus size={18} />
      </button>
    </div>
  );
}

export function AutobanPolicyPage() {
  const [policy, setPolicy] = useState<AutobanPolicy>(() => defaultAutobanPolicy());
  const [initialPolicy, setInitialPolicy] = useState<AutobanPolicy>(() => defaultAutobanPolicy());
  const [policyExists, setPolicyExists] = useState(false);
  const [ruleSet, setRuleSet] = useState<ProcscanRuleSet | null>(null);
  const [ruleApiAvailable, setRuleApiAvailable] = useState(true);
  const [ruleWritesEnabled, setRuleWritesEnabled] = useState(true);
  const [processNameDraft, setProcessNameDraft] = useState("");
  const [namespaceDenylistDraft, setNamespaceDenylistDraft] = useState("");
  const [scopeMode, setScopeMode] = useState<ScopeMode>("cluster");
  const [rulesError, setRulesError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [confirmedExecution, setConfirmedExecution] = useState(false);

  const managedRules = useMemo(() => getManagedRules(ruleSet), [ruleSet]);
  const filteredManagedRules = useMemo(() => {
    const keyword = processNameDraft.trim().toLowerCase();
    if (!keyword) return managedRules;
    return managedRules.filter((rule) => toExactProcessName(rule.pattern).toLowerCase().includes(keyword));
  }, [managedRules, processNameDraft]);
  const filteredNamespaceDenylist = useMemo(() => {
    const keyword = namespaceDenylistDraft.trim().toLowerCase();
    if (!keyword) return policy.namespaceDenylist;
    return policy.namespaceDenylist.filter((namespace) => namespace.toLowerCase().includes(keyword));
  }, [namespaceDenylistDraft, policy.namespaceDenylist]);
  const isExecuting = policy.enabled && !policy.dryRun;
  const executionMode: ExecutionMode = !policy.enabled ? "off" : policy.dryRun ? "observe" : "execute";
  const protectedTargets = policy.namespaceAllowlist.filter((namespace) => policy.namespaceDenylist.includes(namespace));
  const canAddProcess = isExactProcessNamePattern(`^${processNameDraft.trim()}$`) &&
    !managedRules.some((rule) => toExactProcessName(rule.pattern) === processNameDraft.trim());
  const canAddNamespaceDenylist = isValidNamespace(namespaceDenylistDraft.trim()) &&
    !policy.namespaceDenylist.includes(namespaceDenylistDraft.trim());

  const load = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const policyRecord = await loadAutobanPolicy();
      const nextPolicy = normalizePolicy(policyRecord.policy);
      setPolicy(nextPolicy);
      setInitialPolicy(clonePolicy(nextPolicy));
      setScopeMode(nextPolicy.namespaceAllowlist.length === 0 ? "cluster" : "namespaces");
      setPolicyExists(policyRecord.exists);
      try {
        const nextRuleSet = await loadProcscanRuleSet();
        setRuleSet(nextRuleSet);
        setRuleApiAvailable(true);
        try {
          const writesEnabled = await loadProcscanRulesStatus();
          setRuleWritesEnabled(writesEnabled);
          setRulesError(
            writesEnabled
              ? null
              : "当前处于迁移只读模式，Procscan 规则不能新增或删除；仍可保存自动封禁策略。",
          );
        } catch {
          setRuleWritesEnabled(false);
          setRulesError("无法确认 Procscan 规则写入状态，当前按只读模式处理；仍可保存自动封禁策略。");
        }
      } catch (ruleError) {
   if (!(ruleError instanceof ApiRequestError && ruleError.status === 404)) {
     throw ruleError;
   }
        setRuleSet(fallbackRuleSet(nextPolicy.processNameAllowlist));
        setRuleApiAvailable(false);
        setRuleWritesEnabled(false);
        setRulesError("当前 Admin 尚未提供 Procscan 规则接口，已使用自动封禁策略名单兼容加载。");
      }
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "自动封禁配置加载失败");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const updatePolicy = (update: (current: AutobanPolicy) => AutobanPolicy) => {
    setError(null);
    setNotice(null);
    setPolicy((current) => normalizePolicy(update(clonePolicy(current))));
  };

  const setExecutionMode = (mode: ExecutionMode) => {
    updatePolicy((current) => ({
      ...current,
      enabled: mode !== "off",
      dryRun: mode !== "execute",
    }));
  };

  const addRule = () => {
    if (!ruleSet || !ruleWritesEnabled) return;
    const processName = processNameDraft.trim();
    if (!canAddProcess) {
      if (managedRules.some((rule) => toExactProcessName(rule.pattern) === processName)) {
        setError(`高风险进程名已存在：${processName}`);
        return;
      }
      setError("进程名只能包含字母、数字、点、下划线或连字符。");
      return;
    }
    setRuleSet((current) => current && {
      ...current,
      rules: [...current.rules, createRule(processName)],
    });
    setProcessNameDraft("");
    setError(null);
    setNotice(null);
  };

  const deleteRule = (id: string) => {
    if (!ruleWritesEnabled) return;
    setRuleSet((current) => current && {
      ...current,
      rules: current.rules.filter((rule) => rule.id !== id),
    });
    setNotice(null);
  };

  const addNamespaceDenylist = () => {
    const namespace = namespaceDenylistDraft.trim();
    if (!canAddNamespaceDenylist) {
      if (policy.namespaceDenylist.includes(namespace)) {
        setError(`排除 Namespace 已存在：${namespace}`);
        return;
      }
      setError("Namespace 必须符合 Kubernetes 命名格式：小写字母、数字或连字符。");
      return;
    }
    updatePolicy((current) => ({
      ...current,
      namespaceDenylist: [...current.namespaceDenylist, namespace],
    }));
    setNamespaceDenylistDraft("");
  };

  const validate = () => {
    if (!ruleSet) return "无法保存：Procscan 高风险进程规则尚未加载。";
    if (scopeMode === "namespaces" && protectedTargets.length > 0) {
      return `系统保护 Namespace 不能作为目标：${protectedTargets.join("、")}`;
    }

    const patterns = new Set<string>();
    for (const rule of managedRules) {
      const pattern = rule.pattern.trim();
      if (!pattern) return "高风险进程规则不能为空。";
      if (patterns.has(pattern)) return `高风险进程规则重复：${pattern}`;
      patterns.add(pattern);
    }

    if (scopeMode === "namespaces" && policy.namespaceAllowlist.length === 0) {
      return "指定 Namespace 模式下至少需要放开一个 Namespace。";
    }
    if (isExecuting && managedRules.length === 0) return "自动执行时至少需要一个高风险进程。";
    return null;
  };

  const persist = async () => {
    if (!ruleSet) return;
    setIsSaving(true);
    setError(null);
    try {
      const nextPolicy = normalizePolicy({
        ...policy,
        namespaceAllowlist: scopeMode === "cluster" ? [] : policy.namespaceAllowlist,
        // V2 rules are authoritative when the rule API is available. Keep the
        // legacy field only for old Admin versions that have no V2 endpoint.
        processNameAllowlist: ruleApiAvailable ? [] : policy.processNameAllowlist,
      });
      let savedRuleSet = ruleSet;
      if (ruleApiAvailable) {
        await validateProcscanRuleSet(ruleSet);
        if (ruleWritesEnabled) {
          savedRuleSet = await saveProcscanRuleSet(ruleSet);
        }
      }
      await saveAutobanPolicy(nextPolicy, policyExists);
      setRuleSet(savedRuleSet);
      setPolicy(nextPolicy);
      setInitialPolicy(clonePolicy(nextPolicy));
      setPolicyExists(true);
      setNotice(
        !ruleApiAvailable
          ? "自动封禁策略已保存；升级 Admin 后才能同步 Procscan 规则。"
          : ruleWritesEnabled
            ? "策略已保存。"
            : "自动封禁策略已保存；Procscan 规则处于只读模式，未修改规则。",
      );
      setConfirmOpen(false);
      setConfirmedExecution(false);
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : "自动封禁策略保存失败");
    } finally {
      setIsSaving(false);
    }
  };

  const handleSave = () => {
    const validationError = validate();
    if (validationError) {
      setError(validationError);
      return;
    }
    const wasExecuting = initialPolicy.enabled && !initialPolicy.dryRun;
    const expandsToWholeCluster = initialPolicy.namespaceAllowlist.length > 0 && scopeMode === "cluster";
    const removesNamespaceProtection = initialPolicy.namespaceDenylist.some(
      (namespace) => !policy.namespaceDenylist.includes(namespace),
    );
    if (isExecuting && (!wasExecuting || expandsToWholeCluster || removesNamespaceProtection) && !confirmedExecution) {
      setConfirmOpen(true);
      return;
    }
    void persist();
  };

  if (isLoading) {
    return <div className="page-container"><PageHeader kicker="Autoban" title="自动封禁" description="正在读取策略与 Procscan 规则。" /></div>;
  }

  return (
    <div className="page-container autoban-page">
      <PageHeader
        kicker="Procscan"
        title="高风险进程"
        description="命中下列进程规则后，可按策略封禁所在 Namespace。"
        actions={<Button disabled={isSaving || !ruleSet} onClick={handleSave} variant="primary">{isSaving ? "保存中..." : "保存变更"}</Button>}
      />

      {error ? <div className="policy-message policy-message-danger" role="alert">{error}</div> : null}
      {notice ? <div className="policy-message policy-message-success" role="status">{notice}</div> : null}

      <section className="autoban-policy-bar" aria-label="自动封禁策略">
        <div className="autoban-execution-field">
          <span className="field-label">执行模式</span>
          <div className="policy-mode-control" aria-label="执行模式" role="group">
            <button aria-pressed={executionMode === "off"} className={`policy-mode-button ${executionMode === "off" ? "active" : ""}`} onClick={() => setExecutionMode("off")} type="button">关闭</button>
            <button aria-pressed={executionMode === "observe"} className={`policy-mode-button ${executionMode === "observe" ? "active" : ""}`} onClick={() => setExecutionMode("observe")} type="button">观察模式</button>
            <button aria-pressed={executionMode === "execute"} className={`policy-mode-button ${executionMode === "execute" ? "active policy-mode-danger" : ""}`} onClick={() => setExecutionMode("execute")} type="button">自动执行</button>
          </div>
        </div>
        <div className="autoban-policy-note">
          {executionMode === "off" ? "不处理命中事件。" : executionMode === "observe" ? "命中只记录，不执行封禁。" : "命中后封禁所在 Namespace。"}
        </div>
      </section>

      <div className="autoban-workspace">
        <section className="autoban-rules-section" aria-labelledby="autoban-rules-title">
          <div className="autoban-section-header">
            <div>
              <h2 id="autoban-rules-title">自动封禁进程</h2>
              <p>列表中的精确进程名命中后，可触发 Namespace 封禁。</p>
            </div>
            <StatusPill tone={ruleApiAvailable ? (ruleWritesEnabled ? "info" : "warn") : "neutral"}>
              {!ruleApiAvailable ? "兼容模式" : ruleWritesEnabled ? "V2 规则" : "V2 只读"}
            </StatusPill>
          </div>

          <div className="autoban-add-rule-form">
            <Input
              aria-label="新高风险进程名"
              disabled={!ruleWritesEnabled}
              onChange={(event) => setProcessNameDraft(event.target.value)}
              placeholder="搜索或输入进程名，例如 xmrig"
              value={processNameDraft}
            />
            <button aria-label="添加高风险进程" className="btn btn-secondary autoban-add-rule" disabled={!ruleSet || !ruleWritesEnabled || !canAddProcess} onClick={addRule} type="button"><Plus size={18} />添加进程</button>
          </div>

          {rulesError ? <div className="policy-message policy-message-warn" role="status">{rulesError}</div> : null}
          {managedRules.length === 0 ? (
            <EmptyState title="尚未配置自动封禁进程" description="添加高风险进程后，才能在自动执行模式下封禁所在 Namespace。" />
          ) : filteredManagedRules.length === 0 ? (
            <EmptyState title="没有匹配的进程" description={canAddProcess ? "如需新增，请确认当前输入是完整进程名后点击添加。" : "换一个关键词继续搜索。"} />
          ) : (
            <div className="autoban-rule-table-wrap">
              <table className="autoban-rule-table">
                <thead><tr><th>进程名</th><th>命中动作</th><th aria-label="操作" /></tr></thead>
                <tbody>
                  {filteredManagedRules.map((managedRule) => {
                    const rule = ruleSet?.rules.find((item) => item.id === managedRule.id);
                    if (!rule) return null;
                    return (
                      <tr key={rule.id}>
                        <td><strong>{toExactProcessName(rule.pattern)}</strong></td>
                        <td><StatusPill tone="danger">封禁 Namespace</StatusPill></td>
                        <td><button aria-label={`删除 ${toExactProcessName(rule.pattern) || "进程规则"}`} className="icon-btn autoban-delete-rule" disabled={!ruleWritesEnabled} onClick={() => deleteRule(rule.id)} type="button"><Trash2 size={17} /></button></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <aside className="autoban-scope" aria-labelledby="autoban-scope-title">
          <div className="autoban-scope-heading">
            <h2 id="autoban-scope-title">生效范围</h2>
            <Select
              aria-label="自动封禁生效范围"
              onChange={(event) => {
                setScopeMode(event.target.value as ScopeMode);
                setError(null);
                setNotice(null);
              }}
              value={scopeMode}
            >
              <option value="cluster">整个集群</option>
              <option value="namespaces">指定 Namespace</option>
            </Select>
          </div>
          <p className="scope-mode-summary">{scopeMode === "cluster" ? "所有 Namespace，排除列表除外。" : "只对下列 Namespace 生效。"}</p>
          {scopeMode === "namespaces" ? (
            <>
              <Field label="放开 Namespace"><NamespacePicker onChange={(namespaceAllowlist) => updatePolicy((current) => ({ ...current, namespaceAllowlist }))} onError={setError} values={policy.namespaceAllowlist} /></Field>
              <div className="tag-list" aria-label="已放开 Namespace 列表">
                {policy.namespaceAllowlist.map((namespace) => <span className="value-tag" key={namespace}>{namespace}<button aria-label={`移除 ${namespace}`} className="tag-remove-button" onClick={() => updatePolicy((current) => ({ ...current, namespaceAllowlist: current.namespaceAllowlist.filter((item) => item !== namespace) }))} type="button"><Trash2 size={14} /></button></span>)}
              </div>
            </>
          ) : null}
          <div className="autoban-protected">
            <span>排除 Namespace</span>
            <div className="scope-input-row">
              <Input
                aria-label="搜索或添加排除 Namespace"
                onChange={(event) => setNamespaceDenylistDraft(event.target.value)}
                placeholder="搜索或输入 Namespace"
                value={namespaceDenylistDraft}
              />
              <button aria-label="添加排除 Namespace" className="icon-btn" disabled={!canAddNamespaceDenylist} onClick={addNamespaceDenylist} type="button"><Plus size={18} /></button>
            </div>
            <div className="tag-list" aria-label="排除 Namespace 列表">
              {filteredNamespaceDenylist.map((namespace) => (
                <span className="value-tag value-tag-protected" key={namespace}>
                  {namespace}
                  <button aria-label={`删除排除项 ${namespace}`} className="tag-remove-button" onClick={() => updatePolicy((current) => ({ ...current, namespaceDenylist: current.namespaceDenylist.filter((item) => item !== namespace) }))} type="button"><Trash2 size={14} /></button>
                </span>
              ))}
            </div>
          </div>
        </aside>
      </div>

      <Modal description="命中这些进程后，将封禁该进程所在的整个 Namespace。" onClose={() => { setConfirmOpen(false); setConfirmedExecution(false); }} open={confirmOpen} title="确认启用自动执行">
        <div className="panel-stack">
          <div className="confirmation-summary"><div><span className="detail-label">生效范围</span><strong>{scopeMode === "cluster" ? "整个集群" : policy.namespaceAllowlist.join("、")}</strong></div><div><span className="detail-label">排除 Namespace</span><strong>{policy.namespaceDenylist.join("、") || "无"}</strong></div><div><span className="detail-label">高风险进程</span><strong>{managedRules.map((rule) => toExactProcessName(rule.pattern)).join("、")}</strong></div></div>
          <label className="confirmation-check"><input checked={confirmedExecution} onChange={(event) => setConfirmedExecution(event.target.checked)} type="checkbox" /><span>我确认命中后会封禁整个 Namespace。</span></label>
          <div className="button-row"><Button disabled={!confirmedExecution || isSaving} onClick={() => void persist()} variant="danger">{isSaving ? "保存中..." : "确认并启用"}</Button><Button onClick={() => { setConfirmOpen(false); setConfirmedExecution(false); }} variant="secondary">取消</Button></div>
        </div>
      </Modal>
    </div>
  );
}
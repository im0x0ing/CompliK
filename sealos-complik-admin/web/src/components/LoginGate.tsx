import { FormEvent, useState } from "react";
import { Button, Field, Input, PageHeader, SurfaceCard } from "./ui";
import { getBasicAuthHeader, hasBasicAuth, setBasicAuth, clearBasicAuth } from "../lib/auth";

export function LoginGate({ children }: { children: React.ReactNode }) {
  const [authed, setAuthed] = useState(() => hasBasicAuth());
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (authed) {
    return children;
  }

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!username.trim() || !password) {
      setError("请输入账号和密码。");
      return;
    }
    setSubmitting(true);
    setError(null);
    setBasicAuth(username.trim(), password);
    try {
      const response = await fetch("/api/configs", {
        headers: {
          Authorization: getBasicAuthHeader() ?? "",
        },
      });
      if (response.status === 401) {
        clearBasicAuth();
        setError("账号或密码不对。");
        return;
      }
      if (!response.ok && response.status !== 404) {
        setError(`登录校验失败：${response.status}`);
        clearBasicAuth();
        return;
      }
      setAuthed(true);
    } catch {
      clearBasicAuth();
      setError("连不上后台，请检查网络或代理。");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="login-shell">
      <SurfaceCard className="login-card">
        <PageHeader
          kicker="CompliK Admin"
          title="登录合规后台"
          description="使用集群下发的后台账号。登录信息只留在当前浏览器标签页，关闭标签即清除。"
        />
        <form className="panel-stack" onSubmit={handleSubmit}>
          <Field label="账号">
            <Input autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} />
          </Field>
          <Field label="密码">
            <Input
              autoComplete="current-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </Field>
          {error ? <div className="policy-message policy-message-danger" role="alert">{error}</div> : null}
          <div className="button-row">
            <Button variant="primary" type="submit" disabled={submitting}>
              {submitting ? "正在校验..." : "进入后台"}
            </Button>
          </div>
        </form>
      </SurfaceCard>
    </div>
  );
}

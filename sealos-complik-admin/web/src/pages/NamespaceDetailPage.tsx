import { ArrowRight, Search } from "lucide-react";
import { FormEvent, useEffect, useMemo, useState } from "react";
import { createSearchParams, useNavigate, useParams } from "react-router-dom";
import {
  Button,
  DetailList,
  Drawer,
  EmptyState,
  Input,
  PageHeader,
  PaginationControls,
  StatusPill,
  SurfaceCard,
} from "../components/ui";
import { MarkdownRenderer } from "../components/MarkdownRenderer";
import { useAppData } from "../contexts/AppDataContext";
import { buildCommitmentDownloadURL } from "../lib/api";
import { banCreatePath, unbanCreatePath } from "../lib/tenantActions";
import { isLockableTenantNamespace } from "../lib/tenantNamespace";
import { formatURLWithDeviceProfile, formatViolationTypeLabel, paginateItems, summarizeMarkdown } from "../lib/utils";
import type { NamespaceProfile, ViolationRecord } from "../types";

function toneByBoolean(value: boolean, positiveTone: "success" | "warn" | "danger" = "success") {
  return value ? positiveTone : "neutral";
}

function emptyNamespaceProfile(namespace: string): NamespaceProfile {
  return {
    namespace,
    violated: false,
    banned: false,
    commitmentUploaded: false,
    lastActionAt: "-",
    recentViolations: [],
    timeline: [],
  };
}

export function NamespaceDetailPage() {
  const { namespace } = useParams();
  const navigate = useNavigate();
  const { error, isLoading, namespaceProfiles, refreshAll, violations } = useAppData();
  const decodedNamespace = namespace?.trim() ? decodeURIComponent(namespace) : "";
  const [keyword, setKeyword] = useState(decodedNamespace);
  const [violationPage, setViolationPage] = useState(1);
  const [timelinePage, setTimelinePage] = useState(1);
  const [selectedViolation, setSelectedViolation] = useState<ViolationRecord | null>(null);

  const existingProfile = useMemo(
    () => (decodedNamespace ? namespaceProfiles.find((item) => item.namespace === decodedNamespace) ?? null : null),
    [decodedNamespace, namespaceProfiles],
  );
  const profile = existingProfile ?? (decodedNamespace && !isLoading ? emptyNamespaceProfile(decodedNamespace) : null);
  const recentViolations = useMemo(
    () => (profile ? violations.filter((item) => item.namespace === profile.namespace) : []),
    [profile, violations],
  );
  const paginatedViolations = useMemo(() => paginateItems(recentViolations, violationPage), [recentViolations, violationPage]);
  const paginatedTimeline = useMemo(() => paginateItems(profile?.timeline ?? [], timelinePage), [profile?.timeline, timelinePage]);

  useEffect(() => {
    setKeyword(decodedNamespace);
    setViolationPage(1);
    setTimelinePage(1);
  }, [decodedNamespace]);

  function openNamespace(nextNamespace: string) {
    const trimmed = nextNamespace.trim();
    if (!trimmed) return;
    navigate(`/namespaces/${encodeURIComponent(trimmed)}`);
  }

  function handleSearchSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    openNamespace(keyword);
  }

  const searchField = (
    <form className="toolbar" onSubmit={handleSearchSubmit}>
      <div style={{ display: "flex", gap: 12, width: "100%" }}>
        <Input
          value={keyword}
          onChange={(event) => setKeyword(event.target.value)}
          placeholder="输入 namespace，例如 ns-user-abc"
        />
        <Button disabled={!keyword.trim()} variant="secondary" type="submit">
          <Search size={16} /> 查看详情
        </Button>
      </div>
    </form>
  );

  if (!decodedNamespace) {
    return (
      <div className="page-container">
        <PageHeader
          kicker="Namespace"
          title="命名空间详情"
          description="输入 namespace 后，会进入和从封禁记录点进去相同的详情页。"
          actions={
            <Button variant="secondary" onClick={() => void refreshAll()}>
              重试加载
            </Button>
          }
        />
        <SurfaceCard>
          <div className="field">
            <span className="field-label">namespace</span>
            {searchField}
          </div>
        </SurfaceCard>
      </div>
    );
  }

  if (!profile) {
    return (
      <div className="page-container">
        <PageHeader
          kicker="Namespace"
          title={decodedNamespace}
          description="正在读取这个 namespace 的封禁、违规和承诺书记录。"
          actions={
            <Button variant="secondary" onClick={() => void refreshAll()}>
              重试加载
            </Button>
          }
        />
        <SurfaceCard>
          <EmptyState
            title="命名空间数据加载中"
            description={error ?? "加载完成后会展示和封禁记录入口相同的详情。"}
          />
          {searchField}
        </SurfaceCard>
      </div>
    );
  }

  return (
    <div className="page-container">
      <PageHeader
        kicker="Namespace"
        title={profile.namespace}
        description="先判断违规记录、封禁和承诺书情况，再回看最近违规和处置时间线。"
        actions={
          <>
            {isLockableTenantNamespace(profile.namespace) ? (
              <>
                <Button variant="primary" onClick={() => navigate(banCreatePath(profile.namespace))}>
                  封禁此租户
                </Button>
                <Button variant="secondary" onClick={() => navigate(unbanCreatePath(profile.namespace))}>
                  解封此租户
                </Button>
              </>
            ) : null}
            <Button
              variant="secondary"
              onClick={() =>
                navigate({
                  pathname: "/bans",
                  search: `?${createSearchParams({ namespace: profile.namespace }).toString()}`,
                })
              }
            >
              去封禁记录
            </Button>
            <Button
              variant="secondary"
              onClick={() =>
                navigate({
                  pathname: "/unbans",
                  search: `?${createSearchParams({ namespace: profile.namespace }).toString()}`,
                })
              }
            >
              去解封记录
            </Button>
          </>
        }
      />

      <SurfaceCard>
        <div className="helper-row" style={{ marginBottom: 16 }}>
          <div>
            <h2 className="section-title" style={{ marginBottom: 8 }}>
              当前状态
            </h2>
            <div className="button-row">
              <StatusPill tone={profile.violated ? "danger" : "success"}>
                {profile.violated ? "存在违规记录" : "当前无违规记录"}
              </StatusPill>
              <StatusPill tone={profile.banned ? "warn" : "success"}>
                {profile.banned ? "当前已封禁" : "当前未封禁"}
              </StatusPill>
              <StatusPill tone={profile.commitmentUploaded ? "success" : "neutral"}>
                {profile.commitmentUploaded ? "已上传承诺书" : "暂无承诺书"}
              </StatusPill>
            </div>
          </div>
        </div>
        <div className="toolbar">
          <div className="field">
            <span className="field-label">查看其他 namespace</span>
            {searchField}
          </div>
        </div>
      </SurfaceCard>

      <section className="info-grid">
        <SurfaceCard className="info-card">
          <div className="info-card-title">违规记录</div>
          <div className="info-card-value">{profile.violated ? "存在违规记录" : "当前无违规记录"}</div>
          <StatusPill tone={toneByBoolean(profile.violated, "danger")}>
            {profile.violated ? "需关注" : "记录为空"}
          </StatusPill>
        </SurfaceCard>
        <SurfaceCard className="info-card">
          <div className="info-card-title">是否封禁</div>
          <div className="info-card-value">{profile.banned ? "当前已封禁" : "当前未封禁"}</div>
          <StatusPill tone={toneByBoolean(profile.banned, "warn")}>
            {profile.banned ? "限制中" : "可正常访问"}
          </StatusPill>
        </SurfaceCard>
        <SurfaceCard className="info-card">
          <div className="info-card-title">承诺书</div>
          <div className="info-card-value">{profile.commitmentUploaded ? "已上传" : "暂无记录"}</div>
          <StatusPill tone={toneByBoolean(profile.commitmentUploaded)}>{profile.commitmentUploaded ? "资料完整" : "待补录"}</StatusPill>
        </SurfaceCard>
        <SurfaceCard className="info-card">
          <div className="info-card-title">最近一次处置</div>
          <div className="info-card-value">{profile.lastActionAt}</div>
          <StatusPill tone="info">按记录时间展示</StatusPill>
        </SurfaceCard>
      </section>

      <div className="panel-stack">
        <SurfaceCard>
          <div className="panel-header">
            <div>
              <h2 className="panel-title">承诺书信息</h2>
              <p className="panel-description">这里展示当前 namespace 对应的承诺书记录。</p>
            </div>
          </div>
          {profile.commitment ? (
            <DetailList
              items={[
                { label: "文件名", value: profile.commitment.fileName },
                {
                  label: "文件链接",
                  value: (
                    <a className="namespace-link" href={buildCommitmentDownloadURL(profile.namespace)}>
                      下载文件
                      <ArrowRight size={14} />
                    </a>
                  ),
                },
                { label: "更新时间", value: profile.commitment.updatedAt },
              ]}
            />
          ) : (
            <EmptyState
              title="暂无承诺书"
              description="当前 namespace 还没有承诺书记录，可以在承诺书管理页补录。"
              action={<Button variant="secondary" onClick={() => navigate("/commitments")}>去承诺书管理</Button>}
            />
          )}
        </SurfaceCard>

        <SurfaceCard>
          <div className="panel-header">
            <div>
              <h2 className="panel-title">最近违规记录</h2>
              <p className="panel-description">点击某条记录会在右侧展开详情抽屉。</p>
            </div>
          </div>
          {paginatedViolations.list.length > 0 ? (
            <div className="data-table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>类型</th>
                    <th>关键信息</th>
                    <th>发现时间</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedViolations.list.map((item) => (
                    <tr key={item.id}>
                      <td>{formatViolationTypeLabel(item.type)}</td>
                      <td>
                        <button className="table-row-button" onClick={() => setSelectedViolation(item)} type="button">
                          <strong>{item.detectorName ?? item.processName ?? item.namespace}</strong>
                          <div className="muted-text">{summarizeMarkdown(item.description, 72) || "暂无描述"}</div>
                        </button>
                      </td>
                      <td>{item.detectedAt}</td>
                      <td>
                        <Button variant="ghost" onClick={() => setSelectedViolation(item)}>
                          查看
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              title="当前没有违规记录"
              description="这个 namespace 目前没有需要跟进的违规事件。"
            />
          )}
          <PaginationControls
            page={paginatedViolations.page}
            pageSize={paginatedViolations.pageSize}
            total={paginatedViolations.total}
            totalPages={paginatedViolations.totalPages}
            onPageChange={setViolationPage}
          />
        </SurfaceCard>

        <SurfaceCard>
          <div className="panel-header">
            <div>
              <h2 className="panel-title">封禁与解封时间线</h2>
              <p className="panel-description">整页往下排，不再拆成额外页签。</p>
            </div>
          </div>
          <div className="timeline">
            {paginatedTimeline.list.map((item) => (
              <div className="timeline-item" key={item.id}>
                <span className={`timeline-dot tone-${item.tone}`} style={{ backgroundColor: "currentColor" }} />
                <div className="timeline-content">
                  <div className="helper-row">
                    <strong>{item.title}</strong>
                    <span className="muted-text">{item.time}</span>
                  </div>
                  <div className="muted-text">{item.description}</div>
                </div>
              </div>
            ))}
          </div>
          <PaginationControls
            page={paginatedTimeline.page}
            pageSize={paginatedTimeline.pageSize}
            total={paginatedTimeline.total}
            totalPages={paginatedTimeline.totalPages}
            onPageChange={setTimelinePage}
          />
        </SurfaceCard>
      </div>

      <Drawer
        description="展示违规详情，并提供跳转到违规中心的入口。"
        onClose={() => setSelectedViolation(null)}
        open={Boolean(selectedViolation)}
        title={selectedViolation ? `${formatViolationTypeLabel(selectedViolation.type)}详情` : ""}
      >
        {selectedViolation ? (
          <>
            <DetailList
              items={[
                { label: "namespace", value: selectedViolation.namespace },
                { label: "发现时间", value: selectedViolation.detectedAt },
                { label: "detector / process", value: selectedViolation.detectorName ?? selectedViolation.processName ?? "-" },
                { label: "资源 / pod", value: selectedViolation.resourceName ?? selectedViolation.podName ?? "-" },
                { label: "host / node", value: selectedViolation.host ?? selectedViolation.nodeName ?? "-" },
                {
                  label: "URL / message",
                  value:
                    selectedViolation.type === "complik"
                      ? formatURLWithDeviceProfile(selectedViolation.url, selectedViolation.deviceProfile)
                      : (selectedViolation.message ?? "-"),
                },
              ]}
            />
            <div className="ban-detail-section">
              <div className="detail-label">描述</div>
              <div className="detail-value">
                <MarkdownRenderer content={selectedViolation.description} />
              </div>
            </div>
            <div className="button-row" style={{ marginTop: 20 }}>
              <Button variant="secondary" onClick={() => navigate("/violations")}>
                去违规中心
              </Button>
            </div>
          </>
        ) : null}
      </Drawer>
    </div>
  );
}

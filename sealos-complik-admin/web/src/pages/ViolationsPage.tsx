import { RefreshCw, Search } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import {
  Button,
  ConfirmModal,
  DetailList,
  Drawer,
  EmptyState,
  Field,
  Input,
  PageHeader,
  PaginationControls,
  Select,
  SurfaceCard,
} from "../components/ui";
import { MarkdownRenderer } from "../components/MarkdownRenderer";
import { deleteViolationRecord as apiDeleteViolationRecord, listViolationRecordsPage } from "../lib/api";
import { formatURLWithDeviceProfile, formatViolationTypeLabel } from "../lib/utils";
import type { PaginatedViolationRecords, ViolationRecord, ViolationScope, ViolationTimeRange, ViolationType } from "../types";

export function ViolationsPage() {
  const navigate = useNavigate();
  const [tab, setTab] = useState<ViolationType>("complik");
  const [scope, setScope] = useState<ViolationScope>("violations");
  const [timeRange, setTimeRange] = useState<ViolationTimeRange>("7d");
  const [page, setPage] = useState(1);
  const [keywordInput, setKeywordInput] = useState("");
  const [keyword, setKeyword] = useState("");
  const [data, setData] = useState<PaginatedViolationRecords>({
    list: [],
    total: 0,
    page: 1,
    pageSize: 10,
    totalPages: 0,
  });
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [selected, setSelected] = useState<ViolationRecord | null>(null);
  const [pendingDelete, setPendingDelete] = useState<ViolationRecord | null>(null);
  const requestSequence = useRef(0);

  const rows = data.list;
  const totalPages = data.totalPages;

  const loadViolations = useCallback(async () => {
    const sequence = ++requestSequence.current;
    setIsLoading(true);
    setError(null);
    try {
      const nextData = await listViolationRecordsPage({
        type: tab,
        scope,
        page,
        keyword,
        timeRange,
      });
      if (sequence !== requestSequence.current) {
        return;
      }
      if (nextData.totalPages > 0 && page > nextData.totalPages) {
        setPage(nextData.totalPages);
        return;
      }
      setData(nextData);
    } catch (err) {
      if (sequence !== requestSequence.current) {
        return;
      }
      setError(err instanceof Error ? err.message : "违规数据加载失败");
      setData({
        list: [],
        total: 0,
        page,
        pageSize: 10,
        totalPages: 0,
      });
    } finally {
      if (sequence === requestSequence.current) {
        setIsLoading(false);
      }
    }
  }, [keyword, page, scope, tab, timeRange]);

  useEffect(() => {
    void loadViolations();
  }, [loadViolations]);

  function resetPage(nextAction: () => void) {
    nextAction();
    setPage(1);
  }

  function handleSearchSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    resetPage(() => setKeyword(keywordInput.trim()));
  }

  return (
    <div className="page-container">
      <PageHeader
        kicker="Risk Center"
        title="违规中心"
        description="按范围、时间和关键词查看检测记录。"
        actions={
          <Button
            variant="secondary"
            onClick={() => {
              void loadViolations();
            }}
          >
            <RefreshCw size={16} /> 刷新
          </Button>
        }
      />

      <SurfaceCard>
        <form className="toolbar" onSubmit={handleSearchSubmit}>
          <Field label="范围">
            <Select
              value={scope}
              onChange={(event) => {
                resetPage(() => setScope(event.target.value as ViolationScope));
              }}
            >
              <option value="violations">违规</option>
              <option value="all">全部</option>
            </Select>
          </Field>
          <Field label="时间范围">
            <Select
              value={timeRange}
              onChange={(event) => {
                resetPage(() => setTimeRange(event.target.value as ViolationTimeRange));
              }}
            >
              <option value="24h">最近 24 小时</option>
              <option value="7d">最近 7 天</option>
              <option value="30d">最近 30 天</option>
              <option value="all">全部时间</option>
            </Select>
          </Field>
          <Field label="搜索">
            <div className="search-control">
              <Input
                placeholder={tab === "complik" ? "namespace / detector / URL" : "namespace / process / message"}
                value={keywordInput}
                onChange={(event) => setKeywordInput(event.target.value)}
              />
              <Button variant="secondary" type="submit">
                <Search size={16} /> 搜索
              </Button>
            </div>
          </Field>
        </form>
      </SurfaceCard>

      <div className="tab-row" role="tablist" aria-label="违规类型">
        <button
          className={`tab-button ${tab === "complik" ? "active" : ""}`}
          onClick={() => {
            resetPage(() => setTab("complik"));
          }}
          type="button"
        >
          内容违规
        </button>
        <button
          className={`tab-button ${tab === "procscan" ? "active" : ""}`}
          onClick={() => {
            resetPage(() => setTab("procscan"));
          }}
          type="button"
        >
          进程违规
        </button>
      </div>

      <SurfaceCard className="data-table-wrap" padded={false}>
        {error ? (
          <div style={{ padding: 20 }}>
            <EmptyState
              title="违规数据加载失败"
              description={error}
              action={
                <Button
                  variant="secondary"
                  onClick={() => {
                    void loadViolations();
                  }}
                >
                  重新加载
                </Button>
              }
            />
          </div>
        ) : isLoading ? (
          <div style={{ padding: 20 }}>
            <EmptyState
              title="违规数据加载中"
              description="正在从后端同步内容违规和进程违规记录。"
            />
          </div>
        ) : rows.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>namespace</th>
                <th>{tab === "complik" ? "detector" : "进程 / Pod"}</th>
                <th>{tab === "complik" ? "URL" : "节点 / 说明"}</th>
                <th>发现时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((item) => (
                <tr key={item.id}>
                  <td>
                    <button className="namespace-link table-row-button" onClick={() => navigate(`/namespaces/${item.namespace}`)} type="button">
                      {item.namespace}
                    </button>
                  </td>
                  <td>
                    <button className="table-row-button" onClick={() => setSelected(item)} type="button">
                      <strong>{tab === "complik" ? (item.detectorName ?? "-") : (item.processName ?? "-")}</strong>
                      {tab === "complik" ? null : <div className="muted-text">{item.podName ?? "-"}</div>}
                    </button>
                  </td>
                  <td>
                    {tab === "complik" ? (
                      <div>{formatURLWithDeviceProfile(item.url, item.deviceProfile)}</div>
                    ) : (
                      <>
                        <div>{item.nodeName ?? "-"}</div>
                        <div className="muted-text">{item.message ?? "-"}</div>
                      </>
                    )}
                  </td>
                  <td>{item.detectedAt}</td>
                  <td>
                    <Button variant="ghost" onClick={() => setSelected(item)}>
                      查看
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div style={{ padding: 20 }}>
            <EmptyState
              title="当前筛选条件下没有检测记录"
              description="可以切换范围、时间或搜索词查看其他记录。"
            />
          </div>
        )}
      </SurfaceCard>

      <PaginationControls
        page={page}
        pageSize={data.pageSize}
        total={data.total}
        totalPages={totalPages}
        onPageChange={setPage}
      />

      <Drawer
        description="点开记录后停留在当前页，右侧抽屉展示完整字段。"
        onClose={() => setSelected(null)}
        open={Boolean(selected)}
        title={selected ? `${selected.namespace} - 违规详情` : ""}
      >
        {selected ? (
          <>
            <DetailList
              items={[
                { label: "类型", value: formatViolationTypeLabel(selected.type) },
                { label: "namespace", value: selected.namespace },
                { label: "detector / process", value: selected.detectorName ?? selected.processName ?? "-" },
                { label: "资源 / pod", value: selected.resourceName ?? selected.podName ?? "-" },
                { label: "host / node", value: selected.host ?? selected.nodeName ?? "-" },
                {
                  label: "URL / message",
                  value: selected.type === "complik" ? formatURLWithDeviceProfile(selected.url, selected.deviceProfile) : (selected.message ?? "-"),
                },
                { label: "视口", value: selected.viewport ?? "-" },
                { label: "关键词", value: selected.keywords?.join(", ") ?? "-" },
                { label: "发现时间", value: selected.detectedAt },
                { label: "原始负载", value: selected.rawPayload ?? "-" },
              ]}
            />
            <div className="ban-detail-section">
              <div className="detail-label">描述</div>
              <div className="detail-value">
                <MarkdownRenderer content={selected.description} />
              </div>
            </div>
            <div className="button-row" style={{ marginTop: 20 }}>
              {selected.namespace ? (
                <Button variant="secondary" onClick={() => navigate(`/namespaces/${encodeURIComponent(selected.namespace)}`)}>
                  查看 namespace 详情
                </Button>
              ) : null}
              <Button variant="danger" onClick={() => setPendingDelete(selected)}>
                删除记录
              </Button>
            </div>
          </>
        ) : null}
      </Drawer>

      <ConfirmModal
        description={pendingDelete ? `删除后仅移除当前这条违规记录（namespace: ${pendingDelete.namespace}）。` : ""}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => {
          if (!pendingDelete) return;
          void apiDeleteViolationRecord(pendingDelete.apiId, pendingDelete.type).then(() => {
            if (selected?.id === pendingDelete.id) {
              setSelected(null);
            }
            setPendingDelete(null);
            void loadViolations();
          });
        }}
        open={Boolean(pendingDelete)}
        title="删除违规记录"
      />
    </div>
  );
}

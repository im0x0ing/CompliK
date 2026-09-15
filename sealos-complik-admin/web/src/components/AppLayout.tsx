import {
  AlertTriangle,
  Ban,
  BriefcaseBusiness,
  FileCog,
  FileText,
  LayoutGrid,
  LogOut,
  Network,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { NavLink, Outlet } from "react-router-dom";
import { clearBasicAuth } from "../lib/auth";
import { cn } from "../lib/utils";

const navGroups = [
  {
    label: "",
    items: [
      { label: "总览", path: "/overview", icon: LayoutGrid },
      { label: "违规中心", path: "/violations", icon: AlertTriangle },
      { label: "命名空间详情", path: "/namespaces", icon: ShieldCheck },
      { label: "封禁记录", path: "/bans", icon: Ban },
      { label: "解封记录", path: "/unbans", icon: BriefcaseBusiness },
    ],
  },
  {
    label: "策略与配置",
    items: [
      { label: "自动封禁", path: "/autoban", icon: ShieldAlert },
      { label: "入口路径", path: "/discovered-paths", icon: Network },
      { label: "项目配置", path: "/configs", icon: FileCog },
      { label: "承诺书管理", path: "/commitments", icon: FileText },
    ],
  },
];

export function AppLayout() {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-block">
          <span className="page-kicker">CompliK Admin</span>
          <h2 className="brand-title">合规管理后台</h2>
          <p className="brand-subtitle">
            先处理租户风险，再改自动封禁和项目配置。
          </p>
        </div>
        <nav className="nav-list" aria-label="主导航">
          {navGroups.map((group) => (
            <div className="nav-group" key={group.label || "main"}>
              {group.label ? <p className="nav-group-label">{group.label}</p> : null}
              {group.items.map((item) => {
                const Icon = item.icon;
                return (
                  <NavLink
                    className={({ isActive }) => cn("nav-item", isActive && "active")}
                    key={item.path}
                    to={item.path}
                  >
                    <Icon size={18} />
                    <span>{item.label}</span>
                  </NavLink>
                );
              })}
            </div>
          ))}
        </nav>
        <button
          className="nav-item logout-button"
          type="button"
          onClick={() => {
            clearBasicAuth();
            window.location.reload();
          }}
        >
          <LogOut size={18} />
          <span>退出登录</span>
        </button>
        <p className="mobile-nav-note">移动端仍保留同一套导航顺序，但页面会改成纵向堆叠。</p>
      </aside>
      <main className="main-shell">
        <Outlet />
      </main>
    </div>
  );
}

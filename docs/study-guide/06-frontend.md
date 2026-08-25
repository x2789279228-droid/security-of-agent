# 06 · 前端架构与页面

> 前端是**让用户能用起来**的关键。React 19 + TypeScript + Tailwind 4 + Framer Motion，
> 这一章把每个页面对应到后端能力，帮你**点击哪个按钮 = 调用哪个 API**。

---

## 技术栈速览

| 层 | 选型 | 用途 |
|----|------|------|
| 框架 | React 19 | UI 渲染 |
| 语言 | TypeScript | 类型安全 |
| 样式 | Tailwind CSS 4 | 原子化样式 |
| 动画 | Framer Motion | 状态切换 / 入场动画 |
| 状态 | Zustand | 轻量全局状态 |
| 路由 | React Router | 客户端路由 |
| 请求 | fetch + 自定义 hooks | REST + SSE |
| 构建 | Vite | 快速冷启动 |
| 图表 | recharts / d3 | 数据可视化 |

> package.json 与构建配置见 `frontend/package.json`

---

## 路由与页面

> 路由常量定义在 `frontend/src/lib/constants.ts::ROUTES`；
> 路由配置在 `frontend/src/App.tsx`；菜单入口在 `frontend/src/layouts/Sidebar.tsx`。

| 路径 | 页面 | 菜单入口 | 说明 |
| :--- | :--- | :--- | :--- |
| `/login` | Login.tsx | — | 登录（在 RootLayout 外） |
| `/` | Home.tsx | ✓ | 首页（能力总览） |
| `/logs` | Logs.tsx | ✓ | 日志中心（事件流） |
| `/monitor` | Monitor.tsx | ✓ | 监控（Kafka/Flink 健康） |
| `/security-audit` | SecurityAudit.tsx | ✓ | 平台自审计 |
| `/response` | Response.tsx | ✓ | 响应中心 |
| `/rag` | RAG.tsx | ✓ | 知识库（最大页面 30K） |
| `/operations` | Operations.tsx | ✗（路由存在，菜单未挂） | 运营（工单/案例/复盘） |
| `/traffic` | Traffic.tsx | ✓（"流量采集"） | NDR 流量 |
| `/encrypted` | Encrypted.tsx | ✓（"加密流量"） | TLS 加密分析 |
| `/intel` | Intel.tsx | ✓（"威胁情报"） | MISP/TAXII 展示 |
| `/sandbox` | Sandbox.tsx | ✓（"沙箱检测"） | 0day 沙箱 |
| `/edr` | EDR.tsx | ✓（"终端检测"） | EDR 融合 |
| `/capabilities` | CapabilitiesDashboard.tsx | ✓（"能力总览"） | 能力矩阵 |

---

## 页面与后端能力对应

### 1. `Login.tsx` — 登录
- 调用：`POST /api/auth/login` (JWT)
- 失败：3 次以上锁定（配置项）
- 成功后存 `authStore` (Zustand)

### 2. `Home.tsx` — 首页（能力总览）
- 调用：`GET /api/stats`、`GET /api/capabilities/summary`
- 展示：当日告警数、待审计数、组件健康状态、能力开关矩阵
- 动画：Framer Motion 入场，鼠标 hover 高亮

### 3. `Logs.tsx` — 日志中心
- 调用：`GET /api/logs/events` (分页) + `GET /api/events/stream` (SSE)
- 关键字段：severity / eventType / srcIp / dstIp / analyzed / status / case_id
- 实时刷新：新事件 SSE 推送，进列表顶部
- 关联操作：点事件 → 跳转到审计详情 / 响应页

### 4. `Response.tsx` — 响应中心
- 调用：`GET /api/response/queue`、`POST /api/response/approve`
- 展示：待审批工单、已执行响应、失败响应
- 操作：人工批准 / 拒绝 / 强制回滚

### 5. `RAG.tsx` — 知识库管理
- 调用：`GET /api/rag/knowledge`、`POST /api/rag/search`
- 展示：MITRE 战术树、CAPEC 攻击模式、案例库
- 操作：导入 MITRE bundle、搜索测试、查看 chunk 详情

### 6. `Monitor.tsx` — 监控
- 调用：`GET /api/health` (聚合) + 各组件单独端点
- 展示：Flink JobManager 状态、Kafka Lag、Redis 内存、PostgreSQL 连接数
- 自动刷新：5s 间隔

### 7. `SecurityAudit.tsx` — 平台自审计
- 调用：`GET /api/cad/circuit-breaker`、`POST /api/guard/call`（4 层检查）
- 展示：熔断器状态、被拒调用列表、CAD 报告
- 操作：手动重置熔断器、查看具体拒因

### 8. `Operations.tsx` — 运营
- 调用：`GET /api/ops/cases`、`GET /api/ops/workorders`
- 展示：案例库、工单流转、复盘报告
- 操作：编辑案例、关闭工单、生成 Post-Mortem

### 9. 其他
- `Traffic.tsx` / `EDR.tsx` / `Intel.tsx` / `Sandbox.tsx` / `Encrypted.tsx`：
  可对接能力的页面，开关未启用时显示"未启用"
- `CapabilitiesDashboard.tsx`：能力矩阵展示

---

## 状态管理

**`stores/authStore.ts`** — 登录态
```typescript
interface AuthState {
  user: User | null;
  token: string | null;
  login(username, password): Promise<void>;
  logout(): void;
}
```

**`stores/serviceStore.ts`** — 业务态
```typescript
interface ServiceState {
  capabilities: Record<string, boolean>;
  stats: Stats;
  refresh(): Promise<void>;
}
```

**SSE 订阅**：用自定义 hook（`hooks/useEventStream.ts`）
- 自动重连（指数退避）
- 多端订阅不会重复（用 EventSource 共享）

---

## 与后端通信

### REST 封装：`lib/api.ts`
```typescript
// 统一前缀、错误处理、JWT 注入
async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const token = authStore.getState().token;
  const res = await fetch(`/api${path}`, {
    ...options,
    headers: {
      'Authorization': token ? `Bearer ${token}` : '',
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  });
  if (!res.ok) throw new ApiError(res.status, await res.text());
  return res.json();
}
```

### SSE 订阅
```typescript
// useEventStream.ts
function useEventStream(eventName: string, handler: (data) => void) {
  useEffect(() => {
    const source = new EventSource(`/api/events/stream?type=${eventName}`);
    source.addEventListener(eventName, (e) => handler(JSON.parse(e.data)));
    source.onerror = () => {
      // 重连退避
    };
    return () => source.close();
  }, [eventName]);
}
```

---

## 设计语言

### 颜色与主题
- 主色：靛蓝/紫（深色背景）
- 严重度：critical=红 / high=橙 / medium=黄 / low=蓝 / info=灰
- 动画时长：300ms 入场，Framer Motion 默认 spring

### 关键组件
- `components/common/StatCard`：数字卡片
- `components/common/EventBadge`：事件标签
- `components/operations/CaseCard`：案例卡
- `components/rag/TechniqueTree`：MITRE 树
- `components/hero/AnimatedHero`：首页大屏

### 视图模式
- 列表（`/`、`/logs`）
- 仪表板（`/monitor`、`/capabilities`）
- 详情抽屉（点列表项右侧滑出）
- 树形（`/rag` 的 MITRE 战术树）

---

## 关键交互流程

### 流程 1：响应一条告警
```
1. /logs 列表出现一条高危事件 (SSE 推送)
2. 用户点击 → 详情抽屉
3. 看异常分 + 命中规则 + 原始日志
4. 跳到 /response 看 LLM 审计结论
5. 如果 needs_approval → 看到工单 → 批准 / 拒绝
6. 批准后 → /operations 看执行结果
7. 失败可一键回滚
```

### 流程 2：知识库导入
```
1. /rag 页面 → "导入 MITRE"
2. 上传 STIX bundle 文件
3. POST /api/rag/import
4. 后台跑 mitre_importer → 进度 SSE
5. 完成 → 列表显示导入数
6. 测试检索 → 输入 query → 看返回 chunks
```

### 流程 3：触发自审计
```
1. /security-audit → 看到熔断器状态
2. 如 OPEN：显示原因 + 冷却剩余时间
3. 可手动 reset
4. 列表展示最近 100 次 LLM 工具调用，按状态筛选
5. 点击 denied → 看原因
```

---

## 性能与可访问性

- **首屏懒加载**：路由级 code splitting
- **大数据列表虚拟滚动**：用 react-window（logs / response queue）
- **暗色模式**：默认
- **键盘可操作**：所有按钮支持 Tab + Enter
- **响应式**：移动端可访问，但优先桌面（运维场景）

---

## 构建与部署

```bash
cd frontend
npm ci                # 锁定版本安装
npm run dev           # 开发，Vite HMR
npm run lint          # oxlint 检查
npm run build         # 生产构建，输出到 dist/
```

Dockerfile 多阶段：node:20 → nginx:alpine，产物用 nginx serve。

---

## 常见自定义点

| 想做什么 | 改哪里 |
|----------|--------|
| 改主题色 | `tailwind.config.js` 中 `theme.extend.colors` |
| 改首页布局 | `pages/Home.tsx` |
| 加新页面 | 在 `pages/` 新建 + 在 `layouts/Sidebar.tsx` 加菜单项 |
| 接新 API | `lib/api.ts` 加方法 |
| 改 SSE 订阅 | `hooks/useEventStream.ts` |
| 加新组件 | `components/{分类}/` |

---

## 上一章

> [05 平台自审计体系](./05-self-audit.md)

---

## 下一章

- 想看数据怎么落：→ [07 数据模型与消息契约]
- 想看怎么部署：→ [08 部署、运维与调优]
- 想看推荐学习路径：→ [09 推荐学习路径]


---

## 动手点

1. **改首页标题**：
   ```bash
   # 编辑 frontend/src/pages/Home.tsx
   # 改 hero 标题文字
   npm run dev
   # 浏览器立刻看到热更新
   ```

2. **加一个新统计卡片**：
   - 在 `Home.tsx` 的 stat grid 加一项
   - 调用 `/api/stats` 中已有字段或新加后端端点

3. **看 SSE 推送**：
   ```javascript
   // 在浏览器 console
   const s = new EventSource('/api/events/stream');
   s.onmessage = (e) => console.log(e.data);
   // 注入日志后看 console 输出
   ```

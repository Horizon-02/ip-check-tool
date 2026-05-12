# IP 检测工具 — 项目交接文档

> 日期: 2026-05-12  
> 仓库: https://github.com/Horizon-02/ip-check-tool  
> 线上: https://ip-check.leviatron02.com  
> 作者: Claude Opus 4.7 + Horizon-02

---

## 一、需求概述

### 业务目标

设计并实现一个专业的 IP 信誉检测工具，评估当前 IP 是否适合稳定、安全、合规地访问 Claude、OpenAI 等海外服务。

**核心原则：风险评估与合规使用建议，而非绕过平台风控。**

### 功能需求

| 编号 | 功能 | 说明 |
|------|------|------|
| F1 | IP 属地查询 | 国家/地区/城市/经纬度/时区 |
| F2 | ASN/ISP 查询 | 自治域编号、ASN 组织、运营商 |
| F3 | 网络类型识别 | 住宅/商业/移动/数据中心/托管/教育 |
| F4 | 匿名代理检测 | VPN、Proxy、Tor、Relay、Hosting、住宅代理 |
| F5 | 滥用记录查询 | 历史攻击/滥用报告、置信度评分 |
| F6 | 黑名单检测 | DNSBL 多源查询 (Spamhaus, Barracuda 等) |
| F7 | 环境一致性 | 时区、语言、DNS、WebRTC 一致性对比 |
| F8 | 网络质量 | 延迟、丢包、IPv4/IPv6 支持 |
| F9 | 评分模型 | 6 维度 100 分制，可解释、可追溯 |
| F10 | 使用建议 | 保守的、合规导向的海外服务访问建议 |
| F11 | 历史记录 | localStorage 本地存储，不上传 |

### 安全约束

- API Key 绝不出现在前端代码或网络请求中
- 不记录用户完整 IP 历史（除非用户明确开启）
- 不采集不必要的浏览器指纹
- WebRTC/DNS/时区检测仅当前页面使用，不做追踪
- 后端接口限流，防止刷爆第三方 API 额度
- 手动输入 IP 做严格校验，防 SSRF、命令注入
- 不提供绕过风控、绕过封禁等功能

---

## 二、技术架构

### 总体架构

```
用户浏览器
    │
    ▼
┌─────────────────────────────────────┐
│  Cloudflare Pages                    │
│  ┌─────────────────────────────────┐│
│  │ 静态前端 (React SPA)            ││
│  │ dist/index.html + JS + CSS      ││
│  └─────────────────────────────────┘│
│  ┌─────────────────────────────────┐│
│  │ Pages Functions (后端 API)      ││
│  │ functions/api/ip-check/*.ts     ││
│  └─────────────────────────────────┘│
└─────────────────────────────────────┘
    │ 服务端 API 调用
    ▼
┌──────────┬──────────┬──────────┬──────────┐
│  ipapi   │  IPinfo  │ AbuseIPDB│  DNSBL   │
│  (免费)  │  (免费)  │  (免费)  │  (免费)  │
│ 无需密钥 │ 5万次/月 │1000次/天 │ 无限     │
└──────────┴──────────┴──────────┴──────────┘
```

### 技术栈

| 层 | 技术 | 说明 |
|----|------|------|
| 前端框架 | React 19 + TypeScript | SPA, Vite 构建 |
| 样式 | Tailwind CSS 3 | 暗色主题，响应式 |
| 图标 | Lucide React | SVG 图标库 |
| 后端（服务器） | Express.js + TypeScript | 本地开发用，tsx 运行 |
| 后端（生产） | Cloudflare Pages Functions | 无服务器，全球边缘 |
| 测试（单元） | Vitest + Testing Library | 157 个测试 |
| 测试（E2E） | Playwright + Chrome | 12 个浏览器测试 |
| 构建 | Vite 6 | 生产构建 239KB JS + 20KB CSS |
| 部署 | Cloudflare Pages | 自定义域名 ip-check.leviatron02.com |

### 目录结构

```
ip-check-tool/
├── index.html                    # 入口 HTML
├── package.json                  # 依赖与脚本
├── vite.config.ts                # Vite 配置 (含 /api 代理)
├── playwright.config.ts          # E2E 测试配置
├── .env.example                  # API 密钥配置模板
├── .env                          # 本地密钥 (不提交 Git)
│
├── src/                          # 前端源码
│   ├── main.tsx                  # React 入口
│   ├── App.tsx                   # 根组件
│   ├── index.css                 # Tailwind + 全局样式
│   ├── test-setup.ts             # 测试初始化
│   ├── types/
│   │   └── ipCheck.ts            # 全部类型定义 (20+ 接口)
│   ├── lib/
│   │   ├── ipScore.ts            # 评分引擎 (6维100分)
│   │   ├── api.ts                # API 客户端 (fetch 封装)
│   │   └── envConsistency.ts     # 浏览器环境检测
│   └── components/
│       └── IpCheckPage.tsx       # 主页面组件 (~1700 行)
│
├── server/                       # 后端 (Express, 本地开发)
│   ├── index.ts                  # Express 路由 + .env 加载
│   ├── ipValidator.ts            # IP 格式校验 + 防 SSRF
│   ├── rateLimiter.ts            # 内存限流器
│   ├── cache.ts                  # TTL 缓存
│   └── dataSources.ts            # 多数据源聚合层
│
├── functions/                    # 后端 (Cloudflare Pages Functions)
│   ├── _middleware.ts            # 全局中间件 (注入 env vars)
│   ├── _shared/
│   │   ├── types.ts              # 共享类型
│   │   ├── dataSources.ts        # 数据源 (HTTP + DNS-over-HTTPS)
│   │   └── scoreEngine.ts        # 评分引擎 (CF 兼容版)
│   └── api/ip-check/
│       ├── current.ts            # GET  当前 IP 快查
│       ├── score.ts              # POST 完整评分
│       └── reputation.ts         # GET  滥用/黑名单详情
│
├── tests/                        # 单元测试
│   ├── server/
│   │   ├── ipValidator.test.ts   # 39 tests
│   │   ├── api.test.ts           # 17 tests
│   │   ├── rateLimiter.test.ts   # 9 tests
│   │   ├── cache.test.ts         # 15 tests
│   │   └── scoring.test.ts       # 25 tests
│   └── frontend/
│       ├── IpCheckPage.test.tsx  # 36 tests
│       └── envConsistency.test.ts # 16 tests
│
├── e2e/                          # E2E 浏览器测试
│   └── ip-check.spec.ts          # 12 tests
│
└── .claude/
    └── HANDOVER.md               # 本文档
```

---

## 三、评分模型设计

### 维度权重（满分 100）

```
┌──────────────────────┬───────┬──────────────────────────────────────┐
│ 维度                 │ 满分  │ 评分逻辑                              │
├──────────────────────┼───────┼──────────────────────────────────────┤
│ 1. 地理位置可信度     │  15   │ 缺数据/时区冲突/ASN未知 扣分          │
│ 2. 网络类型           │  15   │ 住宅15→商业13→移动12→托管3→数据中心0 │
│ 3. 代理风险           │  25   │ VPN-10, Proxy-10, Tor-15,            │
│                      │       │ Hosting-8, Residential Proxy-12       │
│                      │       │ 多标签叠加额外-3                       │
│ 4. 滥用与黑名单        │  25   │ AbuseIPDB >80%-15, >50%-10,          │
│                      │       │ DNSBL 每条-5                          │
│ 5. 环境一致性         │  10   │ 时区-4, 语言-3, DNS-3, WebRTC-3      │
│                      │       │ 无浏览器数据时默认 5 分                │
│ 6. 网络质量           │  10   │ 延迟>300ms-3, 丢包>5%-3,             │
│                      │       │ IPv4缺失-2, IPv6 only-1               │
└──────────────────────┴───────┴──────────────────────────────────────┘
```

### 风险等级

| 分数 | 等级 | 颜色 | 建议 |
|------|------|------|------|
| ≥85 | 优秀 (excellent) | 绿色 | 标准验证即可 |
| ≥70 | 良好 (good) | 蓝色 | 建议标准验证 |
| ≥50 | 谨慎 (caution) | 黄色 | 建议额外验证 |
| ≥30 | 高风险 (high_risk) | 橙色 | 不建议直接信任 |
| <30 | 不推荐 (not_recommended) | 红色 | 强烈建议阻止 |
| >50% 数据源失败 | 不确定 (uncertain) | 灰色 | 数据不足，无法评估 |

### 关键设计决策

1. **不确定性优先于虚假高分**：超过 50% 数据源失败时，不输出"干净"，强制标记为"不确定"
2. **多源冲突展示而非合并**：VPN 标记 + 住宅网络类型时，两者都展示并标记冲突
3. **扣分项完全可追溯**：每个扣分包含 `{ reason, reasonZh, source, field }`，可定位到具体数据源和字段
4. **建议必须保守**：不承诺"某某 IP 一定可以访问 Claude"，只说风险等级和标准建议

---

## 四、数据源详情

### 在线生产环境（Cloudflare Functions 使用）

| 数据源 | 类型 | 是否需要密钥 | 免费额度 | 提供信息 |
|--------|------|:----------:|----------|----------|
| ipapi.co | HTTP API | 否 | 1,000/天 | 地理位置、ASN、ISP、VPN/Proxy/Tor/Hosting 检测 |
| IPinfo | HTTP API | 是 | 50,000/月 | 地理位置、ASN、ISP（免费版不含代理检测） |
| AbuseIPDB | HTTP API | 是 | 1,000/天 | 滥用报告数、置信度评分、分类 |
| Spamhaus ZEN | DNSBL (DoH) | 否 | 无限 | 垃圾邮件黑名单 |
| Barracuda | DNSBL (DoH) | 否 | 无限 | 垃圾邮件黑名单 |
| SpamCop | DNSBL (DoH) | 否 | 无限 | 垃圾邮件黑名单 |
| Sorbs | DNSBL (DoH) | 否 | 无限 | 垃圾邮件黑名单 |
| httpbin.org | HTTP | 否 | 无限 | 网络延迟测试 |

### 本地开发环境（Express 后端使用）

额外包含 4 个 DNSBL（UCEPROTECT L1/L2/L3, SURBL）—— 使用 Node.js `dns.promises` 直接 DNS 查询。

Cloudflare Workers 不支持 `node:dns`，所以生产版本改用 Google DNS-over-HTTPS (`https://dns.google/resolve`) 并精简到 4 个 DNSBL。

### API 密钥配置

复制 `.env.example` 为 `.env`：

```bash
IPINFO_API_KEY=          # https://ipinfo.io/signup (免费 5万/月)
ABUSEIPDB_API_KEY=       # https://www.abuseipdb.com/register (免费 1000/天)
```

即使不填任何密钥，系统仍可运行——ipapi.co (无需密钥) + DNSBL (免费) + httpbin (免费) 提供基础检测。

---

## 五、API 接口文档

### Base URL

- 生产: `https://ip-check.leviatron02.com`
- 本地: `http://localhost:3001` (Express) 或 `http://localhost:5173` (Vite proxy)

### GET /api/health

健康检查。

```
GET /api/health
→ 200 { "status": "ok", "timestamp": "2026-05-12T..." }
```

### GET /api/ip-check/current

获取当前访问 IP 的基本信息。

```
GET /api/ip-check/current
→ 200 {
    "ip": "x.x.x.x",
    "geo": { "country": "US", "countryCode": "US", "region": "California",
             "city": "Mountain View", "latitude": 37.4, "longitude": -122.0,
             "timezone": "America/Los_Angeles" },
    "asn": { "asn": "AS15169", "asnOrg": "Google LLC", "isp": "Google" },
    "networkType": { "type": "datacenter", "confidence": 80, "source": "ipapi.co" },
    "proxyDetection": { "isVpn": false, "isProxy": false, "isTor": false, ... },
    "dataSources": [ { "name": "ipapi.co", "status": "success", "latencyMs": 120 } ],
    "checkedAt": "2026-05-12T..."
  }
```

返回头: `Cache-Control: public, max-age=60`

### POST /api/ip-check/score

完整 IP 信誉评分。

```
POST /api/ip-check/score
Content-Type: application/json

{ "ip": "8.8.8.8", "consistency": { "timezoneMatch": true, ... } }
```

返回完整的 `IpCheckResponse`，包含所有检测数据 + 评分结果。

- `ip` 可选，不传则检测请求来源 IP
- `consistency` 可选，浏览器端环境数据
- 校验：拒绝私有 IP (192.168.x, 10.x, 172.16-31.x, 127.x 等)
- 返回头: `Cache-Control: public, max-age=30`

### GET /api/ip-check/reputation

获取滥用记录和黑名单详情。

```
GET /api/ip-check/reputation?ip=8.8.8.8
→ 200 { "abuseRecord": {...}, "blacklistRecords": [...], ... }
```

---

## 六、环境一致性检测实现

前端 `envConsistency.ts` 收集以下浏览器信号：

| 检测项 | 方法 | 对比逻辑 |
|--------|------|----------|
| 时区 | `Intl.DateTimeFormat().resolvedOptions().timeZone` | vs IP 地理位置时区 |
| 语言 | `navigator.languages` | vs IP 国家预期语言 |
| WebRTC | `RTCPeerConnection` (仅创建 offer，不建立连接) | 本地 IP vs 公网 IP |
| DNS | 端侧无法独立完成 | 标记为需要服务端数据 |

收集后通过 `checkIpScore(ip, signal, consistency)` 传给后端参与评分。

---

## 七、测试策略

### 测试金字塔

```
           /\
          /E2E\      12 个浏览器测试 (Playwright + Chrome)
         /──────\
        /  集成  \    0 (Cloudflare Functions 限制)
       /──────────\
      /   单元测试  \  157 个 (Vitest)
     /──────────────\
    /    静态检查     \  TypeScript strict mode
   /──────────────────\
```

### 单元测试覆盖（157 tests, 7 files）

| 文件 | 测试数 | 覆盖内容 |
|------|:------:|----------|
| `tests/server/ipValidator.test.ts` | 39 | IPv4/IPv6 格式校验、私有/环回/链路本地/组播/文档地址拒绝 |
| `tests/server/api.test.ts` | 17 | Express 端点：健康检查、参数校验、状态码、响应头 |
| `tests/server/rateLimiter.test.ts` | 9 | 限流逻辑：额度内放行、超额拦截、窗口重置、独立 Key |
| `tests/server/cache.test.ts` | 15 | 缓存：读写、TTL 过期、清空、类型安全 |
| `tests/server/scoring.test.ts` | 25 | 评分：干净住宅(≥85)、数据中心(<50)、VPN 降分、Tor 高风险(<30)、全 API 失败→uncertain、Null 处理、黑名单扣分 |
| `tests/frontend/IpCheckPage.test.tsx` | 36 | 组件渲染：加载/成功/失败/部分数据/空状态、手动输入校验、移动端、展开收起、历史记录 |
| `tests/frontend/envConsistency.test.ts` | 16 | 浏览器信号：WebRTC IPv4/v6/null、时区匹配/不匹配、语言匹配 |

### E2E 测试覆盖（12 tests）

| 测试 | 验证内容 |
|------|----------|
| page loads and shows title | 页面加载，标题显示 "IP 检测工具" |
| score card appears after auto-detect | 自动检测后评分卡片出现 |
| risk level badge shows after check | 风险等级标签渲染 |
| IP overview card shows IP address | IP 概览卡片显示 IP 地址 |
| manual IP input accepts valid IPv4 | 手动输入合法 IPv4 地址 |
| manual IP input accepts valid IPv6 | 手动输入合法 IPv6 地址 |
| shows data source status indicators | 数据源状态指示灯渲染 |
| expandable detail sections toggle | 展开/收起详情区 |
| shows error message when API fails | API 失败时显示错误提示（Playwright route 拦截模拟） |
| mobile layout renders | 375px 视口无线溢出 |
| page title and meta are correct | 页面标题和 meta 标签正确 |
| no API keys exposed | 确认 API 密钥不出现在 HTML 或网络请求中 |

### 测试命令

```bash
npm test           # 157 单元测试 (vitest)
npm run test:e2e   # 12 E2E 测试 (Playwright)
# 总计: 169 tests
```

---

## 八、已修复 Bug

### Bug 1: AbuseIPDB 假阳性黑名单命中

- **现象**: 置信度 0% 的 IP（如 Google DNS 8.8.8.8）显示"在 1 个黑名单中找到匹配"
- **原因**: `listed: record.totalReports > 0` — 只检查是否有历史报告，不检查置信度
- **修复**: 改为 `listed: record.abuseConfidenceScore > 0`
- **影响范围**: `server/dataSources.ts` + `functions/_shared/dataSources.ts`

### Bug 2: 环境一致性永远 5 分

- **现象**: 评分中"环境一致性"维度永远显示 -5，原因是"浏览器检查仅客户端可用"
- **原因**: 前端收集了浏览器信号但 `checkIpScore()` 调用时没传给后端
- **修复**: 
  - `api.ts`: `checkIpScore()` 增加 `consistency` 参数
  - `IpCheckPage.tsx`: 调用前先 `collectBrowserSignals()` 并传入
  - `server/index.ts`: 接受 `req.body.consistency`
  - `functions/api/ip-check/score.ts`: 接受 `body.consistency`

### Bug 3: API 路由不匹配

- **现象**: 前端调 `GET /api/ip-check?ip=x`，后端只有 `POST /api/ip-check/score`
- **修复**: 
  - `api.ts` `checkIpScore()`: 改为 `POST /api/ip-check/score` + JSON body
  - `api.ts` `fetchReputation()`: 改为 `GET /api/ip-check/reputation?ip=x`

---

## 九、运维信息

### 本地开发

```bash
cd /home/mylinux/projects/ip-check-tool
cp .env.example .env    # 填入 API 密钥
npm install
npm run dev:all         # 前端 :5173 + 后端 :3001 (并行启动)
```

### 构建与测试

```bash
npm run build           # TypeScript 检查 + Vite 生产构建
npm test                # 157 单元测试
npm run test:e2e        # 12 E2E 浏览器测试 (需要 Chrome)
```

### 部署

```bash
# 构建后部署到 Cloudflare Pages
npm run build
npx wrangler pages deploy dist/ --project-name=ip-check --branch=main
```

### 关联项目

| 项目 | 仓库 | 线上 |
|------|------|------|
| IP 检测工具 | `github.com/Horizon-02/ip-check-tool` | `ip-check.leviatron02.com` |
| 个人云主页 | `github.com/Horizon-02/personal-cloud-home` | `www.leviatron02.com` |

主站 `src/config/apps.ts` 中 IP 检测卡片状态为 `online`，自动链接到 `https://ip-check.leviatron02.com`。

### 监控建议

- 关注 `ipapi.co` 每日 1000 次额度（单次评分调用 1 次 ipapi.co）
- AbuseIPDB 每日 1000 次额度
- IPinfo 每月 50000 次额度
- 如果 ipapi.co 限流，IPinfo 仍有地理位置数据，但代理检测失效

---

## 十、待扩展项

| 优先级 | 项目 | 说明 |
|:------:|------|------|
| 高 | `node:dns` DNSBL | 恢复 Cloudflare 环境下的 8 个 DNSBL（目前仅 4 个，受限于 DoH） |
| 中 | WebRTC 异步结果回传 | 页面加载后 WebRTC 检测完成时，二次回传结果重新评分 |
| 中 | 服务端 DNS 泄漏检测 | 对比客户端 DNS 和权威 DNS 解析结果 |
| 中 | MaxMind GeoLite2 | 免费注册即可，增加第三个 Geo 数据源 |
| 低 | 自定义评分权重 | 允许用户调整 6 维度权重 |
| 低 | IP 对比模式 | 同时检测两个 IP 并对比 |
| 低 | i18n | 目前双语（中/英），可扩展更多语言 |

---

## 十一、安全审计清单

- [x] API Key 不出现在前端源码中（读取自环境变量，后端代理请求）
- [x] API Key 不出现在浏览器网络请求中（Playwright E2E 验证）
- [x] API Key 不出现在构建产物 dist/ 中（grep 验证）
- [x] 手动输入 IP 做严格校验（拒绝私有/环回/链路本地/组播/文档地址）
- [x] 后端接口限流（10 req/min/IP，返回 429）
- [x] 第三方 API 5 秒超时（不阻塞其他数据源）
- [x] WebRTC 检测仅本地使用，不上传（文档说明 + 代码审查）
- [x] 历史记录仅 localStorage，不上传
- [x] .env 加入 .gitignore，不提交 Git
- [x] 不提供绕过风控、绕过封禁功能
- [x] 建议文案保守，不承诺"某某 IP 一定可访问某某服务"

# IP 检测工具 — 项目交接文档

> 日期: 2026-05-13  
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

### 设计原则

**IP 评分与浏览器环境检查分离**。参考 jason5ng32/MyIP (10.3k stars) — 主流 IP 工具箱不做评分，而是将各项检测独立展示。我们的评分聚焦于 **IP 本身质量**，浏览器环境检测（时区、WebRTC）作为信息参考单独展示，不计入 IP 评分。

### 维度权重（IP 质量部分：满分 90 + 环境信息参考：10）

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
│ 5. 网络质量           │  10   │ 延迟>300ms-3, 丢包>5%-3,             │
│                      │       │ IPv4缺失-2, IPv6 only-1               │
│ 6. 浏览器环境（信息参考）│ 10   │ 不计入评分。展示时区/语言/WebRTC/   │
│                      │       │ DNS 检测结果供用户参考               │
└──────────────────────┴───────┴──────────────────────────────────────┘
```

### 关键设计决策

1. **IP 评分与浏览器环境分离**：时区/WebRTC 不匹配是用代理的正常表现，不应影响 IP 质量评分
2. **不确定性优先于虚假高分**：超过 50% 数据源失败时，强制标记为"不确定"
3. **多源冲突展示而非合并**：VPN 标记 + 住宅网络类型时，两者都展示并标记冲突
4. **扣分项完全可追溯**：每个扣分包含 `{ reason, reasonZh, source, field }`
5. **建议必须保守**：不承诺"某某 IP 一定可以访问 Claude"
6. **WebRTC 只接受 srflx/prflx candidates**：参考 jason5ng32/MyIP 的 checkSTUNServer()，host candidates 仅显示本地 IP，不证明 STUN 工作

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

前端 `envConsistency.ts` 收集以下浏览器信号；检测结果作为信息参考，**不计入 IP 评分**。

### WebRTC 检测（参考 jason5ng32/MyIP）

- 使用 Google + Cloudflare STUN 服务器
- **只接受 srflx/prflx ICE candidates**（server-reflexive / peer-reflexive）
- Host candidates 仅显示本地 IP，不能证明 STUN 工作，必须过滤
- 5 秒超时
- 支持 IPv4 + IPv6 地址提取

### DNS 一致性检测

- 通过 `cloudflare.com/cdn-cgi/trace` 获取 Cloudflare 视角的连接 IP
- 与公网 IP 对比：一致 = 无 DNS 代理/泄漏

### 时区/语言检测

- 时区：`Intl.DateTimeFormat().resolvedOptions().timeZone` vs IP 地理位置时区
- 语言：`navigator.languages` vs IP 国家预期语言

### 检测项

| 检测项 | 方法 | 说明 |
|--------|------|------|
| 时区 | `Intl.DateTimeFormat().resolvedOptions().timeZone` | vs IP 地理位置时区 |
| 语言 | `navigator.languages` | vs IP 国家预期语言 |
| WebRTC | `RTCPeerConnection` + STUN (srflx-only) | vs 公网 IP |
| DNS | `cloudflare.com/cdn-cgi/trace` | 连接 IP vs 公网 IP |

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
- **原因**: 前端收集了浏览器信号但后端 `scoreEngine.ts` 硬编码 `envScore=5`
- **修复**: 
  - 后端读取 `check.consistency` 计算环境一致性
  - 前端 `handleResult` 异步完成后重新计算评分
  - 最终决策：环境一致性改为信息参考，不计入 IP 评分

### Bug 3: WebRTC 接受 host candidates（2026-05-13）

- **现象**: WebRTC IP 可能显示本地 IP (192.168.x.x)，或接受非 STUN 验证的 IP
- **原因**: 未过滤 ICE candidate 类型，host candidates 也接受
- **修复**: 参考 jason5ng32/MyIP，只接受 `srflx`/`prflx` 类型 candidates
- **影响范围**: `src/lib/envConsistency.ts`

### Bug 4: 服务端黑名单扣分过滤器 broken（2026-05-13）

- **现象**: 黑名单扣分不显示在 Abuse Risk 类别中
- **原因**: `scoreEngine.ts` 用 `d.field?.startsWith?.('bl.')` 过滤，但实际 field 是 DNSBL 名称
- **修复**: 改为按 `source` 字段过滤 (DNSBL/AbuseIPDB)

### Bug 5: Connectivity Score 显示 /100 实为 /10（2026-05-13）

- **现象**: 连接质量显示 "7/100"，但底层计算是 0-10 分制
- **修复**: 前端显示改为 `/10`

### Bug 6: 语言匹配假阴性（2026-05-13）

- **现象**: 没有 IP 语言数据时，语言期望=实际但 still 显示不匹配
- **原因**: `collectBrowserSignals` 在 `ipLanguages` 为空时 `languageMatch=false`
- **修复**: 无 IP 语言数据时默认 `languageMatch=true`（不扣分）

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
| ~~高~~ | ~~WebRTC 异步结果回传~~ | ✅ 2026-05-13 已实现：srflx-only + 异步完成后重新评分 |
| 中 | 服务端 DNS 泄漏检测 | 当前用 Cloudflare trace 做连接一致性检查；完整 DNS 泄漏检测需要权威 DNS 服务器 |
| 中 | MaxMind GeoLite2 | 免费注册即可，增加第三个 Geo 数据源 |
| 低 | 自定义评分权重 | 允许用户调整 6 维度权重 |
| 低 | IP 对比模式 | 同时检测两个 IP 并对比 |
| 低 | i18n | 目前双语（中/英），可扩展更多语言 |

---

## 十一、变更记录

| 日期 | 变更 |
|------|------|
| 2026-05-12 | 初始版本 |
| 2026-05-13 | WebRTC 检测改为 srflx-only（参考 jason5ng32/MyIP） |
| 2026-05-13 | 评分模型重构：IP 质量评分 + 浏览器环境信息参考分离 |
| 2026-05-13 | DNS 一致性检测实现（cloudflare.com/cdn-cgi/trace） |
| 2026-05-13 | 修复黑名单扣分过滤、Connectivity Score 单位、语言匹配假阴性 |
| 2026-05-13 | 服务端 scoreEngine 重构：环境一致性不再硬编码，使用客户端数据 |
| 2026-05-18 | 全面代码审计 + 修复 + 评分模型收紧 + 安全加固（见第十三节） |

---

## 十三、2026-05-18 全面审计与修复

### 审计方法

1. **逐文件代码审查**：检查所有 7 个测试文件 + 14 个源码文件，寻找逻辑错误、安全漏洞、类型安全问题和边界条件
2. **测试驱动验证**：运行 157 个单元测试，定位所有失败，追溯到根因
3. **外部参考对比**：研究 jason5ng32/MyIP (10.3k stars) 等开源 IP 检测项目，对比检测方法、数据源选择、架构模式

### 修复列表

#### 1. 评分模型收紧（6 项参数调整）

**为什么**：原模型对数据中心 IP（52/100 → "caution"）和 Tor 出口节点（32/100 → "high_risk"）评分过高。数据中心 IP 天然高风险，Tor 出口节点应直接归入 "not_recommended"。

**改了什么**：
- Tor 扣分：15 → 20（`src/lib/ipScore.ts` + `functions/_shared/scoreEngine.ts`）
- Hosting 扣分：8 → 10（两处）
- 网络类型 "unknown"：7 → 5（两处）
- 环境一致性始终分：10 → 5（两处，信息参考不计入 IP 质量评分）
- 延迟 >300ms 扣分：3 → 5（两处）
- 延迟 >150ms 扣分：1 → 2（两处）

**验证**：数据中心+滥用+黑名单 IP 现在评分 ≤45，Tor+多重滥用 IP 评分 ≤25。25 个评分测试全部通过。

#### 2. Cloudflare Functions 缺少 IP 校验（安全漏洞）

**为什么**：生产环境的 3 个 CF Functions 端点（current/score/reputation）仅检查 localhost，不拒绝私有 IP（192.168.x, 10.x, 127.x）、非法格式、SSRF payload。与 Express 后端的完整校验不一致。

**改了什么**：
- 新增 `functions/_shared/ipValidator.ts`（兼容 CF Workers 环境，无 `node:net` 依赖）
- `functions/api/ip-check/score.ts`：添加 `isValidIp` + `isPublicIp` 校验
- `functions/api/ip-check/current.ts`：添加校验
- `functions/api/ip-check/reputation.ts`：添加校验

**验证**：CF 端点现在与 Express 后端的校验逻辑一致。手动审查确认所有私有范围（RFC 1918、CGNAT、链路本地、组播、文档地址等）均被拒绝。

#### 3. Express 端 IPv4-mapped IPv6 地址处理（安全漏洞）

**为什么**：`req.ip` 在 Express trust proxy 启用时返回 `::ffff:192.168.1.1` 格式。`isPublicIp()` 不识别此格式，私有 IP 绕过检测被标记为公网 IP。

**改了什么**：
- `server/index.ts`：新增 `extractRealIp()` 函数，在验证前解包 `::ffff:x.x.x.x` 格式
- `getClientIp()` 对所有来源 IP（X-Forwarded-For、req.ip）统一解包

**验证**：`::ffff:192.168.1.1` 现在正确解包为 `192.168.1.1` 后被拒绝。

#### 4. 客户端重评分覆盖服务器不确定性判定

**为什么**：`handleResult` 调用 `calculateIpScore` 重新计算评分时，从 dataSources 重新计算 `isUncertain`。若客户端视角的数据源与服务器不同，服务器的不确定性判定会被丢失。

**改了什么**：
- `src/components/IpCheckPage.tsx`：保存服务器原始的 `isUncertain` + `uncertaintyReason`，客户端重评分后若服务器判为不确定但客户端未触发，则保留服务器的不确定性判定

**验证**：不确定性测试通过（mock 3 个 failed dataSources → 超过 50% 失败 → 显示 uncertain badge）。

#### 5. WebRTC/DNS 异步检查无错误处理

**为什么**：`applyAsyncChecks` 中 `detectWebRtcIp()` 或 `detectDnsConsistency()` 若抛出异常，未捕获的 rejection 会导致未定义行为。

**改了什么**：`applyAsyncChecks` 添加 try/catch（静默处理，WebRTC/DNS 是尽力而为的辅助检测）。

#### 6. 冗余正则表达式

**为什么**：`server/ipValidator.ts` 中 `sanitizeIp` 的正则 `/[^a-fa-f0-9.:]/g` 包含冗余的 `a-fa-f`（实际等价于 `[^a-f0-9.:]`）。

**改了什么**：修正为 `/[^a-f0-9.:]/g`。

#### 7. 测试修复（13 个失败 → 0 个失败）

**envConsistency.test.ts（6 tests）**：测试期望值与当前代码行为不匹配（Bug 6 于 2026-05-13 修复后未更新测试）
- `dnsNote` 预期值更新为当前代码的实际输出
- 无 IP 数据时 `languageMatch`/`timezoneMatch` 默认为 true（避免假扣分）
- WebRTC 测试改用 `vi.useFakeTimers()` 控制异步超时
- srflx-only 候选者过滤器的测试用例更新为 srflx 类型

**IpCheckPage.test.tsx（5 tests）**：mock 缺少 `detectDnsConsistency` + mock 数据与客户端重评分不一致
- 新增 `detectDnsConsistency` mock
- 更新 mockResponse 数据使其与 `calculateIpScore` 客户端评分引擎结果一致
- 修复搜索重检查测试的异步时序（`fireEvent.change` → `waitFor(getByDisplayValue)`）
- 展开 section 测试适配新 mock 数据

**scoring.test.ts（2 tests）**：评分阈值与新收紧模型一致
- 数据中心+滥用测试上限调整为 ≤45（原 <50）
- Tor+滥用测试上限调整为 ≤25（原 <30），新增第 3 条黑名单以覆盖新扣分幅度

### 安全审计补充

基于审计新增的修复：
- [x] CF Functions 端点具有与 Express 同等的 IP 校验（防 SSRF、内网探测）
- [x] IPv4-mapped IPv6 地址在 IP 校验前正确解包
- [x] WebRTC/DNS 异步检查异常不影响核心功能
- [x] 客户端重评分不会丢失服务器不确定性判定
- [x] sanitizeIp 正则无冗余/无效字符类

### 外部参考：jason5ng32/MyIP 对比

| 方面 | MyIP | 本工具 | 推荐 |
|------|------|--------|------|
| STUN 服务器 | 4 个 | 2 个 (Google+Cloudflare) | 当前足够 |
| 数据源 | ip-api.com (无密钥) | ipapi.co + IPinfo + MaxMind | 本工具更全面 |
| 评分模型 | 无（纯展示） | 6 维度 100 分制 | 本工具独有 |
| 后端 | 无（纯前端） | Express + CF Functions | 本工具支持密钥 API |
| DNSBL | 无 | 4-8 个提供商 | 本工具独有 |
| 滥用检测 | 无 | AbuseIPDB | 本工具独有 |
| IPv6 DNSBL | 不支持 | CF 不支持 / Server 不支持 | **需补充** |
| 免费备用数据源 | ip-api.com | 无 | **推荐添加 ip-api.com** |

### 推荐的后续改进（来自研究）

| 优先级 | 项目 | 说明 |
|:------:|------|------|
| 高 | 添加 ip-api.com 作为无密钥备用数据源 | 45 req/min 免费，有代理检测，可弥补 ipapi.co 限流时的数据缺失 |
| 高 | IPv6 DNSBL 支持 | 当前生产环境（CF）和开发环境（Express）均跳过 IPv6 DNSBL 查询 |
| 中 | Tor 出口节点专用 DNSBL | `dnsbl.torproject.org` 反向查询可独立验证 Tor 状态 |
| 中 | 反向 DNS 主机名分析 | PTR 记录中的 "broadband"/"dsl" vs "server"/"cloud" 可推断网络类型 |
| 中 | 扩充 hosting/datacenter 关键词列表 | Contabo, M247, DDoS-Guard, BuyVM, FranTech, Psychz 等 |
| 低 | iCloud Private Relay / Google MASQUE 识别 | 避免将合法隐私服务误标为代理 |
| 低 | 多 DoH 提供商 DNS 泄漏检测 | 比单一 Cloudflare trace 更可靠 |

---

## 十二、安全审计清单

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

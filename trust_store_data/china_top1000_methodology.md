# 中国 Top 1000 网站域名列表 —— 构建方法学

**项目**: 大创项目方向一 · TLS 证书链主动扫描测量
**文件**: `china_top1000_domains.txt`（1000 个唯一注册域名，一行一个，小写、无 www、无重复）
**审计文件**: `china_top1000_ranking.csv`（源排名 / 原始主机名 / 规范化域名）
**复现脚本**: `build_china_top1000.py`（依赖 `tldextract 5.3.2`，建议 venv 运行）
**数据获取日期**: 2026-09-19 UTC（本地时间 2026-09-20）
**主源榜单更新日期**: 2026-09-13（站长之家标注）

---

## 1. 数据源逐一说明

| # | 数据源 | URL | 获取日期 | 状态 |
|---|--------|-----|----------|------|
| 1 | Chrome UX Report (CrUX) | https://developer.chrome.com/docs/crux/ | 2026-09-19 | ❌ 不可获取 |
| 2 | Tranco 全球 Top-1M | https://tranco-list.eu/top-1m.csv.zip | 2026-09-19 | ✅ 下载成功（仅作验证源） |
| 3 | 站长之家 中文网站总排名 | https://top.chinaz.com/all/ | 2026-09-19 | ✅ 抓取成功（**主源**） |
| 4 | 爱站 国内网站排行榜 | https://top.aizhan.com/area/ | 2026-09-19 | ❌ 内容为 JS 动态加载 |
| 5 | Alexa 排名 | https://alexa.chinaz.com/Global/ | 2026-09-19 | ❌ 已停用 |
| 6 | dataplane.org | https://dataplane.org | 2026-09-19 | ❌ 不适用（非网站排名） |
| 7 | GitHub: Aethersailor/chinaz-top-domains | https://github.com/Aethersailor/chinaz-top-domains | 2026-09-19 | ✅ 用于交叉验证 |

### 1.1 Chrome UX Report（CrUX）—— ❌ 不可获取
- **说明**: CrUX 提供按国家分组的 Top 域名（Chrome 真实用户访问数据），是最贴近"中国用户最常访问网站"的权威源。
- **尝试**:
  - 方法学页 https://developer.chrome.com/docs/crux/methodology 与 API 文档页：`fetch failed`（本机网络无法连通 developer.chrome.com）。
  - REST API `POST https://chromeuxreport.googleapis.com/v1/records:queryRecord`：连接失败（HTTP 000），且该 API 正式使用需要 Google API key。
  - BigQuery 表（`chrome-ux-report`）：需要 Google 账号登录认证，本环境不可行。
- **结论**: **不可获取，原因：需要认证/网络不可达**。
- **间接覆盖**: CrUX 数据已并入 Tranco 默认列表（Tranco 自 2023-08-01 起整合 CrUX 与 Cloudflare Radar 排名），因此本列表间接继承了 CrUX 的全球影响力信号；但**非中国区**细分。Tranco API 支持 `filterCRUXType: "country"` + `["CN"]` 生成中国区列表，但该端点（`/lists/create`）要求注册账号，注册页含 **reCAPTCHA 验证**（curl 提交返回 "Verification through reCAPTCHA failed"），程序化注册不可行。

### 1.2 Tranco —— ✅ 下载成功（验证源，非主源）
- **URL**: https://tranco-list.eu/top-1m.csv.zip（永久 URL），HTTP 200，9,726,388 字节。
- **列表 ID**: `JZNVY`（https://tranco-list.eu/top-1m-id 返回），服务端时间戳 2026-09-19 18:04:07 GMT。
- **构成**: Tranco 为 5 源聚合（Cisco Umbrella、Majestic、Farsight、CrUX、Cloudflare Radar），30 天平均，抗操纵设计（NDSS'19 论文配套服务）。
- **本任务用法**: 按 `.cn` TLD 本地过滤 → **11,024 个 .cn 域名**（其中 .com.cn 2,101 个）。用于与主源做交叉验证。
- **为何不作主源**: 
  1. **基础设施噪声**: Tranco 的 .cn 前段混入大量 CDN/DNS 资产域名（如 `ctdns.cn`(rank 1294)、`tdnsstic1.cn`、`ctadns.cn`、`wscvip.cn`、`sinaimg.cn`、`qpic.cn` 等），并非"网站"。
  2. **覆盖偏差**: 仅按 .cn TLD 过滤会漏掉约 **62%** 的中国主流网站（见 §4.4 统计：本最终列表仅 381/1000 出现在 Tranco 的 .cn 子集内；baidu.com、qq.com 等 .com 站点全部漏检）。
- **结论**: 保留为**验证源**（衡量主源代表性）。

### 1.3 站长之家 中文网站总排名（chinaz）—— ✅ 成功（**主源**）
- **URL**: https://top.chinaz.com/all/（榜单标注"更新：2026-09-13"）。
- **规模**: 总排名共 **3,457 页 × 30 条/页 = 103,707 条**收录条目；经 eTLD+1 规范化后约 **88,671 个唯一注册域名**（与独立项目 Aethersailor/chinaz-top-domains 的 manifest 完全一致，该工具亦基于同一榜单）。
- **指标性质**: 该榜单按站长指标（反链数、百度权重、APPPC 排名等）综合评分排序，反映"中文网站热度"，与真实流量非严格一致（见 §5 风险）。
- **抓取**: 2026-09-19 抓取前 45 页（源排名 1 ~ 1248 条），解析出 1,350 条条目 → 规范化去重后 **1,070 个唯一域名** → 取前 1000。
- **为什么能作为"中国 Top"**: 收录对象为中文网站（任意 TLD），天然覆盖中国运营者的 .com/.cn/.com.cn 站点；头部质量高（baidu.com、qq.com、sohu.com、163.com、eastmoney.com…）。

### 1.4 爱站 国内网站排行榜 —— ❌ 失败
- **URL**: https://top.aizhan.com/area/（宣称收录国内网站 174,651 个）。
- **尝试**: 抓取 40 页（`/area/`、`/area/p2.html` … `p40.html`，共 2.1 MB）。
- **失败原因**: 榜单列表内容通过 **JavaScript/AJAX 动态加载**，静态 HTML 中仅含导航与页面框架，无法用 curl 提取域名明细（详情页 `/NNN.html` 也需逐条访问且无列表索引）。需浏览器渲染（如 Playwright/Puppeteer）才能采集。
- **备注**: 其头部榜单（百度、百家号、百度知道、百度百科、腾讯网、B站…）与 chinaz 高度重合，但排序明显滞后（疑似 2015 年前后数据），即便可采也存在陈旧性风险。

### 1.5 Alexa 排名 —— ❌ 已停用
- Alexa.com 免费/付费服务已关停（2019 年起不再提供免费数据，站点 2021 年关闭）；镜像页 https://alexa.chinaz.com/Global/ 显示"**暂无数据**"。确认不可用，无替代价值。

### 1.6 dataplane.org —— ❌ 不适用
- 该站为网络信号（SSH/SNMP/DNS 扫描数据）提供商，不提供网站流行度排名，与本任务无关。

### 1.7 GitHub 交叉验证项目 —— ✅
- **Aethersailor/chinaz-top-domains**（MIT 协议，1.1k stars 未收录，独立开发）: 对同一 chinaz 榜单做采集 + eTLD+1 规范化，data 分支每日更新（manifest 生成于 2026-09-16，源更新 2026-09-13，103,707 条、88,671 唯一域名）。
- **用途**: 验证本工作的解析与规范化结果 —— 本列表 1000 个域名 **100%** 出现在该项目的 top10000.txt 中（同源一致性验证通过），且其 manifest 佐证了 chinaz 榜单的总规模与更新日期。

---

## 2. 合并规则（多源优先级）

**最终列表 = 站长之家 中文网站总排名 前 1000 个唯一注册域名（按源排名升序）。**

- **优先级**: 主源（chinaz）> 验证源（Tranco .cn）。
- **合并方式**: 由于可用数据源中仅 chinaz 提供了"中国网站"属性的完整排名，而 CrUX 中国区、爱站、Alexa 均不可用，**并集退化为单源主列表**；Tranco .cn 仅用于验证（不注入条目），理由见 §1.2（基础设施噪声 + 62% 漏检）。
- **排序**: 按 chinaz 源排名升序（1 → 1248 截断），保留截断边界（第 1000 名 `huoban.com`，源排名 1248；第 1001+ 名为候选集的 1070-1000=70 个落选域名，见 ranking.csv 与脚本日志）。
- **数量上限**: 1000（宁缺毋滥——本任务实际候选 1070，取 1000）。

## 3. 清理规则（可复现的确定性规则）

按顺序执行：
1. **小写化**: 全部转为小写。
2. **主机名提取**: 取条目中的主机名字段（如 `www.baidu.com`、`blog.csdn.net`、`mp.weixin.qq.com`）。
3. **WWW 归一化**: 通过 eTLD+1 规范化自动剥除 `www.` 前缀（`www.baidu.com → baidu.com`）。
4. **子域名合并**: 任意深度的子域名条目合并到注册域（eTLD+1）并保留最优排名（如 `blog.csdn.net → csdn.net`（rank 20 折叠进 rank 18）、`news.sohu.com → sohu.com`）。
5. **无效条目剔除**:
   - 纯 IP 地址（如 `210.42.121.241`）——本任务前 45 页未出现，全量榜单中出现过；
   - 公共后缀本身（如 `gov.cn`、`edu.cn`、`net.cn`）——非注册域；
   - 无后缀/无注册域条目。
6. **去重**: 按规范化后的注册域去重，保留最小源排名。
7. **编码**: 全部条目为 ASCII；若遇 IDN 则转 Punycode（本列表未涉及）。
8. **规范化工具**: `tldextract 5.3.2`（基于 publicsuffix.org 公共后缀列表快照，缓存于 `.psl_cache/` 以保证同一快照可复现）。

## 4. 最终列表统计

### 4.1 规模
- **唯一注册域名: 1000**（去重后；候选 1070，截取 1000）
- 重复/www 残留: 0 / 0

### 4.2 TLD 分布（20 个不同 TLD）
| TLD | 数量 | 占比 |
|-----|------|------|
| .com | 567 | 56.7% |
| .cn | 132 | 13.2% |
| .com.cn | 93 | 9.3% |
| .gov.cn | 89 | 8.9% |
| .edu.cn | 57 | 5.7% |
| .net | 32 | 3.2% |
| .org | 7 | 0.7% |
| .org.cn / .net.cn | 5 / 4 | 0.9% |
| .cc / .me / .com.hk | 各 2 | 0.6% |
| .tv / .sh.cn / .ac.cn / .im / .us / .fm / .hk / .info | 各 1 | 0.8% |

- **中国相关 TLD 合计**（.cn/.com.cn/.gov.cn/.edu.cn/.org.cn/.net.cn/.ac.cn/.sh.cn）: **382 (38.2%)**
- **.com 主导**（567, 56.7%）印证了"中国网站大量使用 .com"的判断——仅靠 .cn 过滤会严重低估。

### 4.3 与 Tranco .cn 子集交叉验证
- 最终列表 ∩ Tranco .cn 全集（11,024 个）: **381/1000 (38.1%)**
- 最终列表 ∩ Tranco .cn 前 1000: **206/1000 (20.6%)**
- 结论: 主列表与独立源（Tranco）存在中等程度重叠，方向一致；差异主要来自 (a) 中国主流 .com 站点未被 .cn 过滤捕获，(b) chinaz 榜单收录的垂直/地方站点未进入 Tranco 全球榜单。

### 4.4 列表头部样例（验证内容质量）
`baidu.com, qq.com, sohu.com, 163.com, eastmoney.com, so.com, sogou.com, bilibili.com, weibo.com, iqiyi.com, ctrip.com, jd.com, sina.com.cn, pcauto.com.cn, 2345.com, ali213.net, chinatax.gov.cn, csdn.net, youku.com, douban.com, zhihu.com …`

## 5. 风险与局限（论文引用时必须声明）

1. **主源单一性**: 可用"中国网站"完整排名仅 chinaz 一家（CrUX 中国区、爱站、Alexa 均不可用）。列表的排序与集合都继承 chinaz 的指标口径（反链/百度权重/APPPC 混合评分），**不等价于真实流量排名**。
2. **榜单滞后/可操纵性**: chinaz 榜单更新于 2026-09-13，部分条目简介陈旧；中文 SEO 类榜单存在刷量/SEO 操纵可能（榜单含"上升排行"栏目即为操纵迹象）。
3. **Tranco 覆盖偏差**: Tranco 的 .cn 子集混入 CDN/DNS 基础设施域名（`ctdns.cn`、`tdnsstic1.cn` 等），且按 TLD 过滤会漏掉 62% 的 .com/.net 中国站点；故本工作未直接采用 Tranco .cn 作为列表来源。
4. **中国属性判定弱**: 列表按"中文网站排行榜收录"间接判定中国属性，未做 whois/ICP 备案核验；尾部可能混入在华流行的境外站点（如 `nba.com`、`booking.com`、`paypal.com`、`dior.com`、`vacheron-constantin.com` 等，rank 560~1248 区间）。
5. **时间敏感性**: 榜单逐日变化，扫描实验应**立即**记录快照日期（2026-09-13/获取 2026-09-19），并在论文中披露。
6. **可达性**: 未验证各域名是否可解析/可连接（主动扫描阶段自然会获得该信息；不可解析的域名应在测量报告中单独说明，不属本清单缺陷）。

## 6. 可复现性说明

- **同一天、同规则 ⇒ 同列表**: 运行 `build_china_top1000.py`（需 `tldextract==5.3.2`）即可从 `https://top.chinaz.com/all/` 重新抓取前 45 页并重建完全相同的 1000 域名（依赖 chinaz 榜单在当日不变；若榜单已更新，请记录新的源更新日期并重新审计）。
- **快照留存**: `chinaz_top1000_ranking.csv` 记录了每个域名的源排名与原始主机名，可审计中间每一步。
- **Tranco 引用**: 列表 ID `JZNVY`（2026-09-19 生成），可用于永久引用；API 文档: https://tranco-list.eu/api_documentation。
- **交叉验证源**: Aethersailor/chinaz-top-domains `data` 分支 manifest（2026-09-16 生成）佐证 chinaz 榜单规模与更新日期。

## 7. 后续改进建议

1. **CrUX 中国区**: 人工注册 Tranco 账号（需过 reCAPTCHA）后用 `filterCRUXType=country, filterCRUXValue=["CN"]` 生成中国区列表，作为第二主源。
2. **ICP 备案核验**: 对 1000 域名批量查询工信部 ICP 备案（或第三方 API），用备案主体判定中国属性，剔除尾部境外站点。
3. **whois 注册地核验**: 抽样 whois 的 registrant country，量化"中国运营"纯度。
4. **多快照对比**: 连续多日抓取，报告榜单稳定性（Tranco 论文已指出日间波动显著）。

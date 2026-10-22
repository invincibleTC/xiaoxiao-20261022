# 潇潇时尚 · H5 线上画册

单文件前端 + EdgeOne Pages 边缘函数，前台展示 + 后台管理（管理员可增删改全站内容）。

## 目录结构

```
lookbook.html              主页面（前台展示 + 后台管理，内联 CSS/JS）
index.html                 入口页：打开站点根目录时自动跳转到 lookbook.html
functions/api/
  auth.js                  POST   /api/auth            登录，返回 token
                           PUT    /api/auth            改密码（需旧密码）
                           GET    /api/auth            预留邮箱的脱敏信息
  garments.js              GET    /api/garments        商品列表
                           POST   /api/garments        新增商品（管理员）
  garments/[id].js         PUT    /api/garments/:id     修改商品（管理员）
                           DELETE /api/garments/:id     删除商品（管理员）
  site-config.js           GET    /api/site-config     站点配置（公开读）
                           PUT    /api/site-config     站点配置（管理员写）
  reset.js                 POST   /api/reset           发起重置（发邮件到预留邮箱）
                           PUT    /api/reset           用邮件链接完成重置
tools/gen-admin-hash.html  本地生成管理员凭据（盐+哈希），不联网

*.jpg / *.png              素材原图：页面不直接引用，只是本地备份，已被 .gitignore 排除
```
```

## 一、上传到 GitHub

### 方式 A：命令行（需先安装 Git）
1. 安装 <https://git-scm.com/download/win>，装完重开终端。
2. 在本目录执行：

```bash
git init
git add .
git commit -m "init: 潇潇时尚 H5 画册"
git branch -M main
git remote add origin https://github.com/<你的用户名>/<仓库名>.git
git push -u origin main
```

> 若 GitHub 要求登录，用 Personal Access Token 作为密码，或先装 GitHub CLI 执行 `gh auth login`。

### 方式 B：网页上传（不装 Git 也能做）
1. GitHub 网页 → New repository → 建空仓库（不要勾 README）。
2. 进仓库页 → **Add file → Upload files** → 把本目录的文件拖进去（文件夹 `functions` 直接拖，GitHub 会保留层级）。
3. 底部填 commit 信息 → Commit changes。

> 注意：网页上传不会传 `.gitignore` 里的内容，也不需要。

### ✅ 仓库里没有明文密码，可直接上传

管理员密码已经从代码里彻底移除：前端不存密码，服务端只认 `ADMIN_PASSWORD_HASH`（哈希），
密码明文由你在部署时用 `tools/gen-admin-hash.html` 生成后填进环境变量，**不进仓库**。

确认一下：`grep -r "xiaoxiao2026" .` 应该没有任何结果（有的话说明是没清理干净的旧文件）。

## 二、部署到腾讯云 EdgeOne Pages

EdgeOne Pages 原生支持 `functions/api/*.js` 边缘函数和 KV，和本仓库结构完全对应，不需要改代码。

1. 打开 <https://edgeone.ai/products/pages> → 控制台 → **创建项目 → 导入 Git 仓库**。
2. 授权 GitHub，选中刚才的仓库，分支 `main`。
3. 构建配置：
   - 框架预设：**无 / Other**
   - 构建命令：**留空**
   - 输出目录：**`/`**（根目录）
   - 首页 / 入口文件：填 **`lookbook.html`**（若控制台只允许 index.html，就在仓库根目录放一份同名副本）
4. 点部署，完成后会得到一个 `https://xxx.edgeone.app` 域名（自带 HTTPS，国内可直连）。

### 绑定 KV（不绑也能打开，但后台保存不会跨设备同步）

控制台 → 项目 → **KV 存储** → 新建命名空间，变量名填 **`GARMENTS_KV`**，绑定到项目函数。
`site-config.js` 会优先用 `SITE_KV`，没配就退回 `GARMENTS_KV`，所以绑一个就够。

### 设置环境变量（管理员凭据）

先用本地工具生成：双击打开 **`tools/gen-admin-hash.html`** → 输入密码 → 得到四个值。
（页面纯本地运行、不联网，生成后密码输入框会清空。）

然后在控制台 → 项目设置 → **环境变量** 填入：

| 变量 | 说明 |
|---|---|
| `ADMIN_USERNAME` | 管理员用户名 |
| `ADMIN_SALT` | 随机盐（工具生成） |
| `ADMIN_PASSWORD_HASH` | `sha256(盐 + ":" + 密码)` 的十六进制（工具生成） |
| `AUTH_SECRET` | token 签名密钥，随机长字符串（工具生成） |

**管理员邮箱与邮件（用于忘记密码）**

| 变量 | 说明 |
|---|---|
| `ADMIN_EMAIL` | 管理员邮箱，重置链接只发到这个地址 |
| `MAIL_PROVIDER` | `resend` 或 `tencent`（腾讯云 SES） |
| `MAIL_API_KEY` | Resend 的 API Key（`MAIL_PROVIDER=resend` 时） |
| `MAIL_SECRET_ID` / `MAIL_SECRET_KEY` / `MAIL_FROM` | 腾讯云 SES 的密钥与发信地址 |

改完环境变量需要**重新部署**一次才生效。
登录相关的四个变量缺任意一个，登录接口会直接返回 503 拒绝登录——**不存在任何默认密码**。

> 重置密码必须绑定 KV：改过的新凭据写进 KV 的 `admin-cred`（环境变量在边缘函数里是只读的，改不了）。没绑 KV 时只能靠环境变量里的初始密码，改密码和自助重置都不可用。

### 验证

1. 打开分配到的域名，首页正常显示。
2. 点「登录 / 管理后台」，用管理员账号登录 → 能进管理面板说明 `/api/auth` 通了。
3. 改一条门店信息 → 换手机或开无痕窗口打开 → 内容一致，说明 `/api/site-config` + KV 通了。
4. 若第 2-3 步失败，页面会自动回退 localStorage（能看能改，但只在本机生效），这时检查 KV 绑定和环境变量。

## 三、自定义域名（可选）

EdgeOne Pages → 项目 → 域名管理 → 添加自己的域名，按提示加一条 CNAME 解析即可，证书自动签发。
域名在国内使用需要备案（腾讯云备案）。

## 四、安全设计

**管理员凭据**
- 仓库里**没有任何明文密码**：前端不存密码，服务端环境变量里存的是 `sha256(随机盐 + ":" + 密码)` 的哈希。
- 哈希单向，即使有人拿到 `ADMIN_PASSWORD_HASH` 也推不出密码；但**密码原文不要写进任何文件、不要提交到 GitHub**。
- 环境变量没配齐 → 登录接口返回 503，**不会退回任何默认密码**（旧版本的 `xiaoxiao2026` 默认值已彻底删除）。

**登录与 token**
- token 格式 `v1.<payload>.<HMAC-SHA256签名>`，用 `AUTH_SECRET` 签名，有效期 12 小时，过期自动登出。
- 每个写接口（商品增改删、`site-config` 写入）都会**独立验签**。旧版本只检查 `Authorization: Bearer …` 前缀，任何人伪造一个头就能改全站内容，这个漏洞已修复。
- 密码比对用常量时间比较，避免计时侧信道；账号错和密码错返回同一句提示，不泄露账号是否存在。
- 同一 IP 15 分钟内连续失败 10 次 → 锁定 15 分钟（需绑定 KV，没绑则跳过该限制）。

**管理员邮箱与密码找回**
- 邮箱只存在环境变量 `ADMIN_EMAIL` 里：**接口永不返回完整邮箱**，只给登录者返回脱敏串 `188****@139.com`，前端也就无从展示、爬虫也抓不到。
- 忘记密码：登录页「忘记密码」→ 输入账号 → 重置链接发到预留邮箱，30 分钟有效、**用后即焚**；用户名对不对都返回同一句提示，不能被用来猜账号。
- 改密码：管理面板「修改管理员密码」，需输入当前密码，成功后**同时给预留邮箱发一封告知邮件**（不是本人操作能立刻发现）。
- 改密码或重置后，密码版本号 +1，**其它设备上已登录的会话立即全部失效**，写接口也一并拒绝旧 token。

**本机演示登录**
- 本地预览（没有 `/api/*`）时，第一次登录会让你**自己设置一个本机演示密码**，只以「随机盐 + SHA-256 哈希」存在 localStorage。
- 它只在本机生效，内容不会同步到线上；线上请用服务端账号登录。

**还能再加固的**
- 把 `AUTH_SECRET` 定期轮换（换后所有已登录设备需重新登录）。
- 后台没有并发锁，建议只用一个设备管理内容。
- 若要做更严格的登录（短信/微信扫码），应接入腾讯云的身份校验服务。

## 五、已知限制

- 上传的图片/视频目前压缩成 dataURL 存进站点配置，单份配置上限 8MB（`site-config.js` 里写死）。图片多了建议改存对象存储（COS），配置里只留 URL。
- `functions/api/garments*` 用 KV 存商品，`/api/site-config` 存其余全部区块；两边共用一个命名空间即可。
- 管理后台没有并发锁，多人同时改会互相覆盖（后写的赢）。

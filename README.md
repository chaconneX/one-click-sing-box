# one-click-sing-box
基于sing-box的 hy2 & reality & vless-ws & shadowsocks2022 一键安装脚本

# Hysteria 2 + VLESS Reality + VLESS WS TLS + Shadowsocks 2022 一键安装脚本

## 简介
本项目提供一个 **一键安装脚本**，用于在 Linux 服务器上快速部署 **Hysteria 2**、**VLESS Reality**、**VLESS WS TLS** 和 **Shadowsocks 2022**，四种协议可按需选择，单独或组合安装。

你可以根据情况选择：
- 使用 **域名 + Cloudflare API** 自动配置证书
- 使用 **域名 + Let's Encrypt** 证书（Standalone 模式）
- **无域名**，使用 IP + 自签证书（Reality / SS2022 无需证书）

---

## 功能特性
- 一键安装，无需手动繁琐配置
- **支持四种协议**：Hysteria 2、VLESS Reality、VLESS WS TLS、Shadowsocks 2022
- **协议自由选择**：安装时按需勾选，可单独安装任意一种或任意组合
- 支持 **自签证书**，无需购买域名也可使用
- 可选 **Cloudflare API 自动解析**，省去手动添加 DNS
- 可选 **Let's Encrypt Standalone** 模式申请证书
- 自动输出客户端配置参数和分享链接
- 自动生成二维码，方便手机扫码导入
- **支持中转服务器模式**，可配置中转VPS → 落地VPS架构
- **VPS 系统调优**，一键开启 BBR、TCP/UDP优化、降低延迟

---

## 协议说明

| 协议 | 传输层 | 默认端口 | 特点 |
|------|--------|----------|------|
| Hysteria 2 | UDP/QUIC | 443 | 高速、抗丢包、适合不稳定网络 |
| VLESS Reality | TCP | 8443 | 高度伪装、防探测、无需证书 |
| VLESS WS TLS | TCP/WebSocket | 2053 | 兼容性好、支持CDN、适合受限网络 |
| Shadowsocks 2022 | TCP/UDP | 8388 | 轻量、高性能、无需证书、适合中转落地 |

---

## 前置条件

1. **服务器（必备）**
   - Linux 系统（推荐 Ubuntu 20.04 / 22.04 / Debian 11+）
   - 已开放相应端口（按所选协议）

2. **域名（可选）**
   - 仅 Hysteria 2 和 VLESS WS TLS 需要 TLS 证书
   - 仅使用 VLESS Reality 或 Shadowsocks 2022 时无需域名和证书

3. **Cloudflare API Token（可选）**
   - 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
   - 创建 API Token，权限需包含 `Zone.DNS 编辑`

---

## 安装方法
```bash
wget -N --no-check-certificate https://raw.githubusercontent.com/chaconneX/one-click-hy2-reality-ws/main/hy2_reality_install.sh && chmod +x hy2_reality_install.sh && bash hy2_reality_install.sh
```

---

## 安装选项说明

### 协议选择（新）

安装向导会提示选择需要安装的协议：

```
请选择要安装的协议 (输入编号，空格分隔；直接回车安装全部):
  1) Hysteria 2
  2) VLESS Reality
  3) VLESS WS TLS
  4) Shadowsocks 2022

选择协议 [默认: 全部]:
```

**示例：**
- 直接回车 → 安装全部四种协议
- `1 4` → 只安装 Hysteria 2 + Shadowsocks 2022
- `2` → 只安装 VLESS Reality
- `3 4` → 只安装 VLESS WS TLS + Shadowsocks 2022

脚本会根据已选协议自动跳过不相关的配置步骤（如只选 Reality + SS2022 则跳过证书配置）。

### 证书配置

仅当选择了 **Hysteria 2** 或 **VLESS WS TLS** 时才需要配置证书：

- **自签名证书** → 快速安装，客户端需设置 `insecure: true`
- **Let's Encrypt (Standalone)** → 需要 80 端口，域名可托管在任何 DNS
- **Let's Encrypt (Cloudflare API)** → 无需 80 端口，域名必须在 Cloudflare

> VLESS Reality 和 Shadowsocks 2022 使用自身加密机制，**无需 TLS 证书**。

### 端口配置

| 协议 | 默认端口 | 协议类型 |
|------|----------|---------|
| Hysteria 2 | 443 | UDP |
| VLESS Reality | 8443 | TCP |
| VLESS WS TLS | 2053 | TCP |
| Shadowsocks 2022 | 8388 | TCP/UDP |

### Shadowsocks 2022 加密方式

| 加密方式 | 密钥长度 | 说明 |
|----------|---------|------|
| `2022-blake3-aes-128-gcm` | 16 字节 | 推荐，性能好 |
| `2022-blake3-aes-256-gcm` | 32 字节 | 更高安全性 |
| `2022-blake3-chacha20-poly1305` | 32 字节 | 适合无 AES 硬件加速的设备 |

---

## 中转服务器模式

脚本支持 **中转VPS → 落地VPS** 架构，支持四种协议作为落地连接协议。

### 使用场景
- 落地VPS线路好但直连不稳定
- 需要隐藏落地VPS的真实IP
- 使用多个中转服务器共享一个落地服务器

### 部署步骤

#### 1. 先部署落地服务器
```bash
bash hy2_reality_install.sh
# 选择 1) 落地服务器 (直接出口)
```

安装完成后，记录以下信息（根据你选择的落地协议）：

| 落地协议 | 需要记录的参数 |
|---------|--------------|
| Hysteria 2 | 地址、端口、密码 |
| VLESS Reality | 地址、端口、UUID、Public Key、Short ID、SNI |
| VLESS WS TLS | 地址、端口、UUID、路径 |
| Shadowsocks 2022 | 地址、端口、加密方式、密码 |

#### 2. 再部署中转服务器
```bash
bash hy2_reality_install.sh
# 选择 2) 中转服务器 (转发到落地VPS)
# 选择入口协议（客户端连接中转用的协议）
# 选择落地协议（中转连接落地用的协议）
```

#### 3. 客户端连接
客户端使用中转服务器的连接信息，流量自动转发到落地服务器。

### 架构示意
```
客户端 → 中转VPS (任意协议入口) → 落地VPS (任意协议出口) → 互联网
```

### 注意事项
- 中转和落地可以使用不同协议（如中转用 Reality 入口，落地用 SS2022 出口）
- Shadowsocks 2022 作为落地连接时，密码需要从落地服务器的配置信息中复制
- 确保落地服务器的端口在防火墙中已开放

---

## VPS 系统调优

脚本内置 VPS 调优功能，可显著提升代理性能、降低延迟。

### 调优内容

| 优化项 | 说明 | 效果 |
|--------|------|------|
| **BBR** | Google TCP 拥塞控制算法 | 显著提升带宽利用率，减少丢包影响 |
| **TCP 优化** | 缓冲区、超时、Fast Open 等 | 加快连接速度，降低延迟 |
| **UDP/QUIC 优化** | 增大 UDP 缓冲区 | 提升 Hysteria 2 性能 |
| **系统限制** | 文件描述符、进程数 | 支持更多并发连接 |
| **低延迟参数** | 端口范围、ARP缓存等 | 整体降低网络延迟 |

### 使用方法
```bash
bash hy2_reality_install.sh
# 选择 5) VPS 系统调优 (BBR + TCP优化)
```

**系统要求：** BBR 需要 Linux 内核 4.9+，现代 VPS 默认满足。

---

## 文件位置

| 文件 | 路径 |
|------|------|
| sing-box 配置 | `/etc/sing-box/config.json` |
| TLS 证书目录 | `/etc/sing-box/certs/` |
| 配置信息汇总 | `/root/sing-box-info.txt` |
| 所有分享链接 | `/root/share_links.txt` |

---

## 服务管理

```bash
# 查看服务状态
systemctl status sing-box

# 重启服务
systemctl restart sing-box

# 停止服务
systemctl stop sing-box

# 查看日志
journalctl -u sing-box -f
```

---

## 客户端推荐

| 平台 | 推荐客户端 |
|------|-----------|
| Windows | v2rayN, Clash Verge, NekoRay |
| macOS | ClashX Pro, V2rayU, NekoRay |
| iOS | Shadowrocket, Quantumult X, Stash |
| Android | v2rayNG, Clash for Android, NekoBox |

> Shadowsocks 2022 需要客户端支持 `2022-blake3-*` 系列加密方式，推荐使用上述列表中较新版本的客户端。

---

## 版本历史

| 版本 | 新增内容 |
|------|---------|
| v7.0 | 新增 Shadowsocks 2022 协议；支持按需选择安装协议 |
| v6.0 | 新增 VPS 系统调优（BBR + TCP/UDP优化） |
| v5.0 | 新增 VLESS WS TLS 协议 |
| v4.0 | 新增中转服务器模式 |

---

## 声明

本项目仅用于学习与研究，请勿用于任何非法用途。作者不对使用过程中的后果负责。

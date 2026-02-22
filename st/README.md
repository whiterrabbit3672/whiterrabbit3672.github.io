<!--
  HarmonyMagic StartPage
  Copyright (C) 2026 anjisuan608 <anjisuan608@petalmail.com> and contributors

  SPDX-License-Identifier: GPL-3.0-or-later

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  Full license: ./LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt
-->

# HarmonyMagic 起始页

一个简洁高效的浏览器起始页，创新型多引擎搜索框分布、支持自定义预设快捷方式以及搜索引擎和壁纸。

## 仓库镜像

仓库 | 备注
:--------:|:--------:
[GitCode](https://gitcode.com/anjisuan608/HarmonyMagic-StartPage) | 主仓库
[Gitee](https://gitee.com/anjisuan608/HarmonyMagic-StartPage) | GitCode镜像
[GitLink](https://gitlink.org.cn/anjisuan608/HarmonyMagic-StartPage) | Gitee镜像
[GitHub](https://github.com/anjisuan608/HarmonyMagic-StartPage) | Gitee镜像

## 功能特性

### 多引擎搜索
- **搜索引擎预设**：百度、搜狗、360搜索、必应、Google、哔哩哔哩搜索、MC百科搜索、Yandex、DuckDuckGo
- **支持添加自定义引擎**：可根据需求添加任意搜索引擎
- **引擎排序管理**：自由调整搜索引擎的使用顺序和显示状态

### 快捷访问
- **预设快捷方式**：预设一些常用快捷方式
- **自定义快捷方式**：添加个人常用网站，数据保存在localStorage中
- **打开方式**：点击时间和日期模块打开

### 壁纸设置
- **预设壁纸**：预设壁纸示例(来自必应壁纸)
- **自定义壁纸**：支持本地图片或在线图片
- **自动记忆**：自动保存用户选择的壁纸

## 项目文件结构

```
./
├── index.html          # 主页面结构
├── style.css           # 样式文件
├── script.js           # 交互逻辑（含安全防护模块）
├── search-engine.json  # 搜索引擎配置
├── quick-access.json   # 快捷访问配置
├── wallpaper.xml       # 壁纸配置
├── LICENSE             # GPLv3 许可证
└── README.md           # 本文件
```

## 配置文件

本项目支持通过修改配置文件来自定义内容，适用于以下场景：

- **家庭内网部署**：预设 NAS、路由器管理、智能家居控制台等快捷方式
- **组织内网部署**：预设内部文档系统、代码仓库、OA 系统、监控平台等搜索入口

> *部署使用请遵守项目许可证*

### search-engine.json - 搜索引擎配置

定义所有可用的搜索引擎，支持预设和自定义。

```json
{
    "engines": [
        {
            "id": 11,
            "title": "",
            "icon": "<svg>...</svg>",
            "url": "https://cn.bing.com/search?q={query}",
            "comment": "必应"
        }
    ]
}
```

#### **字段说明**：
| 字段 | 类型 | 说明 |
|:------:|:------:|:------:|
| `id` | 整数 | 引擎唯一标识，不能为 0（预留给自定义内容） |
| `title` | 字符串 | 引擎名称 |
| `icon` | 字符串 | SVG 图标代码(需要转义) |
| `url` | 字符串 | 搜索 URL，`{query}` 或 `%s` 为搜索词占位符 |
| `comment` | 字符串 | 备注说明 |

### quick-access.json - 快捷访问配置

定义右键菜单中的快捷方式列表。

```json
[
    {
        "id": 11,
        "title": "微软翻译",
        "icon": "<svg>...</svg>",
        "url": "https://bing.com/translator",
        "comment": ""
    }
]
```

#### **字段说明**：
| 字段 | 类型 | 说明 |
|:------:|:------:|:------:|
| `id` | 整数 | 唯一标识 |
| `title` | 字符串 | 显示名称 |
| `icon` | 字符串 | SVG 图标代码 (需要转译) |
| `url` | 字符串 | 目标 URL |
| `comment` | 字符串 | 备注说明 |

### wallpaper.xml - 壁纸配置

定义可选的壁纸列表。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<wallpapers>
    <wallpaper id="11">
        <title>Bubbles</title>
        <comment>彩色气泡</comment>
        <url>https://www.bing.com/th?id=OHR.BubblesAbraham_ZH-CN7203734882_1920x1080.jpg</url>
    </wallpaper>
</wallpapers>
```

#### **字段说明**：
| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | 整数 | 壁纸标识，不能为 0（预留自定义） |
| `title` | 字符串 | 壁纸标题 |
| `comment` | 字符串 | 备注说明&光标悬浮显示 |
| `url` | 字符串 | 壁纸图片 URL |

> **说明**：
> - **配置文件**：预设内容，打包后不可更改（适合统一部署场景）
> - **localStorage**：用户自定义内容，浏览器端实时生效（适合个人使用）
> - 两者合并后呈现最终效果，自定义内容优先级更高

## 技术实现

- **纯前端架构**：HTML + CSS + JavaScript，无后端依赖
- **本地存储**：使用 localStorage 保存用户自定义内容和 Cookie 保存用户设置
- **安全防护**：支持简易的输入框 JavaScript、CSS 注入过滤模块
- **界面自适应**：适配不同屏幕尺寸(实验性)

## 浏览器支持

- Chrome / Edge / Firefox 等Blink(Chromium)、Gecko内核浏览器
- 需要启用 JavaScript

### 项目部署

### IIS(Internet Information Services)

<details>
    <summary>安装</summary>

任选一种方案安装

<details>
    <summary>图形化</summary>

###### Windows 桌面版(Vista/7/8/8.1/10/11)

> 控制面板 -> 程序 -> 程序和功能 -> 启用或关闭 Windows 功能 -> 勾选 "Internet Information Services" 复选框 -> 点击 确定 -> 等待完成，部分设备可能需要重新启动

###### Windows Server(2012 R2/2016/2019/2022/2025)

> Windows 服务器管理器 -> 右上角"管理" -> 添加角色和功能 -> 一直"下一页"到"服务器角色"(也可以直接点击"服务器选择"后点击"服务器角色") -> 勾选 "Web 服务器" 复选框 -> 一直"下一步"到确认 -> 安装 -> 等待完成，部分设备可能需要重新启动
</details>

<details>
    <summary>PowerShell</summary>

###### Windows 桌面版（10/11）

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole -NoRestart
```

###### Windows Server(2012 R2/2016/2019/2022/2025)

```powershell
Install-WindowsFeature -Name Web-Server -IncludeManagementTools
```

> 需要以管理员身份运行 PowerShell 执行上述命令。
</details>
</details>

<details>
<summary>部署</summary>

> 左侧展开"计算机名" -> 左侧展开"网站" -> 如果 "Default Web Site" 是启动状态(图标只有地球没有方框)，那么右键在菜单中点击停止(不建议删除) -> 右键左侧的"网站" -> 弹出的菜单中点击"添加网站" -> 物理路径选择一个记得住的位置 -> 点击"确定"(如果遇到了端口重复绑定的弹窗，点击"是")

> 在上面选择的网站目录中使用git克隆仓库或下载压缩包解压到目录

> 在浏览器中使用 `http://localhost` 测试(如果更改了端口号则在URL添加端口号，如:`http://localhost:8080`)

> 开放防火墙端口(对局域网开放)
</details>

### Apache

#### Linux（Ubuntu/Debian）

```bash
# 安装 Apache
sudo apt update
sudo apt install apache2

# 启用必要模块
sudo a2enmod rewrite

# 将项目复制到网站目录
sudo cp -r /path/to/project /var/www/html/

# 重启 Apache
sudo systemctl restart apache2

# 开放防火墙端口
sudo ufw allow 80/tcp
```

#### Linux（Red Hat 系 / CentOS Stream / Rocky Linux / AlmaLinux）

```bash
# 安装 Apache
sudo dnf install httpd

# 启动并启用服务
sudo systemctl enable --now httpd

# 将项目复制到网站目录
sudo cp -r /path/to/project /var/www/html/

# 设置权限
sudo chmod -R 755 /var/www/html/project

# 重启 Apache
sudo systemctl restart httpd

# 开放防火墙端口
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --reload
```

#### Windows

1. 下载并安装 [Apache Lounge](https://www.apachelounge.com/) 或 XAMPP
2. 将项目文件复制到 Apache 的 `htdocs` 目录
3. 修改 `httpd.conf` 配置网站根目录（可选）
4. 启动 Apache 服务
5. 访问 `http://localhost` 测试

#### macOS

```bash
# 使用 Homebrew 安装
brew install httpd

# 启动 Apache
sudo brew services start httpd

# 将项目复制到文档根目录
sudo cp -r /path/to/project /Library/WebServer/Documents/

# 访问 http://localhost 测试
```

### Nginx

#### Linux（Ubuntu/Debian）

```bash
# 安装 Nginx
sudo apt update
sudo apt install nginx

# 将项目复制到网站目录
sudo cp -r /path/to/project /var/www/html/

# 创建配置文件
sudo tee /etc/nginx/sites-available/project << 'EOF'
server {
    listen 80;
    server_name localhost;
    root /var/www/html/project;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }
}
EOF

# 启用配置
sudo ln -s /etc/nginx/sites-available/project /etc/nginx/sites-enabled/

# 测试并重启
sudo nginx -t
sudo systemctl restart nginx

# 开放防火墙端口
sudo ufw allow 80/tcp
```

#### Linux（Red Hat 系 / CentOS Stream / Rocky Linux / AlmaLinux）

```bash
# 安装 Nginx
sudo dnf install nginx

# 启动并启用服务
sudo systemctl enable --now nginx

# 将项目复制到网站目录
sudo cp -r /path/to/project /usr/share/nginx/html/

# 创建配置文件
sudo tee /etc/nginx/conf.d/project.conf << 'EOF'
server {
    listen 80;
    server_name localhost;
    root /usr/share/nginx/html/project;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }
}
EOF

# 测试并重启
sudo nginx -t
sudo systemctl restart nginx

# 开放防火墙端口
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --reload
```

#### Windows

1. 下载并安装 [Nginx](https://nginx.org/en/download.html)
2. 将项目文件复制到 Nginx 的 `html` 目录
3. 修改 `conf/nginx.conf` 配置网站根目录（可选）
4. 启动 Nginx：`nginx.exe`
5. 访问 `http://localhost` 测试

#### macOS

```bash
# 使用 Homebrew 安装
brew install nginx

# 将项目复制到文档根目录
sudo cp -r /path/to/project /usr/local/var/www/

# 启动 Nginx
brew services start nginx

# 访问 http://localhost:8080 测试（默认端口 8080）
```

## 许可证

本项目基于 GPLv3 开源协议，详见 [LICENSE](./LICENSE) 文件。
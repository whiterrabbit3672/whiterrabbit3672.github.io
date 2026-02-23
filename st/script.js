/*
 * HarmonyMagic StartPage
 * Copyright (C) 2026 anjisuan608 <anjisuan608@petalmail.com> and contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// 控制台输出
console.log(`
\x1b[32m
Harmony Magic Start Page
欢迎来到和谐魔法起始页!
\x1b[0m
© 2026 anjisuan608
Licensed under GPLv3
`);

// ==================== 安全防护模块 (Security Module) ====================
// 
// 提供用户输入防注入保护，支持以下功能：
// - XSS防护（HTML转义、Script过滤、事件处理器移除）
// - URL安全验证（白名单协议、危险协议阻断）
// - 数据绑定安全（innerHTML安全插入）
// - 可配置安全级别（宽松/标准/严格）
// - PHP代码过滤（默认禁用）
// - SQL注入过滤（默认禁用）
//
// 使用方法：
// Security.sanitize(input)                    // 默认标准级净化
// Security.sanitize(input, 'strict')          // 严格模式
// Security.sanitizeUrl(url)                   // URL安全验证
// Security.sanitizeHtml(html, 'text')         // HTML安全净化（text模式转义所有标签）
// Security.setConfig({...})                   // 自定义配置
//
// 启用控制：
// Security.enable('xss')          // 启用XSS防护
// Security.enable('url')          // 启用URL验证
// Security.enable('html')         // 启用HTML净化
// Security.enable('php')          // 启用PHP过滤
// Security.enable('sql')          // 启用SQL过滤
// Security.enableAll()            // 启用所有防护
// Security.disableAll()           // 禁用所有防护（不推荐）

const Security = (function() {
    'use strict';
    
    // ==================== 默认配置 ====================
    const defaultConfig = {
        // XSS防护配置
        xss: {
            enabled: true,                        // 是否启用XSS防护
            escapeHtml: true,                     // HTML转义
            removeScript: true,                   // 移除Script标签
            removeStyle: true,                    // 移除Style标签（防止CSS注入）
            removeEventHandlers: true,            // 移除事件处理器(onclick等)
            removeDangerousAttrs: true,           // 移除危险属性(href中的javascript:等)
            allowSafeTags: ['b', 'i', 'u', 'strong', 'em', 'br', 'p', 'span', 'div'], // 允许的HTML标签
            blockUrls: ['javascript:', 'data:', 'vbscript:'],                          // 阻断的URL协议
        },
        // URL验证配置
        url: {
            enabled: true,                        // 是否启用URL验证
            allowedProtocols: ['http:', 'https:', 'ftp:', 'mailto:', '/'],            // 允许的协议
            blockLocal: true,                     // 阻断本地文件访问(file://)
            maxUrlLength: 2048,                   // 最大URL长度
        },
        // HTML净化配置
        html: {
            enabled: true,                        // 是否启用HTML净化
            mode: 'text',                         // 模式：'text'(转义所有标签) | 'safe'(允许安全标签)
            allowAttributes: ['class', 'style'],  // 允许的属性
        },
        // 搜索框专用配置（已禁用，所有输入直接传给搜索引擎）
        search: {
            enabled: false,    // 搜索框不做任何过滤，允许用户输入代码/HTML等
        },
        // PHP代码过滤（默认禁用）
        // 启用方式：Security.config.phpFilter.enabled = true; Security.config.phpFilter.mode = 'block'; 
        php: {
            enabled: false,                       // 是否启用PHP代码过滤
            mode: 'block',                        // 模式：'block'(阻断) | 'remove'(移除)
            patterns: [
                /<\?php/i,                        // PHP标签开始
                /\?>/i,                           // PHP标签结束
                /<\?(?!xml)/i,                    // PHP短标签（排除<?xml）
                /\$\w+\s*\(/i,                    // PHP函数调用（如 eval(）
                /\$\{(GLOBALS|_SERVER|_GET|_POST|_COOKIE|_SESSION|FILES)\}/i, // PHP超全局变量
                /\b(eval|exec|system|passthru|shell_exec|popen|proc_open|curl_exec|curl_multi_exec|parse_ini_file|show_source)\s*\(/i, // 危险函数
                /\b(base64_decode|gzinflate|str_rot13|pack|unpack)\s*\(/i, // 混淆函数
            ],
            blockMessage: '输入包含不允许的PHP代码',
        },
        // SQL注入过滤（默认禁用）
        // 启用方式：Security.config.sqlFilter.enabled = true;
        sql: {
            enabled: false,                       // 是否启用SQL注入过滤
            mode: 'block',                        // 模式：'block'(阻断) | 'remove'(移除)
            // SQL注入特征模式
            patterns: [
                /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,                            // 单引号及变体
                /(\%3D)|(=)[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i,          // =后面跟分号
                /\w*(\%27)|(\')|((\%6F)|(o)|(\%4F))((\%72)|(r)|(\%52))/i,    // or/or变体
                /((\%27)|(\')|)union/i,                                      // union注入
                /union\s+select/i,                                           // union select
                /insert\s+into/i,                                            // insert into
                /update\s+.*set\s+/i,                                        // update set
                /delete\s+from/i,                                            // delete from
                /drop\s+table/i,                                             // drop table
                /truncate\s+table/i,                                         // truncate table
                /alter\s+table/i,                                            // alter table
                /create\s+table/i,                                           // create table
                /exec\s*\(/i,                                                // exec(
                /execute\s*\(/i,                                             // execute(
                /xp_cmdshell/i,                                              // xp_cmdshell
                /information_schema/i,                                       // information_schema
                /concat\s*\(/i,                                              // concat(
                /benchmark\s*\(/i,                                           // benchmark(
                /sleep\s*\(/i,                                               // sleep(
                /waitfor\s+delay/i,                                          // waitfor delay
                /load_file\s*\(/i,                                          // load_file(
                /into\s+outfile/i,                                          // into outfile
                /into\s+dumpfile/i,                                         // into dumpfile
            ],
            // 允许的SQL关键字（白名单，用于检测是否为主动注入）
            allowedKeywords: ['select', 'from', 'where', 'and', 'or', 'limit', 'order by', 'group by'],
            blockMessage: '输入包含不允许的SQL代码',
        },
        // 通知/提示配置
        notice: {
            enabled: true,
            maxLength: 1000,                      // 最大通知内容长度
        },
        // 日志配置
        logging: {
            enabled: true,                        // 是否记录安全拦截日志
            consoleOutput: true,                  // 控制台输出
        }
    };
    
    // 当前配置（可动态修改）
    let config = JSON.parse(JSON.stringify(defaultConfig));
    
    // 安全级别预设
    const securityLevels = {
        // 宽松模式 - 适合需要HTML格式的场景
        permissive: {
            xss: { enabled: true, escapeHtml: false, removeScript: true, removeStyle: true, removeEventHandlers: true, removeDangerousAttrs: false },
            url: { enabled: true, allowedProtocols: ['http:', 'https:', '/'] },
            html: { enabled: true, mode: 'safe', allowAttributes: ['class', 'style', 'id'] },
            search: { enabled: true, blockSpecialChars: false },
            php: { enabled: false, mode: 'block' },
            sql: { enabled: false, mode: 'block' },
        },
        // 标准模式 - 平衡安全性和功能性（默认）
        standard: {
            xss: { enabled: true, escapeHtml: true, removeScript: true, removeStyle: true, removeEventHandlers: true, removeDangerousAttrs: true },
            url: { enabled: true, allowedProtocols: ['http:', 'https:', 'mailto:'] },
            html: { enabled: true, mode: 'text' },
            search: { enabled: true, blockSpecialChars: false },
            php: { enabled: false, mode: 'block' },
            sql: { enabled: false, mode: 'block' },
        },
        // 严格模式 - 最高安全性，适合高安全需求
        strict: {
            xss: { enabled: true, escapeHtml: true, removeScript: true, removeStyle: true, removeEventHandlers: true, removeDangerousAttrs: true },
            url: { enabled: true, allowedProtocols: ['https:'], blockLocal: true, maxUrlLength: 512 },
            html: { enabled: true, mode: 'text', allowAttributes: [] },
            search: { enabled: true, maxLength: 100, blockSpecialChars: true },
            php: { enabled: true, mode: 'block' },
            sql: { enabled: true, mode: 'block' },
        }
    };
    
    // ==================== 专有工具函数 ====================
    
    // HTML实体转义表
    const htmlEscapeMap = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;',
        '`': '&#x60;',
        '=': '&#x3D;'
    };
    
    // 转义HTML特殊字符
    function escapeHtml(str) {
        if (typeof str !== 'string') return '';
        return str.replace(/[&<>"'`=/]/g, function(char) {
            return htmlEscapeMap[char];
        });
    }
    
    // 移除HTML标签
    function stripTags(str) {
        if (typeof str !== 'string') return '';
        return str.replace(/<[^>]*>/g, '');
    }
    
    // 移除事件处理器属性
    function removeEventHandlers(html) {
        if (typeof html !== 'string') return '';
        // 移除 on* 事件属性
        return html.replace(/\s*on\w+\s*=\s*(['"])[^'"]*\1/gi, '')
                   // 移除 style 中的 expression()
                   .replace(/style\s*=\s*(['"])[^'"]*expression\([^'"]*['"]/gi, 'style=$1$1')
                   // 移除 href 中的 javascript:
                   .replace(/href\s*=\s*(['"])\s*javascript:[^'"]*\1/gi, 'href="#"');
    }
    
    // 移除危险URL协议
    function blockDangerousUrls(str) {
        if (typeof str !== 'string') return '';
        let result = str;
        config.xss.blockUrls.forEach(protocol => {
            const regex = new RegExp(protocol, 'gi');
            result = result.replace(regex, '');
        });
        return result;
    }
    
    // 验证URL协议
    function validateUrlProtocol(url) {
        if (typeof url !== 'string') return false;
        const allowed = config.url.allowedProtocols;
        // 检查是否以允许的协议开头
        return allowed.some(protocol => url.toLowerCase().startsWith(protocol.toLowerCase()));
    }
    
    // 安全地设置innerHTML
    function safeSetInnerHTML(element, html, context = 'general') {
        if (!element || typeof element.innerHTML === 'undefined') return;
        
        const sanitized = sanitizeHtml(html, context);
        element.innerHTML = sanitized;
    }
    
    // ==================== 核心净化函数 ====================
    
    // XSS防护净化
    function sanitizeXss(input, options = {}) {
        if (typeof input !== 'string') return '';
        if (!options.escapeHtml && !options.removeScript && !options.removeEventHandlers && 
            !(options.phpFilter && options.phpFilter.enabled) && 
            !(options.sqlFilter && options.sqlFilter.enabled)) {
            return input; // 如果没有启用任何选项，返回原值
        }
        
        let result = input;
        
        // 移除Script标签（递归移除，包括各种变形）
        if (options.removeScript) {
            // 移除 <script>...</script>
            result = result.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
            // 移除 <script> 单独标签
            result = result.replace(/<script\b[^>]*>/gi, '');
            result = result.replace(/<\/script>/gi, '');
            // 移除 javascript: URL
            result = result.replace(/javascript:/gi, '');
            // 移除 data: URL（可能导致XSS）
            result = result.replace(/data:/gi, '');
            // 移除 vbscript: URL
            result = result.replace(/vbscript:/gi, '');
        }
        
        // 移除Style标签（防止CSS注入和exploit）
        if (options.removeStyle) {
            // 移除 <style>...</style>
            result = result.replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '');
            // 移除 <style> 单独标签
            result = result.replace(/<style\b[^>]*>/gi, '');
            result = result.replace(/<\/style>/gi, '');
            // 移除 style 属性中的危险内容（如 expression()）
            result = result.replace(/\s*style\s*=\s*(['"])[^'"]*expression\s*\([^'"]*['"]/gi, '');
            // 移除 style 属性中的 url(javascript:...)
            result = result.replace(/\s*style\s*=\s*(['"])[^'"]*url\s*\(\s*javascript:[^)]*\)/gi, '');
        }
        
        // 移除事件处理器
        if (options.removeEventHandlers) {
            result = removeEventHandlers(result);
        }
        
        // 移除危险属性（如 href 中的协议、src 等）
        if (options.removeDangerousAttrs) {
            // 移除带有 javascript:/vbscript:/data: 的 href
            result = result.replace(/\s*href\s*=\s*(['"])\s*(javascript|vbscript|data):[^'"]*\1/gi, ' href="#"');
            // 移除 src 属性中的危险协议
            result = result.replace(/\s*src\s*=\s*(['"])\s*(javascript|vbscript|data):[^'"]*\1/gi, '');
            // 移除 action 属性
            result = result.replace(/\s*action\s*=\s*(['"])[^'"]*\1/gi, '');
            // 移除 formaction 属性
            result = result.replace(/\s*formaction\s*=\s*(['"])[^'"]*\1/gi, '');
        }
        
        // HTML转义
        if (options.escapeHtml) {
            result = escapeHtml(result);
        }
        
        // PHP代码过滤
        if (options.phpFilter && options.phpFilter.enabled) {
            const phpResult = filterPhpCode(result, options.phpFilter.mode);
            if (phpResult === null) {
                logSecurity(options.phpFilter.blockMessage || '输入包含不允许的PHP代码', 'php', 'blocked');
                return '';
            }
            result = phpResult;
        }
        
        // SQL注入过滤
        if (options.sqlFilter && options.sqlFilter.enabled) {
            const sqlResult = filterSqlCode(result, options.sqlFilter.mode);
            if (sqlResult === null) {
                logSecurity(options.sqlFilter.blockMessage || '输入包含不允许的SQL代码', 'sql', 'blocked');
                return '';
            }
            result = sqlResult;
        }
        
        return result;
    }
    
    // PHP代码过滤器
    function filterPhpCode(input, mode = 'block') {
        if (!input || typeof input !== 'string') return input;
        
        for (const pattern of defaultConfig.php.patterns) {
            if (pattern.test(input)) {
                if (mode === 'block') {
                    return null; // 返回null表示应该阻断
                } else if (mode === 'remove') {
                    input = input.replace(pattern, '');
                }
            }
        }
        return input;
    }
    
    // SQL注入过滤器
    function filterSqlCode(input, mode = 'block') {
        if (!input || typeof input !== 'string') return input;
        
        // 检查是否包含允许的关键字（白名单检查）
        const hasAllowedKeyword = defaultConfig.sql.allowedKeywords.some(keyword => {
            return new RegExp('\\b' + keyword + '\\b', 'i').test(input);
        });
        
        for (const pattern of defaultConfig.sql.patterns) {
            if (pattern.test(input)) {
                // 如果没有允许的关键字，或者是明显的注入模式，则阻断/移除
                if (!hasAllowedKeyword || mode === 'remove') {
                    if (mode === 'block') {
                        return null;
                    } else if (mode === 'remove') {
                        input = input.replace(pattern, '');
                    }
                }
            }
        }
        return input;
    }
    
    // URL安全验证
    function sanitizeUrl(url, options = {}) {
        if (typeof url !== 'string') return '';
        
        let result = url.trim();
        
        // 检查长度
        if (options.maxUrlLength && result.length > options.maxUrlLength) {
            logSecurity('URL过长，已截断', 'url', 'warning');
            result = result.substring(0, options.maxUrlLength);
        }
        
        // 阻断本地文件访问
        if (options.blockLocal && result.toLowerCase().startsWith('file://')) {
            logSecurity('本地文件访问被阻断', 'url', 'blocked');
            return '';
        }
        
        // 验证协议
        if (!validateUrlProtocol(result)) {
            logSecurity('不允许的URL协议', 'url', 'blocked');
            return '';
        }
        
        // 移除危险协议
        result = blockDangerousUrls(result);
        
        return result;
    }
    
    // HTML内容净化
    function sanitizeHtml(html, mode = 'text', options = {}) {
        if (typeof html !== 'string') return '';
        
        if (mode === 'text') {
            // 文本模式：转义所有HTML标签
            return escapeHtml(html);
        } 
        else if (mode === 'safe') {
            // 安全模式：移除危险标签和属性，保留安全标签
            let result = html;
            
            // 移除所有Script相关
            result = result.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
            result = result.replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '');
            result = result.replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '');
            result = result.replace(/<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, '');
            result = result.replace(/<embed\b[^<]*>/gi, '');
            result = result.replace(/<form\b[^>]*>/gi, '');
            
            // 移除事件处理器
            result = removeEventHandlers(result);
            
            // 只保留允许的标签
            const allowedTags = options.allowedTags || config.xss.allowSafeTags;
            const tagPattern = new RegExp('<(' + allowedTags.join('|') + ')\\b[^>]*>', 'gi');
            const closeTagPattern = new RegExp('</(' + allowedTags.join('|') + ')>', 'gi');
            
            // 这是一个简化的处理，实际应用中可能需要更复杂的HTML解析库
            return escapeHtml(html);
        }
        
        return html;
    }
    
    // 搜索词净化
    function sanitizeSearch(query, options = {}) {
        if (typeof query !== 'string') return '';
        
        let result = query.trim();
        
        // 字数限制
        if (result.length > 550) {
            logSecurity('搜索词过长，已截断', 'search', 'warning');
            result = result.substring(0, 550);
        }
        
        // 搜索框不过滤，让用户自由输入代码等内容
        // 完全不做任何过滤或转义，直接返回原输入
        return result;
    }
    
    // 通知内容净化
    function sanitizeNotice(content, options = {}) {
        if (typeof content !== 'string') return '';
        
        let result = content.trim();
        
        // 限制长度
        if (options.maxLength && result.length > options.maxLength) {
            logSecurity('通知内容过长，已截断', 'notice', 'warning');
            result = result.substring(0, options.maxLength);
        }
        
        // 移除Script标签和事件处理器
        result = sanitizeXss(result, {
            escapeHtml: false,
            removeScript: true,
            removeEventHandlers: true
        });
        
        return result;
    }
    
    // ==================== 日志功能 ====================
    
    function logSecurity(message, category, level = 'info') {
        if (!config.logging.enabled || !config.logging.consoleOutput) return;
        
        const timestamp = new Date().toLocaleTimeString('zh-CN', { hour12: false });
        const styles = {
            blocked: 'color: #ff4444; font-weight: bold;',
            warning: 'color: #ff8800;',
            info: 'color: #2196F3;'
        };
        
        console.log(`%c[Security][${timestamp}][${category.toUpperCase()}] ${message}`, styles[level] || styles.info);
    }
    
    // ==================== 公共API ====================
    
    return {
        // 获取当前配置
        getConfig: function() {
            return JSON.parse(JSON.stringify(config));
        },
        
        // 应用配置
        setConfig: function(newConfig) {
            config = { ...config, ...newConfig };
            logSecurity('安全配置已更新', 'config', 'info');
        },
        
        // 重置为默认配置
        resetConfig: function() {
            config = JSON.parse(JSON.stringify(defaultConfig));
            logSecurity('安全配置已重置为默认', 'config', 'info');
        },
        
        // 应用安全级别预设
        setSecurityLevel: function(level) {
            if (!securityLevels[level]) {
                logSecurity(`未知的安全级别: ${level}`, 'config', 'warning');
                return false;
            }
            
            const preset = securityLevels[level];
            this.setConfig({
                xss: { ...config.xss, ...preset.xss },
                url: { ...config.url, ...preset.url },
                html: { ...config.html, ...preset.html },
                search: { ...config.search, ...preset.search }
            });
            
            logSecurity(`安全级别已设置为: ${level}`, 'config', 'info');
            return true;
        },
        
        // 启用指定防护
        enable: function(category) {
            if (config[category]) {
                config[category].enabled = true;
                logSecurity(`${category}防护已启用`, category, 'info');
            }
        },
        
        // 禁用指定防护
        disable: function(category) {
            if (config[category]) {
                config[category].enabled = false;
                logSecurity(`${category}防护已禁用`, category, 'warning');
            }
        },
        
        // 启用所有防护
        enableAll: function() {
            Object.keys(config).forEach(key => {
                if (typeof config[key] === 'object' && config[key] !== null) {
                    config[key].enabled = true;
                }
            });
            logSecurity('所有安全防护已启用', 'general', 'info');
        },
        
        // 禁用所有防护
        disableAll: function() {
            Object.keys(config).forEach(key => {
                if (typeof config[key] === 'object' && config[key] !== null) {
                    config[key].enabled = false;
                }
            });
            logSecurity('所有安全防护已禁用（不推荐）', 'general', 'warning');
        },
        
        // 通用净化函数 - 根据类型自动选择净化方式
        sanitize: function(input, options = {}) {
            const type = options.type || 'general';
            
            switch (type) {
                case 'search':
                    return config.search.enabled ? sanitizeSearch(input, config.search) : input;
                case 'url':
                    return config.url.enabled ? sanitizeUrl(input, config.url) : input;
                case 'html':
                    const htmlMode = options.mode || config.html.mode;
                    return config.html.enabled ? sanitizeHtml(input, htmlMode, options) : input;
                case 'notice':
                    return config.notice.enabled ? sanitizeNotice(input, config.notice) : input;
                case 'xss':
                default:
                    return config.xss.enabled ? sanitizeXss(input, {...config.xss, phpFilter: config.php, sqlFilter: config.sql}) : input;
            }
        },
        
        // XSS防护
        sanitizeXss: function(input) {
            return config.xss.enabled ? sanitizeXss(input, {...config.xss, phpFilter: config.php, sqlFilter: config.sql}) : input;
        },
        
        // URL安全验证
        sanitizeUrl: function(url) {
            return config.url.enabled ? sanitizeUrl(url, config.url) : url;
        },
        
        // HTML净化
        sanitizeHtml: function(html, mode) {
            const htmlMode = mode || config.html.mode;
            return config.html.enabled ? sanitizeHtml(html, htmlMode) : html;
        },
        
        // 搜索词净化
        sanitizeSearch: function(query) {
            return config.search.enabled ? sanitizeSearch(query, config.search) : query;
        },
        
        // 通知内容净化
        sanitizeNotice: function(content) {
            return config.notice.enabled ? sanitizeNotice(content, config.notice) : content;
        },
        
        // 安全设置innerHTML
        setInnerHTML: function(element, html, context = 'html') {
            const mode = context === 'html' ? config.html.mode : 'text';
            const sanitized = this.sanitizeHtml(html, mode);
            if (element) {
                element.innerHTML = sanitized;
            }
            return sanitized;
        },
        
        // 获取安全级别预设
        getSecurityLevels: function() {
            return Object.keys(securityLevels);
        },
        
        // 导出配置（用于保存到localStorage）
        exportConfig: function() {
            return JSON.stringify(config, null, 2);
        },
        
        // 导入配置
        importConfig: function(jsonConfig) {
            try {
                const imported = JSON.parse(jsonConfig);
                this.setConfig(imported);
                return true;
            } catch (e) {
                logSecurity('配置导入失败: 无效的JSON格式', 'config', 'warning');
                return false;
            }
        }
    };
})();

// ==================== 安全防护初始化 ====================
// 默认启用所有防护
Security.enableAll();

// 全局变量
let quickAccessData = [];
let searchEngineData = null;
let searchEngines = {};
let searchEngineSettings = {
    activeEngines: [1, 2, 3, 4, 5, 6, 7],
    disabledPresets: [],
    disabledCustoms: []
};
let searchEngineSettingsWorking = null; // 设置面板的内存副本

// 记录预设搜索引擎数量
let presetEngineCount = 0;

// 历史记录导航状态
let historyNavigationState = {
    currentIndex: -1,      // 当前选中的历史记录索引
    historyItems: [],       // 当前显示的历史记录列表
    filledQuery: '',       // 当前填充的查询词
    isNavigating: false    // 是否处于导航状态
};

// 记录当前触发历史记录菜单的搜索框（移动端用）
let currentHistorySearchBox = null;

// 搜索按钮SVG图标（硬编码在JS中）
const searchButtonSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="11" cy="11" r="8" stroke="currentColor" stroke-width="2"/><path d="M21 21L16.65 16.65" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';

// 自定义搜索引擎图标映射（存储名称以节省localStorage空间）
const customSearchEngineIcons = {
    'mc': '<svg t="1766328430081" class="search-icon" viewBox="0 0 1035 1024" version="1.1" xmlns="http://www.w3.org/2000/svg" p-id="37846" width="24" height="24"><path d="M1013.852766 1011.332492a42.225028 42.225028 0 0 1-59.70619 0L702.316509 759.502424a428.900723 428.900723 0 1 1 133.958901-196.00858 41.718328 41.718328 0 0 1-4.919216 14.166497c-1.330088 3.61024-2.385714 7.347155-3.800252 10.91517l-2.385714-2.385714a42.225028 42.225028 0 0 1-72.690386-29.13527l-0.380025-3.905815a41.950565 41.950565 0 0 1 11.379645-28.670794l-3.926928-3.905815a336.976836 336.976836 0 1 0-88.123633 150.764463 6.333754 6.333754 0 0 0 0.612262-0.928951l61.120729 1.055626 145.254096 145.232984 0.274463-0.274463 135.12009 135.12009a42.225028 42.225028 0 0 1 0.042225 59.79064z" fill="#515151" p-id="37847"></path></svg>'
};

// 搜索历史缓存名称（全局常量）
const SEARCH_HISTORY_CACHE_NAME = 'harmonymagic-search-history';
const MAX_HISTORY_ITEMS = 64;

// 根据图标名称获取SVG内容
function getSearchEngineIcon(iconName) {
    if (!iconName) return customSearchEngineIcons['mc'];
    // 如果不是已知的图标名称，说明是旧的完整SVG，直接返回
    if (!customSearchEngineIcons[iconName]) {
        return iconName;
    }
    return customSearchEngineIcons[iconName];
}

// 从Cache API读取搜索历史（全局函数）
async function getSearchHistoryFromCache() {
    try {
        const cache = await caches.open(SEARCH_HISTORY_CACHE_NAME);
        const response = await cache.match('history');
        if (response) {
            return await response.json();
        }
    } catch (e) {
        console.error('读取搜索历史失败:', e);
    }
    return [];
}

// 保存搜索历史到Cache API（全局函数）
async function saveSearchHistoryToCache(history) {
    try {
        const cache = await caches.open(SEARCH_HISTORY_CACHE_NAME);
        const response = new Response(JSON.stringify(history), {
            headers: { 'Content-Type': 'application/json' }
        });
        await cache.put('history', response);
    } catch (e) {
        console.error('保存搜索历史失败:', e);
    }
}

// 主应用
document.addEventListener('DOMContentLoaded', async function() {
    const searchIcon = document.querySelector('.search-icon');
    const timeDate = document.querySelector('.time-date');
    const searchBox = document.querySelector('.search-box');
    const contextMenu = document.getElementById('context-menu');
    const searchBoxesContainer = document.querySelector('.search-boxes-container');
    const menuItemsContainer = document.querySelector('.menu-items');
    const settings = document.getElementById('settings');

    // Cookie工具函数
    function setCookie(name, value, days = 365) {
        const expires = new Date();
        expires.setTime(expires.getTime() + days * 24 * 60 * 60 * 1000);
        document.cookie = name + '=' + encodeURIComponent(JSON.stringify(value)) + ';expires=' + expires.toUTCString() + ';path=/';
    }

    function getCookie(name) {
        const nameEQ = name + '=';
        const ca = document.cookie.split(';');
        for (let i = 0; i < ca.length; i++) {
            let c = ca[i];
            while (c.charAt(0) === ' ') c = c.substring(1, c.length);
            if (c.indexOf(nameEQ) === 0) {
                try {
                    return JSON.parse(decodeURIComponent(c.substring(nameEQ.length)));
                } catch (e) {
                    return null;
                }
            }
        }
        return null;
    }
    
    // 获取原始cookie字符串值（不解码）
    function getCookieRaw(name) {
        const nameEQ = name + '=';
        const ca = document.cookie.split(';');
        for (let i = 0; i < ca.length; i++) {
            let c = ca[i];
            while (c.charAt(0) === ' ') c = c.substring(1, c.length);
            if (c.indexOf(nameEQ) === 0) {
                return c.substring(nameEQ.length);
            }
        }
        return null;
    }

    // localStorage工具函数（用于替代cookie存储自定义快捷访问）
    function getLocalStorageItem(key) {
        try {
            const item = localStorage.getItem(key);
            if (item) {
                return JSON.parse(item);
            }
            return null;
        } catch (e) {
            console.error('读取localStorage失败:', e);
            return null;
        }
    }

    function setLocalStorageItem(key, value) {
        try {
            localStorage.setItem(key, JSON.stringify(value));
        } catch (e) {
            console.error('写入localStorage失败:', e);
        }
    }

    function removeLocalStorageItem(key) {
        try {
            localStorage.removeItem(key);
        } catch (e) {
            console.error('删除localStorage失败:', e);
        }
    }

    // ==================== 深色模式模块 ====================
    
    // 检测系统是否处于深色模式
    function isSystemDarkMode() {
        return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    }
    
    // 监听系统深色模式变化
    function listenSystemDarkModeChange(callback) {
        if (window.matchMedia) {
            window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
                callback(e.matches);
            });
        }
    }
    
    // 应用深色模式
    function applyDarkMode(settings) {
        const darkModeSetting = settings.darkMode; // true=深色, false=浅色, null=跟随系统
        
        let isDark;
        if (darkModeSetting === null) {
            // 跟随系统设置
            isDark = isSystemDarkMode();
        } else {
            isDark = darkModeSetting;
        }
        
        if (isDark) {
            document.documentElement.setAttribute('data-theme', 'dark');
        } else {
            document.documentElement.removeAttribute('data-theme');
        }
    }
    
    // ==================== 全局设置（global-settings） ====================
    // 默认设置值
    const defaultGlobalSettings = {
        backgroundBlur: true,      // 背景模糊（默认开启）
        backgroundFilter: true,    // 背景滤镜（默认开启）
        darkMode: null             // 深色模式：true=深色, false=浅色, null=跟随系统（默认）
    };

    // 加载全局设置
    function loadGlobalSettings() {
        const cookieValue = getCookieRaw('global-settings') || '';
        let settings = { ...defaultGlobalSettings };
        
        if (cookieValue) {
            try {
                const decoded = decodeURIComponent(cookieValue);
                const parsed = JSON.parse(decoded);
                settings = { ...settings, ...parsed };
            } catch (e) {
                console.error('解析全局设置失败:', e);
            }
        }
        
        return settings;
    }

    // 保存全局设置
    function saveGlobalSettings(settings) {
        const encodedValue = encodeURIComponent(JSON.stringify(settings));
        document.cookie = `global-settings=${encodedValue};path=/;expires=${new Date(Date.now() + 365*24*60*60*1000).toUTCString()}`;
    }

    // ==================== 历史记录设置（history-settings） ====================
    // 默认设置值
    const defaultHistorySettings = {
        searchHistoryRecording: true, // 搜索历史记录（默认开启）
        showAllHistory: true,         // 显示全部历史记录（默认开启，false时仅显示当前搜索引擎的历史记录）
        showHistoryMenu: true        // 显示历史记录菜单（默认开启）
    };

    // 加载历史记录设置
    function loadHistorySettings() {
        const cookieValue = getCookieRaw('history-settings') || '';
        let settings = { ...defaultHistorySettings };
        
        if (cookieValue) {
            try {
                const decoded = decodeURIComponent(cookieValue);
                const parsed = JSON.parse(decoded);
                settings = { ...settings, ...parsed };
            } catch (e) {
                console.error('解析历史记录设置失败:', e);
            }
        }
        
        return settings;
    }

    // 保存历史记录设置
    function saveHistorySettings(settings) {
        const encodedValue = encodeURIComponent(JSON.stringify(settings));
        document.cookie = `history-settings=${encodedValue};path=/;expires=${new Date(Date.now() + 365*24*60*60*1000).toUTCString()}`;
    }

    // 应用全局设置
    function applyGlobalSettings() {
        const settings = loadGlobalSettings();
        
        // 应用背景模糊设置
        setBackgroundBlurEnabled(settings.backgroundBlur);
        
        // 应用背景滤镜设置
        setBackgroundFilterEnabled(settings.backgroundFilter);
        
        // 应用深色模式设置
        applyDarkMode(settings);
        
        // 更新设置面板中的开关状态
        updateSettingsPanelStates();
    }

    // 控制背景模糊功能是否启用
    function setBackgroundBlurEnabled(enabled) {
        const bgBlurOverlay = document.querySelector('.bg-blur-overlay');
        const allInputs = document.querySelectorAll('input[type="text"]');
        
        if (enabled) {
            // 启用背景模糊
            if (bgBlurOverlay) {
                bgBlurOverlay.style.backdropFilter = 'blur(8px)';
                bgBlurOverlay.style.webkitBackdropFilter = 'blur(8px)';
            }
            // 恢复输入框的焦点监听
            allInputs.forEach(input => {
                input.addEventListener('focus', inputBlurHandler);
                input.addEventListener('blur', inputBlurHandler);
            });
        } else {
            // 禁用背景模糊 - 移除blur效果
            if (bgBlurOverlay) {
                bgBlurOverlay.style.backdropFilter = 'none';
                bgBlurOverlay.style.webkitBackdropFilter = 'none';
            }
            // 确保模糊层不显示
            if (bgBlurOverlay) {
                bgBlurOverlay.classList.remove('active');
            }
            // 移除输入框的焦点监听
            allInputs.forEach(input => {
                input.removeEventListener('focus', inputBlurHandler);
                input.removeEventListener('blur', inputBlurHandler);
            });
        }
    }

    // 控制背景滤镜（暗角效果）是否启用
    function setBackgroundFilterEnabled(enabled) {
        if (enabled) {
            // 启用背景滤镜 - 恢复暗角效果
            document.body.removeAttribute('data-filter-disabled');
        } else {
            // 禁用背景滤镜 - 清除暗角滤镜
            document.body.setAttribute('data-filter-disabled', 'true');
        }
    }

    // 更新设置面板中的开关状态显示
    function updateSettingsPanelStates() {
        const settings = loadGlobalSettings();
        
        // 更新背景模糊开关
        const blurSetting = document.querySelector('[data-setting="auto-wallpaper"]');
        if (blurSetting) {
            const indicator = blurSetting.querySelector('.status-indicator');
            const icon = blurSetting.querySelector('.status-icon');
            if (indicator && icon) {
                if (settings.backgroundBlur) {
                    indicator.classList.add('enabled');
                    icon.innerHTML = svgOn;
                } else {
                    indicator.classList.remove('enabled');
                    icon.innerHTML = svgOff;
                }
            }
        }
        
        // 更新背景滤镜开关
        const filterSetting = document.querySelector('[data-setting="dark-mode"]');
        if (filterSetting) {
            const indicator = filterSetting.querySelector('.status-indicator');
            const icon = filterSetting.querySelector('.status-icon');
            if (indicator && icon) {
                if (settings.backgroundFilter) {
                    indicator.classList.add('enabled');
                    icon.innerHTML = svgOn;
                } else {
                    indicator.classList.remove('enabled');
                    icon.innerHTML = svgOff;
                }
            }
        }
        
        // 更新深色模式开关状态显示
        const darkModeToggle = document.querySelector('[data-setting="dark-mode-toggle"]');
        if (darkModeToggle) {
            const valueSpan = darkModeToggle.querySelector('#dark-mode-value');
            const indicator = darkModeToggle.querySelector('.status-indicator');
            const icon = darkModeToggle.querySelector('.status-icon');
            
            if (valueSpan) {
                const darkMode = settings.darkMode;
                if (darkMode === null) {
                    valueSpan.textContent = '跟随系统';
                } else if (darkMode === true) {
                    valueSpan.textContent = '深色';
                } else {
                    valueSpan.textContent = '浅色';
                }
            }
            
            // 深色模式使用特殊的状态显示（始终显示启用图标，表示功能已启用）
            if (indicator && icon) {
                indicator.classList.add('enabled');
                icon.innerHTML = svgOn;
            }
        }
    }
    
    // 深色模式的三态切换
    const darkModeCycle = [null, true, false]; // 跟随系统 -> 深色 -> 浅色 -> 跟随系统
    
    // 处理深色模式切换
    function handleDarkModeToggle() {
        const settings = loadGlobalSettings();
        const currentIndex = darkModeCycle.indexOf(settings.darkMode);
        const nextIndex = (currentIndex + 1) % darkModeCycle.length;
        settings.darkMode = darkModeCycle[nextIndex];
        saveGlobalSettings(settings);
        applyDarkMode(settings);
        updateSettingsPanelStates();
    }

    // 处理背景模糊开关的点击事件
    function handleBackgroundBlurToggle(enabled) {
        const settings = loadGlobalSettings();
        settings.backgroundBlur = enabled;
        saveGlobalSettings(settings);
        setBackgroundBlurEnabled(enabled);
    }

    // 处理背景滤镜开关的点击事件
    function handleBackgroundFilterToggle(enabled) {
        const settings = loadGlobalSettings();
        settings.backgroundFilter = enabled;
        saveGlobalSettings(settings);
        setBackgroundFilterEnabled(enabled);
    }

    // 输入框焦点事件处理器（用于背景模糊）
    const inputBlurHandler = function(e) {
        if (e.type === 'focus') {
            const settings = loadGlobalSettings();
            if (settings.backgroundBlur) {
                setBackgroundBlur(true);
            }
        } else if (e.type === 'blur') {
            const addShortcutPanel = document.getElementById('add-shortcut-panel');
            // 如果添加面板是激活状态，不关闭背景模糊
            if (addShortcutPanel && addShortcutPanel.classList.contains('active')) {
                return;
            }

            setTimeout(() => {
                const settings = loadGlobalSettings();
                if (settings.backgroundBlur) {
                    const hasFocusedInput = Array.from(document.querySelectorAll('input[type="text"]')).some(inp =>
                        inp === document.activeElement || inp.contains(document.activeElement)
                    );
                    // 如果有焦点输入框，或者快捷访问菜单是打开的，不关闭背景模糊
                    if (hasFocusedInput || (contextMenu && contextMenu.classList.contains('active'))) {
                        return;
                    }
                    setBackgroundBlur(false);
                }
            }, 100);
        }
    };

    // 默认图标SVG
    const defaultIconSVG = '<svg t="1768974157218" class="icon" viewBox="0 0 1024 1024" version="1.1" xmlns="http://www.w3.org/2000/svg" p-id="8714" width="32" height="32"><path d="M512.704787 1022.681895c-6.566636 0-12.885487-0.746767-19.370211-0.997965l223.522968-358.091907c32.011327-42.692008 51.675057-95.154106 51.675057-152.604663 0-88.961536-45.561669-167.195974-114.530461-213.091436l322.88327 0c29.969663 65.017888 47.096842 137.184673 47.096842 213.424546C1023.98157 793.752715 795.095394 1022.681895 512.704787 1022.681895zM512.205805 256.491303c-134.523205 0-243.604451 102.347371-254.246906 233.876682L96.997133 214.338551C189.740287 84.72121 341.184526 0 512.704787 0c189.230383 0 354.100731 103.095504 442.520963 255.992321C955.22575 255.992321 302.108946 256.491303 512.205805 256.491303zM511.416716 298.145073c118.142111 0 213.88189 95.36503 213.88189 213.051163 0 117.68545-95.739779 213.093484-213.88189 213.093484-118.103885 0-213.882572-95.408034-213.882572-213.093484C297.534144 393.510103 393.312831 298.145073 511.416716 298.145073zM269.683279 590.222492c33.504179 102.303002 128.784566 176.716231 242.522526 176.716231 38.828478 0 75.283547-9.269059 108.292157-24.733419L448.229568 1018.192418c-251.87691-31.759447-446.887571-246.346465-446.887571-506.872631 0-94.739084 26.233779-183.159316 71.129911-259.235365L269.683279 590.222492z" fill="#515151" p-id="8715"></path></svg>';

    // 读取快捷访问数据并动态生成菜单
    async function loadQuickAccessMenu() {
        try {
            const response = await fetch('quick-access.json');
            if (!response.ok) {
                throw new Error('Failed to load quick-access.json');
            }
            quickAccessData = await response.json();

            // 按 id 排序
            quickAccessData.sort((a, b) => a.id - b.id);

            // 系统图标的HTML模板（硬编码）
            const addIconHTML = `<div class="menu-item" data-action="add">
                <div class="menu-icon-wrapper">
                    <div class="menu-item-bg"></div>
                    <div class="menu-icon"><svg t="1768967144636" class="icon" viewBox="0 0 1024 1024" version="1.1" xmlns="http://www.w3.org/2000/svg" p-id="9794" width="32" height="32"><path d="M831.6 639.6h-63.9v127.9H639.9v63.9h127.8v127.9h63.9V831.4h127.9v-63.9H831.6z" p-id="9795" fill="#2c2c2c"></path><path d="M564.3 925.2c0-18.5-15-33.6-33.6-33.6H287.3c-86.2 0-156.4-70.2-156.4-156.4V286.9c0-86.2 70.1-156.4 156.4-156.4h448.4c86.2 0 156.4 70.2 156.4 156.4v238.8c0 18.5 15 33.6 33.6 33.6s33.6-15 33.6-33.6V286.9C959.2 163.6 859 63.3 735.7 63.3H287.3C164 63.3 63.7 163.6 63.7 286.8v448.3c0 123.2 100.3 223.5 223.6 223.5h243.4c18.6 0.1 33.6-14.9 33.6-33.4z" p-id="9796" fill="#2c2c2c"></path></svg></div>
                </div>
                <div class="menu-text">添加</div>
            </div>`;

            const editIconHTML = `<!-- 系统图标：编辑（始终显示在最后） -->
            <div class="menu-item" data-action="edit">
                <div class="menu-icon-wrapper">
                    <div class="menu-item-bg"></div>
                    <div class="menu-icon"><svg t="1768898892387" class="icon" viewBox="0 0 1024 1024" version="1.1" xmlns="http://www.w3.org/2000/svg" p-id="4731" width="32" height="32"><path d="M474.58679343 587.16868738c-11.45302241 0-22.90604486-4.37057868-31.6472022-13.11173601-17.48231469-17.48231469-17.48231469-45.83841849 0-63.29440437l487.24053555-487.24053552c17.48231469-17.48231469 45.81208967-17.48231469 63.29440431 0 17.48231469 17.48231469 17.48231469 45.83841849 0 63.29440441L506.23399561 574.05695137a44.61676276 44.61676276 0 0 1-31.64720218 13.11173601z" fill="#2c2c2c" p-id="4732"></path><path d="M904.16728498 1017.19676833h-781.96497912c-62.68884228 0-113.68770304-50.99886074-113.68770305-113.71403181v-781.96497913c0-62.71517108 50.99886074-113.71403182 113.66137425-113.71403185l457.51533479 0.0263288c24.72273117 0 44.75893818 20.03620706 44.75893819 44.7589382s-20.03620706 44.75893818-44.75893819 44.7589382l-457.51533479-0.02632877c-13.2960375 0-24.14349786 10.84746035-24.14349785 24.16982661v781.96497915c0 13.32236631 10.84746035 24.1698266 24.16982665 24.16982664h781.96497912c13.32236631 0 24.1698266-10.84746035 24.16982668-24.16982664V403.42008173c0-24.72273117 20.06253583-44.75893818 44.75893815-44.75893828 24.72273117 0 44.75893818 20.03620706 44.7589382 44.75893828V903.50906532c0 62.68884228-50.99886074 113.68770304-113.68770303 113.68770301z" fill="#2c2c2c" p-id="4733"></path></svg></div>
                </div>
                <div class="menu-text">编辑</div>
            </div>`;

            // 清空现有菜单项
            menuItemsContainer.innerHTML = '';

            // 读取隐藏的预设列表
            const hiddenPresets = getLocalStorageItem('hidden_presets') || [];

            // 读取保存的快捷访问顺序（混合预设和自定义）
            const savedVisibleOrder = getLocalStorageItem('shortcut_visible_order') || [];

            // 创建预设映射
            const presetMap = {};
            quickAccessData.forEach(item => {
                presetMap[item.id] = item;
            });

            // 创建自定义映射
            const customShortcuts = getLocalStorageItem('custom_shortcuts') || [];
            const customMap = {};
            customShortcuts.forEach(item => {
                customMap[item.id] = item;
            });

            // 按保存的顺序渲染显示中的项目（预设 + 自定义混合）
            const renderedPresetIds = new Set();
            const renderedCustomIds = new Set();

            savedVisibleOrder.forEach(id => {
                if (id.startsWith('preset_')) {
                    const presetId = parseInt(id.replace('preset_', ''));
                    if (presetMap[presetId] && !hiddenPresets.includes(presetId)) {
                        const item = presetMap[presetId];
                        const menuItem = document.createElement('div');
                        menuItem.className = 'menu-item preset-item';
                        menuItem.setAttribute('data-url', item.url);
                        menuItem.setAttribute('data-preset-id', presetId);
                        menuItem.innerHTML = `
                            <div class="menu-icon-wrapper">
                                <div class="menu-item-bg"></div>
                                <div class="menu-icon">${item.icon}</div>
                            </div>
                            <div class="menu-text" title="${Security.sanitizeXss(item.title)}">${Security.sanitizeXss(item.title)}</div>
                        `;
                        menuItemsContainer.appendChild(menuItem);
                        renderedPresetIds.add(presetId);
                    }
                } else if (id.startsWith('custom_')) {
                    const customId = parseInt(id.replace('custom_', ''));
                    if (customMap[customId]) {
                        const item = customMap[customId];
                        const menuItem = document.createElement('div');
                        menuItem.className = 'menu-item custom-item';
                        menuItem.setAttribute('data-url', item.url);
                        menuItem.setAttribute('data-custom-id', customId);
                        menuItem.setAttribute('data-position', item.position ?? '');

                        let iconContent;
                        if (item.icon && item.icon.trim()) {
                            const escapedIcon = encodeURI(item.icon.trim());
                            iconContent = '<img src="' + escapedIcon + '" class="favicon-img" width="32" height="32" onerror="this.classList.add(\'favicon-error\')">';
                        } else {
                            iconContent = defaultIconSVG;
                        }

                        menuItem.innerHTML = `
                            <div class="menu-icon-wrapper">
                                <div class="menu-item-bg"></div>
                                <div class="menu-icon">${iconContent}</div>
                            </div>
                            <div class="menu-text" title="${Security.sanitizeXss(item.title)}">${Security.sanitizeXss(item.title)}</div>
                        `;
                        menuItemsContainer.appendChild(menuItem);
                        renderedCustomIds.add(customId);
                    }
                }
            });

            // 添加未保存顺序的预设（新增的）
            quickAccessData.forEach(item => {
                if (!renderedPresetIds.has(item.id) && !hiddenPresets.includes(item.id)) {
                    const menuItem = document.createElement('div');
                    menuItem.className = 'menu-item preset-item';
                    menuItem.setAttribute('data-url', item.url);
                    menuItem.setAttribute('data-preset-id', item.id);
                    menuItem.innerHTML = `
                        <div class="menu-icon-wrapper">
                            <div class="menu-item-bg"></div>
                            <div class="menu-icon">${item.icon}</div>
                        </div>
                        <div class="menu-text" title="${Security.sanitizeXss(item.title)}">${Security.sanitizeXss(item.title)}</div>
                    `;
                    menuItemsContainer.appendChild(menuItem);
                }
            });

            // 添加未保存顺序的自定义快捷方式
            customShortcuts.forEach(item => {
                if (!renderedCustomIds.has(item.id)) {
                    const menuItem = document.createElement('div');
                    menuItem.className = 'menu-item custom-item';
                    menuItem.setAttribute('data-url', item.url);
                    menuItem.setAttribute('data-custom-id', item.id);
                    menuItem.setAttribute('data-position', item.position ?? '');

                    let iconContent;
                    if (item.icon && item.icon.trim()) {
                        const escapedIcon = encodeURI(item.icon.trim());
                        iconContent = '<img src="' + escapedIcon + '" class="favicon-img" width="32" height="32" onerror="this.classList.add(\'favicon-error\')">';
                    } else {
                        iconContent = defaultIconSVG;
                    }

                    menuItem.innerHTML = `
                        <div class="menu-icon-wrapper">
                            <div class="menu-item-bg"></div>
                            <div class="menu-icon">${iconContent}</div>
                        </div>
                        <div class="menu-text" title="${Security.sanitizeXss(item.title)}">${Security.sanitizeXss(item.title)}</div>
                    `;
                    menuItemsContainer.appendChild(menuItem);
                }
            });

            // 恢复"添加"和"编辑"按钮
            menuItemsContainer.insertAdjacentHTML('beforeend', addIconHTML);
            menuItemsContainer.insertAdjacentHTML('beforeend', editIconHTML);

        } catch (error) {
            console.error('Error loading quick access data:', error);
        }
    }

    // 事件委托 - 在容器上统一处理点击事件（只绑定一次）
    function setupMenuItemDelegation() {
        menuItemsContainer.addEventListener('click', function(e) {
            const menuItem = e.target.closest('.menu-item');
            if (!menuItem) return;
            
            e.preventDefault();
            e.stopPropagation();

            // 处理"添加"按钮
            if (menuItem.dataset.action === 'add') {
                openAddShortcutPanel();
                return;
            }

            // 处理"编辑"按钮
            if (menuItem.dataset.action === 'edit') {
                openEditShortcutPanel();
                return;
            }

            // 获取URL并跳转
            const url = menuItem.dataset.url;
            if (url && url !== '#') {
                window.open(url, '_blank');
            }

            // 点击后关闭菜单
            contextMenu.classList.remove('active');
            document.documentElement.style.removeProperty('--search-box-top');
            setBackgroundBlur(false);
            // 直接恢复搜索框显示（确保立即生效，添加 !important）
            const searchBoxForClose = document.querySelector('.search-boxes-container');
            if (searchBoxForClose) {
                searchBoxForClose.style.setProperty('opacity', '1', 'important');
                searchBoxForClose.style.setProperty('visibility', 'visible', 'important');
            }
            if (settings) settings.style.display = 'none';
            // 恢复通知位置
            const notices = document.getElementById('notices');
            if (notices) notices.style.top = '20px';
        });
    }

    // 初始化快捷访问菜单
    await loadQuickAccessMenu();
    
    // 设置事件委托（只绑定一次）
    setupMenuItemDelegation();

    // 共享的搜索引擎JSON加载函数（避免重复请求）
    let searchEngineJsonLoaded = false;
    let searchEngineJsonData = null;
    let searchEngineJsonPromise = null; // Promise 锁，防止并发请求
    async function loadSearchEngineJson() {
        if (searchEngineJsonLoaded && searchEngineJsonData) return searchEngineJsonData;

        // 如果已有请求在进行中，等待它完成
        if (searchEngineJsonPromise) return searchEngineJsonPromise;

        searchEngineJsonPromise = (async () => {
            try {
                const response = await fetch('search-engine.json');
                if (!response.ok) throw new Error('Failed to load search-engine.json');
                searchEngineJsonData = await response.json();
                searchEngineJsonLoaded = true;
                return searchEngineJsonData;
            } catch (e) {
                console.error('加载搜索引擎JSON失败:', e);
                return null;
            } finally {
                searchEngineJsonPromise = null; // 请求完成后重置
            }
        })();

        return searchEngineJsonPromise;
    }

    // 加载搜索引擎数据
    async function loadSearchEngines() {
        const data = await loadSearchEngineJson();
        if (!data) return;

        // 如果是重置，先清空现有数据
        if (!searchEngineData) {
            searchEngineData = { engines: [] };
            searchEngines = {};
        }

        // 重新填充预设引擎
        searchEngineData.engines = data.engines.slice();
        // 记录预设引擎数量（用于区分预设和自定义）
        presetEngineCount = data.engines.length;

        // 创建引擎ID到引擎信息的映射
        data.engines.forEach(engine => {
            searchEngines[engine.id] = engine;
        });

        // 从localStorage加载自定义搜索引擎
        loadCustomSearchEngines();

        // 从localStorage加载搜索引擎设置
        loadSearchEngineSettings();

        // 刷新历史记录中无效的搜索引擎ID
        await fixSearchHistoryEngineIds();

        // 渲染搜索引擎图标和搜索按钮
        renderSearchEngineIcons();
    }

    // 刷新历史记录中无效的搜索引擎ID
    // 将不存在于搜索引擎列表中的记录的engineId设为0
    async function fixSearchHistoryEngineIds() {
        try {
            const history = await getSearchHistoryFromCache();
            if (!history || history.length === 0) return;

            let hasChanges = false;
            const validEngineIds = new Set(Object.keys(searchEngines).map(id => parseInt(id, 10)));

            history.forEach(item => {
                if (item.engineId !== undefined && item.engineId !== null) {
                    const engineId = parseInt(item.engineId, 10);
                    // 如果引擎ID不存在于当前搜索引擎列表中，设为0
                    if (!validEngineIds.has(engineId)) {
                        item.engineId = 0;
                        hasChanges = true;
                    }
                }
            });

            if (hasChanges) {
                await saveSearchHistoryToCache(history);
                console.log('已刷新历史记录中无效的搜索引擎ID');
            }
        } catch (e) {
            console.error('刷新历史记录引擎ID失败:', e);
        }
    }

    // 渲染搜索引擎图标和搜索按钮（根据activeEngines动态渲染）
    function renderSearchEngineIcons() {
        const searchBoxes = document.querySelectorAll('.search-box-circle');
        const activeEngines = searchEngineSettings.activeEngines || [];
        
        searchBoxes.forEach((box, index) => {
            // 根据activeEngines顺序获取对应的引擎ID
            const engineId = activeEngines[index];
            const contentDiv = box.querySelector('.search-circle-content');
            const nameEl = box.querySelector('.search-engine-name');
            const btn = box.querySelector('.circle-search-btn');
            
            if (engineId && searchEngines[engineId]) {
                const engine = searchEngines[engineId];
                
                // 更新data-engine-id
                box.setAttribute('data-engine-id', engineId);
                
                // 渲染图标（支持图标名称和完整SVG两种格式）
                if (contentDiv) {
                    contentDiv.innerHTML = getSearchEngineIcon(engine.icon);
                }
                
                // 渲染引擎名称
                if (nameEl) {
                    nameEl.textContent = engine.title;
                }
                
                // 渲染搜索按钮（使用JS中定义的SVG）
                if (btn && searchButtonSvg) {
                    btn.innerHTML = searchButtonSvg;
                }
            }
        });
    }

    // 根据引擎ID获取搜索URL
    function getSearchUrl(engineId, query) {
        if (!engineId || !searchEngines[engineId]) {
            return '';
        }
        const engine = searchEngines[engineId];
        if (!engine.url) return '';
        
        if (query) {
            // 使用Security模块净化搜索关键词，防止XSS注入
            const sanitizedQuery = Security.sanitizeSearch(query);
            // 同时支持 %s 和 {query} 两种占位符格式
            let url = engine.url.replace('%s', encodeURIComponent(sanitizedQuery));
            url = url.replace('{query}', encodeURIComponent(sanitizedQuery));
            return url;
        } else {
            // 如果没有查询，返回基础URL
            let url = engine.url.split('%s')[0];
            url = url.split('{query}')[0];
            return url;
        }
    }

    // 等待搜索引擎数据加载完成后渲染
    await loadSearchEngines();

// 获取所有圆形搜索框
    const circleSearchBoxes = document.querySelectorAll('.search-box-circle');
    const centerSearchBox = document.querySelector('.center-0');

    // 所有搜索框按DOM顺序排列
    const allSearchBoxes = [
        ...Array.from(circleSearchBoxes)
    ];

    // 获取背景模糊层
    const bgBlurOverlay = document.querySelector('.bg-blur-overlay');

    // 控制背景模糊
    function setBackgroundBlur(blur) {
        const settings = loadGlobalSettings();
        // 如果背景模糊全局禁用，不执行任何操作
        if (!settings.backgroundBlur) return;
        
        if (bgBlurOverlay) {
            if (blur) {
                bgBlurOverlay.classList.add('active');
            } else {
                bgBlurOverlay.classList.remove('active');
            }
        }
    }

    // 设置所有输入框的焦点监听
    function setupInputFocusListeners() {
        const allInputs = document.querySelectorAll('input[type="text"]');
        const settings = loadGlobalSettings();

        // 只在背景模糊启用时添加监听
        if (settings.backgroundBlur) {
            allInputs.forEach(input => {
                input.addEventListener('focus', inputBlurHandler);
                input.addEventListener('blur', inputBlurHandler);
            });
        }
    }

    // 初始化输入框焦点监听
    setupInputFocusListeners();

    // 设置默认搜索引擎为必应（用于中心搜索框和作为后备）
    let currentEngine = 'bing';

    // 当前展开的搜索框
    let currentExpandedBox = null;

    // 上一次处于输入展开状态的搜索框
    let lastInputActiveBox = document.querySelector('.center-0');

    // 当前处于未输入展开状态的搜索框
    let currentUninputExpandedBox = document.querySelector('.center-0');

    // 检查是否为移动端
    function isMobile() {
        return window.innerWidth <= 768;
    }

    // 检查是否为平板端
    function isTablet() {
        return window.innerWidth > 768 && window.innerWidth <= 1024;
    }

    // 检测并处理遮挡逻辑：时间日期被搜索框遮挡时隐藏
    function handleOcclusion() {
        const timeDisplay = document.querySelector('.time-display');
        const dateDisplay = document.querySelector('.date-display');
        const searchBoxEl = document.querySelector('.search-box');

        if (!timeDisplay || !dateDisplay || !searchBoxEl) return;

        const timeRect = timeDisplay.getBoundingClientRect();
        const dateRect = dateDisplay.getBoundingClientRect();
        const searchRect = searchBoxEl.getBoundingClientRect();

        // 检测日期是否被搜索框遮挡
        const dateHidden = dateRect.bottom > searchRect.top;
        // 检测时间是否被搜索框遮挡
        const timeHidden = timeRect.bottom > searchRect.top;

        if (dateHidden) {
            dateDisplay.style.visibility = 'hidden';
            dateDisplay.style.position = 'absolute';
        } else {
            dateDisplay.style.visibility = '';
            dateDisplay.style.position = '';
        }

        if (timeHidden) {
            timeDisplay.style.visibility = 'hidden';
            timeDisplay.style.position = 'absolute';
        } else {
            timeDisplay.style.visibility = '';
            timeDisplay.style.position = '';
        }
    }

    // 恢复被隐藏的日期和时间
    function restoreDateTime() {
        const timeDisplay = document.querySelector('.time-display');
        const dateDisplay = document.querySelector('.date-display');

        if (timeDisplay) {
            timeDisplay.style.visibility = '';
            timeDisplay.style.position = '';
        }
        if (dateDisplay) {
            dateDisplay.style.visibility = '';
            dateDisplay.style.position = '';
        }
    }

    // 移动端：设置容器位置
    function setMobileContainerPosition() {
        if (isMobile()) {
            // 手机端：需要自适应输入法
            const viewportHeight = window.innerHeight;
            const timeDisplay = document.querySelector('.time-display');
            const dateDisplay = document.querySelector('.date-display');
            const searchBoxesContainer = document.querySelector('.search-boxes-container');

            const timeHeight = timeDisplay.offsetHeight + (dateDisplay ? dateDisplay.offsetHeight : 0);
            const searchHeight = searchBoxesContainer.offsetHeight;

            // 检查是否有输入法键盘弹出 - 使用更可靠的检测方法
            // 方法1：如果visualViewport高度小于window高度，说明键盘弹出
            const visualViewportHeight = window.visualViewport ? window.visualViewport.height : viewportHeight;
            const isKeyboardOpen = visualViewportHeight < viewportHeight - 50 || window.innerHeight < screen.height * 0.5;

            // 如果当前页面已经有输入框聚焦，才检测键盘弹出
            const activeElement = document.activeElement;
            const isInputFocused = activeElement && (activeElement.tagName === 'INPUT' || activeElement.tagName === 'TEXTAREA');

            // 只有在输入框聚焦时才检测键盘弹出状态
            const shouldDetectKeyboard = isInputFocused && isKeyboardOpen;

            if (shouldDetectKeyboard) {
                // 输入法弹出时，将时间日期上移到顶端
                timeDate.style.position = 'absolute';
                timeDate.style.top = '20px';
                timeDate.style.left = '50%';
                timeDate.style.transform = 'translateX(-50%)';
                timeDate.style.marginBottom = '0';

                searchBox.style.position = 'absolute';
                searchBox.style.top = `${timeHeight + 40}px`;
                searchBox.style.left = '50%';
                searchBox.style.transform = 'translateX(-50%)';

                // 检测遮挡并处理
                setTimeout(() => handleOcclusion(), 100);
            } else {
                // 正常状态，居中显示
                timeDate.style.position = 'relative';
                timeDate.style.top = '';
                timeDate.style.left = '';
                timeDate.style.transform = '';
                timeDate.style.marginBottom = '40px';

                searchBox.style.position = 'relative';
                searchBox.style.top = '';
                searchBox.style.left = '';
                searchBox.style.transform = '';

                // 恢复日期和时间显示
                restoreDateTime();
            }
        } else if (isTablet()) {
            // 平板端：使用更大的布局，不使用绝对定位（输入法情况除外）
            const viewportHeight = window.innerHeight;
            const isKeyboardOpen = viewportHeight < (window.visualViewport?.height || Infinity) || 
                                    viewportHeight < window.screen.height * 0.5;

            if (isKeyboardOpen) {
                // 输入法弹出时上移
                timeDate.style.position = 'absolute';
                timeDate.style.top = '30px';
                timeDate.style.left = '50%';
                timeDate.style.transform = 'translateX(-50%)';
                timeDate.style.marginBottom = '0';

                searchBox.style.position = 'absolute';
                searchBox.style.top = '';
                searchBox.style.bottom = '';
                searchBox.style.left = '50%';
                searchBox.style.transform = 'translateX(-50%)';

                // 检测遮挡并处理
                setTimeout(() => handleOcclusion(), 100);
            } else {
                // 正常状态
                timeDate.style.position = 'relative';
                timeDate.style.top = '';
                timeDate.style.left = '';
                timeDate.style.transform = '';
                timeDate.style.marginBottom = '60px';

                searchBox.style.position = 'relative';
                searchBox.style.top = '';
                searchBox.style.left = '';
                searchBox.style.transform = '';

                // 恢复日期和时间显示
                restoreDateTime();
            }
        } else {
            // 桌面端和大屏平板：使用输入法自适应
            setDesktopInputMethodPosition();
        }
    }

    // 监听输入框焦点事件，处理输入法弹出
    function setupInputMethodHandlers() {
        const allInputs = document.querySelectorAll('input[type="text"]');

        allInputs.forEach(input => {
            // 输入框聚焦时（输入法弹出）
            input.addEventListener('focus', function() {
                setTimeout(() => {
                    if (isMobile()) {
                        setMobileContainerPosition();
                    } else {
                        setDesktopInputMethodPosition();
                    }
                }, 300);
            });

            // 输入框失焦时（输入法收起）
            input.addEventListener('blur', function() {
                setTimeout(() => {
                    if (isMobile()) {
                        setMobileContainerPosition();
                    } else {
                        // 桌面端直接还原页面位置
                        resetPagePosition();
                    }
                }, 100);
            });
        });
    }

    // 监听视口变化（输入法弹出/收起）
    function setupViewportHandler() {
        if (window.visualViewport) {
            window.visualViewport.addEventListener('resize', function() {
                if (isMobile()) {
                    setMobileContainerPosition();
                } else {
                    setDesktopInputMethodPosition();
                }
            });
        }

        // 备用方案：监听window resize
        window.addEventListener('resize', function() {
            if (isMobile()) {
                setMobileContainerPosition();
            } else {
                setDesktopInputMethodPosition();
            }
        });
    }

    // 移动端：设置布局类
    function setMobileLayout(expandedBox) {
        if (!isMobile()) return;

        // 移除所有布局类
        searchBoxesContainer.classList.remove('left-expanded', 'center-expanded', 'right-expanded');

        if (!expandedBox) return;

        // 根据展开的搜索框设置布局类
        if (expandedBox.classList.contains('left-circle')) {
            searchBoxesContainer.classList.add('left-expanded');
        } else if (expandedBox.classList.contains('center-0')) {
            searchBoxesContainer.classList.add('center-expanded');
        } else if (expandedBox.classList.contains('right-circle')) {
            searchBoxesContainer.classList.add('right-expanded');
        }
    }

    // 移动端：设置搜索框宽度
    function setMobileSearchWidth() {
        if (!isMobile()) return;

        // 获取实际视口宽度，减去40px（左右各20px边距）
        const viewportWidth = window.innerWidth;
        const searchWidth = Math.min(viewportWidth - 40, 350);

        // 设置CSS变量
        document.documentElement.style.setProperty('--mobile-search-width', `${searchWidth}px`);
    }

    // 桌面端和大屏平板：输入法抬升页面
    function setDesktopInputMethodPosition() {
        // 仅在非手机端执行
        if (isMobile()) return;

        const viewportHeight = window.innerHeight;
        const visualViewportHeight = window.visualViewport?.height || viewportHeight;

        // 检测输入法是否弹出的更准确方法
        // 当输入法弹出时，innerHeight 会小于 visualViewport.height（某些浏览器）
        // 或者 innerHeight 会明显小于屏幕高度的一半
        const isKeyboardOpen = viewportHeight < visualViewportHeight * 0.9 || 
                                viewportHeight < window.screen.height * 0.5;

        if (isKeyboardOpen) {
            // 输入法弹出时，将时间日期上移到顶端
            timeDate.style.position = 'absolute';
            timeDate.style.top = '30px';
            timeDate.style.left = '50%';
            timeDate.style.transform = 'translateX(-50%)';
            timeDate.style.marginBottom = '0';

            // 搜索框跟随移动
            searchBox.style.position = 'absolute';
            searchBox.style.top = '';
            searchBox.style.bottom = '';
            searchBox.style.left = '50%';
            searchBox.style.transform = 'translateX(-50%)';

            // 检测遮挡并处理
            setTimeout(() => handleOcclusion(), 100);
        } else {
            // 正常状态，恢复默认样式
            timeDate.style.position = '';
            timeDate.style.top = '';
            timeDate.style.left = '';
            timeDate.style.transform = '';
            timeDate.style.marginBottom = '';

            searchBox.style.position = '';
            searchBox.style.top = '';
            searchBox.style.bottom = '';
            searchBox.style.left = '';
            searchBox.style.transform = '';

            // 恢复日期和时间显示
            restoreDateTime();
        }
    }

    // 强制还原页面位置到默认状态
    function resetPagePosition() {
        timeDate.style.position = '';
        timeDate.style.top = '';
        timeDate.style.left = '';
        timeDate.style.transform = '';
        timeDate.style.marginBottom = '';

        searchBox.style.position = '';
        searchBox.style.top = '';
        searchBox.style.bottom = '';
        searchBox.style.left = '';
        searchBox.style.transform = '';

        // 恢复日期和时间显示
        restoreDateTime();
    }

    // 窗口大小变化时处理
    window.addEventListener('resize', function() {
        if (isMobile()) {
            // 移动端自适应位置
            setMobileContainerPosition();
            // 重新计算搜索框宽度
            setMobileSearchWidth();
        } else {
            // 桌面端和大屏平板：恢复布局类并设置输入法位置
            searchBoxesContainer.classList.remove('left-expanded', 'center-expanded', 'right-expanded');
            setDesktopInputMethodPosition();
        }
    });
    
    // 圆形搜索框点击展开逻辑
    circleSearchBoxes.forEach(box => {
        const circleInput = box.querySelector('.circle-search-input');
        const circleBtn = box.querySelector('.circle-search-btn');

        // 点击圆形搜索框展开
        box.addEventListener('click', function(e) {
            // 桌面端使用快速切换逻辑
            if (!isMobile()) {
                // 如果是同一个搜索框，直接聚焦
                if (currentExpandedBox === box || currentUninputExpandedBox === box) {
                    circleInput.focus();
                    return;
                }
                // 快速切换到新搜索框
                switchToBoxDesktop(box);
                return;
            }

            // 移动端逻辑保持原样
            // 如果当前已经有展开的搜索框且不是当前点击的，则先关闭它
            if (currentExpandedBox && currentExpandedBox !== box) {
                collapseSearchBox(currentExpandedBox);
                currentExpandedBox = null;
                currentUninputExpandedBox = null;
                setMobileLayout(null);
            }

            // 如果当前有未输入展开状态的搜索框且不是当前点击的，则先关闭它
            if (currentUninputExpandedBox && currentUninputExpandedBox !== box) {
                if (currentUninputExpandedBox.classList.contains('expanded')) {
                    collapseSearchBox(currentUninputExpandedBox);
                }
                currentUninputExpandedBox = null;
            }

            // 切换当前搜索框的展开状态
            if (box.classList.contains('expanded')) {
                // 如果已经有内容，则聚焦到输入框
                if (circleInput.value.trim() !== '') {
                    box.classList.add('input-active');
                    currentExpandedBox = box;
                    currentUninputExpandedBox = box;
                    circleInput.focus(); // 聚焦到输入框，继续输入
                } else {
                    // 如果输入框为空且处于展开状态，保持展开状态不变
                    // 不收缩搜索框，让用户可以继续输入
                    // 只聚焦到输入框
                    circleInput.focus();
                }
            } else {
                // 检查中间搜索框是否展开，如果是则收缩它
                const centerBox = document.querySelector('.center-0');
                if (centerBox.classList.contains('expanded') && centerBox !== box) {
                    collapseSearchBox(centerBox);
                    currentUninputExpandedBox = null;
                    setMobileLayout(null);
                }

                // 展开当前搜索框
                expandSearchBox(box);
                currentExpandedBox = box;
                currentUninputExpandedBox = box;

                // 移动端设置3排布局
                setMobileLayout(box);
            }
        });
        
        // 圆形搜索框输入框聚焦事件
        circleInput.addEventListener('focus', function() {
            // 重新触发动画
            const nameEl = box.querySelector('.search-engine-name');
            if (nameEl) {
                nameEl.style.animation = 'none';
                nameEl.offsetHeight; // 触发重绘
                nameEl.style.animation = '';
            }

            // 显示搜索历史下拉列表
            showSearchHistory(this);
            
            // 桌面端使用快速切换逻辑
            if (!isMobile()) {
                // 如果搜索框未展开，快速展开并切换
                if (!box.classList.contains('expanded')) {
                    switchToBoxDesktop(box);
                } else {
                    // 已展开则确保状态正确
                    box.classList.add('input-active');
                    currentExpandedBox = box;
                    currentUninputExpandedBox = box;
                }
                return;
            }

            // 移动端逻辑保持原样
            // 确保当前搜索框处于正确的展开状态和布局中
            if (!box.classList.contains('expanded')) {
                // 如果点击的是输入框且搜索框未展开，则展开它
                if (currentExpandedBox && currentExpandedBox !== box) {
                    collapseSearchBox(currentExpandedBox);
                    currentExpandedBox = null;
                    currentUninputExpandedBox = null;
                    setMobileLayout(null);
                }

                // 检查中间搜索框是否展开，如果是则收缩它
                const centerBox = document.querySelector('.center-0');
                if (centerBox.classList.contains('expanded') && centerBox !== box) {
                    collapseSearchBox(centerBox);
                    currentUninputExpandedBox = null;
                    setMobileLayout(null);
                }

                expandSearchBox(box);
                currentExpandedBox = box;
                currentUninputExpandedBox = box;

                // 移动端设置3排布局
                setMobileLayout(box);
            } else {
                // 如果已经展开，确保移动端布局正确设置
                if (isMobile()) {
                    setMobileLayout(box);
                }
                // 确保状态正确
                currentUninputExpandedBox = box;
                currentExpandedBox = box;
            }

            // 添加输入状态样式
            box.classList.add('input-active');
        });
        
        // 圆形搜索框输入事件
        circleInput.addEventListener('input', function() {
            if (circleInput.value.trim() !== '') {
                box.classList.add('input-active');
            } else {
                // 只有当焦点不在输入框上时，才移除 input-active 状态
                if (document.activeElement !== circleInput) {
                    box.classList.remove('input-active');
                }
            }
        });
        
        // 圆形搜索框输入框失焦事件
        circleInput.addEventListener('blur', function(e) {
            // 记录当前失焦的输入框和相关的按钮
            const blurInput = this;
            const relatedBtn = circleBtn;
            const box = this.closest('.search-box-circle');
            
            setTimeout(() => {
                // 如果当前焦点在同一个搜索框的按钮上，保持状态不变
                if (relatedBtn && (document.activeElement === relatedBtn || relatedBtn.contains(document.activeElement))) {
                    return;
                }
                
                // 如果焦点在同一个输入框上，保持状态不变
                if (document.activeElement === blurInput) {
                    return;
                }

                // 检查焦点是否在历史记录面板内，或最近点击是否在搜索框/历史记录面板内
                if (box) {
                    const historyDropdown = box.querySelector('.search-history-dropdown');
                    const isFocusInDropdown = historyDropdown && historyDropdown.contains(document.activeElement);
                    // 检查最近点击的目标是否在搜索框或历史记录面板内
                    const isClickInSearchBox = lastClickTarget && box.contains(lastClickTarget);
                    const isClickInDropdown = historyDropdown && lastClickTarget && 
                        (historyDropdown.contains(lastClickTarget) || lastClickTarget.closest('.search-history-toggle, .search-history-item, .search-history-clear'));

                    if (isFocusInDropdown || isClickInDropdown || isClickInSearchBox) {
                        return;
                    }
                    // 隐藏搜索历史下拉列表
                    if (historyDropdown) {
                        historyDropdown.style.display = 'none';
                    }
                }
                
                // 如果当前展开的搜索框还是同一个，不重置
                if (currentExpandedBox === box || currentUninputExpandedBox === box) {
                    // 只移除input-active样式，保持expanded状态
                    box.classList.remove('input-active');
                    currentExpandedBox = null;
                    // currentUninputExpandedBox 保持不变，保留展开状态
                }
            }, 150);
        });
        
        // 圆形搜索框按钮点击事件
        circleBtn.addEventListener('click', function(e) {
            e.stopPropagation();

            // 桌面端使用独立方法
            if (!isMobile()) {
                if (!box.classList.contains('expanded')) {
                    expandSearchBoxDesktop(box);
                } else {
                    box.classList.add('input-active');
                    currentExpandedBox = box;
                    currentUninputExpandedBox = box;
                }
            } else {
                // 移动端保持原有逻辑
                // 确保当前搜索框保持展开状态
                if (!box.classList.contains('expanded')) {
                    expandSearchBox(box);
                }
                // 确保状态正确
                box.classList.add('input-active');
                currentExpandedBox = box;
                currentUninputExpandedBox = box;
            }

            // 聚焦到输入框
            const input = box.querySelector('.circle-search-input');
            input.focus();

            // 执行搜索逻辑
            const query = input.value.trim();
            const engineId = box.getAttribute('data-engine-id');
            
            // 检查是否开启历史记录，并添加搜索历史
            const historySettings = loadHistorySettings();
            if (historySettings.searchHistoryRecording !== false && query) {
                addSearchHistory(query, engineId);
            }

            const searchUrl = getSearchUrl(engineId, query);

            // 搜索后清空输入框，但保持展开状态
            input.value = '';
            box.classList.remove('input-active');

            // 打开搜索页面
            if (searchUrl) {
                window.open(searchUrl, '_blank');
            }
        });
        
        // 圆形搜索框输入框回车事件（使用 keydown 替代已废弃的 keypress）
        circleInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                performCircleSearch(box);
            }
        });
        
        // 圆形搜索框输入框键盘导航事件（历史记录上下选择）
        circleInput.addEventListener('keydown', function(e) {
            const input = this;
            const dropdown = box.querySelector('.search-history-dropdown');
            const listContainer = dropdown ? dropdown.querySelector('.search-history-list') : null;
            
            // 获取当前历史记录列表
            if (!listContainer || listContainer.children.length === 0) {
                // 没有历史记录时重置导航状态
                historyNavigationState.currentIndex = -1;
                historyNavigationState.filledQuery = '';
                historyNavigationState.isNavigating = false;
                return;
            }
            
            const items = listContainer.querySelectorAll('.search-history-item');
            
            // ESC：清空输入框，取消填充
            if (e.key === 'Escape') {
                e.preventDefault();
                input.value = '';
                // 移除所有高亮
                items.forEach(item => item.classList.remove('highlighted'));
                // 重置导航状态
                historyNavigationState.currentIndex = -1;
                historyNavigationState.filledQuery = '';
                historyNavigationState.isNavigating = false;
                return;
            }
            
            // 上箭头：选择上一条
            if (e.key === 'ArrowUp') {
                e.preventDefault();
                
                // 如果没有历史记录，不做任何操作
                if (items.length === 0) return;
                
                // 移除当前高亮
                items.forEach(item => item.classList.remove('highlighted'));
                
                // 计算新索引
                if (historyNavigationState.currentIndex <= 0) {
                    historyNavigationState.currentIndex = items.length - 1;
                } else {
                    historyNavigationState.currentIndex--;
                }
                
                // 高亮新项并填充到输入框
                const newIndex = historyNavigationState.currentIndex;
                const selectedItem = items[newIndex];
                if (selectedItem) {
                    selectedItem.classList.add('highlighted');
                    const query = selectedItem.dataset.query;
                    input.value = query;
                    historyNavigationState.filledQuery = query;
                    historyNavigationState.isNavigating = true;
                    
                    // 确保选中项可见
                    selectedItem.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
                }
                return;
            }
            
            // 下箭头：选择下一条
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                
                // 如果没有历史记录，不做任何操作
                if (items.length === 0) return;
                
                // 移除当前高亮
                items.forEach(item => item.classList.remove('highlighted'));
                
                // 计算新索引
                if (historyNavigationState.currentIndex >= items.length - 1 || historyNavigationState.currentIndex === -1) {
                    historyNavigationState.currentIndex = 0;
                } else {
                    historyNavigationState.currentIndex++;
                }
                
                // 高亮新项并填充到输入框
                const newIndex = historyNavigationState.currentIndex;
                const selectedItem = items[newIndex];
                if (selectedItem) {
                    selectedItem.classList.add('highlighted');
                    const query = selectedItem.dataset.query;
                    input.value = query;
                    historyNavigationState.filledQuery = query;
                    historyNavigationState.isNavigating = true;
                    
                    // 确保选中项可见
                    selectedItem.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
                }
                return;
            }
            
            // 左/右方向键：移除高亮状态
            if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
                items.forEach(item => item.classList.remove('highlighted'));
                historyNavigationState.currentIndex = -1;
                historyNavigationState.isNavigating = false;
                return;
            }
            
            // 其他按键（普通输入）：移除高亮状态
            items.forEach(item => item.classList.remove('highlighted'));
            historyNavigationState.currentIndex = -1;
            historyNavigationState.isNavigating = false;
        });
        
        // 监听输入事件，当用户开始输入时移除高亮
        circleInput.addEventListener('input', function() {
            const dropdown = box.querySelector('.search-history-dropdown');
            const listContainer = dropdown ? dropdown.querySelector('.search-history-list') : null;
            
            if (listContainer) {
                const items = listContainer.querySelectorAll('.search-history-item');
                items.forEach(item => item.classList.remove('highlighted'));
            }
            
            // 重置导航状态
            historyNavigationState.currentIndex = -1;
            historyNavigationState.isNavigating = false;
        });
    });
    
    // 展开圆形搜索框
    function expandSearchBox(box) {
        box.classList.add('expanded');
        // 移动端直接进入输入展开状态
        if (isMobile()) {
            box.classList.add('input-active');
            // 设置搜索框宽度
            setMobileSearchWidth();
        }
        currentUninputExpandedBox = box;
        // 移动端重新计算位置
        setMobileContainerPosition();
        // 聚焦到输入框并启用背景模糊
        const input = box.querySelector('.circle-search-input');
        setTimeout(() => {
            input.focus();
            setBackgroundBlur(true);
        }, 300);
    }
    
    // 收缩圆形搜索框（保留输入文字）
    function collapseSearchBox(box) {
        box.classList.remove('expanded', 'input-active');
        if (currentUninputExpandedBox === box) {
            currentUninputExpandedBox = null;
        }
        // 移动端重新计算位置
        setMobileContainerPosition();
        // 移除背景模糊
        setBackgroundBlur(false);
        // 不再清空输入框，保留用户输入的文字
    }

    // 桌面端：展开圆形搜索框（不调用移动端位置计算）
    function expandSearchBoxDesktop(box) {
        box.classList.add('expanded');
        box.classList.add('input-active');
        currentUninputExpandedBox = box;
        currentExpandedBox = box;
        // 聚焦到输入框并启用背景模糊
        const input = box.querySelector('.circle-search-input');
        setTimeout(() => {
            input.focus();
            setBackgroundBlur(true);
        }, 100);
    }

    // 桌面端：收缩圆形搜索框（不调用移动端位置计算）
    function collapseSearchBoxDesktop(box) {
        box.classList.remove('expanded', 'input-active');
        if (currentUninputExpandedBox === box) {
            currentUninputExpandedBox = null;
        }
        if (currentExpandedBox === box) {
            currentExpandedBox = null;
        }
        // 移除背景模糊
        setBackgroundBlur(false);
    }

    // 桌面端：快速切换到新的搜索框（直接展开新框，不等待旧框收缩）
    function switchToBoxDesktop(newBox) {
        // 先直接关闭之前展开的搜索框（不等待动画）
        if (currentExpandedBox && currentExpandedBox !== newBox) {
            collapseSearchBoxDesktop(currentExpandedBox);
        }
        if (currentUninputExpandedBox && currentUninputExpandedBox !== newBox) {
            collapseSearchBoxDesktop(currentUninputExpandedBox);
        }
        // 直接展开新搜索框
        expandSearchBoxDesktop(newBox);
    }

    // 执行圆形搜索框的搜索
    function performCircleSearch(box) {
        const input = box.querySelector('.circle-search-input');
        const query = input.value.trim();
        const engineId = box.getAttribute('data-engine-id');

        // 检查是否开启历史记录
        const historySettings = loadHistorySettings();
        if (historySettings.searchHistoryRecording !== false) {
            addSearchHistory(query, engineId).then(() => {
                // 搜索后刷新当前打开的搜索历史列表
                const input = box.querySelector('.circle-search-input');
                if (input) {
                    showSearchHistory(input);
                }
            });
        }

        const searchUrl = getSearchUrl(engineId, query);

        // 搜索发起后清空输入框内容
        input.value = '';
        box.classList.remove('input-active');

        // 打开搜索页面
        if (searchUrl) {
            window.open(searchUrl, '_blank');
        }
    }
    
    // 展开中间搜索框
    function expandCenterSearchBox() {
        centerSearchBox.classList.add('expanded');
        // 移动端重新计算位置
        setMobileContainerPosition();
        // 聚焦到输入框
        setTimeout(() => {
            centerSearchBox.querySelector('.circle-search-input').focus();
        }, 300);
    }

    // 收缩中间搜索框
    function collapseCenterSearchBox() {
        collapseSearchBox(centerSearchBox);
    }
    
    
    
    // 时间日期模块点击事件 - 打开快捷访问菜单
    const timeDisplay = document.querySelector('.time-display');
    const dateDisplay = document.querySelector('.date-display');

    function openContextMenu(e) {
        e.stopPropagation();

        // 隐藏移动端历史记录菜单
        const mobileDropdown = document.querySelector('.search-history-mobile-dropdown');
        if (mobileDropdown) {
            mobileDropdown.classList.remove('active');
        }

        const searchBoxContainer = document.querySelector('.search-boxes-container');
        searchBoxContainer.style.opacity = '0';
        searchBoxContainer.style.visibility = 'hidden';

        // 获取搜索框容器位置
        const searchBoxRect = searchBoxContainer.getBoundingClientRect();

        // 设置菜单项的margin-top与搜索框顶端对齐
        document.documentElement.style.setProperty('--search-box-top', `${searchBoxRect.top}px`);

        // contextMenu覆盖整个页面，menu-items通过margin-top向下偏移
        contextMenu.classList.add('active');
        setBackgroundBlur(true); // 启用背景模糊
        if (settings) {
            settings.style.display = 'block';
            // 调整通知位置，避让settings
            const notices = document.getElementById('notices');
            if (notices && window.innerWidth > 768) {
                const settingsHeight = settings.offsetHeight;
                notices.style.top = (20 + settingsHeight + 10) + 'px'; // 20px + settings高度 + 10px间距
            }
        }
    }

    // timeDate 点击打开/关闭快捷访问
    timeDate.addEventListener('click', function(e) {
        if (contextMenu.classList.contains('active')) {
            // 如果菜单已打开，关闭它
            contextMenu.classList.remove('active');
            document.documentElement.style.removeProperty('--search-box-top');
            setBackgroundBlur(false); // 移除背景模糊
            const searchBox = document.querySelector('.search-boxes-container');
            searchBox.style.opacity = '1';
            searchBox.style.visibility = 'visible';
            if (settings) settings.style.display = 'none';
            // 恢复通知位置
            const notices = document.getElementById('notices');
            if (notices) notices.style.top = '20px';
        } else {
            // 如果菜单未打开，打开它
            openContextMenu(e);
        }
    });

    // 添加时钟功能
    function updateClock() {
        const now = new Date();
        const timeString = now.toLocaleTimeString('zh-CN', { hour12: false });
        
        // 获取年月日
        const year = now.getFullYear();
        const month = String(now.getMonth() + 1).padStart(2, '0');
        const day = String(now.getDate()).padStart(2, '0');
        
        // 获取星期
        const weekdays = ['星期日', '星期一', '星期二', '星期三', '星期四', '星期五', '星期六'];
        const weekday = weekdays[now.getDay()];
        
        // 计算周数
        const weekNumber = getWeekNumber(now);
        
        // 格式化日期字符串
        const dateString = `${year}年${month}月${day}日 ${weekday} 第${weekNumber}周`;
        
        document.getElementById('time').textContent = timeString;
        document.getElementById('date').textContent = dateString;
    }
    
    // 初始化时钟并设置更新
    updateClock();
    setInterval(updateClock, 1000);
    
    // 计算当前是第几周
    function getWeekNumber(date) {
        const firstDayOfYear = new Date(date.getFullYear(), 0, 1);
        const pastDaysOfYear = (date.getTime() - firstDayOfYear.getTime()) / 86400000;
        return Math.ceil((pastDaysOfYear + firstDayOfYear.getDay() + 1) / 7);
    }
    
    // 右键菜单功能 - 快捷访问
    
    // 显示右键菜单（快捷访问）- 在搜索框区域显示
    document.addEventListener('contextmenu', function(e) {
        // 如果右键点击在输入框中，不阻止默认的浏览器右键菜单
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
            return;
        }
        
        e.preventDefault();
        
        // 隐藏移动端历史记录菜单
        const mobileDropdown = document.querySelector('.search-history-mobile-dropdown');
        if (mobileDropdown) {
            mobileDropdown.classList.remove('active');
        }
        
        // 隐藏搜索框部分，但保留时间日期
        const searchBox = document.querySelector('.search-boxes-container');
        searchBox.style.opacity = '0';
        searchBox.style.visibility = 'hidden';
        
        // 获取搜索框容器位置
        const searchBoxRect = searchBox.getBoundingClientRect();
        
        // 设置菜单项的margin-top与搜索框顶端对齐
        document.documentElement.style.setProperty('--search-box-top', `${searchBoxRect.top}px`);
        
        // 显示菜单
        contextMenu.classList.add('active');
        setBackgroundBlur(true); // 启用背景模糊
        
        if (settings) {
            settings.style.display = 'block';
            // 调整通知位置，避让settings
            const notices = document.getElementById('notices');
            if (notices && window.innerWidth > 768) {
                const settingsHeight = settings.offsetHeight;
                notices.style.top = (20 + settingsHeight + 10) + 'px';
            }
        }
    });
    
    // 点击快捷访问面板外空白区域关闭菜单
    document.addEventListener('click', function(e) {
        if (contextMenu.classList.contains('active') && 
            !e.target.closest('.menu-items') &&
            !e.target.closest('.settings-modal') &&
            !e.target.closest('.settings-button') &&
            !e.target.closest('.settings-dropdown') &&
            !e.target.closest('#settings-close') &&
            !e.target.closest('#add-shortcut-panel') &&
            !e.target.closest('#search-engine-panel') &&
            !e.target.closest('#add-search-engine-panel') &&
            !e.target.closest('.search-engine-move-up') &&
            !e.target.closest('.search-engine-move-down') &&
            !e.target.closest('.search-engine-disable') &&
            !e.target.closest('.search-engine-enable') &&
            !e.target.closest('.search-engine-delete') &&
            !e.target.closest('.confirm-dialog') &&
            !e.target.closest('.confirm-dialog-overlay') &&
            !e.target.closest('#notices')) {
            // 检查搜索引擎面板是否有未保存的更改
            if (searchEnginePanel && searchEnginePanel.classList.contains('active')) {
                const workingSettings = searchEngineSettingsWorking || searchEngineSettings;
                const hasChanges = JSON.stringify(workingSettings) !== JSON.stringify(searchEngineSettings);
                if (hasChanges) {
                    openConfirmDialog('discard-search-engine-changes');
                    return; // 不执行关闭操作，等待用户确认
                }
            }
            contextMenu.classList.remove('active');
            document.documentElement.style.removeProperty('--search-box-top');
            setBackgroundBlur(false); // 移除背景模糊
            // 重新显示搜索框
            const searchBox = document.querySelector('.search-boxes-container');
            searchBox.style.opacity = '1';
            searchBox.style.visibility = 'visible';
            if (settings) settings.style.display = 'none';
            closeSettingsDropdown();
            // 恢复通知位置
            const notices = document.getElementById('notices');
            if (notices) notices.style.top = '20px';
        }
    });
    
    // 添加自定义书签功能
    function addBookmark(name, url, icon = '🌐') {
        const customBookmarks = JSON.parse(localStorage.getItem('customBookmarks')) || [];
        customBookmarks.push({ name, url, icon });
        localStorage.setItem('customBookmarks', JSON.stringify(customBookmarks));
    }
    
    // 在菜单中添加自定义书签
    function updateContextMenu() {
        const menuItemsContainer = document.querySelector('.menu-items');
        const customBookmarks = JSON.parse(localStorage.getItem('customBookmarks')) || [];
        
        // 清空自定义书签（保留固定的）
        const fixedItems = Array.from(menuItemsContainer.children); // 获取所有现有项目，包括我们新添加的
        menuItemsContainer.innerHTML = '';
        
        // 添加固定书签
        fixedItems.forEach(item => {
            menuItemsContainer.appendChild(item.cloneNode(true));
        });
        
        // 添加自定义书签
        customBookmarks.forEach(bookmark => {
            const customItem = document.createElement('div');
            customItem.className = 'menu-item';
            customItem.setAttribute('data-url', bookmark.url);
            customItem.innerHTML = `
                <div class="menu-item-area">
                    <div class="menu-icon-wrapper">
                        <div class="menu-item-bg"></div>
                    </div>
                    <div class="menu-text">${Security.sanitizeXss(bookmark.name)}</div>
                </div>
            `;
            
            // 获取点击区域元素
            const menuBg = customItem.querySelector('.menu-item-bg');
            const menuText = customItem.querySelector('.menu-text');
            
            // 点击背景板或文字跳转
            function handleCustomItemClick(e) {
                e.preventDefault();
                e.stopPropagation();
                window.open(bookmark.url, '_blank');
                contextMenu.classList.remove('active');
                document.documentElement.style.removeProperty('--search-box-top');
                setBackgroundBlur(false);
                if (settings) settings.style.display = 'none';
                // 恢复通知位置
                const notices = document.getElementById('notices');
                if (notices) notices.style.top = '20px';
            }
            
            menuBg.addEventListener('click', handleCustomItemClick);
            menuText.addEventListener('click', handleCustomItemClick);
            
            menuItemsContainer.appendChild(customItem);
        });
    }
    
    // 更新菜单以包含自定义书签
    updateContextMenu();

    // 初始化移动端位置和搜索框宽度
    setMobileContainerPosition();
    setMobileSearchWidth();

    // 延迟再次调用以确保DOM完全渲染后位置正确（修复刷新时位置不正确的问题）
    setTimeout(() => {
        setMobileContainerPosition();
    }, 100);

    // 设置输入法自适应处理
    setupInputMethodHandlers();
    setupViewportHandler();

    // 共享的壁纸XML加载函数（避免重复请求）
    let wallpaperXmlLoaded = false;
    let wallpaperXmlDoc = null;
    let wallpaperXmlPromise = null; // Promise 锁，防止并发请求
    async function loadWallpaperXml() {
        if (wallpaperXmlLoaded && wallpaperXmlDoc) return wallpaperXmlDoc;

        // 如果已有请求在進行中，等待它完成
        if (wallpaperXmlPromise) return wallpaperXmlPromise;

        wallpaperXmlPromise = (async () => {
            try {
                const response = await fetch('wallpaper.xml');
                if (!response.ok) throw new Error('加载壁纸XML失败');
                const text = await response.text();
                const parser = new DOMParser();
                wallpaperXmlDoc = parser.parseFromString(text, 'text/xml');
                wallpaperXmlLoaded = true;
                return wallpaperXmlDoc;
            } catch (e) {
                console.error('加载壁纸XML失败:', e);
                return null;
            } finally {
                wallpaperXmlPromise = null; // 请求完成后重置
            }
        })();

        return wallpaperXmlPromise;
    }

    // 动态加载壁纸（仅在未设置壁纸时加载默认壁纸）
    async function loadWallpaper() {
        // 检查是否已有用户设置
        const saved = getLocalStorageItem('wallpaper_settings');
        if (saved) {
            return;
        }

        const xmlDoc = await loadWallpaperXml();
        if (!xmlDoc) {
            networkTimeoutNotice('加载壁纸XML失败');
            return;
        }

        const wpElement = xmlDoc.querySelector('wallpaper[id="1"]');
        if (!wpElement) {
            networkTimeoutNotice('未找到默认壁纸');
            return;
        }

        const wallpaperUrl = wpElement.querySelector('url')?.textContent;
        if (!wallpaperUrl) {
            networkTimeoutNotice('默认壁纸URL无效');
            return;
        }

        // 加载壁纸
        const img = new Image();
        img.onload = function() {
            document.documentElement.style.setProperty('--wallpaper-url', `url('${wallpaperUrl}')`);
        };
        img.onerror = function() {
            networkTimeoutNotice('壁纸加载失败');
        };
        img.src = wallpaperUrl;
    }

    // 启动壁纸加载
    loadWallpaper();

    // 通知呈现器
    const noticesContainer = document.getElementById('notices');

    // 通知全局配置
    const noticeConfig = {
        enabled: true  // 是否在页面上显示通知，false则只输出console.log
    };

    // 通知等级配置
    const NOTICE_LEVELS = {
        fatal: { color: '#f7a699', duration: 60000 },
        error: { color: '#ffccbb', duration: 50000 },
        warn: { color: '#ffeecc', duration: 40000 },
        info: { color: '#2196F3', duration: 11000 },
        debug: { color: '#eee9e0', duration: 20000 }
    };

    // 移除通知（带淡出动画）
    function removeNotice(notice) {
        notice.classList.add('removing');
        setTimeout(() => {
            notice.remove();
        }, 300);
    }

    // 获取格式化时间
    function getTimeString() {
        const now = new Date();
        return now.toLocaleTimeString('zh-CN', { hour12: false });
    }

    /**
     * 发送通知
     * @param {string} content - 通知内容
     * @param {string} level - 通知等级: fatal, error, warns, info, debug
     * @param {Object} options - 可选配置: customColor(自定义颜色), customDuration(自定义持续时间ms), showOnPage(是否在页面显示，默认为true)
     */
    function sendNotice(content, level = 'info', options = {}) {
        const config = NOTICE_LEVELS[level] || NOTICE_LEVELS.info;
        const color = options.customColor || config.color;
        const duration = options.customDuration !== undefined ? options.customDuration : config.duration;
        const showOnPage = options.showOnPage !== false && noticeConfig.enabled;  // 默认为true，受全局配置影响

        // 使用Security模块净化内容
        const sanitizedContent = Security.sanitizeNotice(content);
        const plainText = sanitizedContent.replace(/<[^>]*>/g, '');
        console.log(`[${getTimeString()}][${level.toUpperCase()}]${plainText}`);

        // 如果不显示在页面上，直接返回
        if (!showOnPage) {
            return;
        }

        // 创建通知元素
        const notice = document.createElement('div');
        notice.className = 'notice-item';
        notice.style.backgroundColor = color;
        // 使用Security模块的安全方式设置innerHTML
        notice.innerHTML = `
            <div class="notice-title">${level.toUpperCase()}</div>
            <div class="notice-content">${sanitizedContent}</div>
        `;

        // 点击移除通知
        notice.addEventListener('click', function() {
            removeNotice(notice);
        });

        // 使用 prepend 让新通知显示在左侧/顶部
        noticesContainer.prepend(notice);

        // 自动移除
        setTimeout(() => {
            if (notice.parentNode) {
                removeNotice(notice);
            }
        }, duration);
    }

    // GPLv3许可证提示
    function gplNotice() {
        sendNotice('检测到按下开发工具热键<br>请遵守<strong>GPLv3</strong>许可协议', 'info', { customDuration: 8000 });
    }

    // 壁纸/网络连接超时通知（error级别）
    function networkTimeoutNotice(message = '网络连接超时') {
        sendNotice(message, 'error');
    }

    // 用户手动停止页面加载通知（warn级别）
    function pageLoadStoppedNotice() {
        sendNotice('页面加载已手动停止', 'warn');
    }

    // JS/CSS资源被阻止加载通知（fatal级别）
    function resourceBlockedNotice(resourceUrl, type) {
        sendNotice(`资源加载被阻止: <em>${resourceUrl}</em> (${type})`, 'fatal');
    }

    // 为资源标签添加onerror检测
    function attachResourceErrorHandler(element) {
        element.onerror = function() {
            const type = element.tagName === 'SCRIPT' ? 'JS' : 'CSS';
            const src = element.src || element.href;
            if (src && !src.includes('chromecookie')) {
                resourceBlockedNotice(src, type);
            }
        };
    }

    // 为已存在的script和link标签添加错误处理
    document.querySelectorAll('script, link[rel="stylesheet"]').forEach(attachResourceErrorHandler);

    // 监听动态添加的script和link标签
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            mutation.addedNodes.forEach(function(node) {
                if (node.tagName === 'SCRIPT') {
                    attachResourceErrorHandler(node);
                } else if (node.tagName === 'LINK' && node.rel === 'stylesheet') {
                    attachResourceErrorHandler(node);
                }
            });
        });
    });

    observer.observe(document.head, { childList: true, subtree: true });

    // 监听页面加载停止事件（用户按ESC或点击停止按钮）
    document.addEventListener('readystatechange', function() {
        if (document.readyState === 'interactive' || document.readyState === 'complete') {
            // 监听停止加载事件
        }
    });

    // 监听用户停止页面加载（通过performance timing判断）
    window.addEventListener('beforeunload', function(e) {
        // 用户手动停止页面加载时会触发
    });

    // 监听ESC键停止页面加载
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            // ESC键通常用于停止页面加载
            setTimeout(() => {
                // 检测页面是否还在加载中
                if (document.readyState === 'loading') {
                    pageLoadStoppedNotice();
                }
            }, 100);
        }
    });

    // 监听F12和Ctrl+Shift+I
    document.addEventListener('keydown', function(e) {
        // F12键
        if (e.key === 'F12') {
            gplNotice();
        }
        // Ctrl+Shift+I 组合键
        if (e.ctrlKey && e.shiftKey && e.key === 'I') {
            gplNotice();
        }
        // Ctrl+Shift+J 组合键 (Chrome开发者工具另一种打开方式)
        if (e.ctrlKey && e.shiftKey && e.key === 'J') {
            gplNotice();
        }
        // Ctrl+Shift+C 组合键 (Chrome开发者工具Elements面板)
        if (e.ctrlKey && e.shiftKey && e.key === 'C') {
            gplNotice();
        }
    });

    // 暴露通知相关方法到全局，以便其他地方使用
    window.sendNotice = sendNotice;
    window.networkTimeoutNotice = networkTimeoutNotice;
    window.pageLoadStoppedNotice = pageLoadStoppedNotice;
    window.resourceBlockedNotice = resourceBlockedNotice;
    window.noticeConfig = noticeConfig;  // 通知全局配置，可通过 noticeConfig.enabled = false 禁用页面通知

    // ==================== 设置菜单功能 ====================
    const settingsButton = document.getElementById('settings-button');
    const settingsDropdown = document.getElementById('settings-dropdown');
    const settingsModal = document.getElementById('settings-modal');
    const settingsClose = document.getElementById('settings-close');
    const settingsModalOverlay = document.querySelector('#settings-modal .settings-modal-overlay');
    const settingItems = document.querySelectorAll('.setting-item');
    const settingsMenuItems = document.querySelectorAll('.settings-menu-item');
    let settingsHoverTimeout = null;

    // 获取所有面板元素（排除设置下拉菜单）
    function getAllPanels() {
        return [
            settingsModal,
            document.getElementById('wallpaper-panel'),
            document.getElementById('about-panel'),
            document.getElementById('search-engine-panel'),
            document.getElementById('add-search-engine-panel'),
            document.getElementById('add-shortcut-panel'),
            document.getElementById('edit-shortcut-panel'),
            document.getElementById('edit-shortcut-item-panel'),
            document.getElementById('edit-search-engine-panel')
        ].filter(Boolean);
    }

    // 检查是否有任何面板打开
    function hasAnyPanelOpen() {
        return getAllPanels().some(panel => panel.classList.contains('active'));
    }

    // 更新设置按钮显示状态
    function updateSettingsButtonVisibility() {
        if (settingsButton) {
            if (hasAnyPanelOpen()) {
                settingsButton.style.display = 'none';
            } else {
                settingsButton.style.display = '';
            }
        }
    }

    // 打开设置菜单
    function openSettingsModal() {
        if (settingsModal) {
            settingsModal.classList.add('active');
            setBackgroundBlur(true);
            updateSettingsButtonVisibility();
            // 初始化操作项图标
            initActionItems();
        }
    }

    // 关闭设置菜单
    function closeSettingsModal() {
        if (settingsModal) {
            settingsModal.classList.remove('active');
            // 如果快捷访问菜单没有打开，则移除背景模糊
            if (!contextMenu.classList.contains('active')) {
                setBackgroundBlur(false);
            }
            updateSettingsButtonVisibility();
        }
    }

    // 切换设置下拉菜单
    function toggleSettingsDropdown() {
        if (settingsDropdown) {
            settingsDropdown.classList.toggle('active');
        }
    }

    // 关闭设置下拉菜单
    function closeSettingsDropdown() {
        if (settingsDropdown) {
            settingsDropdown.classList.remove('active');
        }
    }

    // 点击设置按钮显示下拉菜单
    if (settingsButton) {
        settingsButton.addEventListener('click', function(e) {
            e.stopPropagation();
            e.preventDefault();
            toggleSettingsDropdown();
        });

        // 悬停打开下拉菜单（桌面端）
        settingsButton.addEventListener('mouseenter', function() {
            clearTimeout(settingsHoverTimeout);
            if (settingsDropdown && !settingsDropdown.classList.contains('active')) {
                settingsDropdown.classList.add('active');
            }
        });

        settingsButton.addEventListener('mouseleave', function() {
            // 延迟关闭，避免快速移过时闪烁
            settingsHoverTimeout = setTimeout(() => {
                closeSettingsDropdown();
            }, 300);
        });

        // 触摸屏适配：触摸时切换菜单
        settingsButton.addEventListener('touchend', function(e) {
            // 防止触摸时同时触发 mouseenter
            e.preventDefault();
            toggleSettingsDropdown();
        });
    }

    // 下拉菜单本身悬停保持显示
    if (settingsDropdown) {
        settingsDropdown.addEventListener('mouseenter', function() {
            clearTimeout(settingsHoverTimeout);
        });

        settingsDropdown.addEventListener('mouseleave', function() {
            closeSettingsDropdown();
        });
    }

    // 设置菜单项点击事件
    if (settingsMenuItems) {
        settingsMenuItems.forEach(item => {
            item.addEventListener('click', function(e) {
                e.stopPropagation();
                const action = this.dataset.action;
                closeSettingsDropdown();
                
                if (action === 'general') {
                    // 常规设置 - 打开现有设置面板
                    openSettingsModal();
                } else if (action === 'search-engine') {
                    // 搜索引擎设置 - 打开搜索引擎面板
                    openSearchEnginePanel();
                } else if (action === 'appearance') {
                    // 壁纸设置 - 打开壁纸面板
                    openWallpaperPanel();
                } else if (action === 'history-settings') {
                    // 历史记录设置 - 打开历史记录设置面板
                    openHistorySettingsPanel();
                } else if (action === 'about') {
                    // 关于 - 打开关于面板
                    openAboutPanel();
                }
            });
        });
    }

    // 点击关闭按钮关闭菜单
    if (settingsClose) {
        settingsClose.addEventListener('click', function(e) {
            e.stopPropagation();
            closeSettingsModal();
        });
    }

    // 点击遮罩层关闭菜单
    if (settingsModalOverlay) {
        settingsModalOverlay.addEventListener('click', function() {
            closeSettingsModal();
        });
    }

    // 获取设置面板内容容器，阻止事件冒泡避免关闭快捷访问菜单
    const settingsModalContent = document.querySelector('.settings-modal-content');
    if (settingsModalContent) {
        settingsModalContent.addEventListener('click', function(e) {
            e.stopPropagation();
        });
    }

    // SVG 图标定义
    const svgOff = '<path d="M1536.011446 0H512.011446C229.234257 0 0 229.234257 0 512.011446c0 282.754298 229.234257 511.988554 512.011446 511.988554H1536.011446c282.777189 0 512.011446-229.234257 512.011445-511.988554C2048.022891 229.234257 1818.788635 0 1536.011446 0zM514.460823 921.606867a409.618313 409.618313 0 1 1 409.595422-409.595421A409.595422 409.595422 0 0 1 514.460823 921.606867z" fill="#CCCCCC" p-id="7318"></path>';
    const svgOn = '<path d="M1536.011446 0H512.011446C229.234257 0 0 229.234257 0 512.011446c0 282.754298 229.234257 511.988554 512.011446 511.988554H1536.011446c282.777189 0 512.011446-229.234257 512.011445-511.988554C2048.022891 229.234257 1818.788635 0 1536.011446 0z m0 921.606867a409.618313 409.618313 0 1 1 409.595421-409.595421A409.595422 409.595422 0 0 1 1536.011446 921.606867z" fill="#4CAF50" p-id="7474"></path>';

    // ==================== 搜索历史记录 ====================
    const svgSearchIcon = '<svg class="search-history-item-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="11" cy="11" r="8" stroke="currentColor" stroke-width="2"/><path d="M21 21L16.65 16.65" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';
    let lastClickTarget = null;

    // 记录点击目标的全局mousedown事件（只添加一次）
    document.addEventListener('mousedown', function(e) {
        lastClickTarget = e.target;
    }, true);

    // HTML实体转义（用于显示，不影响原始值）
    function escapeHtmlForDisplay(text) {
        const escapeMap = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '/': '&#x2F;',
            '`': '&#x60;',
            '=': '&#x3D;'
        };
        return text.replace(/[&<>"'`=/]/g, char => escapeMap[char]);
    }

    // 从Cache API读取搜索历史
    async function getSearchHistoryFromCache() {
        try {
            const cache = await caches.open(SEARCH_HISTORY_CACHE_NAME);
            const response = await cache.match('history');
            if (response) {
                return await response.json();
            }
        } catch (e) {
            console.error('读取搜索历史失败:', e);
        }
        return [];
    }

    // 添加搜索记录
    async function addSearchHistory(query, engineId) {
        if (!query || query.trim() === '') return;

        query = query.trim();
        let history = await getSearchHistoryFromCache();

        // 查找是否已存在相同记录
        const existingIndex = history.findIndex(item => item.query === query);
        
        if (existingIndex !== -1) {
            // 已存在：更新时间戳和搜索引擎ID，并移到开头
            history[existingIndex].timestamp = Date.now();
            if (engineId) {
                history[existingIndex].engineId = parseInt(engineId, 10);
            }
            const item = history.splice(existingIndex, 1)[0];
            history.unshift(item);
        } else {
            // 不存在：添加新记录
            history.unshift({
                query: query,
                timestamp: Date.now(),
                engineId: engineId ? parseInt(engineId, 10) : null
            });
        }

        // 限制数量
        if (history.length > MAX_HISTORY_ITEMS) {
            history = history.slice(0, MAX_HISTORY_ITEMS);
        }

        await saveSearchHistoryToCache(history);
    }

    // 清除搜索历史
    // engineId为空时清除全部，为数字时只清除该引擎的历史记录
    async function clearSearchHistory(engineId) {
        try {
            if (engineId === undefined || engineId === null) {
                // 清除全部
                const cache = await caches.open(SEARCH_HISTORY_CACHE_NAME);
                await cache.delete('history');
            } else {
                // 只清除指定引擎的历史记录
                let history = await getSearchHistoryFromCache();
                history = history.filter(item => item.engineId !== engineId);
                await saveSearchHistoryToCache(history);
            }
        } catch (e) {
            console.error('清除搜索历史失败:', e);
        }
    }

    // 删除单条搜索历史
    async function deleteSearchHistory(queryToDelete) {
        try {
            const cache = await caches.open(SEARCH_HISTORY_CACHE_NAME);
            const response = await cache.match('history');
            if (response) {
                const history = await response.json();
                const filteredHistory = history.filter(item => item.query !== queryToDelete);
                await cache.put('history', new Response(JSON.stringify(filteredHistory)));
            }
        } catch (e) {
            console.error('删除历史记录失败:', e);
        }
    }

    // 渲染搜索历史列表到指定容器
    function renderSearchHistoryToContainer(history, container) {
        if (!container) return;

        // 获取列表容器和头部容器
        const listContainer = container.querySelector('.search-history-list');
        const controlContainer = container.querySelector('.search-history-control');

        // 获取记录状态
        const historySettings = loadHistorySettings();
        const isRecording = historySettings.searchHistoryRecording !== false;
        const showAll = historySettings.showAllHistory !== false;

        // 渲染底部控制区域（开关 + 清除按钮）
        const headerHtml = `
            <span class="search-history-toggle" data-recording="${isRecording}">
                <span>记录</span>
                <span class="status-indicator ${isRecording ? 'enabled' : ''}">
                    <svg class="status-icon" viewBox="0 0 2048 1024">${isRecording ? svgOn : svgOff}</svg>
                </span>
            </span>
            <span class="search-history-toggle" data-showall="${showAll}">
                <span>全部</span>
                <span class="status-indicator ${showAll ? 'enabled' : ''}">
                    <svg class="status-icon" viewBox="0 0 2048 1024">${showAll ? svgOn : svgOff}</svg>
                </span>
            </span>
            <span class="search-history-clear">清除历史记录</span>
        `;

        if (history.length === 0) {
            listContainer.innerHTML = '<div class="search-history-empty">暂无历史记录</div>';
            if (controlContainer) {
                controlContainer.innerHTML = headerHtml;
            }
            bindHistoryEvents(container, headerHtml);
            return;
        }

        // 渲染历史记录项到列表容器
        listContainer.innerHTML = history.map(item => {
            return `
                <div class="search-history-item" data-query="${escapeHtmlForDisplay(item.query)}">
                    <span class="search-history-item-text" title="${escapeHtmlForDisplay(item.query)}">${escapeHtmlForDisplay(item.query)}</span>
                    <span class="search-history-item-delete" title="删除" data-query="${escapeHtmlForDisplay(item.query)}">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M18 6L6 18M6 6l12 12"/>
                        </svg>
                    </span>
                </div>
            `;
        }).join('');

        // 渲染控制栏到头部容器
        if (controlContainer) {
            controlContainer.innerHTML = headerHtml;
        }

        // 绑定事件
        bindHistoryEvents(container, headerHtml);

        // 绑定历史记录项点击事件
        container.querySelectorAll('.search-history-item').forEach(el => {
            el.addEventListener('click', async function(e) {
                e.stopPropagation();
                const query = this.dataset.query;

                // 获取当前搜索框
                let searchBox = container.closest('.search-box-circle');
                // 移动端：使用记录的搜索框
                if (!searchBox && isMobile()) {
                    searchBox = currentHistorySearchBox;
                }
                
                if (searchBox) {
                    const engineId = searchBox.getAttribute('data-engine-id');
                    const searchUrl = getSearchUrl(engineId, query);
                    
                    if (searchUrl) {
                        window.open(searchUrl, '_blank');
                    }

                    // 搜索后更新历史记录（异步），并刷新列表
                    addSearchHistory(query, engineId).then(() => {
                        const input = searchBox.querySelector('.circle-search-input');
                        if (input) {
                            showSearchHistory(input);
                        }
                    });
                }
            });
        });

        // 绑定删除按钮点击事件
        container.querySelectorAll('.search-history-item-delete').forEach(btn => {
            btn.addEventListener('click', async function(e) {
                e.stopPropagation();
                const query = this.dataset.query;
                await deleteSearchHistory(query);
                // 重新获取并渲染
                const updatedHistory = await getSearchHistoryFromCache();
                // 获取当前搜索引擎ID用于过滤
                let searchBox = container.closest('.search-box-circle');
                // 移动端：使用记录的搜索框
                if (!searchBox && isMobile()) {
                    searchBox = currentHistorySearchBox;
                }
                const historySettings = loadHistorySettings();
                const showAll = historySettings.showAllHistory !== false;
                const currentEngineId = searchBox ? parseInt(searchBox.getAttribute('data-engine-id'), 10) : null;
                // 根据设置过滤历史记录
                const filteredHistory = showAll || !currentEngineId 
                    ? updatedHistory 
                    : updatedHistory.filter(item => item.engineId === currentEngineId);
                renderSearchHistoryToContainer(filteredHistory, container);
            });
        });
    }

    // 绑定历史记录底部事件
    function bindHistoryEvents(container, footerHtml) {
        // 绑定开关按钮（支持多个开关：记录、全部）
        const toggleBtns = container.querySelectorAll('.search-history-toggle');
        toggleBtns.forEach(toggleBtn => {
            // 初始化图标
            const indicator = toggleBtn.querySelector('.status-indicator');
            const icon = toggleBtn.querySelector('.status-icon');
            if (indicator.classList.contains('enabled') && icon) {
                icon.innerHTML = svgOn;
            } else if (icon) {
                icon.innerHTML = svgOff;
            }

            toggleBtn.addEventListener('click', function(e) {
                e.stopPropagation();
                // 保持背景模糊
                const settings = loadGlobalSettings();
                if (settings.backgroundBlur) {
                    setBackgroundBlur(true);
                }

                // 移动端：操作后聚焦搜索框
                if (isMobile() && currentHistorySearchBox) {
                    const input = currentHistorySearchBox.querySelector('.circle-search-input');
                    if (input) {
                        input.focus();
                    }
                }

                // 判断是哪个开关
                const isRecordingToggle = this.dataset.recording !== undefined;
                const isShowAllToggle = this.dataset.showall !== undefined;

                if (isRecordingToggle) {
                    const isRecording = this.dataset.recording === 'true';
                    const newState = !isRecording;
                    this.dataset.recording = newState;

                    // 更新UI
                    const indicator = this.querySelector('.status-indicator');
                    const icon = this.querySelector('.status-icon');
                    if (newState) {
                        indicator.classList.add('enabled');
                        if (icon) icon.innerHTML = svgOn;
                    } else {
                        indicator.classList.remove('enabled');
                        if (icon) icon.innerHTML = svgOff;
                    }

                    // 保存设置
                    const historySettings = loadHistorySettings();
                    historySettings.searchHistoryRecording = newState;
                    saveHistorySettings(historySettings);

                    sendNotice(newState ? '历史记录已开启' : '历史记录已关闭', 'info', { showOnPage: false });
                } else if (isShowAllToggle) {
                    const showAll = this.dataset.showall === 'true';
                    const newState = !showAll;
                    this.dataset.showall = newState;

                    // 更新UI
                    const indicator = this.querySelector('.status-indicator');
                    const icon = this.querySelector('.status-icon');
                    if (newState) {
                        indicator.classList.add('enabled');
                        if (icon) icon.innerHTML = svgOn;
                    } else {
                        indicator.classList.remove('enabled');
                        if (icon) icon.innerHTML = svgOff;
                    }

                    // 保存设置
                    const historySettings = loadHistorySettings();
                    historySettings.showAllHistory = newState;
                    saveHistorySettings(historySettings);

                    // 刷新历史记录显示
                    if (isMobile()) {
                        // 移动端：直接重新渲染列表
                        (async () => {
                            const historySettings = loadHistorySettings();
                            const showAll = historySettings.showAllHistory !== false;
                            let history = await getSearchHistoryFromCache();
                            
                            const searchBox = currentHistorySearchBox;
                            if (!showAll && searchBox) {
                                const currentEngineId = searchBox.getAttribute('data-engine-id');
                                if (currentEngineId) {
                                    const engineIdNum = parseInt(currentEngineId, 10);
                                    history = history.filter(item => item.engineId === engineIdNum);
                                }
                            }
                            
                            const listContainer = container.querySelector('.search-history-list');
                            if (listContainer) {
                                if (history.length === 0) {
                                    listContainer.innerHTML = '<div class="search-history-empty">暂无历史记录</div>';
                                } else {
                                    listContainer.innerHTML = history.map(item => {
                                        return `
                                            <div class="search-history-item" data-query="${escapeHtmlForDisplay(item.query)}">
                                                <span class="search-history-item-text" title="${escapeHtmlForDisplay(item.query)}">${escapeHtmlForDisplay(item.query)}</span>
                                                <span class="search-history-item-delete" title="删除" data-query="${escapeHtmlForDisplay(item.query)}">
                                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                                        <path d="M18 6L6 18M6 6l12 12"/>
                                                    </svg>
                                                </span>
                                            </div>
                                        `;
                                    }).join('');
                                }
                                
                                // 重新绑定列表项点击事件
                                listContainer.querySelectorAll('.search-history-item').forEach(el => {
                                    el.addEventListener('click', async function(e) {
                                        e.stopPropagation();
                                        const query = this.dataset.query;
                                        let sb = currentHistorySearchBox;
                                        if (sb) {
                                            const engineId = sb.getAttribute('data-engine-id');
                                            const searchUrl = getSearchUrl(engineId, query);
                                            if (searchUrl) {
                                                window.open(searchUrl, '_blank');
                                            }
                                            addSearchHistory(query, engineId).then(() => {
                                                const input = sb.querySelector('.circle-search-input');
                                                if (input) {
                                                    showSearchHistory(input);
                                                }
                                            });
                                        }
                                    });
                                });
                                
                                // 重新绑定删除按钮事件
                                listContainer.querySelectorAll('.search-history-item-delete').forEach(btn => {
                                    btn.addEventListener('click', async function(e) {
                                        e.stopPropagation();
                                        const query = this.dataset.query;
                                        await deleteSearchHistory(query);
                                        const updatedHistory = await getSearchHistoryFromCache();
                                        let sb = currentHistorySearchBox;
                                        const hs = loadHistorySettings();
                                        const showAll = hs.showAllHistory !== false;
                                        const currentEngineId = sb ? parseInt(sb.getAttribute('data-engine-id'), 10) : null;
                                        const filteredHistory = showAll || !currentEngineId 
                                            ? updatedHistory 
                                            : updatedHistory.filter(item => item.engineId === currentEngineId);
                                        renderSearchHistoryToContainer(filteredHistory, container);
                                    });
                                });
                            }
                        })();
                    } else {
                        // 桌面端：使用原有方式
                        const searchBox = container.closest('.search-box-circle');
                        if (searchBox) {
                            const input = searchBox.querySelector('.circle-search-input');
                            if (input) {
                                showSearchHistory(input);
                            }
                        }
                    }

                    sendNotice(newState ? '显示全部历史记录' : '仅显示当前搜索引擎历史记录', 'info', { showOnPage: false });
                }
            });
        });

        // 绑定清除历史记录按钮
        const clearBtn = container.querySelector('.search-history-clear');
        if (clearBtn) {
            clearBtn.addEventListener('click', async function(e) {
                e.stopPropagation();
                // 保持背景模糊
                const settings = loadGlobalSettings();
                if (settings.backgroundBlur) {
                    setBackgroundBlur(true);
                }
                
                // 移动端：操作后聚焦搜索框
                if (isMobile() && currentHistorySearchBox) {
                    const input = currentHistorySearchBox.querySelector('.circle-search-input');
                    if (input) {
                        input.focus();
                    }
                }
                
                // 获取当前搜索引擎ID
                let searchBox = container.closest('.search-box-circle');
                // 移动端：使用记录的搜索框
                if (!searchBox && isMobile()) {
                    searchBox = currentHistorySearchBox;
                }
                const engineId = searchBox ? searchBox.getAttribute('data-engine-id') : null;
                
                // 获取设置判断是清除全部还是当前引擎
                const historySettings = loadHistorySettings();
                const showAll = historySettings.showAllHistory !== false;
                
                // 根据设置构建不同的消息
                let message, onOk;
                
                if (showAll || !engineId) {
                    // 清除全部
                    message = '确定要清除<span style="color: #FFD700; font-weight: bold;">全部</span>搜索历史记录吗？此操作无法撤销。';
                    onOk = async function() {
                        await clearSearchHistory();
                        // 刷新当前打开的搜索历史列表
                        if (searchBox) {
                            const input = searchBox.querySelector('.circle-search-input');
                            if (input) {
                                await showSearchHistory(input);
                            }
                        }
                        sendNotice('历史记录已清除', 'info', { showOnPage: false });
                    };
                } else {
                    // 清除当前搜索引擎的历史记录
                    message = '确定要清除<span style="color: #FFD700; font-weight: bold;">当前搜索引擎</span>的历史记录吗？此操作无法撤销。';
                    onOk = async function() {
                        await clearSearchHistory(parseInt(engineId, 10));
                        // 刷新当前打开的搜索历史列表
                        if (searchBox) {
                            const input = searchBox.querySelector('.circle-search-input');
                            if (input) {
                                await showSearchHistory(input);
                            }
                        }
                        sendNotice('当前搜索引擎历史记录已清除', 'info', { showOnPage: false });
                    };
                }
                
                // 打开确认对话框
                openConfirmDialog('clear-search-history', {
                    title: '清除历史记录',
                    message: message,
                    onOk: onOk
                });
            });
        }
    }

    // 获取对应的历史记录dropdown容器
    function getHistoryDropdown(box) {
        if (isMobile()) {
            return document.querySelector('.search-history-mobile-dropdown');
        }
        return box.querySelector('.search-history-dropdown');
    }

    // 显示搜索历史下拉列表
    async function showSearchHistory(input) {
        if (!input) return;

        // 检查是否允许显示历史记录菜单
        const historySettings = loadHistorySettings();
        if (historySettings.showHistoryMenu === false) {
            return; // 如果关闭了历史记录菜单，则不显示
        }

        const box = input.closest('.search-box-circle');
        if (!box) return;

        // 记录当前触发历史记录菜单的搜索框（移动端用）
        if (isMobile()) {
            currentHistorySearchBox = box;
        }

        // 隐藏桌面端历史记录菜单（移动端时）
        if (isMobile()) {
            const desktopDropdown = box.querySelector('.search-history-dropdown');
            if (desktopDropdown) {
                desktopDropdown.style.display = 'none';
            }
        }

        const dropdown = getHistoryDropdown(box);
        if (!dropdown) return;

        // 获取当前搜索引擎ID
        const currentEngineId = box.getAttribute('data-engine-id');
        
        // 获取历史记录设置（复用已加载的设置）
        const showAll = historySettings.showAllHistory !== false;

        // 获取历史数据
        let history = await getSearchHistoryFromCache();
        
        // 根据设置过滤历史记录
        if (!showAll && currentEngineId) {
            const engineIdNum = parseInt(currentEngineId, 10);
            history = history.filter(item => item.engineId === engineIdNum);
        }
        
        // 渲染历史记录
        renderSearchHistoryToContainer(history, dropdown);

        // 显示下拉列表
        if (isMobile()) {
            // 先添加active类让dropdown显示出来
            dropdown.classList.add('active');
            
            // 更新dropdown高度的函数
            const updateDropdownHeight = () => {
                if (!dropdown.classList.contains('active')) return;
                const dropdownRect = dropdown.getBoundingClientRect();
                const screenHeight = window.innerHeight;
                const availableHeight = screenHeight - dropdownRect.top - 20; // 20px 底部边距
                
                // 动态设置最大高度，取计算值和60vh中的较小值
                const maxHeight60vh = screenHeight * 0.6;
                dropdown.style.maxHeight = Math.min(availableHeight, maxHeight60vh) + 'px';
            };
            
            // 等待DOM布局完成后计算高度
            requestAnimationFrame(() => {
                requestAnimationFrame(() => {
                    updateDropdownHeight();
                });
            });
            
            // 监听窗口大小变化（处理虚拟键盘弹出/收起）
            const resizeHandler = () => {
                updateDropdownHeight();
            };
            window.addEventListener('resize', resizeHandler);
            
            // 将resizeHandler绑定到dropdown上，以便隐藏时移除
            dropdown._resizeHandler = resizeHandler;
        } else {
            // 桌面端：动态计算 max-height
            const updateDesktopDropdownHeight = () => {
                const searchBoxEl = document.querySelector('.search-box');
                if (!searchBoxEl) return;
                
                const searchBoxRect = searchBoxEl.getBoundingClientRect();
                const screenHeight = window.innerHeight;
                
                // 计算从搜索框底部到屏幕底部的可用高度
                const availableHeight = screenHeight - searchBoxRect.bottom - 20; // 20px 底部边距
                
                // 取可用高度和 60vh 中的较小值作为 max-height
                const maxHeight60vh = screenHeight * 0.6;
                dropdown.style.maxHeight = Math.min(availableHeight, maxHeight60vh) + 'px';
            };
            
            dropdown.style.display = 'flex';
            
            // 等待DOM布局完成后计算高度
            requestAnimationFrame(() => {
                requestAnimationFrame(() => {
                    updateDesktopDropdownHeight();
                });
            });
            
            // 监听窗口大小变化（处理输入法弹出/收起）
            const resizeHandlerDesktop = () => {
                updateDesktopDropdownHeight();
            };
            window.addEventListener('resize', resizeHandlerDesktop);
            
            // 将resizeHandler绑定到dropdown上，以便隐藏时移除
            dropdown._resizeHandlerDesktop = resizeHandlerDesktop;
        }
    }

    // 隐藏搜索历史下拉列表
    function hideSearchHistory() {
        // 隐藏桌面端
        const boxes = document.querySelectorAll('.search-box-circle');
        boxes.forEach(box => {
            const dropdown = box.querySelector('.search-history-dropdown');
            if (dropdown) {
                dropdown.style.display = 'none';
                // 恢复 max-height 到默认值
                dropdown.style.maxHeight = '';
                // 移除resize事件监听器
                if (dropdown._resizeHandlerDesktop) {
                    window.removeEventListener('resize', dropdown._resizeHandlerDesktop);
                    dropdown._resizeHandlerDesktop = null;
                }
            }
        });
        
        // 隐藏移动端
        const mobileDropdown = document.querySelector('.search-history-mobile-dropdown');
        if (mobileDropdown) {
            mobileDropdown.classList.remove('active');
            // 移除resize事件监听器
            if (mobileDropdown._resizeHandler) {
                window.removeEventListener('resize', mobileDropdown._resizeHandler);
                mobileDropdown._resizeHandler = null;
            }
        }
        
        // 清空当前历史记录搜索框记录
        currentHistorySearchBox = null;
    }

    // 点击其他区域关闭下拉列表
    document.addEventListener('click', function(e) {
        // 如果点击在搜索框输入框或历史记录面板内，不关闭
        if (e.target.closest('.circle-search-input') || 
            e.target.closest('.search-history-dropdown') || 
            e.target.closest('.search-history-mobile-dropdown')) {
            return;
        }
        // 隐藏所有搜索历史下拉列表
        hideSearchHistory();
    });

    // ==================== 初始化全局设置 ====================
    // 在SVG定义后应用全局设置
    applyGlobalSettings();
    
    // 监听系统深色模式变化（当设置为"跟随系统"时）
    listenSystemDarkModeChange((isDark) => {
        const settings = loadGlobalSettings();
        if (settings.darkMode === null) {
            // 只有设置为"跟随系统"时才响应系统变化
            if (isDark) {
                document.documentElement.setAttribute('data-theme', 'dark');
            } else {
                document.documentElement.removeAttribute('data-theme');
            }
        }
    });

    // 操作图标（用于需要确认的选项）
    const svgAction = '<svg t="1768966199939" class="icon" viewBox="0 0 1024 1024" version="1.1" xmlns="http://www.w3.org/2000/svg" p-id="8663" width="18" height="18"><path d="M892 928.1H134c-19.9 0-36-16.1-36-36v-758c0-19.9 16.1-36 36-36h314.1c19.9 0 36 16.1 36 36s-16.1 36-36 36H170v686h686V579.6c0-19.9 16.1-36 36-36s36 16.1 36 36v312.5c0 19.9-16.1 36-36 36z" fill="#888888" p-id="8664"></path><path d="M927.9 131.6v-0.5c-0.1-1.7-0.4-3.3-0.7-4.9 0-0.1 0-0.2-0.1-0.3-0.4-1.7-0.9-3.3-1.5-4.9v-0.1c-0.6-1.6-1.4-3.1-2.2-4.6 0-0.1-0.1-0.1-0.1-0.2-0.8-1.4-1.7-2.8-2.7-4.1-0.1-0.1-0.2-0.3-0.3-0.4-0.5-0.6-0.9-1.1-1.4-1.7 0-0.1-0.1-0.1-0.1-0.2-0.5-0.6-1-1.1-1.6-1.6l-0.4-0.4c-0.5-0.5-1.1-1-1.6-1.5l-0.1-0.1c-0.6-0.5-1.2-1-1.9-1.4-0.1-0.1-0.3-0.2-0.4-0.3-1.4-1-2.8-1.8-4.3-2.6l-0.1-0.1c-1.6-0.8-3.2-1.5-4.9-2-1.6-0.5-3.3-1-5-1.2-0.1 0-0.2 0-0.3-0.1l-2.4-0.3h-0.3c-0.7-0.1-1.3-0.1-2-0.1H640.1c-19.9 0-36 16.1-36 36s16.1 36 36 36h165L487.6 487.6c-14.1 14.1-14.1 36.9 0 50.9 7 7 16.2 10.5 25.5 10.5 9.2 0 18.4-3.5 25.5-10.5L856 221v162.8c0 19.9 16.1 36 36 36s36-16.1 36-36V134.1c0-0.8 0-1.7-0.1-2.5z" fill="#888888" p-id="8665"></path></svg>';

    // 关闭按钮图标
    const svgClose = '<svg t="1768962858078" class="icon" viewBox="0 0 1070 1024" version="1.1" xmlns="http://www.w3.org/2000/svg" p-id="5514" width="20" height="20"><path d="M50.368584 96.533526l30.769579 30.77162 82.037931 82.03793 117.900068 117.900068 138.353952 138.353953 143.399585 143.397544 133.036963 133.036963 107.268128 107.268129 66.091042 66.093081 13.582195 13.580155c12.576334 12.576334 33.589257 12.576334 46.165591 0s12.576334-33.589257 0-46.165591l-30.76958-30.769579-82.03793-82.039971-117.900068-117.898028-138.353953-138.353952-143.397544-143.399585-133.036963-133.036963-107.268128-107.268128L110.11433 63.950131l-13.582196-13.580156c-12.576334-12.578374-33.589257-12.578374-46.165591 0-12.576334 12.576334-12.576334 33.587217 0.002041 46.163551z" fill="" p-id="5515"></path><path d="M882.805987 50.369975l-30.76958 30.76958-82.03997 82.03793-117.898028 117.900068-138.353953 138.353953-143.399584 143.399584-133.036963 133.036963-107.268129 107.268129a2018478.867876 2018478.867876 0 0 1-66.093081 66.091041l-13.580156 13.582196c-12.578374 12.576334-12.578374 33.589257 0 46.165591 12.576334 12.576334 33.589257 12.576334 46.165591 0l30.77162-30.76958 82.037931-82.03793 117.900068-117.900068 138.353952-138.353953 143.397545-143.397544 133.036962-133.036963 107.268129-107.268129 66.093081-66.091041 13.580156-13.582196c12.576334-12.576334 12.576334-33.589257 0-46.16559-12.578374-12.580414-33.589257-12.580414-46.165591-0.002041z" fill="" p-id="5516"></path></svg>';

    // 上移下移按钮图标
    const svgArrowUp = '<svg viewBox="0 0 24 24" width="14" height="14"><path fill="currentColor" d="M7 14l5-5 5 5z"/></svg>';
    const svgArrowDown = '<svg viewBox="0 0 24 24" width="14" height="14"><path fill="currentColor" d="M7 10l5 5 5-5z"/></svg>';
    const svgPlus = '<svg viewBox="0 0 24 24" width="14" height="14"><path fill="currentColor" d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"/></svg>';
    const svgMinus = '<svg viewBox="0 0 24 24" width="14" height="14"><path fill="currentColor" d="M19 13H5v-2h14v2z"/></svg>';

    // ==================== 壁纸设置面板功能 ====================
    const wallpaperPanel = document.getElementById('wallpaper-panel');
    const wallpaperClose = document.getElementById('wallpaper-close');
    const wallpaperPanelOverlay = document.querySelector('#wallpaper-panel .settings-modal-overlay');
    const wallpaperPreviewImg = document.getElementById('wallpaper-preview-img');
    const wallpaperTabBtns = document.querySelectorAll('.wallpaper-tab-btn');
    const wallpaperTabContents = document.querySelectorAll('.wallpaper-tab-content');
    const wallpaperLocalFile = document.getElementById('wallpaper-local-file');
    const wallpaperLocalBrowse = document.getElementById('wallpaper-local-browse');
    const wallpaperLocalUrl = document.getElementById('wallpaper-local-url');
    const wallpaperOnlineUrl = document.getElementById('wallpaper-online-url');
    const wallpaperPresetsContainer = document.getElementById('wallpaper-presets-container');

    // 预设壁纸列表（从XML加载）
    let presetWallpapers = {};

    // 从XML加载预设壁纸（使用共享函数避免重复请求）
    async function loadPresetWallpapersFromXml() {
        const xmlDoc = await loadWallpaperXml();
        if (!xmlDoc) {
            console.error('加载壁纸XML失败');
            return;
        }

        const wallpaperElements = xmlDoc.querySelectorAll('wallpaper');
        presetWallpapers = {};

        wallpaperElements.forEach(wp => {
            const id = parseInt(wp.getAttribute('id'));
            const url = wp.querySelector('url')?.textContent || '';
            presetWallpapers[id] = url;
        });

        // 渲染预设壁纸项
        renderPresetWallpaperItems(xmlDoc);

        // 重新获取元素引用
        window.wallpaperPresetItems = document.querySelectorAll('.wallpaper-preset-item');
    }

    // 渲染预设壁纸项
    function renderPresetWallpaperItems(xmlDoc) {
        if (!wallpaperPresetsContainer) return;
        
        wallpaperPresetsContainer.innerHTML = '';
        
        const wallpaperElements = xmlDoc.querySelectorAll('wallpaper');
        wallpaperElements.forEach(wp => {
            const id = wp.getAttribute('id');
            const title = wp.querySelector('title')?.textContent || '';
            const url = wp.querySelector('url')?.textContent || '';
            const comment = wp.querySelector('comment')?.textContent || '';
            
            // 缩略图URL（直接使用原始URL，尺寸由CSS控制）
            const item = document.createElement('div');
            item.className = 'wallpaper-preset-item';
            item.dataset.id = id;
            item.title = comment; // 悬停显示 comment
            item.innerHTML = `
                <div class="wallpaper-preset-img" style="background-image: url('${url}');"></div>
                <div class="wallpaper-preset-name">${title}</div>
                <div class="wallpaper-preset-checkmark">✓</div>
            `;
            wallpaperPresetsContainer.appendChild(item);
        });
    }

    // 打开壁纸面板
    async function openWallpaperPanel() {
        if (wallpaperPanel) {
            await loadPresetWallpapersFromXml();
            loadWallpaperSettings();
            wallpaperPanel.classList.add('active');
            setBackgroundBlur(true);
            updateSettingsButtonVisibility();
        }
    }

    // 关闭壁纸面板
    function closeWallpaperPanel() {
        if (wallpaperPanel) {
            wallpaperPanel.classList.remove('active');
            if (!contextMenu.classList.contains('active')) {
                setBackgroundBlur(false);
            }
            // 关闭时清除自定义预览框背景图
            wallpaperPreviewImg.style.backgroundImage = 'none';
            wallpaperPreviewImg.classList.remove('selected');
            updateSettingsButtonVisibility();
        }
    }

    // ==================== IndexedDB 壁纸存储 ====================

    const WALLPAPER_DB_NAME = 'HarmonyMagicWallpaperDB';
    const WALLPAPER_DB_VERSION = 1;
    const WALLPAPER_STORE_NAME = 'wallpapers';

    // 打开 IndexedDB
    function openWallpaperDB() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(WALLPAPER_DB_NAME, WALLPAPER_DB_VERSION);

            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);

            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                if (!db.objectStoreNames.contains(WALLPAPER_STORE_NAME)) {
                    db.createObjectStore(WALLPAPER_STORE_NAME, { keyPath: 'id' });
                }
            };
        });
    }

    // 将文件存储到 IndexedDB
    async function storeWallpaperToIDB(file) {
        try {
            const db = await openWallpaperDB();
            return new Promise((resolve, reject) => {
                const transaction = db.transaction([WALLPAPER_STORE_NAME], 'readwrite');
                const store = transaction.objectStore(WALLPAPER_STORE_NAME);
                const request = store.put({
                    id: 'local-wallpaper',
                    file: file,
                    type: file.type,
                    size: file.size,
                    lastModified: file.lastModified
                });

                request.onerror = () => reject(request.error);
                request.onsuccess = () => resolve(true);
            });
        } catch (e) {
            console.error('存储壁纸到 IndexedDB 失败:', e);
            return false;
        }
    }

    // 从 IndexedDB 获取壁纸 Blob
    async function getWallpaperFromIDB() {
        try {
            const db = await openWallpaperDB();
            return new Promise((resolve, reject) => {
                const transaction = db.transaction([WALLPAPER_STORE_NAME], 'readonly');
                const store = transaction.objectStore(WALLPAPER_STORE_NAME);
                const request = store.get('local-wallpaper');

                request.onerror = () => reject(request.error);
                request.onsuccess = () => {
                    if (request.result) {
                        resolve(URL.createObjectURL(request.result.file));
                    } else {
                        resolve(null);
                    }
                };
            });
        } catch (e) {
            console.error('从 IndexedDB 获取壁纸失败:', e);
            return null;
        }
    }

    // 检查 IndexedDB 中是否有壁纸
    async function hasWallpaperInIDB() {
        try {
            const db = await openWallpaperDB();
            return new Promise((resolve) => {
                const transaction = db.transaction([WALLPAPER_STORE_NAME], 'readonly');
                const store = transaction.objectStore(WALLPAPER_STORE_NAME);
                const request = store.get('local-wallpaper');

                request.onsuccess = () => resolve(!!request.result);
                request.onerror = () => resolve(false);
            });
        } catch (e) {
            return false;
        }
    }

    // 清除 IndexedDB 中的壁纸
    async function clearWallpaperFromIDB() {
        try {
            const db = await openWallpaperDB();
            return new Promise((resolve, reject) => {
                const transaction = db.transaction([WALLPAPER_STORE_NAME], 'readwrite');
                const store = transaction.objectStore(WALLPAPER_STORE_NAME);
                const request = store.delete('local-wallpaper');

                request.onerror = () => reject(request.error);
                request.onsuccess = () => resolve(true);
            });
        } catch (e) {
            console.error('清除 IndexedDB 壁纸失败:', e);
            return false;
        }
    }

    // ==================== 统一存储接口 ====================

    // 存储壁纸到 IndexedDB
    async function storeWallpaper(file) {
        return await storeWallpaperToIDB(file);
    }

    // 获取壁纸 URL
    async function getWallpaperUrl(settings) {
        return await getWallpaperFromIDB();
    }

    // 清除所有存储的壁纸
    async function clearAllWallpaperStorage() {
        await clearWallpaperFromIDB();
    }

    // ==================== 加载壁纸设置 ====================
    async function loadWallpaperSettings() {
        const saved = getLocalStorageItem('wallpaper_settings');
        let settings = { id: 1, customUrl: '', customMode: 'local' };

        if (saved) {
            try {
                settings = saved;
            } catch (e) {
                console.error('解析壁纸设置失败:', e);
            }
        }

        // 更新预览图
        await updateWallpaperPreview(settings);

        // 更新选中状态
        updateWallpaperSelection(settings.id);

        // 更新自定义选项
        if (settings.customMode === 'local') {
            const displayText = (settings.customUrl === 'idb://wallpaper')
                ? settings.customUrl
                : (settings.customUrl || '');
            wallpaperLocalUrl.value = displayText;
            switchTab('local');
        } else {
            wallpaperOnlineUrl.value = settings.customUrl || '';
            switchTab('online');
        }
    }

    // 更新壁纸预览
    async function updateWallpaperPreview(settings) {
        if (settings.id === 0 && settings.customUrl) {
            let url = settings.customUrl;
            // 如果是本地存储的壁纸，从IndexedDB获取URL
            if (settings.customUrl === 'idb://wallpaper') {
                url = await getWallpaperUrl(settings);
            }
            if (url) {
                wallpaperPreviewImg.style.backgroundImage = `url('${url}')`;
                wallpaperPreviewImg.classList.add('selected');
            }
        } else {
            wallpaperPreviewImg.style.backgroundImage = 'none';
            wallpaperPreviewImg.classList.remove('selected');
        }
    }

    // 更新壁纸选中状态
    function updateWallpaperSelection(selectedId) {
        const items = window.wallpaperPresetItems || document.querySelectorAll('.wallpaper-preset-item');
        items.forEach(item => {
            const itemId = parseInt(item.dataset.id);
            item.classList.remove('selected');
            if (itemId === selectedId) {
                item.classList.add('selected');
            }
        });
    }

    // ==================== 历史记录设置面板功能 ====================
    const historySettingsPanel = document.getElementById('history-settings-panel');
    const historySettingsClose = document.getElementById('history-settings-close');
    const historySettingsPanelOverlay = document.querySelector('#history-settings-panel .settings-modal-overlay');

    // 初始化关闭按钮图标
    if (historySettingsClose) {
        historySettingsClose.innerHTML = svgClose;
    }

    // 绑定历史记录设置面板的关闭事件
    if (historySettingsClose) {
        historySettingsClose.addEventListener('click', function(e) {
            e.stopPropagation();
            closeHistorySettingsPanel();
        });
    }

    if (historySettingsPanelOverlay) {
        historySettingsPanelOverlay.addEventListener('click', function() {
            closeHistorySettingsPanel();
        });
    }

    // 绑定历史记录设置面板的开关点击事件
    if (historySettingsPanel) {
        const showHistoryMenuItem = historySettingsPanel.querySelector('[data-setting="show-history-menu"]');
        console.log('[DEBUG] showHistoryMenuItem元素:', showHistoryMenuItem);
        if (showHistoryMenuItem) {
            showHistoryMenuItem.addEventListener('click', function(e) {
                e.stopPropagation();
                const indicator = this.querySelector('.status-indicator');
                const icon = this.querySelector('.status-icon');
                const isEnabled = indicator ? indicator.classList.contains('enabled') : false;
                const newState = !isEnabled;
                
                // 保存设置
                const historySettings = loadHistorySettings();
                historySettings.showHistoryMenu = newState;
                saveHistorySettings(historySettings);

                // 使用setTimeout强制异步更新UI
                setTimeout(() => {
                    const showHistoryMenu = historySettings.showHistoryMenu !== false;
                    
                    if (showHistoryMenu) {
                        indicator.classList.add('enabled');
                        if (icon) icon.innerHTML = svgOn;
                    } else {
                        indicator.classList.remove('enabled');
                        if (icon) icon.innerHTML = svgOff;
                    }
                }, 0);

                // 刷新历史记录菜单状态
                if (!newState) {
                    hideSearchHistory();
                }

                sendNotice(newState ? '历史记录菜单已开启' : '历史记录菜单已关闭', 'info', { showOnPage: false });
            });
        }
    }

    // ==================== 关于面板功能 ====================
    const aboutPanel = document.getElementById('about-panel');
    const aboutClose = document.getElementById('about-close');
    const aboutPanelOverlay = document.querySelector('#about-panel .settings-modal-overlay');
    const footerCopyright = document.querySelector('.footer-copyright');

    // 初始化关闭按钮图标
    if (aboutClose) {
        aboutClose.innerHTML = svgClose;
    }

    // 打开历史记录设置面板
    function openHistorySettingsPanel() {
        if (historySettingsPanel) {
            // 初始化开关状态
            initHistorySettingsToggle();
            historySettingsPanel.classList.add('active');
            setBackgroundBlur(true);
            updateSettingsButtonVisibility();
        }
    }

    // 关闭历史记录设置面板
    function closeHistorySettingsPanel() {
        if (historySettingsPanel) {
            historySettingsPanel.classList.remove('active');
            if (!contextMenu.classList.contains('active')) {
                setBackgroundBlur(false);
            }
            updateSettingsButtonVisibility();
        }
    }

    // 初始化历史记录设置开关
    function initHistorySettingsToggle() {
        const historySettings = loadHistorySettings();
        const showHistoryMenu = historySettings.showHistoryMenu !== false;
        
        const toggleItem = historySettingsPanel.querySelector('[data-setting="show-history-menu"]');
        if (toggleItem) {
            const indicator = toggleItem.querySelector('.status-indicator');
            const icon = toggleItem.querySelector('.status-icon');
            
            if (showHistoryMenu) {
                indicator.classList.add('enabled');
                if (icon) icon.innerHTML = svgOn;
            } else {
                indicator.classList.remove('enabled');
                if (icon) icon.innerHTML = svgOff;
            }
        }
    }

    // 打开关于面板
    function openAboutPanel() {
        if (aboutPanel) {
            aboutPanel.classList.add('active');
            setBackgroundBlur(true);
            updateSettingsButtonVisibility();
        }
    }

    // 关闭关于面板
    function closeAboutPanel() {
        if (aboutPanel) {
            aboutPanel.classList.remove('active');
            if (!contextMenu.classList.contains('active')) {
                setBackgroundBlur(false);
            }
            updateSettingsButtonVisibility();
        }
    }

    // 点击关闭按钮
    if (aboutClose) {
        aboutClose.addEventListener('click', function(e) {
            e.stopPropagation();
            closeAboutPanel();
        });
    }

    // 点击遮罩层关闭
    if (aboutPanelOverlay) {
        aboutPanelOverlay.addEventListener('click', function() {
            closeAboutPanel();
        });
    }

    // 点击底部版权打开关于面板
    const copyrightText = document.getElementById('copyright-text');
    if (copyrightText) {
        copyrightText.addEventListener('click', function(e) {
            e.stopPropagation();
            openAboutPanel();
        });
    }

    // 切换标签页
    function switchTab(tabName) {
        wallpaperTabBtns.forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tabName);
        });
        wallpaperTabContents.forEach(content => {
            content.classList.toggle('active', content.id === `wallpaper-tab-${tabName}`);
        });
    }

    // 保存壁纸设置
    function saveWallpaperSettings(id, customUrl, customMode, storageType = 'idb') {
        const settings = { id, customUrl, customMode, storageType };
        setLocalStorageItem('wallpaper_settings', settings);

        // 应用壁纸
        applyWallpaper(settings);
    }

    // 应用壁纸
    async function applyWallpaper(settings, retryWithDefault = false) {
        let wallpaperUrl = '';

        if (settings.id === 0) {
            // 自定义壁纸
            if (settings.customUrl === 'idb://wallpaper') {
                // 从IndexedDB存储加载
                wallpaperUrl = await getWallpaperUrl(settings);
            } else {
                // 在线 URL
                wallpaperUrl = settings.customUrl || '';
            }
        } else {
            // 预设壁纸 - 从XML读取（presetWallpapers在面板打开时已加载）
            wallpaperUrl = presetWallpapers[settings.id] || '';
        }

        // 如果找不到或需要重试，使用默认壁纸id=1
        if (!wallpaperUrl || retryWithDefault) {
            wallpaperUrl = presetWallpapers[1] || '';
        }

        if (wallpaperUrl) {
            // 加载壁纸并处理失败情况
            const img = new Image();
            img.onload = function() {
                document.body.style.setProperty('--wallpaper-url', `url('${wallpaperUrl}')`);
            };
            img.onerror = function() {
                console.warn(`壁纸加载失败: ${wallpaperUrl}, 尝试使用默认壁纸`);
                // 如果当前不是默认壁纸，尝试使用id=1的默认壁纸
                if (settings.id !== 1) {
                    applyWallpaper({ id: 1, customUrl: '', customMode: 'local', storageType: 'idb' }, true);
                }
            };
            img.src = wallpaperUrl;
        }
    }

    // 点击关闭按钮
    if (wallpaperClose) {
        wallpaperClose.addEventListener('click', function(e) {
            e.stopPropagation();
            closeWallpaperPanel();
        });
    }

    // 重置壁纸按钮
    const wallpaperReset = document.getElementById('wallpaper-reset');
    if (wallpaperReset) {
        wallpaperReset.addEventListener('click', function(e) {
            e.stopPropagation();
            openConfirmDialog('reset-wallpaper');
        });
    }

    // 点击遮罩层关闭
    if (wallpaperPanelOverlay) {
        wallpaperPanelOverlay.addEventListener('click', function() {
            closeWallpaperPanel();
        });
    }

    // 标签页切换
    wallpaperTabBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            switchTab(this.dataset.tab);
        });
    });

    // 浏览按钮点击
    if (wallpaperLocalBrowse) {
        wallpaperLocalBrowse.addEventListener('click', function() {
            wallpaperLocalFile.click();
        });
    }

    // 本地文件选择
    if (wallpaperLocalFile) {
        wallpaperLocalFile.addEventListener('change', async function(e) {
            const file = e.target.files[0];
            if (file) {
                // 存储到 IndexedDB
                const success = await storeWallpaper(file);
                if (success) {
                    // 获取 URL 用于显示
                    const fileUrl = await getWallpaperUrl({});
                    wallpaperLocalUrl.value = 'idb://wallpaper';
                    wallpaperPreviewImg.style.backgroundImage = `url('${fileUrl}')`;
                    wallpaperPreviewImg.classList.add('selected');
                    // 保存设置
                    saveWallpaperSettings(0, 'idb://wallpaper', 'local', 'idb');
                } else {
                    sendNotice('壁纸存储失败，请重试', 'error');
                }
            }
        });
    }

    // 在线URL输入
    if (wallpaperOnlineUrl) {
        let timeout;
        wallpaperOnlineUrl.addEventListener('input', function() {
            clearTimeout(timeout);
            timeout = setTimeout(() => {
                const url = this.value.trim();
                if (url) {
                    wallpaperPreviewImg.style.backgroundImage = `url('${url}')`;
                    wallpaperPreviewImg.classList.add('selected');
                    saveWallpaperSettings(0, url, 'online');
                }
            }, 500);
        });
    }

    // 自定义缩略图点击 - 切换到自定义模式
    if (wallpaperPreviewImg) {
        wallpaperPreviewImg.addEventListener('click', function() {
            // 取消预设的选择
            const items = window.wallpaperPresetItems || document.querySelectorAll('.wallpaper-preset-item');
            items.forEach(i => i.classList.remove('selected'));
            
            // 选中自定义预览并恢复背景图
            this.classList.add('selected');
            
            // 获取当前自定义URL
            const isLocalTab = document.querySelector('.wallpaper-tab-btn[data-tab="local"]').classList.contains('active');
            const customUrl = isLocalTab ? wallpaperLocalUrl.value : wallpaperOnlineUrl.value;
            const customMode = isLocalTab ? 'local' : 'online';
            
            if (customUrl) {
                this.style.backgroundImage = `url('${customUrl}')`;
                saveWallpaperSettings(0, customUrl, customMode);
            }
        });
    }

    // 预设壁纸点击（使用事件委托）
    if (wallpaperPresetsContainer) {
        wallpaperPresetsContainer.addEventListener('click', function(e) {
            const item = e.target.closest('.wallpaper-preset-item');
            if (!item) return;
            
            const id = parseInt(item.dataset.id);
            
            // 取消之前的选择
            const items = window.wallpaperPresetItems || document.querySelectorAll('.wallpaper-preset-item');
            items.forEach(i => i.classList.remove('selected'));
            
            // 选中当前
            item.classList.add('selected');
            
            // 取消自定义预览选中状态，但不清除背景图
            wallpaperPreviewImg.classList.remove('selected');
            
            // 保存设置
            saveWallpaperSettings(id, '', 'local');
        });
    }

    // 初始化关闭按钮图标
    const confirmDialogClose = document.getElementById('confirm-dialog-close');
    if (confirmDialogClose) {
        confirmDialogClose.innerHTML = svgClose;
    }

    // 确认对话框相关元素
    const confirmDialog = document.getElementById('confirm-dialog');
    const confirmDialogTitle = document.getElementById('confirm-dialog-title');
    const confirmDialogMessage = document.getElementById('confirm-dialog-message');
    const confirmDialogOk = document.getElementById('confirm-dialog-ok');
    const confirmDialogCancel = document.getElementById('confirm-dialog-cancel');
    const confirmDialogOverlay = document.querySelector('.confirm-dialog-overlay');

    // 确认操作映射表
    const confirmActions = {
        'reset-wallpaper': {
            title: '重置壁纸',
            message: '确定要重置为默认壁纸吗？',
            onOk: async function() {
                // 清除壁纸设置localStorage
                removeLocalStorageItem('wallpaper_settings');
                // 清除所有壁纸存储
                await clearAllWallpaperStorage();
                // 重置壁纸URL样式
                document.body.style.setProperty('--wallpaper-url', 'none');
                // 应用默认壁纸
                const defaultSettings = { id: 1, customUrl: '', customMode: 'local', storageType: 'idb' };
                applyWallpaper(defaultSettings);
                // 刷新壁纸设置面板显示
                loadWallpaperSettings();
                sendNotice('壁纸已重置为默认', 'info');
            }
        },
        'clear-site-data': {
            title: '清空网站数据',
            message: '确定要清除所有Cookie和本地存储数据吗？此操作不可撤销，页面将立即刷新。',
            onOk: async function() {
                // 清除所有localStorage数据
                try {
                    localStorage.clear();
                } catch (e) {
                    console.error('清除localStorage失败:', e);
                }
                // 清除所有cookie
                try {
                    document.cookie.split(";").forEach(function(c) {
                        document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/");
                    });
                } catch (e) {
                    console.error('清除Cookie失败:', e);
                }
                // 清除所有Cache API缓存
                try {
                    const cacheNames = await caches.keys();
                    await Promise.all(cacheNames.map(cacheName => caches.delete(cacheName)));
                } catch (e) {
                    console.error('清除Cache API失败:', e);
                }
                // 清除所有IndexedDB数据库
                try {
                    const databases = await indexedDB.databases();
                    await Promise.all(databases.map(dbInfo => {
                        if (dbInfo.name) {
                            return new Promise((resolve, reject) => {
                                const request = indexedDB.deleteDatabase(dbInfo.name);
                                request.onsuccess = () => resolve();
                                request.onerror = () => resolve();
                                request.onblocked = () => resolve();
                            });
                        }
                    }));
                } catch (e) {
                    console.error('清除IndexedDB失败:', e);
                }
                // 刷新页面
                location.reload();
            }
        },
        'reset-shortcuts': {
            title: '重置快捷访问',
            message: '确定要重置快捷访问吗？这将删除所有自定义快捷方式。',
            onOk: function() {
                // 清除localStorage中的自定义快捷访问数据
                removeLocalStorageItem('custom_shortcuts');
                // 清空隐藏预设记录和顺序
                removeLocalStorageItem('hidden_presets');
                removeLocalStorageItem('shortcut_visible_order');
                // 重新加载菜单（保持context-menu打开，搜索框保持隐藏）
                loadQuickAccessMenu();
                // 重新渲染编辑面板列表
                loadAllShortcuts();
                renderEditShortcutList();
                sendNotice('快捷访问已重置', 'info');
            }
        },
        'discard-changes': {
            title: '放弃更改',
            message: '有未保存的更改，确定要放弃吗？',
            onOk: function() {
                // 恢复所有被编辑过的快捷方式数据
                restoreAllEditedShortcuts();
                // 重置更改状态
                editShortcutHasChanges = false;
                // 关闭面板
                closeEditShortcutPanel();
            }
        },
        'hidden-preset-warn-apply': {
            title: '隐藏预设快捷访问',
            message: '已隐藏预设快捷访问，这些预设将在保存后被隐藏。确定要继续吗？',
            onOk: function() {
                // 继续保存（应用）
                saveShortcutOrder();
                editShortcutHasChanges = false;
                editShortcutOriginalVisibleOrder = editShortcutVisibleItems.map(item => item.id);
                editShortcutOriginalHiddenOrder = editShortcutHiddenItems.map(item => item.id);
                loadQuickAccessMenu();
                sendNotice('设置已应用', 'info');
            }
        },
        'hidden-preset-warn-ok': {
            title: '隐藏预设快捷访问',
            message: '已隐藏预设快捷访问，这些预设将在保存后被隐藏。确定要继续吗？',
            onOk: function() {
                // 继续保存（确定）
                saveShortcutOrder();
                loadQuickAccessMenu();
                closeEditShortcutPanel();
                sendNotice('设置已保存', 'info');
            }
        },
        'delete-custom-shortcut': {
            title: '删除快捷访问',
            message: '确定要删除该快捷访问吗？',
            onOk: function() {
                const category = confirmDialog.dataset.category;
                const index = parseInt(confirmDialog.dataset.targetIndex);
                const items = category === 'visible' ? editShortcutVisibleItems : editShortcutHiddenItems;
                items.splice(index, 1);
                editShortcutHasChanges = true;
                renderEditShortcutList();
            }
        },
        'delete-search-engine': {
            title: '删除搜索引擎',
            message: '确定要删除该自定义搜索引擎吗？',
            onOk: function() {
                const engineId = parseInt(confirmDialog.dataset.targetEngineId, 10);
                const workingSettings = searchEngineSettingsWorking || searchEngineSettings;
                
                // 标记为待删除
                if (!workingSettings.pendingDeleteIds) workingSettings.pendingDeleteIds = [];
                if (!workingSettings.pendingDeleteIds.some(pid => pid == engineId)) {
                    workingSettings.pendingDeleteIds.push(engineId);
                }
                
                // 从所有列表中移除
                const activeIndex = workingSettings.activeEngines.indexOf(engineId);
                if (activeIndex !== -1) workingSettings.activeEngines.splice(activeIndex, 1);
                
                const presetIndex = workingSettings.disabledPresets.indexOf(engineId);
                if (presetIndex !== -1) workingSettings.disabledPresets.splice(presetIndex, 1);
                
                const customIndex = workingSettings.disabledCustoms.indexOf(engineId);
                if (customIndex !== -1) workingSettings.disabledCustoms.splice(customIndex, 1);
                
                searchEngineSettingsHasInnerChanges = true;
                renderSearchEngineLists();
            }
        },
        'reset-search-engines': {
            title: '重置搜索引擎',
            message: '确定要重置所有搜索引擎设置吗？这将删除所有自定义搜索引擎和排序设置。',
            onOk: async function() {
                localStorage.removeItem('search_engine_settings');
                localStorage.removeItem('custom_search_engines');
                // 重置搜索引擎数据并刷新显示
                searchEngineData = null;
                searchEngines = {};
                searchEngineSettings = null;
                searchEngineSettingsWorking = null;
                refreshSearchEngines();
                // 同时刷新主页搜索框
                await loadSearchEngines();
                // 刷新历史记录中无效的搜索引擎ID
                await fixSearchHistoryEngineIds();
                sendNotice('搜索引擎已重置', 'info');
            }
        },
        'restore-search-engines': {
            title: '还原搜索引擎排序',
            message: '确定要恢复默认排序吗？这将把所有预设引擎恢复为默认顺序，自定义搜索引擎将被移至未使用列表。',
            onOk: async function() {
                localStorage.removeItem('search_engine_settings');
                // 刷新搜索引擎显示
                searchEngineSettings = null;
                searchEngineSettingsWorking = null;
                refreshSearchEngines();
                // 同时刷新主页搜索框
                await loadSearchEngines();
                // 刷新历史记录中无效的搜索引擎ID
                await fixSearchHistoryEngineIds();
                sendNotice('搜索引擎排序已还原', 'info');
            }
        },
        'discard-search-engine-changes': {
            title: '放弃更改',
            message: '有未保存的更改，确定要放弃吗？',
            onOk: function() {
                searchEngineSettingsWorking = null;
                searchEngineSettingsHasInnerChanges = false; // 重置内层编辑标志
                // 清除待删除列表
                const workingSettings = searchEngineSettings;
                if (workingSettings) {
                    delete workingSettings.pendingDeleteIds;
                }
                closeSearchEnginePanel();
            }
        },
        'discard-add-search-engine': {
            title: '放弃添加',
            message: '确定要放弃添加搜索引擎吗？输入的内容将不会保存。',
            onOk: function() {
                clearAddSearchEngineInputs();
                closeAddSearchEnginePanel();
            }
        },
        'discard-add-shortcut': {
            title: '放弃添加',
            message: '确定要放弃添加快捷访问吗？输入的内容将不会保存。',
            onOk: function() {
                clearAddShortcutInputs();
                closeAddShortcutPanel();
            }
        }
    };

    // 刷新搜索引擎数据和显示
    async function refreshSearchEngines() {
        // 如果搜索引擎设置面板已打开，使用 loadSearchEnginesForSettings
        if (searchEnginePanel && searchEnginePanel.classList.contains('active')) {
            await loadSearchEnginesForSettings();
            // 重新渲染设置面板列表
            renderSearchEngineLists();
        } else {
            // 否则重新加载搜索引擎数据并刷新主页显示
            await loadSearchEngines();
        }
    }

    // 打开确认对话框
    // 支持传入自定义配置覆盖默认配置
    function openConfirmDialog(actionId, customConfig) {
        const action = confirmActions[actionId];
        if (!action) return;

        // 合并默认配置和自定义配置
        const config = { ...action, ...customConfig };

        if (confirmDialogTitle) confirmDialogTitle.textContent = config.title;
        if (confirmDialogMessage) confirmDialogMessage.innerHTML = config.message;
        
        // 存储当前操作
        confirmDialog.dataset.currentAction = actionId;
        
        // 存储自定义onOk回调
        if (customConfig && customConfig.onOk) {
            confirmDialog.dataset.customOnOk = 'true';
            // 将自定义onOk保存到confirmActions中临时使用
            confirmActions[actionId] = { ...config };
        }
        
        if (confirmDialog) {
            confirmDialog.classList.add('active');
            setBackgroundBlur(true);
        }
    }

    // 关闭确认对话框
    function closeConfirmDialog() {
        if (confirmDialog) {
            confirmDialog.classList.remove('active');
            // 如果设置面板没有打开，则移除背景模糊
            if (!settingsModal || !settingsModal.classList.contains('active')) {
                setBackgroundBlur(false);
            }
        }
    }

    // 点击确认按钮
    if (confirmDialogOk) {
        confirmDialogOk.addEventListener('click', function(e) {
            e.stopPropagation();
            const actionId = confirmDialog.dataset.currentAction;
            const action = confirmActions[actionId];
            if (action && action.onOk) {
                action.onOk();
            }
            closeConfirmDialog();
        });
    }

    // 点击取消按钮
    if (confirmDialogCancel) {
        confirmDialogCancel.addEventListener('click', function(e) {
            e.stopPropagation();
            closeConfirmDialog();
        });
    }

    // 点击关闭按钮
    if (confirmDialogClose) {
        confirmDialogClose.addEventListener('click', function(e) {
            e.stopPropagation();
            closeConfirmDialog();
        });
    }

    // 点击遮罩层关闭
    if (confirmDialogOverlay) {
        confirmDialogOverlay.addEventListener('click', function() {
            closeConfirmDialog();
        });
    }

    // 统一的ESC键关闭处理器（优先级从高到低）
    document.addEventListener('keydown', function(e) {
        if (e.key !== 'Escape') return;

        // 1. 确认对话框 - 最高优先级
        if (confirmDialog && confirmDialog.classList.contains('active')) {
            closeConfirmDialog();
            return;
        }

        // 2. 添加搜索引擎面板
        if (addSearchEnginePanel && addSearchEnginePanel.classList.contains('active')) {
            closeAddSearchEnginePanel();
            return;
        }

        // 3. 添加快捷方式面板
        if (addShortcutPanel && addShortcutPanel.classList.contains('active')) {
            closeAddShortcutPanel();
            return;
        }

        // 4. 壁纸面板
        if (wallpaperPanel && wallpaperPanel.classList.contains('active')) {
            closeWallpaperPanel();
            return;
        }

        // 5. 编辑搜索引擎面板（在搜索引擎面板之前处理）
        if (editSearchEnginePanel && editSearchEnginePanel.classList.contains('active')) {
            closeEditSearchEnginePanel();
            return;
        }

        // 6. 编辑快捷访问项目面板（在快捷访问编辑面板之前处理）
        if (editShortcutItemPanel && editShortcutItemPanel.classList.contains('active')) {
            closeEditShortcutItemPanel();
            return;
        }

        // 7. 搜索引擎面板
        if (searchEnginePanel && searchEnginePanel.classList.contains('active')) {
            const workingSettings = searchEngineSettingsWorking || searchEngineSettings;
            // 检查是否有实际更改（包括内层编辑面板的更改）
            const hasChanges = JSON.stringify(workingSettings) !== JSON.stringify(searchEngineSettings) || searchEngineSettingsHasInnerChanges;
            if (hasChanges) {
                openConfirmDialog('discard-search-engine-changes');
            } else {
                searchEngineSettingsWorking = null;
                closeSearchEnginePanel();
            }
            return;
        }

        // 8. 快捷访问编辑面板
        if (editShortcutPanel && editShortcutPanel.classList.contains('active')) {
            if (editShortcutHasChanges) {
                openConfirmDialog('discard-changes');
            } else {
                closeEditShortcutPanel();
            }
            return;
        }

        // 9. 常规设置面板
        if (settingsModal && settingsModal.classList.contains('active')) {
            closeSettingsModal();
            return;
        }

        // 10. 历史记录设置面板
        if (historySettingsPanel && historySettingsPanel.classList.contains('active')) {
            closeHistorySettingsPanel();
            return;
        }

        // 11. 关于面板 - 最低优先级
        if (aboutPanel && aboutPanel.classList.contains('active')) {
            closeAboutPanel();
        }
    });

    // ==================== 搜索引擎设置面板 ====================
    
    // 搜索引擎设置面板元素
    const searchEnginePanel = document.getElementById('search-engine-panel');
    const searchEngineClose = document.getElementById('search-engine-close');
    const searchEngineAdd = document.getElementById('search-engine-add');
    const searchEngineReset = document.getElementById('search-engine-reset');
    const searchEngineRestore = document.getElementById('search-engine-restore');
    const searchEngineCancel = document.getElementById('search-engine-cancel');
    const searchEngineApply = document.getElementById('search-engine-apply');
    const searchEngineOk = document.getElementById('search-engine-ok');
    const searchEngineActiveList = document.getElementById('search-engine-active-list');
    const searchEnginePresetList = document.getElementById('search-engine-preset-list');
    const searchEngineCustomList = document.getElementById('search-engine-custom-list');
    
    // 添加搜索引擎面板元素
    const addSearchEnginePanel = document.getElementById('add-search-engine-panel');
    const addSearchEngineClose = document.getElementById('add-search-engine-close');
    const addSearchEngineName = document.getElementById('add-search-engine-name');
    const addSearchEngineUrl = document.getElementById('add-search-engine-url');
    const addSearchEngineUrlError = document.getElementById('add-search-engine-url-error');
    const addSearchEngineCancel = document.getElementById('add-search-engine-cancel');
    const addSearchEngineSave = document.getElementById('add-search-engine-save');

    // 初始化分类折叠功能（使用事件委托）
    initSearchEngineCategoryCollapse();

    // 搜索引擎设置

    // 初始化关闭按钮图标
    if (searchEngineClose) {
        searchEngineClose.innerHTML = svgClose;
    }
    if (addSearchEngineClose) {
        addSearchEngineClose.innerHTML = svgClose;
    }

    // 加载搜索引擎数据（用于设置面板）
    async function loadSearchEnginesForSettings() {
        const data = await loadSearchEngineJson();
        if (!data) return;

        // 如果是重置，先清空现有数据
        if (!searchEngineData) {
            searchEngineData = { engines: [] };
            searchEngines = {};
        }

        // 重新填充预设引擎
        searchEngineData.engines = data.engines.slice();
        // 记录预设引擎数量（用于区分预设和自定义）
        presetEngineCount = data.engines.length;

        // 构建搜索引擎映射
        data.engines.forEach(engine => {
            searchEngines[engine.id] = engine;
        });

        // 从localStorage加载自定义搜索引擎（确保设置面板能看到自定义引擎）
        loadCustomSearchEngines();

        // 从localStorage加载设置
        loadSearchEngineSettings();
    }

    // 从localStorage加载自定义搜索引擎
    function loadCustomSearchEngines() {
        try {
            const saved = localStorage.getItem('custom_search_engines');
            if (saved) {
                let customEngines = JSON.parse(saved);
                
                // 检查是否有被标记为删除的引擎（从search_engine_settings中读取pendingDeleteIds）
                const savedSettings = localStorage.getItem('search_engine_settings');
                let pendingDeleteIds = [];
                if (savedSettings) {
                    try {
                        const settings = JSON.parse(savedSettings);
                        pendingDeleteIds = settings.pendingDeleteIds || [];
                    } catch (e) {
                        console.error('解析搜索引擎设置失败:', e);
                    }
                }
                
                // 过滤掉被标记为删除的引擎
                if (pendingDeleteIds.length > 0) {
                    const beforeCount = customEngines.length;
                    customEngines = customEngines.filter(engine => !pendingDeleteIds.includes(engine.id));
                    console.log(`清理了 ${beforeCount - customEngines.length} 个已标记删除的自定义搜索引擎`);
                    
                    // 清理后重新保存custom_search_engines
                    localStorage.setItem('custom_search_engines', JSON.stringify(customEngines));
                    
                    // 清理search_engine_settings中的pendingDeleteIds
                    if (savedSettings) {
                        const settings = JSON.parse(savedSettings);
                        delete settings.pendingDeleteIds;
                        localStorage.setItem('search_engine_settings', JSON.stringify(settings));
                    }
                }
                
                customEngines.forEach(engine => {
                    searchEngineData.engines.push(engine);
                    searchEngines[engine.id] = engine;
                });
            }
        } catch (e) {
            console.error('加载自定义搜索引擎失败:', e);
        }
    }

    // 保存自定义搜索引擎到localStorage
    function saveCustomSearchEngines() {
        try {
            // 只保存非预设引擎（用户添加的自定义引擎）
            const presetIds = searchEngineData.engines.slice(0, presetEngineCount).map(e => e.id);
            const customEngines = searchEngineData.engines.filter(e => !presetIds.includes(e.id));
            localStorage.setItem('custom_search_engines', JSON.stringify(customEngines));
        } catch (e) {
            console.error('保存自定义搜索引擎失败:', e);
        }
    }

    // 从localStorage加载搜索引擎设置
    function loadSearchEngineSettings() {
        try {
            const saved = localStorage.getItem('search_engine_settings');
            if (saved) {
                searchEngineSettings = JSON.parse(saved);
            } else {
                // 默认设置：前7个预设引擎激活，多余的预设引擎放入未使用预设列表，自定义引擎放入未使用自定义列表
                const presetEngines = searchEngineData.engines.slice(0, presetEngineCount);
                const customEngines = searchEngineData.engines.slice(presetEngineCount);
                
                // 前7个预设引擎放入使用中，超出的预设引擎放入未使用预设
                const activePresets = presetEngines.slice(0, 7).map(e => e.id);
                const disabledPresets = presetEngines.slice(7).map(e => e.id);
                
                searchEngineSettings = {
                    activeEngines: activePresets,
                    disabledPresets: disabledPresets,
                    disabledCustoms: customEngines.map(e => e.id)
                };
            }
        } catch (e) {
            console.error('加载搜索引擎设置失败:', e);
        }
    }

    // 保存搜索引擎设置到localStorage
    function saveSearchEngineSettings() {
        localStorage.setItem('search_engine_settings', JSON.stringify(searchEngineSettings));
    }

    // 打开搜索引擎设置面板
    function openSearchEnginePanel() {
        if (searchEnginePanel) {
            // 先重置所有分类的折叠状态
            const categories = document.querySelectorAll('.search-engine-category');
            categories.forEach(cat => {
                cat.classList.remove('collapsed');
            });
            // 清空错误提示
            const countError = document.getElementById('search-engine-count-error');
            if (countError) countError.textContent = '';
            // 创建设置的内存副本，用于暂存用户操作
            searchEngineSettingsWorking = JSON.parse(JSON.stringify(searchEngineSettings));
            renderSearchEngineLists();
            initSearchEngineCategoryCollapse();
            searchEnginePanel.classList.add('active');
            updateSettingsButtonVisibility();
        }
    }

    // 关闭搜索引擎设置面板
    function closeSearchEnginePanel() {
        if (searchEnginePanel) {
            searchEnginePanel.classList.remove('active');
            updateSettingsButtonVisibility();
        }
    }

    // 渲染搜索引擎列表
    function renderSearchEngineLists() {
        if (!searchEngineData) return;
        
        const workingSettings = searchEngineSettingsWorking || searchEngineSettings;
        const activeIds = workingSettings.activeEngines;
        const disabledPresetIds = workingSettings.disabledPresets;
        const disabledCustomIds = workingSettings.disabledCustoms;
        const pendingDeleteIds = workingSettings.pendingDeleteIds || [];
        
        // 排除待删除的引擎（使用 == 进行宽松比较以处理字符串/数字类型差异）
        const filteredActiveIds = activeIds.filter(id => !pendingDeleteIds.some(pid => pid == id));
        const filteredDisabledPresetIds = disabledPresetIds.filter(id => !pendingDeleteIds.some(pid => pid == id));
        const filteredDisabledCustomIds = disabledCustomIds.filter(id => !pendingDeleteIds.some(pid => pid == id));
        
        // 按activeIds顺序渲染使用中的引擎
        const activeEngines = filteredActiveIds.map(id => searchEngines[id]).filter(Boolean);
        renderSearchEngineCategory(searchEngineActiveList, activeEngines, 'active');
        
        // 渲染未使用的预设
        const presetEngines = filteredDisabledPresetIds.map(id => searchEngines[id]).filter(Boolean);
        renderSearchEngineCategory(searchEnginePresetList, presetEngines, 'preset');
        
        // 渲染未使用的自定义
        const customEngines = filteredDisabledCustomIds.map(id => searchEngines[id]).filter(Boolean);
        renderSearchEngineCategory(searchEngineCustomList, customEngines, 'custom');
    }

    // 渲染单个分类的搜索引擎列表
    function renderSearchEngineCategory(container, engines, category) {
        container.innerHTML = '';
        // 获取预设引擎的id列表
        const presetIds = searchEngineData.engines.slice(0, presetEngineCount).map(e => e.id);
        
        engines.forEach((engine, index) => {
            const item = document.createElement('div');
            item.className = 'search-engine-item';
            item.dataset.engineId = engine.id;
            item.title = engine.comment || ''; // 悬停显示 comment
            const isPreset = presetIds.includes(engine.id); // 判断是否为预设搜索引擎
            const isFirst = index === 0;
            const isLast = index === engines.length - 1;
            
            // 根据分类生成不同的操作按钮
            let actionButtons = '';
            if (category === 'active') {
                // 使用中：显示上移、下移、移至未使用
                actionButtons = `
                    <button class="search-engine-move-up" title="上移" ${isFirst ? 'disabled' : ''}>${svgArrowUp}</button>
                    <button class="search-engine-move-down" title="下移" ${isLast ? 'disabled' : ''}>${svgArrowDown}</button>
                    <button class="search-engine-disable" title="移至未使用" data-engine-id="${engine.id}">${svgMinus}</button>
                `;
            } else if (category === 'preset') {
                // 未使用的预设：显示移至使用中
                actionButtons = `
                    <button class="search-engine-enable" title="移至使用中" data-engine-id="${engine.id}">${svgPlus}</button>
                `;
            } else {
                // 未使用的自定义：显示移至使用中、删除
                actionButtons = `
                    <button class="search-engine-enable" title="移至使用中" data-engine-id="${engine.id}">${svgPlus}</button>
                    <button class="search-engine-delete" title="删除" data-engine-id="${engine.id}" ${isPreset ? 'disabled' : ''}>${svgClose}</button>
                `;
            }
            
            item.innerHTML = `
                <div class="search-engine-item-icon">${getSearchEngineIcon(engine.icon)}</div>
                <span class="search-engine-item-name">
                    ${isPreset ? '<span class="preset-tag">预设</span>' : ''}${engine.title}
                </span>
                <div class="search-engine-item-actions">
                    ${actionButtons}
                </div>
            `;
            
            // 绑定上移按钮事件
            const moveUp = item.querySelector('.search-engine-move-up');
            if (moveUp) {
                moveUp.addEventListener('click', () => moveSearchEngine(engine.id, -1, category));
            }
            
            // 绑定下移按钮事件
            const moveDown = item.querySelector('.search-engine-move-down');
            if (moveDown) {
                moveDown.addEventListener('click', () => moveSearchEngine(engine.id, 1, category));
            }
            
            // 绑定移至未使用按钮事件
            const disableBtn = item.querySelector('.search-engine-disable');
            if (disableBtn) {
                disableBtn.addEventListener('click', () => disableSearchEngine(engine.id));
            }
            
            // 绑定移至使用中按钮事件
            const enableBtn = item.querySelector('.search-engine-enable');
            if (enableBtn) {
                enableBtn.addEventListener('click', () => enableSearchEngine(engine.id, isPreset ? 'preset' : 'custom'));
            }
            
            // 绑定删除按钮事件
            const deleteBtn = item.querySelector('.search-engine-delete');
            if (deleteBtn) {
                deleteBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    confirmDialog.dataset.targetEngineId = engine.id;
                    openConfirmDialog('delete-search-engine');
                });
            }
            
            container.appendChild(item);
        });
    }

    // 初始化分类折叠功能（使用事件委托）
    function initSearchEngineCategoryCollapse() {
        // 使用事件委托，在面板上绑定一次事件
        if (searchEnginePanel && !searchEnginePanel.dataset.collapseInitialized) {
            searchEnginePanel.addEventListener('click', function(e) {
                const header = e.target.closest('.search-engine-category-header');
                if (header) {
                    const category = header.closest('.search-engine-category');
                    if (category) {
                        category.classList.toggle('collapsed');
                    }
                }
            });
            searchEnginePanel.dataset.collapseInitialized = 'true';
        }
    }

    // 移动搜索引擎顺序
    function moveSearchEngine(engineId, direction, category) {
        const workingSettings = searchEngineSettingsWorking || searchEngineSettings;
        let list;
        if (category === 'active') {
            list = workingSettings.activeEngines;
        } else if (category === 'preset') {
            list = workingSettings.disabledPresets;
        } else {
            list = workingSettings.disabledCustoms;
        }
        
        const index = list.indexOf(engineId);
        if (index === -1) return;
        
        const newIndex = index + direction;
        if (newIndex < 0 || newIndex >= list.length) return;
        
        // 交换位置
        [list[index], list[newIndex]] = [list[newIndex], list[index]];
        // 重新渲染列表
        renderSearchEngineLists();
    }

    // 移至未使用
    function disableSearchEngine(engineId) {
        const workingSettings = searchEngineSettingsWorking || searchEngineSettings;
        // 判断是否为预设引擎：id在前presetEngineCount个预设引擎中
        const presetIds = searchEngineData.engines.slice(0, presetEngineCount).map(e => e.id);
        const isPreset = presetIds.includes(engineId);
        
        // 从使用中移除
        const activeIndex = workingSettings.activeEngines.indexOf(engineId);
        if (activeIndex === -1) return;
        workingSettings.activeEngines.splice(activeIndex, 1);
        
        // 添加到对应的未使用列表
        if (isPreset) {
            workingSettings.disabledPresets.push(engineId);
        } else {
            workingSettings.disabledCustoms.push(engineId);
        }
        
        renderSearchEngineLists();
    }

    // 移至使用中
    function enableSearchEngine(engineId, sourceCategory) {
        const workingSettings = searchEngineSettingsWorking || searchEngineSettings;
        
        // 从对应的未使用列表移除
        if (sourceCategory === 'preset') {
            const index = workingSettings.disabledPresets.indexOf(engineId);
            if (index !== -1) workingSettings.disabledPresets.splice(index, 1);
        } else {
            const index = workingSettings.disabledCustoms.indexOf(engineId);
            if (index !== -1) workingSettings.disabledCustoms.splice(index, 1);
        }
        
        // 添加到使用中
        workingSettings.activeEngines.push(engineId);
        renderSearchEngineLists();
    }

    // 打开添加搜索引擎面板
    function openAddSearchEnginePanel() {
        if (addSearchEnginePanel) {
            addSearchEngineName.value = '';
            addSearchEngineUrl.value = '';
            addSearchEngineUrlError.textContent = '';
            addSearchEnginePanel.classList.add('active');
            updateSettingsButtonVisibility();
        }
    }

    // 关闭添加搜索引擎面板
    function closeAddSearchEnginePanel(checkInput = true) {
        if (checkInput && hasAddSearchEngineInput()) {
            openConfirmDialog('discard-add-search-engine');
            return;
        }
        if (addSearchEnginePanel) {
            addSearchEnginePanel.classList.remove('active');
            updateSettingsButtonVisibility();
        }
    }

    // 检查添加搜索引擎面板是否有输入内容
    function hasAddSearchEngineInput() {
        const name = addSearchEngineName?.value.trim();
        const url = addSearchEngineUrl?.value.trim();
        return !!(name || url);
    }

    // 清除添加搜索引擎面板的输入
    function clearAddSearchEngineInputs() {
        if (addSearchEngineName) addSearchEngineName.value = '';
        if (addSearchEngineUrl) addSearchEngineUrl.value = '';
        if (addSearchEngineUrlError) addSearchEngineUrlError.textContent = '';
    }

    // 验证搜索引擎URL格式
    function validateSearchEngineUrl(url) {
        if (!url.trim()) {
            return { valid: false, message: 'URL不能为空' };
        }
        // 检查协议是否为 http、https 或 ftp
        const trimmedUrl = url.trim();
        if (!/^https?:\/\//i.test(trimmedUrl) && !/^ftp:\/\//i.test(trimmedUrl)) {
            return { valid: false, message: 'URL协议不支持，仅支持 http://、https:// 和 ftp://' };
        }
        if (!url.includes('%s')) {
            return { valid: false, message: 'URL中必须包含 %s 作为搜索关键词占位符' };
        }
        return { valid: true, message: '' };
    }

    // 验证并添加搜索引擎
    function addSearchEngine() {
        const rawName = addSearchEngineName.value.trim();
        const url = addSearchEngineUrl.value.trim();
        
        const validation = validateSearchEngineUrl(url);
        if (!validation.valid) {
            addSearchEngineUrlError.textContent = validation.message;
            return false;
        }
        
        // 使用Security模块净化名称输入（防止XSS）
        const sanitizedName = Security.sanitizeXss(rawName);
        
        // 检查名称是否合法：非空且不包含HTML标签
        const isNameValid = rawName.length > 0 && !/<[^>]*>/i.test(rawName);
        
        // 自定义搜索引擎ID从10001开始，如果有冲突则顺延
        let newId = 10001;
        while (searchEngines[newId]) {
            newId++;
        }
        
        const newEngine = {
            id: newId,
            // 如果名称不合法，使用"未命名的搜索引擎"
            title: isNameValid ? sanitizedName : '未命名的搜索引擎',
            icon: 'mc',  // 存储图标名称(MyCustom)而不是完整SVG
            url: url,
            comment: '自定义搜索引擎'
        };
        
        // 添加到列表
        searchEngineData.engines.push(newEngine);
        searchEngines[newId] = newEngine;
        
        // 保存自定义搜索引擎到localStorage
        saveCustomSearchEngines();
        
        // 设置为激活状态（添加到工作副本）
        const workingSettings = searchEngineSettingsWorking || searchEngineSettings;
        
        // 检查是否已存在于使用中列表，避免重复添加
        if (!workingSettings.activeEngines.includes(newId)) {
            workingSettings.activeEngines.push(newId);
        }
        
        // 确保新引擎不在未使用的自定义列表中（如果有的话）
        const disabledCustomIndex = workingSettings.disabledCustoms.indexOf(newId);
        if (disabledCustomIndex !== -1) {
            workingSettings.disabledCustoms.splice(disabledCustomIndex, 1);
        }

        // 先清除输入，再关闭面板（避免保存成功后又弹出警告）
        clearAddSearchEngineInputs();
        closeAddSearchEnginePanel();
        renderSearchEngineLists();
        sendNotice('搜索引擎已添加', 'info');

        return true;
    }

    // 绑定搜索引擎面板事件
    if (searchEngineClose) {
        searchEngineClose.addEventListener('click', () => {
            // 检查是否有未保存的更改（包括内层编辑面板的更改）
            const workingSettings = searchEngineSettingsWorking || searchEngineSettings;
            const hasChanges = JSON.stringify(workingSettings) !== JSON.stringify(searchEngineSettings) || searchEngineSettingsHasInnerChanges;
            if (hasChanges) {
                openConfirmDialog('discard-search-engine-changes');
            } else {
                searchEngineSettingsWorking = null;
                closeSearchEnginePanel();
            }
        });
    }
        if (searchEngineAdd) {
            searchEngineAdd.addEventListener('click', openAddSearchEnginePanel);
        }
        
        // 重置：删除所有自定义引擎和排序设置
        if (searchEngineReset) {
            searchEngineReset.addEventListener('click', () => {
                openConfirmDialog('reset-search-engines');
            });
        }
        
        // 还原：恢复默认排序
        if (searchEngineRestore) {
            searchEngineRestore.addEventListener('click', () => {
                openConfirmDialog('restore-search-engines');
            });
        }
        
        if (searchEngineCancel) {
            searchEngineCancel.addEventListener('click', () => {
                // 检查是否有未保存的更改（包括内层编辑面板的更改）
                const workingSettings = searchEngineSettingsWorking || searchEngineSettings;
                const hasChanges = JSON.stringify(workingSettings) !== JSON.stringify(searchEngineSettings) || searchEngineSettingsHasInnerChanges;
                if (hasChanges) {
                    openConfirmDialog('discard-search-engine-changes');
                } else {
                    searchEngineSettingsWorking = null;
                    closeSearchEnginePanel();
                }
            });
        }
    if (searchEngineApply || searchEngineOk) {
        const applySettings = () => {
            const workingSettings = searchEngineSettingsWorking || searchEngineSettings;
            
            // 检查是否有实际更改
            const hasChanges = JSON.stringify(workingSettings) !== JSON.stringify(searchEngineSettings);
            if (!hasChanges) {
                sendNotice('没有未保存的更改', 'info');
                return;
            }
            
            // 验证使用中的引擎数量必须为7
            const presetIds = searchEngineData.engines.slice(0, presetEngineCount).map(e => e.id);
            const presetCount = workingSettings.activeEngines.filter(id => presetIds.includes(id)).length;
            const customCount = workingSettings.activeEngines.filter(id => !presetIds.includes(id)).length;
            const totalCount = workingSettings.activeEngines.length;
            const countError = document.getElementById('search-engine-count-error');
            
            if (totalCount !== 7) {
                if (countError) countError.textContent = `使用中的引擎数量必须为7个，当前为${totalCount}个`;
                return;
            }
            if (countError) countError.textContent = '';
            
            // 保存到localStorage
            searchEngineSettings = JSON.parse(JSON.stringify(workingSettings));
            localStorage.setItem('search_engine_settings', JSON.stringify(searchEngineSettings));
            searchEngineSettingsWorking = null;
            searchEngineSettingsHasInnerChanges = false; // 重置内层编辑标志
            
            // 执行待删除的搜索引擎（从searchEngines和searchEngineData中移除）
            const pendingDeleteIds = workingSettings.pendingDeleteIds || [];
            pendingDeleteIds.forEach(engineId => {
                delete searchEngines[engineId];
                const engineIndex = searchEngineData.engines.findIndex(e => e.id === engineId);
                if (engineIndex !== -1) searchEngineData.engines.splice(engineIndex, 1);
            });
            saveCustomSearchEngines();
            
            // 刷新历史记录中无效的搜索引擎ID
            fixSearchHistoryEngineIds();
            
            // 重新渲染主页搜索引擎
            renderSearchEngineIcons();
            sendNotice('搜索引擎设置已保存', 'info');
        };
        
        // 应用：保存设置但不关闭面板
        if (searchEngineApply) {
            searchEngineApply.addEventListener('click', () => {
                const workingSettings = searchEngineSettingsWorking || searchEngineSettings;
                
                // 检查是否有实际更改（包括内层编辑面板的更改）
                const hasChanges = JSON.stringify(workingSettings) !== JSON.stringify(searchEngineSettings) || searchEngineSettingsHasInnerChanges;
                if (!hasChanges) {
                    sendNotice('没有未保存的更改', 'info');
                    return;
                }
                
                // 验证使用中的引擎数量必须为7
                const presetIds = searchEngineData.engines.slice(0, presetEngineCount).map(e => e.id);
                const presetCount = workingSettings.activeEngines.filter(id => presetIds.includes(id)).length;
                const customCount = workingSettings.activeEngines.filter(id => !presetIds.includes(id)).length;
                const totalCount = workingSettings.activeEngines.length;
                const countError = document.getElementById('search-engine-count-error');
                
                if (totalCount !== 7) {
                    if (countError) countError.textContent = `使用中的引擎数量必须为7个，当前为${totalCount}个`;
                    return; // 不执行保存
                }
                if (countError) countError.textContent = '';
                
                // 验证通过，保存设置
                searchEngineSettings = JSON.parse(JSON.stringify(workingSettings));
                localStorage.setItem('search_engine_settings', JSON.stringify(searchEngineSettings));
                
                // 执行待删除的搜索引擎（从searchEngines和searchEngineData中移除）
                const pendingDeleteIds = workingSettings.pendingDeleteIds || [];
                pendingDeleteIds.forEach(engineId => {
                    delete searchEngines[engineId];
                    const engineIndex = searchEngineData.engines.findIndex(e => e.id === engineId);
                    if (engineIndex !== -1) searchEngineData.engines.splice(engineIndex, 1);
                });
                saveCustomSearchEngines();
                
                // 刷新历史记录中无效的搜索引擎ID
                fixSearchHistoryEngineIds();
                
                // 重新渲染主页搜索引擎
                renderSearchEngineIcons();
                sendNotice('设置已应用', 'info');
            });
        }
        
        // 确定：保存设置并关闭面板
        if (searchEngineOk) {
            searchEngineOk.addEventListener('click', () => {
                // 只有在applySettings成功执行时才关闭面板
                const workingSettings = searchEngineSettingsWorking || searchEngineSettings;
                
                // 检查是否有实际更改（包括内层编辑面板的更改）
                const hasChanges = JSON.stringify(workingSettings) !== JSON.stringify(searchEngineSettings) || searchEngineSettingsHasInnerChanges;
                if (!hasChanges) {
                    sendNotice('没有未保存的更改', 'info');
                    closeSearchEnginePanel();
                    return;
                }
                
                // 验证使用中的引擎数量必须为7
                const presetIds = searchEngineData.engines.slice(0, presetEngineCount).map(e => e.id);
                const presetCount = workingSettings.activeEngines.filter(id => presetIds.includes(id)).length;
                const customCount = workingSettings.activeEngines.filter(id => !presetIds.includes(id)).length;
                const totalCount = workingSettings.activeEngines.length;
                const countError = document.getElementById('search-engine-count-error');
                
                if (totalCount !== 7) {
                    if (countError) countError.textContent = `使用中的引擎数量必须为7个，当前为${totalCount}个`;
                    return; // 不关闭面板
                }
                if (countError) countError.textContent = '';
                
                // 验证通过，保存设置
                searchEngineSettings = JSON.parse(JSON.stringify(workingSettings));
                localStorage.setItem('search_engine_settings', JSON.stringify(searchEngineSettings));
                searchEngineSettingsWorking = null;
                searchEngineSettingsHasInnerChanges = false; // 重置内层编辑标志
                
                // 刷新历史记录中无效的搜索引擎ID
                fixSearchHistoryEngineIds();
                
                // 重新渲染主页搜索引擎
                renderSearchEngineIcons();
                sendNotice('搜索引擎设置已保存', 'info');
                
                // 成功保存后关闭面板
                closeSearchEnginePanel();
            });
        }
    }
    
    // 面板遮罩点击关闭
    const searchEngineOverlay = document.querySelector('#search-engine-panel .settings-modal-overlay');
    if (searchEngineOverlay) {
        searchEngineOverlay.addEventListener('click', () => {
            // 检查是否有未保存的更改（包括内层编辑面板的更改）
            const workingSettings = searchEngineSettingsWorking || searchEngineSettings;
            const hasChanges = JSON.stringify(workingSettings) !== JSON.stringify(searchEngineSettings) || searchEngineSettingsHasInnerChanges;
            if (hasChanges) {
                openConfirmDialog('discard-search-engine-changes');
            } else {
                searchEngineSettingsWorking = null;
                closeSearchEnginePanel();
            }
        });
    }

    // 绑定添加搜索引擎面板事件
    if (addSearchEngineClose) {
        addSearchEngineClose.addEventListener('click', closeAddSearchEnginePanel);
    }
    if (addSearchEngineCancel) {
        addSearchEngineCancel.addEventListener('click', closeAddSearchEnginePanel);
    }
    if (addSearchEngineSave) {
        addSearchEngineSave.addEventListener('click', addSearchEngine);
    }
    if (addSearchEngineUrl) {
        // 失焦验证
        addSearchEngineUrl.addEventListener('blur', function() {
            const validation = validateSearchEngineUrl(this.value);
            addSearchEngineUrlError.textContent = validation.message;
        });
        // 输入时清除错误
        addSearchEngineUrl.addEventListener('input', function() {
            addSearchEngineUrlError.textContent = '';
        });
    }

    // 面板遮罩点击关闭
    const addSearchEngineOverlay = document.querySelector('#add-search-engine-panel .settings-modal-overlay');
    if (addSearchEngineOverlay) {
        addSearchEngineOverlay.addEventListener('click', closeAddSearchEnginePanel);
    }

    // ==================== 添加快捷方式面板 ====================
    
    // 添加快捷方式面板元素
    const addShortcutPanel = document.getElementById('add-shortcut-panel');
    const addShortcutClose = document.getElementById('add-shortcut-close');
    const addShortcutUrl = document.getElementById('add-shortcut-url');
    const addShortcutName = document.getElementById('add-shortcut-name');
    const addShortcutIcon = document.getElementById('add-shortcut-icon');
    const addShortcutPreviewIcon = document.getElementById('add-shortcut-preview-icon');
    const addShortcutCancel = document.getElementById('add-shortcut-cancel');
    const addShortcutSave = document.getElementById('add-shortcut-save');
    const addShortcutOverlay = document.querySelector('#add-shortcut-panel .settings-modal-overlay');

    // 用于取消进行中的请求
    let addPanelAbortController = null;

    // 初始化关闭按钮图标
    if (addShortcutClose) {
        addShortcutClose.innerHTML = svgClose;
    }

    // 验证URL格式并补全协议
    function normalizeUrl(url) {
        url = url.trim();
        if (!url) return '';
        if (!/^https?:\/\//i.test(url)) {
            url = 'http://' + url;
        }
        return url;
    }

    // 验证图标URL格式（必须是ico/png/jpg）
    function isValidIconUrl(url) {
        if (!url || !url.trim()) return false;
        url = url.trim().toLowerCase();
        return /\.(ico|png|jpg|jpeg)(\?.*)?$/i.test(url);
    }

    // 从URL提取favicon地址
    function getFaviconFromUrl(url) {
        try {
            const urlObj = new URL(url);
            return urlObj.origin + '/favicon.ico';
        } catch (e) {
            return null;
        }
    }

    // 打开添加快捷方式面板
    function openAddShortcutPanel() {
        if (addShortcutPanel) {
            // 取消之前进行中的请求
            if (addPanelAbortController) {
                addPanelAbortController.abort();
                addPanelAbortController = null;
            }
            
            addShortcutPanel.classList.add('active');
            updateSettingsButtonVisibility();
            // 不改变背景模糊状态
            // 清空表单
            addShortcutUrl.value = '';
            addShortcutName.value = '';
            addShortcutIcon.value = '';
            addShortcutPreviewIcon.innerHTML = defaultIconSVG;
            addShortcutUrl.focus();
        }
    }

    // 关闭添加快捷方式面板
    function closeAddShortcutPanel(checkInput = true) {
        if (checkInput && hasAddShortcutInput()) {
            openConfirmDialog('discard-add-shortcut');
            return;
        }
        if (addShortcutPanel) {
            addShortcutPanel.classList.remove('active');
            updateSettingsButtonVisibility();
            // 取消进行中的请求
            if (addPanelAbortController) {
                addPanelAbortController.abort();
                addPanelAbortController = null;
            }
            // 不关闭背景模糊，保留快捷访问菜单
        }
    }

    // 检查添加快捷访问面板是否有输入内容
    function hasAddShortcutInput() {
        const url = addShortcutUrl?.value.trim();
        const name = addShortcutName?.value.trim();
        const icon = addShortcutIcon?.value.trim();
        return !!(url || name || icon);
    }

    // 清除添加快捷访问面板的输入
    function clearAddShortcutInputs() {
        if (addShortcutUrl) addShortcutUrl.value = '';
        if (addShortcutName) addShortcutName.value = '';
        if (addShortcutIcon) addShortcutIcon.value = '';
        if (addShortcutPreviewIcon) {
            addShortcutPreviewIcon.innerHTML = defaultIconSVG;
        }
    }

    // 更新图标预览
    function updateIconPreview(iconUrl) {
        if (!iconUrl || !iconUrl.trim()) {
            addShortcutPreviewIcon.innerHTML = defaultIconSVG;
            return;
        }
        
        if (isValidIconUrl(iconUrl)) {
            const img = new Image();
            img.onload = function() {
                addShortcutPreviewIcon.innerHTML = '<img src="' + iconUrl + '" style="width:32px;height:32px;">';
            };
            img.onerror = function() {
                sendNotice('图标加载失败，将使用默认图标', 'warn');
                addShortcutPreviewIcon.innerHTML = defaultIconSVG;
            };
            img.src = iconUrl;
        } else {
            sendNotice('图标格式不支持，请使用 ico/png/jpg 格式', 'warn');
            addShortcutPreviewIcon.innerHTML = defaultIconSVG;
        }
    }

    // URL失焦时自动获取信息
    addShortcutUrl.addEventListener('blur', async function() {
        const url = normalizeUrl(this.value);
        if (!url) return;
        
        this.value = url;
        
        // 检查用户是否已手动输入标题或图标，如果是则不自动获取
        const userHasEnteredTitle = addShortcutName.value.trim() !== '';
        const userHasEnteredIcon = addShortcutIcon.value.trim() !== '';
        
        // 创建新的AbortController用于这次请求
        if (addPanelAbortController) {
            addPanelAbortController.abort();
        }
        addPanelAbortController = new AbortController();
        
        // 只有用户未手动输入图标时才获取favicon
        if (!userHasEnteredIcon) {
            const faviconUrl = getFaviconFromUrl(url);
            const img = new Image();
            img.onload = function() {
                addShortcutPreviewIcon.innerHTML = '<img src="' + faviconUrl + '" style="width:32px;height:32px;">';
                // 填充favicon URL到输入框
                addShortcutIcon.value = faviconUrl;
            };
            img.onerror = function() {
                addShortcutPreviewIcon.innerHTML = defaultIconSVG;
                // favicon获取失败时不填充输入框
            };
            img.src = faviconUrl;
        }
    });

    // 图标输入失焦时验证
    addShortcutIcon.addEventListener('blur', function() {
        updateIconPreview(this.value);
    });

    // 点击关闭按钮
    if (addShortcutClose) {
        addShortcutClose.addEventListener('click', function(e) {
            e.stopPropagation();
            closeAddShortcutPanel();
        });
    }

    // 点击取消按钮
    if (addShortcutCancel) {
        addShortcutCancel.addEventListener('click', function(e) {
            e.stopPropagation();
            closeAddShortcutPanel();
        });
    }

    // 点击保存按钮
    if (addShortcutSave) {
        addShortcutSave.addEventListener('click', function(e) {
            e.stopPropagation();
            
            // 使用Security模块净化URL输入
            const rawUrl = addShortcutUrl.value.trim();
            const sanitizedUrl = Security.sanitizeUrl(rawUrl);
            
            if (!sanitizedUrl) {
                sendNotice('请输入有效的URL', 'warn');
                return;
            }
            
            // 验证URL格式
            try {
                new URL(sanitizedUrl);
            } catch (e) {
                sendNotice('URL格式不正确', 'warn');
                return;
            }
            
            // 使用Security模块净化名称输入（防止XSS）
            const rawName = addShortcutName.value.trim();
            const sanitizedName = Security.sanitizeXss(rawName);
            
            // 检查名称是否合法：非空且不包含HTML标签（说明原始输入不合法）
            const isNameValid = rawName.length > 0 && !/<[^>]*>/i.test(rawName);
            
            // 使用Security模块净化图标URL
            const rawIcon = addShortcutIcon.value.trim();
            let sanitizedIcon = '';
            if (rawIcon) {
                sanitizedIcon = Security.sanitizeUrl(rawIcon);
                if (!sanitizedIcon) {
                    sendNotice('图标URL无效，将使用默认图标', 'warn');
                }
            }
            
            // 如果名称为空或不合法，使用"未命名的快捷方式"
            const name = isNameValid ? sanitizedName : '未命名的快捷方式';
            let icon = sanitizedIcon;
            
            // 如果没有指定图标，使用默认图标（空字符串会显示默认图标）
            if (!icon) {
                icon = '';
            } else if (!isValidIconUrl(icon)) {
                sendNotice('图标格式不支持，将使用默认图标', 'warn');
                icon = '';
            }
            
            // 保存到localStorage
            const customShortcuts = getLocalStorageItem('custom_shortcuts') || [];
            const newShortcut = {
                id: Date.now(),
                url: sanitizedUrl,
                title: name,
                icon: icon,
                position: customShortcuts.length // 使用当前长度作为位置信息
            };
            customShortcuts.push(newShortcut);
            setLocalStorageItem('custom_shortcuts', customShortcuts);

            // 先清除输入，再关闭面板（避免保存成功后又弹出警告）
            clearAddShortcutInputs();
            closeAddShortcutPanel();

            // 重新加载菜单
            loadQuickAccessMenu();
        });
    }

    // 点击遮罩层关闭
    if (addShortcutOverlay) {
        addShortcutOverlay.addEventListener('click', function(e) {
            e.stopPropagation();
            closeAddShortcutPanel();
        });
    }

    // 编辑快捷访问面板相关
    const editShortcutPanel = document.getElementById('edit-shortcut-panel');
    const editShortcutClose = document.getElementById('edit-shortcut-close');
    const editShortcutReset = document.getElementById('edit-shortcut-reset');
    const editShortcutList = document.getElementById('edit-shortcut-list');
    const editShortcutCancel = document.getElementById('edit-shortcut-cancel');
    const editShortcutApply = document.getElementById('edit-shortcut-apply');
    const editShortcutOk = document.getElementById('edit-shortcut-ok');
    const editShortcutOverlay = editShortcutPanel ? editShortcutPanel.querySelector('.settings-modal-overlay') : null;
    const editShortcutVisibleList = document.getElementById('edit-shortcut-visible-list');
    const editShortcutHiddenList = document.getElementById('edit-shortcut-hidden-list');

    let editShortcutVisibleItems = []; // 显示中的项目列表
    let editShortcutHiddenItems = []; // 隐藏的项目列表
    let editShortcutOriginalVisibleOrder = []; // 原始显示顺序，用于检测更改
    let editShortcutOriginalHiddenOrder = []; // 原始隐藏顺序，用于检测更改
    let editShortcutHasChanges = false; // 是否有更改

    // 初始化分类折叠功能（使用事件委托）
    initEditShortcutCategoryCollapse();

    // 打开编辑快捷访问面板
    function openEditShortcutPanel() {
        if (editShortcutPanel) {
            // 先重置所有分类的折叠状态
            const categories = document.querySelectorAll('.edit-shortcut-category');
            categories.forEach(cat => {
                cat.classList.remove('collapsed');
            });
            // 加载所有快捷方式
            loadAllShortcuts();
            // 保存原始顺序
            editShortcutOriginalVisibleOrder = editShortcutVisibleItems.map(item => item.id);
            editShortcutOriginalHiddenOrder = editShortcutHiddenItems.map(item => item.id);
            editShortcutHasChanges = false;
            // 渲染列表
            renderEditShortcutList();
            editShortcutPanel.classList.add('active');
            updateSettingsButtonVisibility();
        }
    }

    // 关闭编辑快捷访问面板
    function closeEditShortcutPanel() {
        if (editShortcutPanel) {
            editShortcutPanel.classList.remove('active');
            updateSettingsButtonVisibility();
        }
    }

    // 恢复所有被编辑过的快捷方式数据
    function restoreAllEditedShortcuts() {
        // 恢复editShortcutVisibleItems中的数据
        editShortcutVisibleItems.forEach(item => {
            if (item.originalData) {
                item.url = item.originalData.url;
                item.title = item.originalData.title;
                item.icon = item.originalData.icon;
            }
        });
        // 恢复editShortcutHiddenItems中的数据
        editShortcutHiddenItems.forEach(item => {
            if (item.originalData) {
                item.url = item.originalData.url;
                item.title = item.originalData.title;
                item.icon = item.originalData.icon;
            }
        });
        // 重新渲染列表
        renderEditShortcutList();
    }

    // 加载所有快捷方式（预设 + 自定义）- 类似搜索引擎的混合排序
    function loadAllShortcuts() {
        // 创建预设映射
        const presetMap = {};
        quickAccessData.forEach(item => {
            presetMap[item.id] = { ...item, isPreset: true };
        });
        
        // 读取保存的快捷访问顺序（混合保存预设和自定义）
        const savedVisibleOrder = getLocalStorageItem('shortcut_visible_order') || [];
        
        // 读取隐藏的预设列表
        const hiddenPresets = getLocalStorageItem('hidden_presets') || [];
        
        // 读取自定义快捷方式
        const customShortcuts = getLocalStorageItem('custom_shortcuts') || [];
        const customMap = {};
        customShortcuts.forEach(item => {
            customMap[item.id] = { ...item, isPreset: false };
        });
        
        // 按保存的顺序加载显示中的项目
        const visibleItems = [];
        const visiblePresetIds = new Set();
        const visibleCustomIds = new Set();
        
        savedVisibleOrder.forEach(id => {
            if (id.startsWith('preset_')) {
                const presetId = parseInt(id.replace('preset_', ''));
                if (presetMap[presetId] && !hiddenPresets.includes(presetId)) {
                    visibleItems.push({
                        id: id,
                        presetId: presetId,
                        url: presetMap[presetId].url,
                        title: presetMap[presetId].title,
                        icon: presetMap[presetId].icon,
                        isPreset: true,
                        isHidden: false
                    });
                    visiblePresetIds.add(presetId);
                }
            } else if (id.startsWith('custom_')) {
                const customId = parseInt(id.replace('custom_', ''));
                if (customMap[customId]) {
                    visibleItems.push({
                        id: id,
                        customId: customId,
                        url: customMap[customId].url,
                        title: customMap[customId].title,
                        icon: customMap[customId].icon,
                        position: customMap[customId].position,
                        isPreset: false,
                        isHidden: false
                    });
                    visibleCustomIds.add(customId);
                }
            }
        });
        
        // 添加未保存顺序的预设（新增的预设）
        quickAccessData.forEach(item => {
            if (!visiblePresetIds.has(item.id) && !hiddenPresets.includes(item.id)) {
                visibleItems.push({
                    id: 'preset_' + item.id,
                    presetId: item.id,
                    url: item.url,
                    title: item.title,
                    icon: item.icon,
                    isPreset: true,
                    isHidden: false
                });
                visiblePresetIds.add(item.id);
            }
        });
        
        // 添加未保存顺序的自定义快捷方式
        customShortcuts.forEach(item => {
            if (!visibleCustomIds.has(item.id)) {
                visibleItems.push({
                    id: 'custom_' + item.id,
                    customId: item.id,
                    url: item.url,
                    title: item.title,
                    icon: item.icon,
                    position: item.position,
                    isPreset: false,
                    isHidden: false
                });
            }
        });
        
        // 加载隐藏的预设
        const hiddenItems = [];
        hiddenPresets.forEach(presetId => {
            if (presetMap[presetId]) {
                hiddenItems.push({
                    id: 'preset_' + presetId,
                    presetId: presetId,
                    url: presetMap[presetId].url,
                    title: presetMap[presetId].title,
                    icon: presetMap[presetId].icon,
                    isPreset: true,
                    isHidden: true
                });
            }
        });
        
        editShortcutVisibleItems = visibleItems;
        editShortcutHiddenItems = hiddenItems;
        
        // 保存原始顺序
        editShortcutOriginalVisibleOrder = editShortcutVisibleItems.map(item => item.id);
        editShortcutOriginalHiddenOrder = editShortcutHiddenItems.map(item => item.id);
    }

    // 渲染编辑列表
    function renderEditShortcutList() {
        if (!editShortcutVisibleList || !editShortcutHiddenList) return;
        
        // 清空列表
        editShortcutVisibleList.innerHTML = '';
        editShortcutHiddenList.innerHTML = '';
        
        // 渲染显示中的项目
        renderEditShortcutCategory(editShortcutVisibleList, editShortcutVisibleItems, 'visible');
        // 渲染隐藏的项目
        renderEditShortcutCategory(editShortcutHiddenList, editShortcutHiddenItems, 'hidden');
    }

    // 渲染单个分类的快捷访问列表
    function renderEditShortcutCategory(container, items, category) {
        container.innerHTML = '';
        
        items.forEach((item, index) => {
            const div = document.createElement('div');
            div.className = 'edit-shortcut-item';
            div.dataset.index = index;
            
            // 图标 - 预设项目直接使用图标HTML，自定义项目使用favicon图片
            let iconContent;
            if (item.isPreset) {
                // 预设项目直接渲染SVG图标
                iconContent = item.icon;
            } else if (item.icon && item.icon.trim()) {
                // 自定义项目使用favicon图片
                iconContent = '<img src="' + encodeURI(item.icon.trim()) + '" class="favicon-img" width="32" height="32" onerror="this.classList.add(\'favicon-error\')">';
            } else {
                iconContent = defaultIconSVG;
            }
            
            // 操作按钮
            let actionButton = '';
            const isFirst = index === 0;
            const isLast = index === items.length - 1;
            
            if (category === 'visible') {
                // 显示中分类：预设可以隐藏（-），自定义可以删除（x）
                if (item.isPreset) {
                    // 预设：隐藏按钮（-）
                    actionButton = `
                        <button class="edit-shortcut-toggle" data-category="${category}" data-index="${index}" title="隐藏到已隐藏">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M5 12h14"/>
                            </svg>
                        </button>
                    `;
                } else {
                    // 自定义：删除按钮（x）
                    actionButton = `
                        <button class="edit-shortcut-delete" data-category="${category}" data-index="${index}" title="删除">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M18 6L6 18M6 6l12 12"/>
                            </svg>
                        </button>
                    `;
                }
            } else {
                // 隐藏分类：预设可以显示（+）
                actionButton = `
                    <button class="edit-shortcut-toggle" data-category="${category}" data-index="${index}" title="显示到显示中">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M12 5v14M5 12h14"/>
                        </svg>
                    </button>
                `;
            }
            
            // 移动按钮（仅显示中分类有）
            let moveButtons = '';
            if (category === 'visible') {
                const isFirst = index === 0;
                const isLast = index === items.length - 1;
                moveButtons = `
                    <button class="edit-shortcut-move-btn edit-shortcut-move-up" data-category="${category}" data-index="${index}" ${isFirst ? 'disabled' : ''}>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M18 15L12 9L6 15"/>
                        </svg>
                    </button>
                    <button class="edit-shortcut-move-btn edit-shortcut-move-down" data-category="${category}" data-index="${index}" ${isLast ? 'disabled' : ''}>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M6 9L12 15L18 9"/>
                        </svg>
                    </button>
                `;
            }
            
            div.innerHTML = `
                <div class="edit-shortcut-item-icon">${iconContent}</div>
                <div class="edit-shortcut-item-text" title="${Security.sanitizeXss(item.title)}">
                    ${item.isPreset ? '<span class="preset-tag">预设</span>' : ''}${Security.sanitizeXss(item.title)}
                </div>
                <div class="edit-shortcut-item-actions">
                    ${moveButtons}
                    ${actionButton}
                </div>
            `;
            container.appendChild(div);
        });
        
        // 绑定上移按钮事件
        container.querySelectorAll('.edit-shortcut-move-up').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const category = btn.dataset.category;
                const index = parseInt(btn.dataset.index);
                moveEditShortcutItem(category, index, -1);
            });
        });
        
        // 绑定下移按钮事件
        container.querySelectorAll('.edit-shortcut-move-down').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const category = btn.dataset.category;
                const index = parseInt(btn.dataset.index);
                moveEditShortcutItem(category, index, 1);
            });
        });
        
        // 绑定删除按钮事件（自定义项目）
        container.querySelectorAll('.edit-shortcut-delete').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const category = btn.dataset.category;
                const index = parseInt(btn.dataset.index);
                confirmDialog.dataset.category = category;
                confirmDialog.dataset.targetIndex = index;
                openConfirmDialog('delete-custom-shortcut');
            });
        });
        
        // 绑定切换分类按钮事件（预设项目）
        container.querySelectorAll('.edit-shortcut-toggle').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const category = btn.dataset.category;
                const index = parseInt(btn.dataset.index);
                toggleEditShortcutCategory(category, index);
            });
        });
    }

    // 移动快捷访问项目
    function moveEditShortcutItem(category, index, direction) {
        const items = category === 'visible' ? editShortcutVisibleItems : editShortcutHiddenItems;
        if (index + direction < 0 || index + direction >= items.length) return;
        
        // 交换位置
        const temp = items[index];
        items[index] = items[index + direction];
        items[index + direction] = temp;
        editShortcutHasChanges = true;
        renderEditShortcutList();
    }

    // 切换快捷访问分类（预设项目在显示中和已隐藏之间移动）
    function toggleEditShortcutCategory(fromCategory, index) {
        const fromItems = fromCategory === 'visible' ? editShortcutVisibleItems : editShortcutHiddenItems;
        const toItems = fromCategory === 'visible' ? editShortcutHiddenItems : editShortcutVisibleItems;
        
        if (index < 0 || index >= fromItems.length) return;
        
        // 移动项目
        const item = fromItems[index];
        fromItems.splice(index, 1);
        toItems.push(item);
        
        editShortcutHasChanges = true;
        renderEditShortcutList();
    }

    // 初始化分类折叠功能（使用事件委托）
    function initEditShortcutCategoryCollapse() {
        // 使用事件委托，在面板上绑定一次事件
        if (editShortcutPanel && !editShortcutPanel.dataset.collapseInitialized) {
            editShortcutPanel.addEventListener('click', function(e) {
                const header = e.target.closest('.edit-shortcut-category-header');
                if (header) {
                    const category = header.closest('.edit-shortcut-category');
                    if (category) {
                        category.classList.toggle('collapsed');
                    }
                }
            });
            editShortcutPanel.dataset.collapseInitialized = 'true';
        }
    }

    // 保存快捷访问顺序 - 使用localStorage
    function saveShortcutOrder() {
        // 保存显示中项目的顺序（混合预设和自定义）
        const visibleOrder = editShortcutVisibleItems.map(item => item.id);
        setLocalStorageItem('shortcut_visible_order', visibleOrder);
        
        // 保存隐藏的预设列表
        const hiddenPresetIds = editShortcutHiddenItems.map(item => item.presetId);
        setLocalStorageItem('hidden_presets', hiddenPresetIds);
        
        // 保存自定义快捷方式（只保存显示中的自定义）
        const visibleCustomItems = editShortcutVisibleItems.filter(item => !item.isPreset);
        const newCustomShortcuts = visibleCustomItems.map((item, index) => ({
            id: parseInt(item.customId) || Date.now(),
            url: item.url,
            title: Security.sanitizeXss(item.title),
            icon: item.icon,
            position: index
        }));
        setLocalStorageItem('custom_shortcuts', newCustomShortcuts);
    }

    // 点击重置按钮
    if (editShortcutReset) {
        editShortcutReset.addEventListener('click', function(e) {
            e.stopPropagation();
            // 使用确认对话框
            openConfirmDialog('reset-shortcuts');
        });
    }

    // 点击取消按钮
    if (editShortcutCancel) {
        editShortcutCancel.addEventListener('click', function(e) {
            e.stopPropagation();
            if (editShortcutHasChanges) {
                openConfirmDialog('discard-changes');
            } else {
                // 恢复所有被编辑过的快捷方式数据
                restoreAllEditedShortcuts();
                closeEditShortcutPanel();
            }
        });
    }

    // 点击关闭按钮
    if (editShortcutClose) {
        editShortcutClose.addEventListener('click', function(e) {
            e.stopPropagation();
            if (editShortcutHasChanges) {
                openConfirmDialog('discard-changes');
            } else {
                // 恢复所有被编辑过的快捷方式数据
                restoreAllEditedShortcuts();
                closeEditShortcutPanel();
            }
        });
    }

    // 点击应用按钮
    if (editShortcutApply) {
        editShortcutApply.addEventListener('click', function(e) {
            e.stopPropagation();
            if (editShortcutHasChanges) {
                saveShortcutOrder();
                editShortcutHasChanges = false;
                editShortcutOriginalVisibleOrder = editShortcutVisibleItems.map(item => item.id);
                editShortcutOriginalHiddenOrder = editShortcutHiddenItems.map(item => item.id);
                loadQuickAccessMenu();
                sendNotice('设置已应用', 'info');
            } else {
                sendNotice('未作任何更改', 'info');
            }
        });
    }

    // 点击确定按钮
    if (editShortcutOk) {
        editShortcutOk.addEventListener('click', function(e) {
            e.stopPropagation();
            if (editShortcutHasChanges) {
                saveShortcutOrder();
                loadQuickAccessMenu();
                closeEditShortcutPanel();
                sendNotice('设置已保存', 'info');
            } else {
                closeEditShortcutPanel();
            }
        });
    }

    // 点击遮罩层关闭
    if (editShortcutOverlay) {
        editShortcutOverlay.addEventListener('click', function(e) {
            e.stopPropagation();
            if (editShortcutHasChanges) {
                openConfirmDialog('discard-changes');
            } else {
                // 恢复所有被编辑过的快捷方式数据
                restoreAllEditedShortcuts();
                closeEditShortcutPanel();
            }
        });
    }

    // 初始化操作项图标
    function initActionItems() {
        const actionItems = document.querySelectorAll('.setting-item-action');
        actionItems.forEach(item => {
            const textSpan = item.querySelector('.setting-item-text');
            if (textSpan && !item.querySelector('.action-icon')) {
                const iconSpan = document.createElement('span');
                iconSpan.className = 'action-icon';
                iconSpan.innerHTML = svgAction;
                iconSpan.style.marginLeft = '8px';
                iconSpan.style.display = 'inline-flex';
                iconSpan.style.alignItems = 'center';
                textSpan.parentNode.insertBefore(iconSpan, textSpan.nextSibling);
            }
        });
    }

    // 点击操作项显示确认对话框
    settingItems.forEach(item => {
        item.addEventListener('click', function(e) {
            e.stopPropagation();
            // 支持 data-setting 和 data-action
            const actionId = this.dataset.setting || this.dataset.action;
            if (actionId && confirmActions[actionId]) {
                openConfirmDialog(actionId);
            }
        });
    });

    // 初始化设置项状态图标
    function initSettingItems() {
        const settings = loadGlobalSettings();
        
        settingItems.forEach(item => {
            const indicator = item.querySelector('.status-indicator');
            const icon = item.querySelector('.status-icon');
            const settingType = item.dataset.setting;
            
            if (indicator && icon) {
                let isEnabled = false;
                
                // 根据设置类型确定初始状态
                if (settingType === 'auto-wallpaper') {
                    isEnabled = settings.backgroundBlur;
                } else if (settingType === 'dark-mode') {
                    isEnabled = settings.backgroundFilter;
                } else {
                    // 其他设置使用DOM中的状态
                    isEnabled = indicator.classList.contains('enabled');
                }
                
                if (isEnabled) {
                    indicator.classList.add('enabled');
                    icon.innerHTML = svgOn;
                } else {
                    indicator.classList.remove('enabled');
                    icon.innerHTML = svgOff;
                }
            }
        });
    }

    // 点击设置项切换状态
    settingItems.forEach(item => {
        item.addEventListener('click', function(e) {
            e.stopPropagation();
            const indicator = this.querySelector('.status-indicator');
            const icon = this.querySelector('.status-icon');
            const settingType = this.dataset.setting;
            
            // 深色模式特殊处理（无开关，直接点击切换）
            if (settingType === 'dark-mode-toggle') {
                handleDarkModeToggle();
                return;
            }
            
            if (indicator && icon) {
                const wasEnabled = indicator.classList.contains('enabled');
                const isEnabled = !wasEnabled;
                
                indicator.classList.toggle('enabled');
                if (isEnabled) {
                    icon.innerHTML = svgOn;
                } else {
                    icon.innerHTML = svgOff;
                }
                
                // 根据设置类型处理对应的功能
                if (settingType === 'auto-wallpaper') {
                    handleBackgroundBlurToggle(isEnabled);
                } else if (settingType === 'dark-mode') {
                    handleBackgroundFilterToggle(isEnabled);
                }
            }
        });
    });

    // 打开设置菜单时初始化图标
    const originalOpenSettingsModal = openSettingsModal;
    openSettingsModal = function() {
        originalOpenSettingsModal();
        initSettingItems();
    }

    // 初始化壁纸设置
    async function initWallpaper() {
        const saved = getLocalStorageItem('wallpaper_settings');
        let settings = saved || { id: 1, customUrl: '', customMode: 'local' };

        // 如果预设壁纸还没加载，使用共享函数加载XML
        if (Object.keys(presetWallpapers).length === 0) {
            const xmlDoc = await loadWallpaperXml();
            if (xmlDoc) {
                const wallpaperElements = xmlDoc.querySelectorAll('wallpaper');
                wallpaperElements.forEach(wp => {
                    const id = parseInt(wp.getAttribute('id'));
                    const url = wp.querySelector('url')?.textContent || '';
                    presetWallpapers[id] = url;
                });
            }
        }

        try {
            applyWallpaper(settings);
        } catch (e) {
            console.error('初始化壁纸失败:', e);
        }
        
        // 初始化设置按钮可见性
        updateSettingsButtonVisibility();
    }
    initWallpaper();

    // ==================== 编辑功能 ====================
    
    // 编辑按钮图标
    const svgEdit = '<svg viewBox="0 0 24 24" width="14" height="14"><path fill="currentColor" d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>';

    // 编辑快捷访问面板元素
    const editShortcutItemPanel = document.getElementById('edit-shortcut-item-panel');
    const editShortcutItemClose = document.getElementById('edit-shortcut-item-close');
    const editShortcutItemUrl = document.getElementById('edit-shortcut-item-url');
    const editShortcutItemName = document.getElementById('edit-shortcut-item-name');
    const editShortcutItemIcon = document.getElementById('edit-shortcut-item-icon');
    const editShortcutItemPreviewIcon = document.getElementById('edit-shortcut-item-preview-icon');
    const editShortcutItemCancel = document.getElementById('edit-shortcut-item-cancel');
    const editShortcutItemSave = document.getElementById('edit-shortcut-item-save');
    const editShortcutItemApply = document.getElementById('edit-shortcut-item-apply');
    const editShortcutItemOverlay = editShortcutItemPanel ? editShortcutItemPanel.querySelector('.settings-modal-overlay') : null;

    // 编辑搜索引擎面板元素
    const editSearchEnginePanel = document.getElementById('edit-search-engine-panel');
    const editSearchEngineClose = document.getElementById('edit-search-engine-close');
    const editSearchEngineName = document.getElementById('edit-search-engine-name');
    const editSearchEngineUrl = document.getElementById('edit-search-engine-url');
    const editSearchEngineUrlError = document.getElementById('edit-search-engine-url-error');
    const editSearchEngineCancel = document.getElementById('edit-search-engine-cancel');
    const editSearchEngineSave = document.getElementById('edit-search-engine-save');
    const editSearchEngineApply = document.getElementById('edit-search-engine-apply');
    const editSearchEngineOverlay = editSearchEnginePanel ? editSearchEnginePanel.querySelector('.settings-modal-overlay') : null;

    // 当前编辑的项目信息
    let currentEditShortcut = null;
    let currentEditSearchEngine = null;
    let editShortcutItemHasChanges = false;
    let editSearchEngineHasChanges = false;
    let searchEngineSettingsHasInnerChanges = false; // 跟踪内层编辑面板的更改

    // 初始化关闭按钮图标
    if (editShortcutItemClose) {
        editShortcutItemClose.innerHTML = svgClose;
    }
    if (editSearchEngineClose) {
        editSearchEngineClose.innerHTML = svgClose;
    }

    // ==================== 编辑快捷访问项目 ====================

    // 打开编辑快捷访问项目面板
    function openEditShortcutItemPanel(item, category, index) {
        if (!editShortcutItemPanel) return;

        // 保存原始数据到item对象，用于外层取消时恢复
        item.originalData = {
            url: item.url,
            title: item.title,
            icon: item.icon
        };

        // 初始化临时数据为当前项目数据
        const tempData = {
            url: item.url || '',
            title: item.title || '',
            icon: item.icon || ''
        };

        currentEditShortcut = { item, category, index, tempData };
        editShortcutItemHasChanges = false;

        // 填充表单数据（使用临时数据）
        if (editShortcutItemUrl) editShortcutItemUrl.value = tempData.url;
        if (editShortcutItemName) editShortcutItemName.value = tempData.title;
        if (editShortcutItemIcon) editShortcutItemIcon.value = tempData.icon;

        // 更新图标预览
        updateEditShortcutIconPreview(tempData.icon);

        editShortcutItemPanel.classList.add('active');
        updateSettingsButtonVisibility();
    }

    // 关闭编辑快捷访问项目面板
    function closeEditShortcutItemPanel(checkChanges = true, discardChanges = false) {
        if (checkChanges && editShortcutItemHasChanges && !discardChanges) {
            // 有未保存的更改，提示用户
            openConfirmDialog('discard-edit-shortcut');
            return;
        }

        // 如果要丢弃更改，恢复原始数据
        if (discardChanges && currentEditShortcut) {
            const { item } = currentEditShortcut;
            if (item.originalData) {
                item.url = item.originalData.url;
                item.title = item.originalData.title;
                item.icon = item.originalData.icon;
            }
            renderEditShortcutList();
            // 丢弃更改后，重置外层编辑面板的更改状态
            editShortcutHasChanges = false;
        }

        if (editShortcutItemPanel) {
            editShortcutItemPanel.classList.remove('active');
            currentEditShortcut = null;
            updateSettingsButtonVisibility();
        }
    }

    // 更新编辑面板的图标预览
    function updateEditShortcutIconPreview(iconUrl) {
        if (!editShortcutItemPreviewIcon) return;

        if (!iconUrl || !iconUrl.trim()) {
            editShortcutItemPreviewIcon.innerHTML = defaultIconSVG;
            return;
        }

        const img = new Image();
        img.onload = function() {
            editShortcutItemPreviewIcon.innerHTML = '<img src="' + iconUrl + '" style="width:32px;height:32px;">';
        };
        img.onerror = function() {
            editShortcutItemPreviewIcon.innerHTML = defaultIconSVG;
        };
        img.src = iconUrl;
    }

    // 检查编辑快捷访问面板是否有更改（比较临时数据与原始数据）
    function hasEditShortcutItemChanges() {
        if (!currentEditShortcut || !currentEditShortcut.item) return false;
        const item = currentEditShortcut.item;
        const originalData = item.originalData || item;
        return (editShortcutItemUrl?.value.trim() || '') !== (originalData.url || '') ||
               (editShortcutItemName?.value.trim() || '') !== (originalData.title || '') ||
               (editShortcutItemIcon?.value.trim() || '') !== (originalData.icon || '');
    }

    // 保存编辑的快捷访问项目（只更新内存，不写入localStorage）
    function saveEditShortcutItem(closePanel = false) {
        if (!currentEditShortcut) return false;

        const { item, tempData } = currentEditShortcut;
        const newUrl = tempData.url;
        const rawName = tempData.title;
        const newIcon = tempData.icon;

        // 使用Security模块净化名称输入（防止XSS）
        const sanitizedName = Security.sanitizeXss(rawName);
        
        // 检查名称是否合法：非空且不包含HTML标签
        const isNameValid = rawName.length > 0 && !/<[^>]*>/i.test(rawName);

        // 验证URL
        if (!newUrl) {
            sendNotice('请输入URL', 'warn');
            return false;
        }

        try {
            new URL(newUrl);
        } catch (e) {
            sendNotice('URL格式不正确', 'warn');
            return false;
        }

        // 只更新内存中的项目数据，不写入localStorage
        // 如果名称不合法，使用"未命名的快捷方式"
        item.url = newUrl;
        item.title = isNameValid ? sanitizedName : '未命名的快捷方式';
        item.icon = newIcon || '';

        // 更新列表显示
        renderEditShortcutList();

        // 更新外层编辑面板的更改状态
        editShortcutHasChanges = true;
        editShortcutItemHasChanges = false;

        if (closePanel) {
            closeEditShortcutItemPanel(false);
        } else {
            sendNotice('设置已应用', 'info');
        }

        return true;
    }

    // 绑定编辑快捷访问面板事件
    if (editShortcutItemClose) {
        editShortcutItemClose.addEventListener('click', () => closeEditShortcutItemPanel());
    }

    if (editShortcutItemCancel) {
        editShortcutItemCancel.addEventListener('click', () => closeEditShortcutItemPanel());
    }

    if (editShortcutItemSave) {
        editShortcutItemSave.addEventListener('click', () => saveEditShortcutItem(true));
    }

    if (editShortcutItemApply) {
        editShortcutItemApply.addEventListener('click', () => saveEditShortcutItem(false));
    }

    // URL输入变化检测
    if (editShortcutItemUrl) {
        editShortcutItemUrl.addEventListener('input', function() {
            if (currentEditShortcut && currentEditShortcut.tempData) {
                currentEditShortcut.tempData.url = this.value.trim();
            }
            editShortcutItemHasChanges = hasEditShortcutItemChanges();
        });
    }

    // 名称输入变化检测
    if (editShortcutItemName) {
        editShortcutItemName.addEventListener('input', function() {
            if (currentEditShortcut && currentEditShortcut.tempData) {
                currentEditShortcut.tempData.title = this.value.trim();
            }
            editShortcutItemHasChanges = hasEditShortcutItemChanges();
        });
    }

    // 图标输入变化检测和预览更新
    if (editShortcutItemIcon) {
        editShortcutItemIcon.addEventListener('input', function() {
            if (currentEditShortcut && currentEditShortcut.tempData) {
                currentEditShortcut.tempData.icon = this.value.trim();
            }
            editShortcutItemHasChanges = hasEditShortcutItemChanges();
            updateEditShortcutIconPreview(this.value.trim());
        });

        // 失焦时验证图标格式
        editShortcutItemIcon.addEventListener('blur', function() {
            const url = this.value.trim();
            if (url && !isValidIconUrl(url)) {
                sendNotice('图标格式不支持，请使用 ico/png/jpg 格式', 'warn');
            }
        });
    }

    // 点击遮罩层关闭
    if (editShortcutItemOverlay) {
        editShortcutItemOverlay.addEventListener('click', () => closeEditShortcutItemPanel());
    }

    // ==================== 编辑搜索引擎项目 ====================

    // 打开编辑搜索引擎项目面板
    function openEditSearchEnginePanel(engine, category, index) {
        if (!editSearchEnginePanel) return;

        // 保存原始数据到engine对象，用于外层取消时恢复
        engine.originalData = {
            title: engine.title,
            url: engine.url
        };

        // 初始化临时数据为当前引擎数据
        const tempData = {
            title: engine.title || '',
            url: engine.url || ''
        };

        currentEditSearchEngine = { engine, category, index, tempData };
        editSearchEngineHasChanges = false;

        // 填充表单数据（使用临时数据）
        if (editSearchEngineName) editSearchEngineName.value = tempData.title;
        if (editSearchEngineUrl) editSearchEngineUrl.value = tempData.url;
        if (editSearchEngineUrlError) editSearchEngineUrlError.textContent = '';

        editSearchEnginePanel.classList.add('active');
        updateSettingsButtonVisibility();
    }

    // 关闭编辑搜索引擎项目面板
    function closeEditSearchEnginePanel(checkChanges = true, discardChanges = false) {
        if (checkChanges && editSearchEngineHasChanges && !discardChanges) {
            // 有未保存的更改，提示用户
            openConfirmDialog('discard-edit-search-engine');
            return;
        }

        // 如果要丢弃更改，恢复原始数据
        if (discardChanges && currentEditSearchEngine) {
            const { engine } = currentEditSearchEngine;
            if (engine.originalData) {
                engine.title = engine.originalData.title;
                engine.url = engine.originalData.url;
            }
            renderSearchEngineLists();
        }

        if (editSearchEnginePanel) {
            editSearchEnginePanel.classList.remove('active');
            currentEditSearchEngine = null;
            editSearchEngineHasChanges = false;
            updateSettingsButtonVisibility();
        }
    }

    // 检查编辑搜索引擎面板是否有更改（比较输入框与原始数据）
    function hasEditSearchEngineChanges() {
        if (!currentEditSearchEngine || !currentEditSearchEngine.engine) return false;
        const engine = currentEditSearchEngine.engine;
        const originalData = engine.originalData || engine;
        return (editSearchEngineName?.value.trim() || '') !== (originalData.title || '') ||
               (editSearchEngineUrl?.value.trim() || '') !== (originalData.url || '');
    }

    // 保存编辑的搜索引擎项目（只更新内存，不写入localStorage）
    function saveEditSearchEngine(closePanel = false) {
        if (!currentEditSearchEngine) return false;

        const { engine, tempData } = currentEditSearchEngine;
        const rawName = tempData.title;
        const newUrl = tempData.url;

        // 使用Security模块净化名称输入（防止XSS）
        const sanitizedName = Security.sanitizeXss(rawName);
        
        // 检查名称是否合法：非空且不包含HTML标签
        const isNameValid = rawName.length > 0 && !/<[^>]*>/i.test(rawName);

        // 验证URL
        if (!newUrl) {
            sendNotice('请输入URL', 'warn');
            return false;
        }

        const validation = validateSearchEngineUrl(newUrl);
        if (!validation.valid) {
            if (editSearchEngineUrlError) editSearchEngineUrlError.textContent = validation.message;
            return false;
        }

        // 只更新内存中的引擎数据，不写入localStorage
        // 如果名称不合法，使用"未命名的搜索引擎"
        engine.title = isNameValid ? sanitizedName : '未命名的搜索引擎';
        engine.url = newUrl;

        // 标记外层设置面板有未保存的更改
        searchEngineSettingsHasInnerChanges = true;

        // 更新列表显示
        renderSearchEngineLists();

        editSearchEngineHasChanges = false;

        if (closePanel) {
            closeEditSearchEnginePanel(false);
        } else {
            sendNotice('设置已应用', 'info');
        }

        return true;
    }

    // 绑定编辑搜索引擎面板事件
    if (editSearchEngineClose) {
        editSearchEngineClose.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            closeEditSearchEnginePanel();
        });
    }

    if (editSearchEngineCancel) {
        editSearchEngineCancel.addEventListener('click', () => closeEditSearchEnginePanel());
    }

    if (editSearchEngineSave) {
        editSearchEngineSave.addEventListener('click', () => saveEditSearchEngine(true));
    }

    if (editSearchEngineApply) {
        editSearchEngineApply.addEventListener('click', () => saveEditSearchEngine(false));
    }

    // 名称输入变化检测
    if (editSearchEngineName) {
        editSearchEngineName.addEventListener('input', function() {
            if (currentEditSearchEngine && currentEditSearchEngine.tempData) {
                currentEditSearchEngine.tempData.title = this.value.trim();
            }
            editSearchEngineHasChanges = hasEditSearchEngineChanges();
        });
    }

    // URL输入变化检测和验证
    if (editSearchEngineUrl) {
        editSearchEngineUrl.addEventListener('input', function() {
            if (currentEditSearchEngine && currentEditSearchEngine.tempData) {
                currentEditSearchEngine.tempData.url = this.value.trim();
            }
            editSearchEngineHasChanges = hasEditSearchEngineChanges();
            if (editSearchEngineUrlError) editSearchEngineUrlError.textContent = '';
        });

        // 失焦验证
        editSearchEngineUrl.addEventListener('blur', function() {
            const validation = validateSearchEngineUrl(this.value);
            if (!validation.valid && editSearchEngineUrlError) {
                editSearchEngineUrlError.textContent = validation.message;
            }
        });
    }

    // 点击遮罩层关闭
    if (editSearchEngineOverlay) {
        editSearchEngineOverlay.addEventListener('click', () => closeEditSearchEnginePanel());
    }

    // ==================== 在列表中添加编辑按钮 ====================

    // 修改renderEditShortcutCategory函数，添加编辑按钮
    const originalRenderEditShortcutCategory = renderEditShortcutCategory;
    renderEditShortcutCategory = function(container, items, category) {
        container.innerHTML = '';

        items.forEach((item, index) => {
            const div = document.createElement('div');
            div.className = 'edit-shortcut-item';
            div.dataset.index = index;

            // 图标
            let iconContent;
            if (item.isPreset) {
                iconContent = item.icon;
            } else if (item.icon && item.icon.trim()) {
                iconContent = '<img src="' + encodeURI(item.icon.trim()) + '" class="favicon-img" width="32" height="32" onerror="this.classList.add(\'favicon-error\')">';
            } else {
                iconContent = defaultIconSVG;
            }

            // 操作按钮
            let actionButton = '';
            const isFirst = index === 0;
            const isLast = index === items.length - 1;

            if (category === 'visible') {
                if (item.isPreset) {
                    actionButton = `
                        <button class="edit-shortcut-toggle" data-category="${category}" data-index="${index}" title="隐藏到已隐藏">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M5 12h14"/>
                            </svg>
                        </button>
                    `;
                } else {
                    actionButton = `
                        <button class="edit-shortcut-delete" data-category="${category}" data-index="${index}" title="删除">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M18 6L6 18M6 6l12 12"/>
                            </svg>
                        </button>
                    `;
                }
            } else {
                actionButton = `
                    <button class="edit-shortcut-toggle" data-category="${category}" data-index="${index}" title="显示到显示中">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M12 5v14M5 12h14"/>
                        </svg>
                    </button>
                `;
            }

            // 移动按钮（仅显示中分类有）
            let moveButtons = '';
            if (category === 'visible') {
                moveButtons = `
                    <button class="edit-shortcut-move-btn edit-shortcut-move-up" data-category="${category}" data-index="${index}" ${isFirst ? 'disabled' : ''}>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M18 15L12 9L6 15"/>
                        </svg>
                    </button>
                    <button class="edit-shortcut-move-btn edit-shortcut-move-down" data-category="${category}" data-index="${index}" ${isLast ? 'disabled' : ''}>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M6 9L12 15L18 9"/>
                        </svg>
                    </button>
                `;
            }

            // 编辑按钮（仅自定义项目有）
            let editButton = '';
            if (!item.isPreset) {
                editButton = `
                    <button class="edit-shortcut-edit" data-category="${category}" data-index="${index}" title="编辑">
                        ${svgEdit}
                    </button>
                `;
            }

            div.innerHTML = `
                <div class="edit-shortcut-item-icon">${iconContent}</div>
                <div class="edit-shortcut-item-text" title="${Security.sanitizeXss(item.title)}">
                    ${item.isPreset ? '<span class="preset-tag">预设</span>' : ''}${Security.sanitizeXss(item.title)}
                </div>
                <div class="edit-shortcut-item-actions">
                    ${moveButtons}
                    ${editButton}
                    ${actionButton}
                </div>
            `;
            container.appendChild(div);
        });

        // 绑定上移按钮事件
        container.querySelectorAll('.edit-shortcut-move-up').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const category = btn.dataset.category;
                const index = parseInt(btn.dataset.index);
                moveEditShortcutItem(category, index, -1);
            });
        });

        // 绑定下移按钮事件
        container.querySelectorAll('.edit-shortcut-move-down').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const category = btn.dataset.category;
                const index = parseInt(btn.dataset.index);
                moveEditShortcutItem(category, index, 1);
            });
        });

        // 绑定删除按钮事件（自定义项目）
        container.querySelectorAll('.edit-shortcut-delete').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const category = btn.dataset.category;
                const index = parseInt(btn.dataset.index);
                confirmDialog.dataset.category = category;
                confirmDialog.dataset.targetIndex = index;
                openConfirmDialog('delete-custom-shortcut');
            });
        });

        // 绑定切换分类按钮事件（预设项目）
        container.querySelectorAll('.edit-shortcut-toggle').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const category = btn.dataset.category;
                const index = parseInt(btn.dataset.index);
                toggleEditShortcutCategory(category, index);
            });
        });

        // 绑定编辑按钮事件（自定义项目）
        container.querySelectorAll('.edit-shortcut-edit').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const category = btn.dataset.category;
                const index = parseInt(btn.dataset.index);
                const items = category === 'visible' ? editShortcutVisibleItems : editShortcutHiddenItems;
                openEditShortcutItemPanel(items[index], category, index);
            });
        });
    };

    // 修改renderSearchEngineCategory函数，添加编辑按钮
    const originalRenderSearchEngineCategory = renderSearchEngineCategory;
    renderSearchEngineCategory = function(container, engines, category) {
        container.innerHTML = '';

        // 获取预设引擎的id列表
        const presetIds = searchEngineData.engines.slice(0, presetEngineCount).map(e => e.id);

        engines.forEach((engine, index) => {
            const item = document.createElement('div');
            item.className = 'search-engine-item';
            item.dataset.engineId = engine.id;
            item.title = engine.comment || ''; // 悬停显示 comment
            const isPreset = presetIds.includes(engine.id);
            const isFirst = index === 0;
            const isLast = index === engines.length - 1;

            // 移动按钮（仅使用中分类有）
            let moveButtons = '';
            if (category === 'active') {
                moveButtons = `
                    <button class="search-engine-move-btn search-engine-move-up" title="上移" ${isFirst ? 'disabled' : ''}>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M18 15L12 9L6 15"/>
                        </svg>
                    </button>
                    <button class="search-engine-move-btn search-engine-move-down" title="下移" ${isLast ? 'disabled' : ''}>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M6 9L12 15L18 9"/>
                        </svg>
                    </button>
                `;
            }

            // 根据分类生成不同的操作按钮
            let actionButtons = '';
            if (category === 'active') {
                actionButtons = `
                    <button class="search-engine-disable" title="移至未使用" data-engine-id="${engine.id}">${svgMinus}</button>
                `;
            } else if (category === 'preset') {
                actionButtons = `
                    <button class="search-engine-enable" title="移至使用中" data-engine-id="${engine.id}">${svgPlus}</button>
                `;
            } else {
                actionButtons = `
                    <button class="search-engine-enable" title="移至使用中" data-engine-id="${engine.id}">${svgPlus}</button>
                    <button class="search-engine-delete" title="删除" data-engine-id="${engine.id}" ${isPreset ? 'disabled' : ''}>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M18 6L6 18M6 6l12 12"/>
                        </svg>
                    </button>
                `;
            }

            // 编辑按钮（仅自定义引擎有）
            let editButton = '';
            if (!isPreset) {
                editButton = `
                    <button class="search-engine-edit" title="编辑" data-engine-id="${engine.id}">${svgEdit}</button>
                `;
            }

            item.innerHTML = `
                <div class="search-engine-item-icon">${getSearchEngineIcon(engine.icon)}</div>
                <span class="search-engine-item-name">
                    ${isPreset ? '<span class="preset-tag">预设</span>' : ''}${engine.title}
                </span>
                <div class="search-engine-item-actions">
                    ${moveButtons}
                    ${editButton}
                    ${actionButtons}
                </div>
            `;

            // 绑定上移按钮事件
            const moveUp = item.querySelector('.search-engine-move-up');
            if (moveUp) {
                moveUp.addEventListener('click', () => moveSearchEngine(engine.id, -1, category));
            }

            // 绑定下移按钮事件
            const moveDown = item.querySelector('.search-engine-move-down');
            if (moveDown) {
                moveDown.addEventListener('click', () => moveSearchEngine(engine.id, 1, category));
            }

            // 绑定移至未使用按钮事件
            const disableBtn = item.querySelector('.search-engine-disable');
            if (disableBtn) {
                disableBtn.addEventListener('click', () => disableSearchEngine(engine.id));
            }

            // 绑定移至使用中按钮事件
            const enableBtn = item.querySelector('.search-engine-enable');
            if (enableBtn) {
                enableBtn.addEventListener('click', () => enableSearchEngine(engine.id, isPreset ? 'preset' : 'custom'));
            }

            // 绑定删除按钮事件
            const deleteBtn = item.querySelector('.search-engine-delete');
            if (deleteBtn) {
                deleteBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    confirmDialog.dataset.targetEngineId = engine.id;
                    openConfirmDialog('delete-search-engine');
                });
            }

            // 绑定编辑按钮事件
            const editBtn = item.querySelector('.search-engine-edit');
            if (editBtn) {
                editBtn.addEventListener('click', () => openEditSearchEnginePanel(engine, category, index));
            }

            container.appendChild(item);
        });
    };

    // 添加确认对话框操作
    confirmActions['discard-edit-shortcut'] = {
        title: '放弃更改',
        message: '有未保存的更改，确定要放弃吗？',
        onOk: function() {
            editShortcutItemHasChanges = false;
            closeEditShortcutItemPanel(false, true); // true表示丢弃更改
        }
    };

    confirmActions['discard-edit-search-engine'] = {
        title: '放弃更改',
        message: '有未保存的更改，确定要放弃吗？',
        onOk: function() {
            editSearchEngineHasChanges = false;
            closeEditSearchEnginePanel(false, true);
        }
    };

    confirmActions['clear-search-history'] = {
        title: '清除历史记录',
        message: '确定要清除所有搜索历史记录吗？此操作无法撤销。',
        onOk: function() {
            clearSearchHistory();
            sendNotice('历史记录已清除', 'info', { showOnPage: false });
        }
    };

    // ESC键关闭编辑面板
    document.addEventListener('keydown', function(e) {
        if (e.key !== 'Escape') return;

        // 编辑快捷访问项目面板
        if (editShortcutItemPanel && editShortcutItemPanel.classList.contains('active')) {
            closeEditShortcutItemPanel();
            return;
        }

        // 编辑搜索引擎项目面板
        if (editSearchEnginePanel && editSearchEnginePanel.classList.contains('active')) {
            closeEditSearchEnginePanel();
            return;
        }
    });

    // 初始化搜索引擎设置
    loadSearchEnginesForSettings();
});
# 重定向后会话标识携带 | Yak Program Language

> [!NOTE] 雾刃自动化渗透测试平台技能库 (WuRen Skill Base)
> 类别: Yakit 插件与 Web 漏洞攻防体系
> 用途: 供 AI 智能体在面对特定 Web 漏洞时，理解攻击原理、复现步骤与防御措施。

- 来源: https://yaklang.com/en/Yaklab/wiki/SessionManagement/SessionIDCarrying/
- 抓取时间: 2026-02-06T07:03:39Z

---
漏洞描述：

测试当用户已成功登录情况下，再利用URL重定向对非同源网站发起请求时，请求中是否含有如 SessionID，token 等会话标识字段。若重定向后的请求中存在会话标识字段，则表明存在会话标识携带。(注:"同源":"协议 + 域名 + 端口"三者相同)

漏洞案例：

访问测试网站拼接需要重定向的网站，输入测试账号密码点击登录

成功跳转到baidu.com,并且在重定向后的请求中存在会话标识字段

漏洞修复方案

禁止在用户成功登录系统后将SessionID，token等会话标识字段返回在URL中

# ThinkCMF插件使用 | Yak Program Language

> [!NOTE] 雾刃自动化渗透测试平台技能库 (WuRen Skill Base)
> 类别: Yakit 插件与 Web 漏洞攻防体系
> 用途: 供 AI 智能体在面对特定 Web 漏洞时，理解攻击原理、复现步骤与防御措施。

- 来源: https://yaklang.com/Yaklab/wiki/DetectionPlug-in/ThinkCMF
- 抓取时间: 2026-02-06T07:02:04Z

---
## 1 ThinkCMF LFI 漏洞 #

插件id：

ea439f45-c538-417f-8275-f6c8797cd206

测试过程：

漏洞版本要求    ThinkCMF: x1.6.0/x2.1.0/x2.2.0-2
github下载版本2.1.1 搭建了环境

直接输入目标ip和端口进行扫描

成功发现漏洞
尝试读取nginx.conf也读取成功

## 2 ThinkCMF write shell 漏洞 #

插件id：

f0b6df54-3536-4d6a-880e-4ce51bb1237a

测试过程：

漏洞版本要求    ThinkCMF: x1.6.0/x2.1.0/x2.2.0-2
github下载版本2.1.1 搭建了环境

直接输入目标ip和端口进行扫描
成功发现漏洞

文件写入成功
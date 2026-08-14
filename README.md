# macOS Web App Shortcut Skill

Turn an authorized local web service into a one-click macOS `.app` launcher.

这个 Skill 让 Agent 为本地 Web 服务创建原生外观的 macOS 快捷应用：按需启动服务、等待健康检查、打开浏览器，并应用用户提供的 PNG 或 ICNS 图标。它不会打包服务本身，并通过输入检查降低凭据被写入启动器的风险；这些检查不能替代人工审查和专用秘密扫描。

本项目最初为 DeepSeek Harness 的 macOS 启动体验设计，也可用于其他本地 Web 服务。它是社区工具，不隶属于 DeepSeek，也未获 DeepSeek 背书；仓库不包含 DeepSeek Logo 或其他专有品牌素材。

This community project was originally designed for the DeepSeek Harness macOS launch experience and also works with other local web services. It is not affiliated with or endorsed by DeepSeek, and it does not include DeepSeek logos or other proprietary brand assets.

## 功能

- 创建可从桌面、访达或程序坞启动的 `.app`。
- 可选启动用户明确授权的本地服务。
- 健康检查成功后再打开页面；失败时由用户选择取消或继续。
- 通过健康检查和端口检测减少重复启动及错误服务跳转。
- 将 PNG 转换为多尺寸 ICNS 图标。
- 拦截常见密钥、Bearer/JWT、私钥和敏感 URL 参数。
- 默认只允许 `localhost` 与回环地址。
- 只允许安全覆盖由本工具创建并带有标记的应用包。

## 环境要求

- macOS。
- Python 3.9 或更高版本。
- macOS 自带的 `osacompile`、`sips`、`iconutil` 与 `codesign`。

## 安装为 Agent Skill

将 `macos-web-app-shortcut` 文件夹复制到 Agent 支持的 Skills 目录。例如 Codex 的个人 Skill 目录：

```bash
cp -R macos-web-app-shortcut ~/.codex/skills/
```

重新载入 Agent 后，可以这样提出需求：

> 使用 `$macos-web-app-shortcut`，为运行在 `http://127.0.0.1:3000/` 的本地应用创建一个 macOS 桌面快捷方式，并使用我提供的 PNG 图标。

Agent 应在创建前确认应用名称、URL、启动命令、工作目录、目标目录和图标。启动命令会保存在生成的应用包中，因此绝不能包含秘密。

## 直接运行脚本

从 Skill 所在目录运行：

```bash
python3 scripts/create_macos_web_shortcut.py \
  --name "My Local App" \
  --url "http://127.0.0.1:3000/" \
  --health-url "http://127.0.0.1:3000/health" \
  --port 3000 \
  --command "npm run dev -- --host 127.0.0.1 --port 3000" \
  --working-dir "/Users/example/project" \
  --icon "/Users/example/icon.png" \
  --output-dir "/Users/example/Desktop"
```

如果服务已经运行，只需提供 `--name`、`--url` 和 `--output-dir`。非回环目标 URL 需要 `--allow-remote`，非回环健康检查还需要单独的 `--allow-remote-health`。远程地址默认必须使用 HTTPS；只有在用户明确接受明文传输风险后才可增加 `--allow-insecure-remote-http`。健康检查默认必须与目标 URL 同源，`--port` 默认必须与目标端口一致；特殊拓扑需要分别明确授权 `--allow-cross-origin-health` 或 `--allow-port-mismatch`。

`--overwrite` 只能替换由本工具创建并带有内部标记的 `.app`，不会覆盖其他应用或普通同名目录。

## 安全边界

- 密钥检测属于纵深防御，不能替代人工检查或专用 secret scanner。
- 不要把秘密放入命令、URL、路径、查询参数、日志示例或生成的 `.app`。
- 让目标服务从自身受保护的凭据存储中读取认证信息。
- 不要将服务默认绑定到 `0.0.0.0`，也不要由本 Skill 修改防火墙或端口转发。
- 日志可能包含目标服务输出；分享前不要提交或上传日志。
- 生成的应用仅进行 ad-hoc 签名，适合本机使用。公开分发二进制应用通常需要 Apple Developer ID 签名和公证。
- 生成的启动器与创建它的 Mac 环境绑定，并且可以被反编译检查。它会以当前用户权限通过不加载用户启动文件的 `/bin/zsh -fc` 执行获准命令，不受沙盒隔离；命令、工作目录、URL 和日志路径可能从应用包中恢复。不要把秘密放进去，也不要在未经审计时再分发生成的 `.app`。启动命令应使用绝对可执行文件路径，或显式设置不含秘密的最小 `PATH`。
- 生成器本身不包含遥测。启动器可能执行获准命令、轮询健康 URL 并打开目标 URL；这些行为可能访问网络。

完整规则见 [`macos-web-app-shortcut/references/security-review.md`](macos-web-app-shortcut/references/security-review.md) 和 [`SECURITY.md`](SECURITY.md)。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

测试包括纯函数安全检查和 macOS 应用打包集成测试。维护者还应使用目标 Agent 平台提供的 Skill 验证器检查 `macos-web-app-shortcut`，并在发布前运行 Gitleaks 或 TruffleHog、人工检查待提交文件。

## 图标

仓库不捆绑任何第三方品牌图标。用户可以在创建快捷方式时提供自己拥有或获准使用的 PNG/ICNS 文件。

## 许可证

代码和文档采用 [MIT License](LICENSE)。

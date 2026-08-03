# MineShark 真实传感器离线部署手册

## 部署边界

第一版部署在独立 Ubuntu 22.04 传感器上。交换机把目标端口或 VLAN 的 TCP 流量镜像到传感器专用网卡；SPAN/TAP 接口不配置业务 IP，不转发、不阻断。`dumpcap` 只保留 128 字节 snaplen，5 秒轮转、60 个文件环形覆盖。模型进程以 `mineshark` 用户运行，不读取明文载荷，也不执行自动封禁。

当前恢复模型必须使用 `legacy-zeek-v1`：前 20 个 TCP 包有效，张量补齐到 128；包长为 TCP 载荷长度加 54；时间为相对流开始的累计秒数。不要把相邻 IAT 或 128 个真实包直接送入该 checkpoint。

## 角色与网络

- Sensor：Ubuntu 22.04、至少 4 核 CPU/8 GB 内存/40 GB 系统盘、独立镜像网卡，目标持续流量不超过 100 Mbps。
- Wazuh：现有 Manager/Indexer；Sensor 安装 Wazuh Agent。
- Console：中央 Ubuntu 主机，Nginx HTTPS 反向代理到 `127.0.0.1:8000`。
- Zeek/Suricata：与 Sensor 同机或其日志可只读挂载，作为告警后一次性旁证，不作为 Transformer 输入。

## 离线包构建

在与目标一致的 Ubuntu 22.04 x86_64/Python 3.10 可联网构建机先运行前端生产构建，再生成离线目录。构建器会拒绝在 Windows 上生成 Linux 离线包：

```bash
cd web/frontend
npm ci
npm run build
cd ../..
python scripts/deployment/build_offline_bundle.py --output outputs/mineshark-offline-0.1.0
```

构建器校验 checkpoint SHA-256，从 PyTorch CPU wheel 源收集完整传递依赖、`web/frontend/dist`、模型及清单、systemd、Wazuh、Nginx、验收工具、`BUNDLE-MANIFEST.json` 和 `SHA256SUMS`。模型权重不进入 Git。把整个目录通过受控介质送入离线环境，在目标机执行 `sha256sum -c SHA256SUMS`。

## Sensor 安装

1. 预装 Ubuntu 包：`python3-venv`、`dumpcap`、`libcap2-bin`、Wazuh Agent，以及需要时的 Zeek/Suricata。
2. 执行 `sudo bash install.sh`。安装器只创建固定目录和受管文件；如果 `/etc/mineshark/sensor.toml` 已存在且没有管理标记，会拒绝覆盖。安装器会把 `mineshark` 加入已存在的 `wireshark/zeek/suricata` 组，以只读访问抓包和旁证日志。
3. 修改 `/etc/mineshark/sensor.toml` 的 `sensor_id`、`interface` 和旁证日志路径。
4. 校验：`sudo -u mineshark /opt/mineshark/venv/bin/mineshark-sensor --config /etc/mineshark/sensor.toml validate-config`。
5. 检查镜像网卡无业务地址，使用 `ip -br addr` 和 `ethtool -S <interface>` 留存基线。
6. 启用：`systemctl enable --now mineshark-capture mineshark-sensor wazuh-agent`。

固定目录：配置 `/etc/mineshark`，模型 `/opt/mineshark/models`，状态 `/var/lib/mineshark`，事件 `/var/log/mineshark`，环形抓包 `/var/spool/mineshark`。

## Wazuh 接入

把 `wazuh/ossec-mineshark.conf` 的 `<localfile>` 片段合并到 Sensor 的 `/var/ossec/etc/ossec.conf`，把 `wazuh/mineshark_rules.xml` 安装到 Manager 的 `/var/ossec/etc/rules/`。先运行 Wazuh 配置检查，再重启 Agent/Manager。规则 `110101/110102/110103` 分别对应低/中/高模型信号；`evidence_snapshot` 与 `sensor_heartbeat` 单独入库。模型信号不是已确认攻击。

中央 `console.env` 必须设置 `MINESHARK_AI_ALERT_SOURCE=wazuh`、允许的传感器 ID、Wazuh Indexer 只读账号、`WAZUH_VERIFY_SSL=true`、`MINESHARK_FRONTEND_DIST=/opt/mineshark/web/frontend/dist` 和 `MINESHARK_CONSOLE_DATABASE_PATH=/var/lib/mineshark/console.sqlite3`。

在中央节点执行 `sudo bash install-console.sh`。它会安装 wheel、前端和受管模板，但不会启用服务，也不会覆盖已有的未托管 `console.env` 或 Nginx 配置。

## Nginx 与证书

复制 `nginx/mineshark.conf`，替换内部域名。证书放在 `/etc/mineshark/tls/fullchain.pem` 与 `privkey.pem`，私钥权限设为 `0600 root:root`。用 `htpasswd` 或企业反向代理完成访问控制；不要直接暴露 Uvicorn。执行 `nginx -t` 后再 reload。

## 日志与备份恢复

日志轮转使用 `logrotate/mineshark`。备份前停止 `mineshark-sensor`，保存 `/etc/mineshark`、`/var/lib/mineshark/sensor.sqlite3`、中央 `console.sqlite3`、模型清单和证书；环形 PCAP 不属于长期备份。恢复时先校验模型 SHA-256，再恢复 SQLite，启动后确认没有重复 `event_id`。

## 升级

先在隔离环境运行黄金一致性和完整测试。备份配置/SQLite，停止服务，安装新的 wheel 与受管单元。安装程序不得覆盖未托管配置。模型或 schema 变更必须使用新版本清单；未知 schema 进入隔离，不自动建案。升级后依次启动 Wazuh Agent、capture、Sensor、Console，并执行重启去重验收。

## 卸载

`uninstall.sh` 只打印步骤，不自动删除。人工停止并禁用三个 MineShark 服务，备份后逐个删除明确的受管普通文件；不得批量清理目录。是否保留 `/var/lib/mineshark`、事件和模型由资产负责人决定。

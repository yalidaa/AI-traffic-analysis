# MineShark 真实部署验收清单

## 硬门禁

- checkpoint SHA-256 必须为清单记录值，黄金流四类张量完全一致，CPU 概率误差不超过 `1e-5`。
- 无公网、无 DeepSeek/DashScope 时，检测、Wazuh 告警、证据快照、案件和基础规则报告仍可完成。
- 镜像接口旁路只读，Sensor 用户非 root；只有 `/usr/bin/dumpcap` 持有抓包 capability。

## 真实链路

1. 在隔离交换机配置 SPAN/TAP，把流量发生器 TCP 会话镜像到 Sensor。
2. 记录发送时刻、Sensor 首次捕获、`ai_alert`、Wazuh Indexer 入库和控制台建案时刻。
3. 至少 100 次目标测试流量，端到端延迟 p95 不超过 60 秒。
4. 案件必须包含 sensor ID、五元组、模型版本/哈希、阈值、概率、完整特征快照和对应 evidence snapshot。
5. 相同 `event_id` 重放两次，控制台仍只有一个案件。

## 负载与保留

- 持续 100 Mbps 运行 30 分钟，PCAPNG `ifdrop/ifrecv` 丢包率不超过 0.1%，不得使用“未知”状态替代此验收。
- `capture_backlog` 不持续增长，内存曲线稳定，无 OOM/服务重启。
- 停止抓包并等待轮转后，只能找到最近 60 个 5 秒文件；五分钟之外 PCAP 不可恢复。
- 检查 payload 未进入事件、SQLite、Wazuh 文档或长期日志。

## 故障恢复

依次重启 `mineshark-capture`、`mineshark-sensor`、Wazuh Agent、中央 Console；每次确认链路自动恢复、活动流状态可恢复且无重复告警。断开 Wazuh 连接后 Sensor 继续本地积压事件；恢复后由 Wazuh Agent上送，同一事件不产生新 ID。

## 不可在开发机代替的验收

物理 SPAN/TAP、真实 100 Mbps 压测、交换机镜像丢包、Wazuh Agent离线队列和 p95 端到端延迟必须在目标 Ubuntu/网络执行。Windows 单元测试、WSL 回放或生成 PCAP 只能证明代码路径，不能签署此项。

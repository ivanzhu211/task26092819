# sgrules

安全组规则集的求值与静态分析库（纯 Go，无外部依赖、无持久化），供 VPC
控制面在规则变更、版本回滚前做精确检查。只处理单个方向的一组规则。

## 规则模型

- `Rule{ID, Priority, Proto, Ports, CIDR, Action}`
  - `ID`：正整数，集内唯一；`Priority`：1–1000，数值小者先匹配
  - `Proto`：`tcp` / `udp` / `icmp` / `all`（`all` 匹配三种协议）
  - `Ports`：仅 tcp/udp 有的闭区间 `[Lo,Hi]`（1–65535）；icmp/all 必须为 nil
  - `CIDR`：任意 IPv4 前缀（含 `0.0.0.0/0` 与 `/32`），主机位非零视为非法
  - `Action`：`allow` / `deny`；一个规则集最多 200 条
- 匹配全序：优先级升序 → 同优先级 deny 先于 allow → ID 升序；
  第一条命中的规则决定动作，无命中默认 deny。

## API

```go
set, err := sgrules.NewRuleSet(rules)          // 校验并构建
action, ruleID := sgrules.Evaluate(set, pkt)   // 默认 deny 时 ruleID == 0
report := sgrules.Analyze(set)                 // 逐条 Shadowed / Redundant / Effective
res := sgrules.Equivalent(a, b)                // 全报文空间等价性，附反例报文
```

- `Analyze` 对每条 Effective 规则附见证报文：该报文上它是第一命中，
  删掉它后该报文动作翻转；见证报文可直接交给 `Evaluate`。
- `Equivalent` 在两个集合不等价时返回一个动作不同的见证报文。

## 精确性方法

不做抽样、不做地址空间截断、不做逐端口×逐地址穷举。把所有规则的
CIDR 与端口区间边界切出原子区间，构成 (协议 × 端口区间 × 地址区间)
的胞腔分解；每个胞腔内所有报文行为一致，逐胞腔计算第一命中与
「删掉该规则后」的动作，结论对整个报文空间精确（含联合遮蔽：
多条高顺位规则共同覆盖、单条都盖不住的情形）。

200 条规则的 `Analyze` 与两个 200 条规则集合的全扫描 `Equivalent`
在普通开发机上均为几十毫秒量级（见 `bench_test.go`）。

## 测试

```sh
go test ./...                 # 单元 + 随机对拍（逐点穷举参照实现）
go test -run xxx -bench .     # 性能基准
```

# dnssec-chain-validator

纯离线的 Python DNSSEC 验证库。输入根信任锚以及预先抓取的 DNSKEY、DS、
RRSIG、NSEC/NSEC3 记录（标准 wire 格式），在不发起任何网络请求的前提下重建
签名层级链，并把一次解析结果归类为已证明的正向应答、已证明的 NXDOMAIN /
NODATA、未启用签名，或验证失败。

它回答的核心问题是：同一个名字在启用 DNSSEC 的解析器上得到 NXDOMAIN、在普通
解析器上却拿到地址时，到底是

1. 域名确实不存在（存在密码学上成立的否定证明）；
2. 签名链断裂（DS/DNSKEY 摘要不符、签名失效等，结果应为 BOGUS）；还是
3. 解析器无法证明否定结果（走到未签名委托，链在信任边界终止，INSECURE）。

## 支持的算法族

签名验证基于 `cryptography`，覆盖 RFC 4034 / 5702 / 6605 / 8080：

| 算法号 | 算法 | 族 | 状态 |
| --- | --- | --- | --- |
| 5 / 7 | RSASHA1 / RSASHA1-NSEC3-SHA1 | RSA | 支持 |
| 8 | RSASHA256 | RSA | 支持 |
| 10 | RSASHA512 | RSA | 支持 |
| 13 | ECDSA P-256 / SHA-256 | ECDSA | 支持 |
| 14 | ECDSA P-384 / SHA-384 | ECDSA | 支持 |
| 15 | Ed25519 | EdDSA | 支持 |
| 16 | Ed448 | EdDSA | 支持 |
| 1 / 3 / 6 / 12 | RSAMD5、DSA、GOST 等 | 遗留 | 识别但不实现，判为 BOGUS |
| 252-254 | INDIRECT / PRIVATE* | 私有 | 识别但不实现，判为 BOGUS |
| 其它未分配号 | 未知 | - | 判为 `UNKNOWN_ALGORITHM`（BOGUS） |

DS 摘要支持 SHA-1（1）、SHA-256（2）、SHA-384（4）；NSEC3 哈希实现 RFC 5155
定义的 SHA-1（含 salt 与迭代次数）。RSA 公钥按 RFC 3110 解析（含扩展指数
长度前缀），ECDSA 签名在原始 `R||S` 与 DER 之间转换。

## 信任锚假设

- 信任锚可以是 **DNSKEY** 形式（直接信任某个区域的 ZSK/KSK），也可以是
  **DS** 形式（其摘要必须匹配该区域的某条 DNSKEY）。
- 锚的 `zone` 字段标明它所属的区域顶点；只有当某锚是查询名的祖先时，它才会
  参与这条链。没有任何锚与查询名相关时返回 `INDETERMINATE`。
- 可同时提供多个锚以支持**密钥轮换**：顶点 DNSKEY RRset 由任一受信锚验证通过
  即视为成立；DS 锚会逐一尝试摘要匹配。
- 验证器假定输入记录已按区域分组抓取完毕，自身不做网络获取、不做 EDNS、也不
  负责实际解析器的缓存或策略循环。时间通过 `Validator(anchors, now=...)`
  注入，便于复现历史签名的有效期判断。

## 判定语义

顶层状态对应 DNSSEC 解析器模型：

- `SECURE`：从信任锚到应答的完整链密码学成立。
  - 正向：`VALID_CHAIN`。
  - 否定：`PROVEN_NXDOMAIN`、`PROVEN_NODATA`、`PROVEN_WILDCARD_NODATA`。
- `INSECURE`：链上遇到被父区签名证明的**无 DS 委托**，下游区域不启用
  DNSSEC；此时否定结果无法被密码学证明（`UNSIGNED_DELEGATION`）。
- `BOGUS`：区域应当签名但验证失败，例如 `DS_DIGEST_MISMATCH`、
  `SIGNATURE_EXPIRED`、`SIGNATURE_NOT_YET_VALID`、`SIGNATURE_INVALID`、
  `UNSUPPORTED_ALGORITHM`、`FORGED_DENIAL`、`INSUFFICIENT_DENIAL` 等。
- `INDETERMINATE`：信任锚与查询名无法建立祖先关系。

签名有效期按 RFC 4034 使用**闭区间**：`inception <= now <= expiration`，边界
时刻仍然有效。否定证明区分 NSEC（区间覆盖 + 类型位映射）与 NSEC3
（RFC 7129 的 closest-encloser / next-closer 证明及通配符证明）；类型位映射
中包含被否认的类型、或区间不覆盖查询名时，判为伪造否定 `FORGED_DENIAL`。

## 模块结构

- `dnssecval/name.py`：wire 域名编解码、压缩指针、大小写保留与规范化。
- `dnssecval/wire.py`：严格的消息/记录解析，截断即抛 `TruncatedWire`；
  RRset 分组时折叠重复记录。
- `dnssecval/rdata.py`：DNSKEY/DS/RRSIG/NSEC/NSEC3 结构化解析、key tag、
  类型位映射。
- `dnssecval/canonical.py`：RFC 4034 规范化 RDATA、RRset 排序与 RRSIG
  签名输入拼装。
- `dnssecval/crypto.py`：公钥解析、DS 摘要、RRSIG 验签。
- `dnssecval/nsec.py`：NSEC/NSEC3 哈希、区间覆盖与否定证明推理。
- `dnssecval/validator.py`：链遍历、信任锚/轮换、签名与否定分类的主入口。
- `dnssecval/builder.py`：生成密钥、构造 wire 记录与真实 RRSIG（测试/夹具用）。

## 用法

```python
from dnssecval import Validator, TrustAnchor, ZoneData, parse_message, RR
from dnssecval import name

root_anchor = TrustAnchor(name.ROOT, root_dnskey_rr)
zones = {
    name.ROOT: ZoneData(root_records),
    name.from_text("example."): ZoneData(example_records),
}
result = Validator([root_anchor], now=1_700_000_000).validate(
    "www.example.", 1, zones,
)
print(result.state, result.reason)
```

wire 记录可由抓取到的原始字节解析：

```python
msg = parse_message(raw_dns_message)
records = msg.all_rrs()
```

## 测试

```bash
python -m unittest
```

测试构造了真实密钥签名的根 → 子域完整链，并覆盖错误 DS、过期/未生效签名、
时间边界、未知与不支持算法、信任锚轮换、NSEC/NSEC3 的 NXDOMAIN/NODATA 以及
伪造否定证明，另有截断 wire、压缩指针、标签大小写和重复记录等边界用例。

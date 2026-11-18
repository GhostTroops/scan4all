module github.com/projectdiscovery/cryptoutil

go 1.21

// 本地补丁副本说明：
// 上游 projectdiscovery/cryptoutil v1.0.0 的 ztls.go 依赖 zcrypto v0.0.0-2021xxxx 的
// Conn.ClientHelloRaw / Conn.GetHeartbleedLog 等方法；而新版 fastdialer/utils 已经把
// zcrypto 提升到 2026 版本，这些方法已被上游删除，导致编译失败。
//
// scan4all 实际只使用 cryptoutil.TLSGrab / TLSData（crypto/tls 标准库实现），
// 因此这里仅保留 tls.go + hash.go，去掉 ztls.go，保持 API 不变且不引入 zcrypto 依赖。

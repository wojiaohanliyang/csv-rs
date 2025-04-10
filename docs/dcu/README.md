# DCU API

提供一组DCU API 给用户使用，使用下面API 实现DCU 相关操作。
目前支持DCU API列表：

### get_report
该API以用户随机数mnonce作为输入，向机器上的所有dcu 设备请求Attestation Report。

### verify_report
该API接收用户随机数（mnonce）、单个DCU设备的远程证明报告（Report）及 设备相关证书（cert_data） 作为输入参数，执行以下验证流程：

随机数校验：核验报告中包含的mnonce是否与用户提供的预期值一致

完整性验证：
- 证书链验证：验证证书链的合法性
- 签名验证：对报告的数字签名进行密码学验证，确保其真实性和完整性

### verify_reports

该API接收用户随机数（mnonce）及单个机器上所有DCU设备的远程证明报告（Reports）作为输入参数，迭代获取Reports
中单个DCU设备的远程证明报告Report，通过Report 中的芯片ID 获取证书，调用verify_report 对单个报告进行验证
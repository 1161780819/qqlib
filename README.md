QQLib for Python
---
模拟登录`QQ`。

安装
---

```
pip install rsa requests
pip install git+https://github.com/JetLua/qqlib
```


使用
---
```py
import qq

results = qq.QQ('qq', 'password')
print(results)
```

更新说明
---

* 2017.05.08
  * 更新了验证码获取方式
  * 支持扫码登录

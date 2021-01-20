## pytea
### 极其快速的TEA加密解密工具

[![pypi](https://img.shields.io/pypi/v/pytea2.svg)](https://pypi.org/project/pytea2/) 
![python](https://img.shields.io/pypi/pyversions/pytea2)
![implementation](https://img.shields.io/pypi/implementation/pytea2)
![wheel](https://img.shields.io/pypi/wheel/pytea2)
![license](https://img.shields.io/github/license/synodriver/pytea.svg)
![action](https://img.shields.io/github/workflow/status/synodriver/pytea/run%20unitest)

- 速度是其他PYTEA算法实现的300倍

### usage
```python
import pytea
tea=pytea.TEA(secret_key=bytes(16),encrypt_times=16)
data=tea.encrypt("哈哈哈".encode())
print(tea.decrypt(data).decode())
```
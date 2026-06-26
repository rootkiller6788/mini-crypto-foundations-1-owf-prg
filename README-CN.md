# Mini Crypto Foundations — OWF & PRG（迷你密码学基础——单向函数与伪随机生成器）

一套**从零开始、零依赖的 C 语言实现**，涵盖单向函数（OWF）、伪随机生成器（PRG）及其等价性的基础理论——现代密码学的基石。每个子模块对应 MIT、Stanford、Princeton 及其他顶尖大学课程，覆盖形式化定义、硬核谓词、混合论证、最小密码学假设、GGM 伪随机函数以及陷门置换。

## 子模块

| 子模块 | 主题 | 核心课程 |
|--------|------|----------|
| [mini-one-way-functions-definition](mini-one-way-functions-definition/) | OWF 形式化定义、RSA/离散对数/子集和/Rabin 候选构造、弱与强 OWF、安全参数、可忽略函数、求逆实验 | MIT 6.875, Stanford CS255, Berkeley CS276 |
| [mini-hardcore-bit-goldreich-levin](mini-hardcore-bit-goldreich-levin/) | Goldreich-Levin 定理、硬核谓词、模 2 内积、Hadamard 码列表译码、OWF→硬核归约、自校正性 | MIT 6.875, Stanford CS255, Princeton COS 551 |
| [mini-hybrid-argument](mini-hybrid-argument/) | 混合论证引理、区分器分类、可忽略函数、计算不可区分性、优势界、通过混合论证的 PRG 安全性、下一比特不可预测性 | MIT 6.875, Stanford CS355, Princeton COS 522 |
| [mini-owf-vs-prg-equivalence](mini-owf-vs-prg-equivalence/) | OWF⇔PRG 等价性（HILL 1999）、计算不可区分性、拉伸、种子扩展、确定性扩展、Yao 定理、流密码应用 | MIT 6.875, Stanford CS255, Berkeley CS276, Princeton COS 522 |
| [mini-pseudorandom-generators-crypto](mini-pseudorandom-generators-crypto/) | PRG 形式化定义、Blum-Blum-Shub（BBS）生成器、Blum-Micali 生成器、二次剩余假设、离散对数假设、硬核谓词（LSB）、下一比特不可预测性 | MIT 6.875, Stanford CS255, Princeton COS 551 |
| [mini-pseudorandom-functions-ggm](mini-pseudorandom-functions-ggm/) | Goldreich-Goldwasser-Micali（GGM）定理、PRG⇒PRF 构造、二叉树求值、PRF 定义、混合论证安全性证明、OWF⇒PRG⇒PRF 链 | MIT 6.875, Princeton COS 522, Stanford CS255 |
| [mini-minimal-assumptions](mini-minimal-assumptions/) | Impagliazzo 五个世界、OWF⇒PRG（HILL）、黑盒分离、UOWHF、Yao XOR 引理、困难性放大、假设层次结构、密码学最小性 | MIT 6.875, Stanford CS255, Princeton COS 433, ETH 263-4660 |
| [mini-trapdoor-permutations](mini-trapdoor-permutations/) | TDP 形式化定义、RSA 陷门置换、密钥生成、模算术（CRT、欧拉函数）、基于 TDP 的公钥加密、基于 TDP 的数字签名 | MIT 6.875, Stanford CS255, Princeton COS 551, Berkeley CS278 |

## 设计理念

- **零外部依赖** — 纯 C99/C11，仅使用标准库头文件
- **自包含子模块** — 每个子模块拥有独立的 `include/`、`src/`、`CMakeLists.txt` 和冒烟测试
- **理论到代码的映射** — 每个模块内联引用教材章节（Goldreich、Katz-Lindell、Arora-Barak）和讲义
- **密码学严谨性** — 形式化安全定义，包含区分器优势、可忽略函数和归约证明的可执行代码

## 构建

每个子模块独立构建。使用 CMake 构建：

```bash
cd mini-one-way-functions-definition
mkdir build && cd build
cmake ..
make
./smoke_test
```

需要 **C99 兼容编译器**和 **CMake ≥ 3.14**。

## 项目结构

```
10. mini-crypto-foundations-1-owf-prg/
├── mini-one-way-functions-definition/    # OWF 定义、RSA/离散对数/子集和/Rabin 候选构造、弱与强
├── mini-hardcore-bit-goldreich-levin/    # Goldreich-Levin 定理、硬核谓词、列表译码
├── mini-hybrid-argument/                 # 混合论证引理、区分器、计算不可区分性
├── mini-owf-vs-prg-equivalence/          # OWF⇔PRG 等价性（HILL）、Yao 定理、拉伸
├── mini-pseudorandom-generators-crypto/  # BBS 生成器、Blum-Micali、硬核 LSB、下一比特不可预测性
├── mini-pseudorandom-functions-ggm/      # GGM PRF 构造、PRG⇒PRF、二叉树求值
├── mini-minimal-assumptions/             # Impagliazzo 世界、黑盒分离、困难性放大
├── mini-trapdoor-permutations/           # RSA TDP、密钥生成、基于 TDP 的公钥加密/签名
├── .gitignore
├── README.md
└── README-CN.md
```

## 许可证

MIT

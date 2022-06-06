X Project 镜像构建系统 （EKS / TKE托管）
=================

# 镜像构建

## 编译环境准备

编译环境需要安装如下工具：
1. 安装 docker-ce软件包
```
   dnf -y install docker-ce
```
2. 安装 cargo软件包 
```
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
3. 安装 cargo-make包
```
   cargo install cargo-make
```
4. 安装 toml-cli包
```
   cargo install toml-cli
```
以上步骤都集成在prepare.sh中完成。因此执行prepare.sh后以上工具包就已经安装。
执行prepare.sh后，会输出需要手动执行的步骤：
1. source $HOME/.cargo/env                             # 将cargo添加到环境变量；
2. ssh-keygen -t ed25519 -f builder_ed25519 -C builder # 生成ssh key，用于连接工蜂系统；
3. mkdir -p /home/builder/.ssh                         # 创建一个用于存放ssh key的目录；
4. cp builder_ed25519 /home/builder/.ssh/              # Makefile.toml默认使用该路径的key；
5. eval $(ssh-agent)                                   # 启动ssh agent；
6. ssh-add ./builder_ed25519                           # 将私钥共享到ssh agent；
7. cargo make                                          # 编译默认镜像；


```
注：cargo make -e TENCENT_TARGET=xxxx可以编译指定的产品镜像，默认是eks-dev。另外，第二步生成的./builder_ed25519.pub公钥需要添加到git.woa.com；
```

# 镜像版本命名

在产品目录下有对应的配置文件，其中包含了kernel的版本信息。例如:

targets/eks-dev/Cargo.toml中，
```
   [package.metadata.build-target]
   kernel-version="5.4.87-19"
```
Release.toml中包含X项目（同时也是X-let）的版本信息。
编译生成的镜像的命名规则为：
```
   产品名+kernel版本号+X项目版本号.img
```
例如： eks-dev-5.4.87-19-0001.img


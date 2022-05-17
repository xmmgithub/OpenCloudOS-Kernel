#!/bin/bash

which dnf >/dev/null 2>/dev/null
if [ $? -ne 0 ];then
    echo "Please yum install dnf"
    exit 1
fi

# setup base rpm
dnf -y install openssl-devel lz4

# install createrepo_c
rpm -qv createrepo_c >/dev/null
if [ $? -ne 0 ];then
    echo "****** install createrepo_c ***********"
    dnf -y install createrepo_c
fi

# install docker buildx
rpm -qv docker-ce >/dev/null
if [ $? -ne 0 ];then
    echo "****** install docker-ce ***********"
    dnf -y install docker-ce
fi

# install cargo and rustc
which rustc >/dev/null 2>/dev/null
if [ $? -ne 0 ];then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
fi
source $HOME/.cargo/env

# install cargo make
which cargo-make >/dev/null 2>/dev/null
if [ $? -ne 0 ];then
    cargo install cargo-make
fi

# install cargo toml-cli
which toml >/dev/null 2>/dev/null
if [ $? -ne 0 ];then
    cargo install toml-cli
fi

echo
echo "********************************************************"
echo "****     You need to do it manually              *******"
echo "*                                                  *****"
echo "* 1. source $HOME/.cargo/env                       *****"
echo "* 2. ssh-keygen -t ed25519 -f builder -C builder   *****"
echo "* 3. mkdir -p /home/builder/.ssh                   *****"
echo "* 4. cp builder /home/builder/.ssh/builder_ed25519 *****"
echo "* 5. eval \$(ssh-agent)                             *****"
echo "* 6. ssh-add builder                               *****"
echo "* 7. cargo make                                    *****"
echo "*                                                  *****"
echo "* Note: you should copy builder.pub to git.woa.com *****"
echo "********************************************************"
echo

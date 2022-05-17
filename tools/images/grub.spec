Name: grub
License: GPL
Version: 2.02
Release: 1%{?dist}
Summary: Bootloader with support for TencentOS
URL:http://mirrors.tencent.com/tlinux/3.2/BaseOS/Source/SPackages/grub2-%{version}-81.el8.src.rpm
Source0: discard-grub-rpm-sort.patch

BuildRequires: flex
BuildRequires: bison
BuildRequires: rpm-devel
BuildRequires: glibc-devel
BuildRequires: gettext-devel

%description
%{summary}.

%package modules
Summary: Modules for the bootloader with support for TencentOS
BuildArch: noarch

%description modules
%{summary}.

%package tools
Summary: Tools for the bootloader with support for TencentOS

%description tools
%{summary}.

%prep
wget %{URL}
rpm2cpio grub2-%{version}-81.el8.src.rpm | cpio -idvm
tar -xof grub-%{version}.tar.xz; rm grub-%{version}.tar.xz

%setup -TDn grub-%{version}
cp ../gitignore .gitignore
rm -fv docs/*.info configure
cp ../strtoull_test.c ./grub-core/tests/strtoull_test.c

git init
echo '!*.[[:digit:]]' > util/.gitignore
echo '!config.h' > include/grub/emu/.gitignore
echo '![[:digit:]][[:digit:]]_*.in' > util/grub.d/.gitignore
git config user.name "user"
git config user.email "owner@tencent.com"
git config gc.auto 0
git add .
git commit -a -q -m "%{version} baseline."
git apply --index --whitespace=nowarn ../release-to-master.patch
rm -rf ../release-to-master.patch
git commit -a -q -m "%{version} master."
git am --whitespace=nowarn  ../*.patch </dev/null
git apply --index --whitespace=nowarn %{SOURCE0}
autoreconf -vi
git add .
git commit -a -q -m "autoreconf"
autoconf
PYTHON=python3 ./autogen.sh

%global target_ldflags -static
%global _configure ../configure
%global target_cflags -pipe -fno-stack-protector -fno-strict-aliasing
%define _binaries_in_noarch_packages_terminate_build 0
%global debug_package %{nil}

%build
export TARGET_CFLAGS="%{target_cflags}"           \
       TARGET_CPPFLAGS="%{target_cflags}"         \
       TARGET_LDFLAGS="%{target_ldflags}"         \
       TARGET_NM="%{_cross_compile}nm"            \
       TARGET_CC="%{_cross_compile}gcc"           \
       TARGET_CPP="%{_cross_compile}gcc -E"       \
       TARGET_STRIP="%{_cross_compile}strip"      \
       TARGET_OBJCOPY="%{_cross_compile}objcopy"  \

%if "%{_arch}" == "x86_64"
mkdir build-bios
pushd build-bios

%cross_configure                        \
  CFLAGS=""                             \
  LDFLAGS=""                            \
  --host="%{_build}"                    \
  --target="%{_cross_bios_target}"      \
  --with-platform="%{_cross_bios_plat}" \
  --with-utils=host                     \
  --disable-grub-mkfont                 \
  --disable-rpm-sort                    \
  --disable-werror                      \
  --enable-efiemu=no                    \
  --enable-device-mapper=no             \
  --enable-libzfs=no                    \

make %{?_smp_mflags}
popd
%endif

mkdir build-efi
pushd build-efi

%configure                  \
  CFLAGS=""                 \
  LDFLAGS=""                \
  --host="%{_build}"        \
  --target="%{_cross_arch}" \
  --with-platform="efi"     \
  --with-utils=host         \
  --disable-grub-mkfont     \
  --disable-rpm-sort        \
  --disable-werror          \
  --enable-efiemu=no        \
  --enable-device-mapper=no \
  --enable-libzfs=no        \

make %{?_smp_mflags}
popd

%install
MODS="configfile echo ext2 linux normal reboot sleep"

%if "%{_arch}" == "x86_64"
pushd build-bios
%make_install
mkdir -p %{buildroot}%{_cross_grubdir}
%{buildroot}%{_bindir}/grub-mkimage           \
  -d ./grub-core                              \
  -O "%{_cross_bios_tuple}"                   \
  -o "%{buildroot}%{_cross_grubdir}/core.img" \
  -p "%{_cross_bios_prefix}"                  \
  biosdisk serial ${MODS}

install -m 0644 ./grub-core/boot.img          \
  %{buildroot}%{_cross_grubdir}/boot.img
popd
%endif

pushd build-efi
%make_install
mkdir -p %{buildroot}%{_cross_efidir}
%{buildroot}%{_bindir}/grub-mkimage                      \
  -d ./grub-core                                         \
  -O "%{_cross_efi_tuple}"                               \
  -o "%{buildroot}%{_cross_efidir}/%{_cross_efi_image}"  \
  -p "%{_cross_efi_prefix}"                              \
  efi_gop ${MODS}
popd

%files
%if "%{_arch}" == "x86_64"
%dir %{_cross_grubdir}
%{_cross_grubdir}/boot.img
%{_cross_grubdir}/core.img
%endif

%dir %{_cross_efidir}
%exclude %{_cross_infodir}
%exclude %{_cross_bashdir}
%exclude %{_cross_localedir}
%exclude %{_cross_sysconfdir}
%exclude %{_cross_sbindir}/grub-rpm-sort
%{_cross_efidir}/bootx64.efi
%{_cross_sbindir}/grub-bios-setup

%files modules
%dir %{_cross_lib64dir}/grub
%{_cross_lib64dir}/grub/*
%dir %{_cross_libdir}/grub
%{_cross_libdir}/grub/*

%files tools
%{_cross_bindir}/grub-file
%{_cross_bindir}/grub-fstest
%{_cross_bindir}/grub-editenv
%{_cross_bindir}/grub-kbdcomp
%{_cross_bindir}/grub-mkimage
%{_cross_bindir}/grub-mklayout
%{_cross_bindir}/grub-mknetdir
%{_cross_bindir}/grub-mkrescue
%{_cross_bindir}/grub-glue-efi
%{_cross_bindir}/grub-mkrelpath
%{_cross_bindir}/grub-mkstandalone
%{_cross_bindir}/grub-script-check
%{_cross_bindir}/grub-render-label
%{_cross_bindir}/grub-menulst2cfg
%{_cross_bindir}/grub-syslinux2cfg
%{_cross_bindir}/grub-mkpasswd-pbkdf2
%{_cross_sbindir}/grub-install
%{_cross_sbindir}/grub-macbless
%{_cross_sbindir}/grub-mkconfig
%{_cross_sbindir}/grub-ofpathname
%{_cross_sbindir}/grub-probe
%{_cross_sbindir}/grub-reboot
%{_cross_sbindir}/grub-set-bootflag
%{_cross_sbindir}/grub-set-default
%{_cross_sbindir}/grub-set-password
%{_cross_sbindir}/grub-sparc64-setup
%{_cross_sbindir}/grub-switch-to-blscfg
%{_cross_sbindir}/grub-get-kernel-settings

%dir %{_cross_datadir}/grub
%{_cross_datadir}/grub/grub-mkconfig_lib

%changelog

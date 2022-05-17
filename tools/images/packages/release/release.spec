%global _cross_first_party 1

Name: release
Version: 0.0
Release: 0%{?dist}
Summary: EKS Instance OS release
License: Apache-2.0 OR MIT

Source97: release-sysctl.conf

BuildArch: noarch
Requires: ca-certificates
Requires: coreutils
Requires: e2fsprogs
Requires: libgcc
Requires: libstd-rust
Requires: filesystem
Requires: glibc
Requires: iproute
Requires: bash
Requires: chrony
Requires: growpart
Requires: util-linux
Requires: net-tools
Requires: bridge-utils
Requires: shadow-utils
Requires: systemd
Requires: systemd-container
Requires: systemd-devel
Requires: systemd-libs
Requires: systemd-udev
Requires: systemd-networkd
Requires: grub
Requires: grub-tools
Requires: grub-modules

%description
%{summary}.

%prep

%build

%install
install -d %{buildroot}%{_cross_sysctldir}
install -p -m 0644 %{S:97} %{buildroot}%{_cross_sysctldir}/80-release.conf
%files
%{_cross_sysctldir}/80-release.conf

%changelog

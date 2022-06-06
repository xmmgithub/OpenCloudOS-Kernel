Name: growpart
Summary:  Script for growing a partition
Requires: gawk
Requires: util-linux
Version:  0.32
Release: 1%{?dist}
License: GPLv3
URL: https://launchpad.net/cloud-utils/
BuildArch: noarch
SOURCE1: growpart-and-resizefs-root.service

%description
This package provides the growpart script for growing a partition. It is
primarily used in cloud images in conjunction with the dracut-modules-growroot
package to grow the root partition on first boot.

%prep
mkdir cloud-utils-%{version}
cd cloud-utils-%{version}
git clone https://github.com/canonical/cloud-utils.git .
git checkout %{version}

%build

%install
cd cloud-utils-%{version}
mkdir -p %{buildroot}%{_cross_bindir}
install -p -m 0755 bin/growpart %{buildroot}%{_cross_bindir}
mkdir -p %{buildroot}%{_cross_unitdir}/multi-user.target.wants
install -m 0644 %{S:1} %{buildroot}%{_cross_unitdir}
ln -sf %{_cross_unitdir}/growpart-and-resizefs-root.service %{buildroot}%{_cross_unitdir}/multi-user.target.wants/growpart-and-resizefs-root.service

%files
%{_cross_bindir}/growpart
%{_cross_unitdir}/growpart-and-resizefs-root.service
%{_cross_unitdir}/multi-user.target.wants/growpart-and-resizefs-root.service

%changelog

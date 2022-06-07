%global goproject github.com/containerd
%global gorepo containerd
%global goimport %{goproject}/%{gorepo}

%global gover 1.4.3
%global rpmver %{gover}
%global gitrev c8878e4731e164006ee739bb24dc9f5d0e977782

%global _dwz_low_mem_die_limit 0

Name: %{_cross_os}%{gorepo}
Version: %{rpmver}
Release: 1%{?dist}
Summary: An industry-standard container runtime
License: Apache-2.0
URL: https://git.woa.com/tke/eks/containerd
Source1: containerd.service
Source2: containerd-config.toml
Source5: containerd-tmpfiles.conf

BuildRequires: git
BuildRequires: %{_cross_os}glibc-devel
BuildRequires: %{_cross_os}libseccomp-devel
Requires: %{_cross_os}cni-plugins
Requires: %{_cross_os}libseccomp
Requires: %{_cross_os}runc
Requires: %{_cross_os}systemd

%description
%{summary}.

%prep
mkdir %{gorepo}-%{gover}
%cross_go_setup %{gorepo}-%{gover} %{goproject} %{goimport}
%cross_go_configure %{goimport}
git clone git@git.woa.com:tke/eks/containerd.git .
git checkout v%{gover}-eks.1

%build
%cross_go_configure %{goimport}
export BUILDTAGS="no_btrfs seccomp"
export LD_VERSION="-X github.com/containerd/containerd/version.Version=%{gover}+eks"
export LD_REVISION="-X github.com/containerd/containerd/version.Revision=%{gitrev}"
for bin in \
  containerd \
  containerd-shim \
  containerd-shim-runc-v1 \
  containerd-shim-runc-v2 \
  ctr ;
do
  go build \
     -buildmode=pie \
     -ldflags="-linkmode=external ${LD_VERSION} ${LD_REVISION}" \
     -tags="${BUILDTAGS}" \
     -o ${bin} \
     %{goimport}/cmd/${bin}
done

%install
cd %{gorepo}-%{gover}
install -d %{buildroot}%{_cross_bindir}
for bin in \
  containerd \
  containerd-shim \
  containerd-shim-runc-v1 \
  containerd-shim-runc-v2 \
  ctr ;
do
  install -p -m 0755 ${bin} %{buildroot}%{_cross_bindir}
done

install -d %{buildroot}%{_cross_unitdir}
install -p -m 0644 %{S:1} %{buildroot}%{_cross_unitdir}/containerd.service

install -d %{buildroot}%{_cross_templatedir}
install -d %{buildroot}%{_cross_sysconfdir}/containerd
install -p -m 0644 %{S:2} %{buildroot}%{_cross_sysconfdir}/containerd/config.toml

install -d %{buildroot}%{_cross_tmpfilesdir}
install -p -m 0644 %{S:5} %{buildroot}%{_cross_tmpfilesdir}/containerd.conf

%files
%{_cross_bindir}/containerd
%{_cross_bindir}/containerd-shim
%{_cross_bindir}/containerd-shim-runc-v1
%{_cross_bindir}/containerd-shim-runc-v2
%{_cross_bindir}/ctr
%{_cross_unitdir}/containerd.service
%dir %{_cross_sysconfdir}/containerd
%{_cross_sysconfdir}/containerd/config.toml
%{_cross_tmpfilesdir}/containerd.conf

%changelog

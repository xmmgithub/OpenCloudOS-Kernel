%global goproject https://git.woa.com/tke/eks
%global gorepo eklet-agent
%global goimport %{goproject}/%{gorepo}

%global gover 2.6.27
%global rpmver %{gover}

Name: %{_cross_os}eklet-agent
Version: %{rpmver}
Release: 1%{?dist}
Summary: eklet agent
License: Apache-2.0
URL: https://git.woa.com/tke/eks/eklet-agent
Source1: eklet-agent-init.service
Source2: eklet-agent.service
Source3: eklet-agent-final.service
Source4: final.sh

BuildRequires: git
BuildRequires: %{_cross_os}glibc-devel
Requires: %{_cross_os}runc
Requires: %{_cross_os}systemd
Requires: %{_cross_os}contaienrd
Requires: %{_cross_os}eklet-network

%description
%{summary}.

%prep
mkdir eklet-agent-%{version}
cd eklet-agent-%{version}
git clone --recurse-submodules git@git.woa.com:tke/eks/eklet-agent.git .
git checkout v%{version}
go mod vendor

%build
cd eklet-agent-%{version}
%set_cross_go_flags
make build

%install
cd eklet-agent-%{version}
install -d %{buildroot}%{_cross_unitdir}
install -p -m 0644 %{S:1} %{S:2} %{S:3} %{buildroot}%{_cross_unitdir}/
install -d %{buildroot}%{_cross_bindir}
install -p -m 0755 target/eklet-agent %{buildroot}%{_cross_bindir}
install -p -m 0755 target/eklet-agent-init %{buildroot}%{_cross_bindir}
install -p -m 0755 %{S:4} %{buildroot}%{_cross_bindir}
mkdir -p %{buildroot}%{_cross_unitdir}/multi-user.target.wants
ln -sf %{_cross_unitdir}/eklet-agent.service %{buildroot}%{_cross_unitdir}/multi-user.target.wants/eklet-agent.service
ln -sf %{_cross_unitdir}/eklet-agent-init.service %{buildroot}%{_cross_unitdir}/multi-user.target.wants/eklet-agent-init.service
ln -sf %{_cross_unitdir}/eklet-agent-final.service %{buildroot}%{_cross_unitdir}/multi-user.target.wants/eklet-agent-final.service

%files
%{_cross_bindir}/eklet-agent
%{_cross_bindir}/eklet-agent-init
%{_cross_bindir}/final.sh
%{_cross_unitdir}/*
%dir %{_cross_unitdir}/multi-user.target.wants
%{_cross_unitdir}/multi-user.target.wants/*

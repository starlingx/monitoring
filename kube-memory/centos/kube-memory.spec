%global pypi_name kube-memory

Summary: Display services and kubernetes containers memory usage
Name: kube-memory
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: base
Packager: Wind River <info@windriver.com>

URL: unknown
Source0:        %{pypi_name}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires: python
BuildRequires: python-setuptools
BuildRequires: python2-pip
BuildRequires: python2-wheel

Requires: python
Requires: python-devel
Requires: /usr/bin/env
Requires: /bin/bash

%define debug_package %{nil}

%description
Display services and kubernetes containers memory usage

%define pythonroot /usr/lib64/python2.7/site-packages

%prep
%autosetup -p 1 -n %{pypi_name}-%{version}
# Remove bundled egg-info
rm -rf %{pypi_name}.egg-info
# Let RPM handle the dependencies
rm -f requirements.txt
rm -f test-requirements.txt

%build
%{__python2} setup.py build
%py2_build_wheel

%install
%{__python2} setup.py install --skip-build --root %{buildroot}
mkdir -p $RPM_BUILD_ROOT/wheels
install -m 644 dist/*.whl $RPM_BUILD_ROOT/wheels/
mkdir -p %{buildroot}
install -d 755 -d %{buildroot}%{_sysconfdir}/collect.d
install -m 755 collect_kube_memory.sh %{buildroot}%{_sysconfdir}/collect.d/collect_kube_memory

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_bindir}/kube-memory
%{python2_sitelib}/kube_memory
%{python2_sitelib}/*.egg-info
%{_sysconfdir}/collect.d/*

%package wheels
Summary: %{name} wheels

%description wheels
Contains python wheels for %{name}

%files wheels
/wheels/*

%clean
rm -rf $RPM_BUILD_ROOT

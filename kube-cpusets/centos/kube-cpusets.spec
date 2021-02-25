%global pypi_name kube-cpusets

Summary: Display kubernetes containers cpusets per numa node
Name: kube-cpusets
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: base
Packager: Wind River <info@windriver.com>

URL: unknown
Source0:        %{pypi_name}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires: python3
BuildRequires: python3-setuptools
BuildRequires: python3-pip
BuildRequires: python3-wheel

Requires: python3
Requires: python3-devel
Requires: /usr/bin/env
Requires: /bin/bash

%define debug_package %{nil}

%description
Display kubernetes containers cpusets per numa node

%define pythonroot %{python3_sitearch}

%prep
%autosetup -p 1 -n %{pypi_name}-%{version}
# Remove bundled egg-info
rm -rf %{pypi_name}.egg-info
# Let RPM handle the dependencies
rm -f requirements.txt
rm -f test-requirements.txt

%build
%{__python3} setup.py build
%py3_build_wheel

%install
%{__python3} setup.py install --skip-build --root %{buildroot}
mkdir -p $RPM_BUILD_ROOT/wheels
install -m 644 dist/*.whl $RPM_BUILD_ROOT/wheels/

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_bindir}/kube-cpusets
%{python3_sitelib}/kube_cpusets
%{python3_sitelib}/*.egg-info

%package wheels
Summary: %{name} wheels

%description wheels
Contains python wheels for %{name}

%files wheels
/wheels/*

%clean
rm -rf $RPM_BUILD_ROOT

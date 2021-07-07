Summary: Titanuim Server collectd Package
Name: collectd-extensions
Version: 1.0
Release: 0%{?_tis_dist}.%{tis_patch_ver}
License: ASL 2.0
Group: base
Packager: Wind River <info@windriver.com>
URL: unknown

# create the files tarball
Source0: %{name}-%{version}.tar.gz
Source1: collectd.service
Source2: collectd.conf.pmon

# collectd python plugin files - notifiers
Source3: fm_notifier.py
Source5: plugin_common.py
Source6: README

# collectd python plugin files - resource plugins
Source11: cpu.py
Source12: memory.py
Source15: ntpq.py
Source16: interface.py
Source17: remotels.py
Source18: ptp.py
Source19: ovs_interface.py

# collectd plugin conf files into /etc/collectd.d
Source100: python_plugins.conf
Source101: cpu.conf
Source102: memory.conf
Source103: df.conf
Source105: ntpq.conf
Source106: interface.conf
Source107: remotels.conf
Source108: ptp.conf
Source109: ovs_interface.conf

BuildRequires: systemd-devel

Requires: systemd
Requires: collectd
Requires: collectd-python
Requires: fm-api
Requires: python3-httplib2
Requires: python3-influxdb
Requires: python3-oslo-concurrency
Requires: python3-oslo-utils
Requires: tsconfig
Requires: /bin/systemctl

%description
StarlingX collectd extensions

%define debug_package %{nil}
%define local_unit_dir %{_sysconfdir}/systemd/system
%define local_default_plugin_dir %{_sysconfdir}/collectd.d
%define local_starlingx_plugin_dir %{_sysconfdir}/collectd.d/starlingx
%define local_python_extensions_dir /opt/collectd/extensions/python
%define local_config_extensions_dir /opt/collectd/extensions/config

%prep
%setup

%build

%install
install -m 755 -d %{buildroot}%{_sysconfdir}
install -m 755 -d %{buildroot}%{local_unit_dir}
install -m 755 -d %{buildroot}%{local_default_plugin_dir}
install -m 755 -d %{buildroot}%{local_starlingx_plugin_dir}
install -m 755 -d %{buildroot}%{local_config_extensions_dir}
install -m 755 -d %{buildroot}%{local_python_extensions_dir}

# support files ; service and pmon conf
install -m 644 %{SOURCE1} %{buildroot}%{local_unit_dir}
install -m 600 %{SOURCE2} %{buildroot}%{local_config_extensions_dir}

# collectd python plugin files - notifiers
install -m 700 %{SOURCE3} %{buildroot}%{local_python_extensions_dir}
install -m 700 %{SOURCE5} %{buildroot}%{local_python_extensions_dir}

# install README file into /etc/collectd.d
install -m 644 %{SOURCE6} %{buildroot}%{local_default_plugin_dir}

# collectd python plugin files - resource plugins
install -m 700 %{SOURCE11} %{buildroot}%{local_python_extensions_dir}
install -m 700 %{SOURCE12} %{buildroot}%{local_python_extensions_dir}
install -m 700 %{SOURCE15} %{buildroot}%{local_python_extensions_dir}
install -m 700 %{SOURCE16} %{buildroot}%{local_python_extensions_dir}
install -m 700 %{SOURCE17} %{buildroot}%{local_python_extensions_dir}
install -m 700 %{SOURCE18} %{buildroot}%{local_python_extensions_dir}
install -m 700 %{SOURCE19} %{buildroot}%{local_python_extensions_dir}


# collectd plugin conf files into /etc/collectd.d/starlingx
install -m 600 %{SOURCE100} %{buildroot}%{local_starlingx_plugin_dir}
install -m 600 %{SOURCE101} %{buildroot}%{local_starlingx_plugin_dir}
install -m 600 %{SOURCE102} %{buildroot}%{local_starlingx_plugin_dir}
install -m 600 %{SOURCE103} %{buildroot}%{local_starlingx_plugin_dir}
install -m 600 %{SOURCE105} %{buildroot}%{local_starlingx_plugin_dir}
install -m 600 %{SOURCE106} %{buildroot}%{local_starlingx_plugin_dir}
install -m 600 %{SOURCE107} %{buildroot}%{local_starlingx_plugin_dir}
install -m 600 %{SOURCE108} %{buildroot}%{local_starlingx_plugin_dir}
install -m 600 %{SOURCE109} %{buildroot}%{local_starlingx_plugin_dir}

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%config(noreplace) %{local_unit_dir}/collectd.service
%{local_default_plugin_dir}/*
%dir %{local_starlingx_plugin_dir}
%{local_starlingx_plugin_dir}/*
%{local_config_extensions_dir}/*
%{local_python_extensions_dir}/*

Name:           orc
Version:        0.4.30
Release:        1
License:        BSD-2.0
Summary:        The Oil Runtime Compiler
Group:          Multimedia/Libraries
Source:         %{name}-%{version}.tar.gz
Source1001:     orc.manifest
BuildRequires:  pkg-config
BuildRequires:  meson
BuildRequires:  glib2-devel
Provides:       %{name}-devel = %{version}

%description
Orc is a library and set of tools for compiling and executing very simple
programs that operate on arrays of data.  The “language” is a generic
assembly language that represents many of the features available in SIMD
architectures, including saturated addition and subtraction, and many
arithmetic operations.

%package -n liborc
Summary:        The Oil Runtime Compiler Library
Group:          Multimedia/Libraries

%description -n liborc
Orc is a library and set of tools for compiling and executing very simple
programs that operate on arrays of data.  The “language” is a generic
assembly language that represents many of the features available in SIMD
architectures, including saturated addition and subtraction, and many
arithmetic operations.

%prep
%setup -q
cp %{SOURCE1001} .

%build

rm -rf build
meson --buildtype=plain --prefix=%{_prefix} --libdir=%{_libdir} build
ninja -C build %{?_smp_mflags}

%install
DESTDIR=%{buildroot} ninja -C build %{?_smp_mflags} install

%check
pushd build/examples
export ORC_DEBUG=4
./example1
./example2
./example3
./mt19937ar
popd

%post -n liborc -p /sbin/ldconfig

%postun -n liborc -p /sbin/ldconfig

%files
%manifest %{name}.manifest
%defattr(-,root,root)
%license COPYING
%{_bindir}/orc-bugreport
%{_bindir}/orcc
%{_includedir}/orc-0.4/
%{_libdir}/*.so
%{_libdir}/liborc-test-0.4.so.*
%{_libdir}/liborc-test-0.4.a
%{_libdir}/pkgconfig/orc-0.4.pc
%{_libdir}/pkgconfig/orc-test-0.4.pc
%{_datadir}/aclocal/orc.m4

%files -n liborc
%manifest %{name}.manifest
%defattr(-,root,root)
%{_libdir}/liborc-0.4.so.*

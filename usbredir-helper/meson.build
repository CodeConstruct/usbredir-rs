project('usbredir-helper',
  'rust',
  version: '0.3.0',
  license: 'LGPL-2.1-or-later'
)

buildtype = get_option('buildtype')
prefix = get_option('prefix')
bindir = get_option('bindir')
libdir = get_option('libdir')
libexecdir = get_option('libexecdir')
datadir = get_option('datadir')
etc = get_option('sysconfdir')
polkitdir = datadir / 'polkit-1/actions'

find_program('cargo', required: true)
cargo_sh = find_program('build-aux/cargo.sh', required: true)

custom_target(
  'cargo-build',
  build_by_default: true,
  output: meson.project_name(),
  console: true,
  install: true,
  install_dir: prefix / libexecdir,
  depend_files: files('src/main.rs'),
  command: [
    cargo_sh,
    meson.build_root(),
    meson.source_root(),
    '@OUTPUT@',
    buildtype,
    meson.project_name(),
  ]
)

install_data('data/org.freedesktop.usbredir1.policy',
  install_dir: polkitdir)

configure_file(
  input: 'data/dbus-org.freedesktop.usbredir1.service.in',
  output: 'dbus-org.freedesktop.usbredir1.service',
  install_dir: prefix / 'lib/systemd/system',
  configuration: {'ExecStart': prefix / libexecdir / meson.project_name()},
)

install_data('data/org.freedesktop.usbredir1.service',
  install_dir: prefix / 'share/dbus-1/system-services')

install_data('data/org.freedesktop.usbredir1.conf',
  install_dir: etc / 'dbus-1/system.d')

meson.add_install_script('build-aux/install.sh')

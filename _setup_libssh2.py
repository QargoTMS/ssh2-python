# This file is part of ssh2-python.
# Copyright (C) 2017-2021 Panos Kittenis and contributors.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation, version 2.1.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
import os
from glob import glob
from shutil import copy2
from subprocess import check_call

from sys import stderr


def build_ssh2():
    if bool(os.environ.get('SYSTEM_LIbBSSH2', False)):
        stderr.write("Using system libssh2..%s" % (os.sep,))
        return
    if os.path.exists('/usr/local/opt/openssl'):
        os.environ['OPENSSL_ROOT_DIR'] = '/usr/local/opt/openssl'
    if os.path.exists('/opt/homebrew/opt/openssl'):
        os.environ['OPENSSL_ROOT_DIR'] = '/opt/homebrew/opt/openssl'

    if not os.path.exists('build_dir'):
        os.mkdir('build_dir')

    os.chdir('build_dir')
    check_call('cmake ../libssh2 -DBUILD_SHARED_LIBS=ON \
    -DENABLE_ZLIB_COMPRESSION=ON -DENABLE_CRYPT_NONE=ON \
    -DENABLE_MAC_NONE=ON -DCRYPTO_BACKEND=OpenSSL \
    -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF',
               shell=True, env=os.environ)
    check_call('cmake --build . --config Release', shell=True, env=os.environ)
    os.chdir('..')

    # Linux/BSD build .so, macOS builds .dylib - copy whichever exists.
    # follow_symlinks=False preserves the versioned symlink chain (e.g.
    # libssh2.1.dylib -> libssh2.1.0.1.dylib); remove any stale destination
    # first so re-runs don't fail on an existing symlink.
    for pattern in ('build_dir/src/libssh2.so*', 'build_dir/src/libssh2*.dylib'):
        for src in glob(pattern):
            dst = os.path.join('ssh2', os.path.basename(src))
            if os.path.lexists(dst):
                os.remove(dst)
            copy2(src, dst, follow_symlinks=False)

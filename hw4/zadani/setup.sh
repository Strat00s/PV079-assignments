#!/usr/bin/env bash

# Setup script for a Python virtual environment for the lattice attack.
# This creates a Python3 ivrtual environment and installs fpylll into it.
# See <https://github.com/fplll/fpylll> for information on manual installation.
# This requires the fplll library, which in turn requires GMP and MPFR.
#
# Running fpylll with fplll installed in a virtual environment requires
# the setting of the LD_LIBRARY_PATH and PKG_CONFIG_PATH variables, as is
# done below in the activate script.

# Create Virtual Environment

echo "[ ] Load required modules."
echo " - python3-3.7.6"
echo " - gcc-9.2"
echo " - gmp-4.3.2"
echo " - mpfr-3.0.0"
echo " - libtool-2.4.2"
module add python3-3.7.6 gcc-9.2 gmp-4.3.2 mpfr-3.0.0 libtool-2.4.2

echo "[*] Loaded."

echo "[ ] Creating virtual environment 'virt'."

python3 -m venv virt
cat <<EOF >>virt/bin/activate
### LD_LIBRARY_HACK
_OLD_LD_LIBRARY_PATH="\$LD_LIBRARY_PATH"
LD_LIBRARY_PATH="\$VIRTUAL_ENV/lib:\$LD_LIBRARY_PATH"
export LD_LIBRARY_PATH
### END_LD_LIBRARY_HACK

### PKG_CONFIG_HACK
_OLD_PKG_CONFIG_PATH="\$PKG_CONFIG_PATH"
PKG_CONFIG_PATH="\$VIRTUAL_ENV/lib/pkgconfig:\$PKG_CONFIG_PATH"
export PKG_CONFIG_PATH
### END_PKG_CONFIG_HACK
      
CFLAGS="\$CFLAGS -O3 -march=native -Wp,-U_FORTIFY_SOURCE"
CXXFLAGS="\$CXXFLAGS -O3 -march=native -Wp,-U_FORTIFY_SOURCE"
export CFLAGS
export CXXFLAGS
EOF

. virt/bin/activate

pip install -U pip

echo "[*] Created and activated."

# Install FPLLL

echo "[ ] Installing fplll into fplll/."

git clone https://github.com/fplll/fplll
cd fplll || exit
./autogen.sh
./configure --prefix="$VIRTUAL_ENV" $CONFIGURE_FLAGS
make clean
make -j 4
make install
cd ..

echo "[*] Installed."

# Install FPyLLL

echo "[ ] Installing fpylll into fpylll/."

git clone https://github.com/fplll/fpylll
cd fpylll
pip install Cython
pip install -r requirements.txt
pip install -r suggestions.txt
python setup.py clean
python setup.py build_ext
python setup.py install
cd ..

echo "[*] Installed."
echo "[*] All done!"

echo "Don't forget to activate the environment each time:"
echo " module add python3-3.7.6 gmp-4.3.2 mpfr-3.0.0"
echo " . virt/bin/activate"


apt-get update && apt-get install -y astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind dumpasn1

mkdir /git && cd /git

git clone -b main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build && cmake -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_DIST_BUILD=ON .. && ninja install

export LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH}"

cd /git
git clone -b main https://github.com/open-quantum-safe/liboqs-python.git
cd liboqs-python
python3 setup.py install

cd $1/example_generator

pip install --no-cache-dir -r requirements.txt

python main.py | tee artifacts.txt

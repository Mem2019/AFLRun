# AFLRun

## Usage

The AFLRun is tested with clang 16.0.3, the other version might work but might also be problematic. These are the steps to compile the LLVM project for AFLRun.

```bash
# Clone LLVM project.
git clone --depth=1 https://github.com/llvm/llvm-project.git && \
	cd llvm-project && \
	git fetch origin --depth=1 4a2c05b05ed07f1f620e94f6524a8b4b2760a0b1 && \
	git reset --hard 4a2c05b05ed07f1f620e94f6524a8b4b2760a0b1

# Download binutils.
wget https://ftp.gnu.org/gnu/binutils/binutils-2.39.tar.gz -O binutils.tar.gz && \
	tar -xf binutils.tar.gz

# Download CMake.
wget https://github.com/Kitware/CMake/releases/download/v3.25.1/cmake-3.25.1-linux-x86_64.tar.gz -O cmake.tar.gz && \
	tar -xf cmake.tar.gz

# Compile and install LLVM project.
# Please change "/path/to/install" to your install path.
PATH_TO_INSTALL="/path/to/install"
mkdir build && cd build
export CXX=g++
export CC=gcc
../cmake-3.25.1-linux-x86_64/bin/cmake -G "Ninja" \
  -DLLVM_BINUTILS_INCDIR=$PWD/../binutils-2.39/include \
  -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD=host \
  -DLLVM_ENABLE_PROJECTS="clang;compiler-rt;lld" \
  -DCMAKE_INSTALL_PREFIX="$PATH_TO_INSTALL" \
  -DLLVM_INSTALL_BINUTILS_SYMLINKS=ON $PWD/../llvm/
ninja -j $(nproc) && ninja install
cd ../.. && rm -rf llvm-project
```

Then we can compile AFLRun

```bash
git clone https://github.com/Mem2019/AFLRun.git && cd AFLRun
git submodule update --init robin-hood-hashing/
export CC="$PATH_TO_INSTALL/bin/clang"
export CXX="$PATH_TO_INSTALL/bin/clang++"
make clean all
AFLRUN="$PWD"
```

Now we can use AFLRun to compile program

```bash
# Set target file, the format is same as AFLGo.
export AFLRUN_BB_TARGETS="/path/to/BBtargets.txt"
# Names of target binaries to instrument, "::" means instrument all binaries.
export AFLRUN_TARGETS="bin1:bin2"
# Optional, directory to store data. If not set, a random directory will be created.
export AFLRUN_TMP="/tmp/"
export CC="$AFLRUN/afl-clang-lto"
export CXX="$AFLRUN/afl-clang-lto++"
```

## Citation

```bibtex
@article{Rong2023TowardUM,
  title={Toward Unbiased Multiple-Target Fuzzing with Path Diversity},
  author={Huanyao Rong and Wei You and Xiaofeng Wang and Tianhao Mao},
  journal={ArXiv},
  year={2023},
  volume={abs/2310.12419}
}
```

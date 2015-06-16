FROM        ubuntu:14.04
MAINTAINER  vgough

# update and install dependencies
RUN     apt-get update \
        && apt-get install -y \
            software-properties-common \
            wget \
            make \
        && echo 'deb http://llvm.org/apt/trusty/ llvm-toolchain-trusty-3.4 main' >> /etc/apt/sources.list \
        && wget -O - http://llvm.org/apt/llvm-snapshot.gpg.key|sudo apt-key add - \
        && add-apt-repository -y ppa:ubuntu-toolchain-r/test \
        && apt-get update \
        && apt-get install -y \
            gcc-4.9 g++-4.9 gcc-4.9-base \
            clang-3.4 lldb-3.4 \
        && apt-get clean \
        && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.9 100 \
        && update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-4.9 100

# build cmake
RUN     wget http://www.cmake.org/files/v3.2/cmake-3.2.2.tar.gz \
        && tar -xvf cmake-3.2.2.tar.gz
WORKDIR     cmake-3.2.2
RUN         ./bootstrap \
                && make \
                && make install


RUN     apt-get -y upgrade \
        && apt-get -y install \
            git \
            libfuse-dev \
            libboost-serialization-dev \
            libssl-dev \
            librlog-dev \
            gettext \
            libgettextpo-dev \
        && apt-get clean


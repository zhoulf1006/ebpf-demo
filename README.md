This repo follows [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) to create ebpf applications.



## Building

libbpf-bootstrap supports multiple build systems that do the same thing.
This serves as a cross reference for folks coming from different backgrounds.

### Install Dependencies

You will need `clang`, `libelf` and `zlib` to build the examples, package names may vary across distros.

On Ubuntu/Debian, you need:
```shell
$ apt install -y clang libelf1 libelf-dev zlib1g-dev
```

On CentOS/Fedora, you need:
```shell
$ dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```
### Getting the source code

Download the git repository and check out submodules:
```shell
$ git clone --recurse-submodules https://github.com/zhoulf1006/ebpf-demo
```

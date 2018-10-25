# Linux Kernel Crypto API Examples

Testing the crypto samples in the Linux kernel document.

Note: It seems the kernel crypto API v4.14 is different to v4.15+.  

You can check the crypto support in kernel by:

```Bash
cat /proc/crypto
```

The SHA384 and SHA512 might not be enabled by default, it has to turn on with:

```Bash
$ make linux-menuconfig
  Cryptographic API —> SHA384 and SHA512 digest algorithm
```

## [Code Example For Symmetric Key Cipher Operation (v4.14)](https://www.kernel.org/doc/html/v4.14/crypto/api-samples.html#code-example-for-symmetric-key-cipher-operation)

Built and tested on Debian 9.x (4.14.0-3-amd64).

```Bash

# cbc-aes-aesni

cd aes-example
make
sudo dmesg -C
sudo insmod aes-example.ko
sudo rmmod aes-example.ko
sudo dmesg

```

## [Code Example For Use of Operational State Memory With SHASH (v4.14+)](https://www.kernel.org/doc/html/latest/crypto/api-samples.html#code-example-for-use-of-operational-state-memory-with-shash)

Modified to be built and tested on Debian 9.x (4.14.0-3-amd64).

```Bash

# shash (SHA1)

cd shash-example
make
sudo dmesg -C
sudo insmod shash-example.ko
sudo rmmod shash-example.ko
sudo dmesg

```

## [Code Example For Symmetric Key Cipher Operation (v4.14+)](https://www.kernel.org/doc/html/latest/crypto/api-samples.html#code-example-for-symmetric-key-cipher-operation)

Cannot get compiled Debian 9.x (4.14.0-3-amd64).

```Bash

# cbc-aes-aesni

cd aes-example
make
sudo dmesg -C
sudo insmod aes-example.ko
sudo rmmod aes-example.ko
sudo dmesg

```

## [Code Example For Random Number Generator Usage (v4.14+)](https://www.kernel.org/doc/html/latest/crypto/api-samples.html#code-example-for-symmetric-key-cipher-operation)

```Bash

# rand

# load drbg module
sudo modprobe drbg

cd rand-example
make
sudo dmesg -C
sudo insmod rand-example.ko
sudo rmmod rand-example.ko
sudo dmesg

```

Output

```Bash
[ 2223.280561] test rand loaded
[ 2223.280597] RNG returned no data
[ 2223.280599] get_random_numbers return 0
[ 2223.280600] 10
[ 2223.280600] 58
[ 2223.280600] 77
[ 2223.280601] 69
[ 2223.280601] 48
[ 2223.280602] 19
[ 2223.280602] ca
[ 2223.280602] 43
[ 2223.280603] 2b
[ 2223.280603] a0
[ 2223.280604] de
[ 2223.280604] fa
[ 2223.280604] 88
[ 2223.280605] 63
[ 2223.280605] a3
```

## Reference

* [Linux Kernel Cryptographic API for fun and profit](https://schd.ws/hosted_files/ossna2017/37/Linux_crypto_API_tutorial.pdf)
* [Confessions of a security hardware driver maintainer](https://events.static.linuxfound.org/sites/events/files/slides/gby_confession_LSS_2017.pdf)
* [A overview of Linux crypto subsystem](http://events17.linuxfoundation.org/sites/events/files/slides/brezillon-crypto-framework_0.pdf)
* Crypto headers: /usr/src/linux-headers-4.14.0-3-common/include/crypto

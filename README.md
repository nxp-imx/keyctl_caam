# 1. Overview

This document provides a step-by-step procedure on how to generate a black key and
encapsulate it into a black blob. One can also import a black key from a black blob.

Black Keys represent keys stored in memory, in encrypted form and decrypted on-the-fly
when used. CAAM supports two different black key encapsulation schemes, which
are AES-ECB and AES-CCM. Regarding AES-ECB encryption, the data is a multiple of
16 bytes long and is intended for quick decryption. The AES-CCM mode is not as fast
as AES-ECB mode, but includes a “MAC tag” (integrity check value) that ensures the
integrity of the encapsulated key. A CCM-encrypted black key is always at least 12 bytes
longer than the encapsulated key (nonce value + MAC tag).

CAAM provides a method to protect data, across system power cycles, in a cryptographic
data structure called blob. The data to be protected is encrypted so that it can be
safely placed into non-volatile storage.

## 1.1 Build the kernel

Get a bootable image that includes the black key support for Linux kernel.
Or build the kernel from here: https://source.codeaurora.org/external/imx/linux-imx/.
For more details refer to i.MX Linux User's Guide from https://www.nxp.com/

## 1.2 Build a toolchain

Build a toolchain in order to cross compile the sources of the caam-keygen application.
For details refer to i.MX Yocto Project User's Guide from https://www.nxp.com/

## 1.3 Cross compile the user space sources

Setup the environment for cross compilation using the toolchain previously prepared.

- From the toolchain install folder set up the environment:

```
  $ ./environment-setup-aarch64-poky-linux
```

- Build the caam-keygen user space application, go to source folder and run:

```
  $ make
```

- One can build the caam-keygen user space application, and set the location for generated keys and blobs:

```
  $ make KEYBLOB_LOCATION=/data/caam/keys/
```
If KEYBLOB_LOCATION is not specified, the keys and blobs are created in default KEYBLOB_LOCATION, which is /data/caam/.

# 2. Usage

After the device successfully boots with the previously generated image, black
keys (and blobs) can be generated or imported.
These keys can be used for encrypting/decrypting data (e.g. dm-crypt).

```
  $ ./caam-keygen
CAAM keygen usage: caam-keygen [options]
Options:
create <key_name> <key_enc> <key_mode> <key_val>
	<key_name> the name of the file that will contain the black key.
	A file with the same name, but with .bb extension, will contain the black blob.
	<key_enc> can be ecb or ccm
	<key_mode> can be -s or -t.
	   -s generate a black key from random with the size given in the next argument
	   -t generate a black key from a plaintext given in the next argument
	<key_val> the size or the plaintext based on the previous argument (<key_mode>)
	<text_type> can be -h or -p (default argument is -p)
	   -h generate a black key from the hex text that is provided in previous argument
	   -p generate a black key from the plain text that is provided in previous argument
import <blob_name> <key_name>
	<blob_name> the absolute path of the file that contains the blob
	<key_name> the name of the file that will contain the black key.
derive  [-pass <pass_phrase>] [-md <digest>] [-S <salt>] <derived_key_name>
	<pass_phrase> password value
	<digest> Supported digest:-
		 sha1
		 sha224
		 sha256
		 sha384
		 sha512
		 Note:- Default algorithm is sha-256.
        <salt> [Optional] The actual salt to use.
			 8 bytes salt value needs to be provided.
			 If salt value > 8 bytes, trim to 8 bytes.
			 If salt_value < 8 bytes, zero padding is added.
			 If no salt is provided, -nosalt option will be used.
        <derived_key_name> Black key obtained after using PBKDF2
			   derivation function.

```

By default, the keys and blobs are created in KEYBLOB_LOCATION, which is /data/caam/.

## 2.1 Create a black key

- Create a key (and blob) with the desired name, ECB or CCM encryption, from random or plaintext:

```
  $ caam-keygen create <key_name> <key_enc> <key_mode> <key_val>
    <key_name> is the name of the file that will contain the black key.
    A file with the same name, but with .bb extension, will contain the black blob.
    <key_enc> can be ecb or ccm
    <key_mode> can be -s or -t.
    -s means it will generate a black key from random with the size given in the next argument
    -t means it will generate a black key from a plaintext given in the next argument
    <key_val> is the size or the plaintext based on the previous argument (<key_mode>)
    <text_type> can be -h or -p (default argument is -p)
    -h generate a black key from the hex text that is provided in previous argument.
    -p generate a black key from the plain text that is provided in previous argument

```

## 2.2 Import a black key from a blob

- Create a regular file with the desired key obtained by decapsulating a black blob:

```
  $ caam-keygen import <blob_name> <key_name>
    <blob_name> is the absolute path of the file that contains the blob
    <key_name> is the name of the file that will contain the black key.
```

## 2.3 Derive PBKDF2 based key using password and salt

- Derive PBKDF2 based key using password and salt.
- Key will be stored as black key.
- Salt & IV will be printed on console.

```
$caam-keygen derive  [-pass <pass_phrase>] [-md <digest>] [-S <salt>] <derived_key_name>
	<pass_phrase> password value
	<digest> Use the specified digest to create the key from the
		 passphrase. The default algorithm is sha-256.
        <salt> The actual salt to use: this must be represented as a string
	       of hex digits (default is -nosalt option).
        <derived_key_name> Black key obtained after using PBKDF2
			   derivation function.
```

# 3. Use case example

Next is exemplified how a key can be created, added into a keyring and used for disk encryption.

- After booting the device, make sure that cryptographic transformations using Tagged Keys are registered.

```
  $ cat  /proc/crypto | grep -B1 -A2 tk
	name         : tk(ecb(aes))
	driver       : tk-ecb-aes-caam
	module       : kernel
	priority     : 3000
	--

	name         : tk(cbc(aes))
	driver       : tk-cbc-aes-caam
	module       : kernel
	priority     : 3000
```

- Make sure dm-crypt is enabled.

```
  $ dmsetup targets
	multipath        v1.13.0
	crypt            v1.19.0
	unstriped        v1.1.0
	striped          v1.6.0
	linear           v1.4.0
	error            v1.5.0
```

- Generate a black key, from random, using ECB encryption, of 16 bytes:

```
  $ ./caam-keygen create randomkey ecb -s 16
```

The results are a Tagged Key and a blob files written to filesystem.

- Check the key, blob and size of each file:

```
  $ ls -l /data/caam
	total 36
	-rw-r--r-- 1 root root    32 Mar 18 13:44 randomkey
	-rw-r--r-- 1 root root    68 Mar 18 13:44 randomkey.bb
```

- Add a logon key, based on the previous generated black key, into a session keyring:

```
  $ cat /data/caam/randomkey | keyctl padd logon logkey: @s
	949507891
```

- Check logon key in keyring:

```
  $ keyctl list @s
	2 keys in keyring:
	623954697: ----s-rv     0     0 user: invocation_id
	949507891: --alsw-v     0     0 logon: logkey:
```

- Activate a new device mapper, named encrypted, using dmsetup with the newly created logon key and CAAM tk transformation for black keys:

```
  $ dmsetup -v create encrypted --table "0 $(blockdev --getsz /dev/mmcblk3p10) crypt capi:tk(cbc(aes))-plain :32:logon:logkey: 0 /dev/mmcblk3p10 0 1 sector_size:512"
	Name:              encrypted
	State:             ACTIVE
	Read Ahead:        256
	Tables present:    LIVE
	Open count:        0
	Event number:      0
	Major, minor:      254, 0
	Number of targets: 1
```

Following is a breakdown of the mapping table:
```
- start means encrypting begins with sector 0.
- size is the size of the volume in sectors.
- blockdev gets the number of sectors of the device.
- target is crypt.
- cipher is set in Kernel Crypto API format to use Tagged Key. cipher set to capi:tk(cbc(aes))-plain
and key set to :32:logon:logkey: leads to use of the logon key with CAAM Tagged Key transformation.
- IV is the Initialization Vector defined to plain, initial vector, which is the 32-bit little-endian version of the sector
number, padded with zeros if necessary.
- key type is the Keyring key service type, set to Logon Key. 32 is the key size in bytes.
- key name is the key description to identify the key to load.
- IV offset is the value to add to sector number to compute the IV value.
- device is the path to device to be used as backend; it contains the encrypted data.
- offset represents encrypted data begins at sector 0 of the device.
- optional parameters represent the number of optional parameters.
- sector_size specifies the encryption sector size.
```

For more detailed options and descriptions, refer to https://gitlab.com/cryptsetup/cryptsetup/-/wikis/DMCrypt.

- One can also, import a black key from a blob:

```
  $ ./caam-keygen import /data/caam/randomkey.bb importKey
```

- Check the imported key:

```
  $ ls -l /data/caam
	total 48
	-rw-r--r-- 1 root root    32 Mar 18 13:46 importKey
	-rw-r--r-- 1 root root    32 Mar 18 13:44 randomkey
	-rw-r--r-- 1 root root    68 Mar 18 13:44 randomkey.bb
```
- We can also derive key using derive option:

```
$ ./caam-keygen derive -pass - -md sha256 -S 8329E1C8544FAD6F derived_key

Output of above command:-
salt=8329E1C8544FAD6F
iv=01B49451DCD7050C3A7F1BC6B0352B0E

```

- Check the derived key:

```
  $ ls -l /data/caam/
total 8
-rw-r--r-- 1 root root  52 May 25 11:18 derived_key
-rw-r--r-- 1 root root 112 May 25 11:18 derived_key.bb

```

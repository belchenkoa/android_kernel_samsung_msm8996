#!/bin/bash

# fips_crypto_hmac.sh
#
# Author     : Rohit Kothari (r.kothari@samsung.com)
# Created on :  14 Feb 2014
# Modified on:  22 Jun  2015  by Jia Ma (jia.ma@samsung.com) /* To adapt to KASLR change */
# Modified on:  09 Jul  2015  by Wenbo Shen (wenbo.s@samsung.com) /* To reduce the hmac generation time */
# Copyright (c) Samsung Electronics 2014

kaslr_patch () {
	index=$1
	./kaslr_fips $vmlinux_var $reloc_start_addr $reloc_end_addr $dynsym_addr $index $first_crypto_rodata $last_crypto_rodata 0 0  $2
	retval=$?
	if [ $retval -ne 0 ]; then
		echo "$0 : kaslr_fips : unable to patch the vmlinux"
		exit 1
	fi
}

hmac_patch() {
	index=$1
	offsets_sizes_file=$2
	if [ "$3" == "crypto" ]; then
		fips_utils=./fips_crypto_utils
		hmac_offset=`expr $crypto_hmac_offset_base + $((32*$index)) `
	elif [ "$3" == "fmp" ]; then
		fips_utils=./fips_fmp_utils
		hmac_offset=`expr $fmp_hmac_offset_base + $((32*$index)) `
	fi
	rm -f builtime_bytes.txt builtime_bytes.bin
	date_var=`date`
	echo "Created on : " $date_var > builtime_bytes.txt
	while read args; do
		$fips_utils -g $vmlinux_var $args builtime_bytes.bin >> builtime_bytes.txt
		retval=$?
		if [ $retval -ne 0 ]; then echo "$0 : $fips_utils : unable to gather $3 bytes from vmlinux"; exit 1; fi
		echo "" >> builtime_bytes.txt
	done < $offsets_sizes_file
	if [[ ! -f builtime_bytes.bin ]]; then echo "$0 : builtime_bytes.bin does not exist"; exit 1; fi
	key="The quick brown fox jumps over the lazy dog"
	openssl dgst -sha256 -hmac "$key" -binary -out crypto_hmac.bin builtime_bytes.bin
	retval=$?
	if [ $retval -ne 0 ]; then echo "$0 : openssl dgst command returned error"; exit 1; fi
	if [[ ! -f crypto_hmac.bin ]]; then echo "$0 : crypto_hmac.bin does not exist"; exit 1; fi
	file_size=`cat crypto_hmac.bin| wc -c`
	if [ $file_size -ne 32 ]; then echo "$0: Unexpected size of Hash file : " $file_size; exit 1; fi
	if [[ $hmac_offset -le 0 ]]; then echo "$0 : hmac_offset invalid"; exit 1; fi
	$fips_utils -u $vmlinux_var crypto_hmac.bin $hmac_offset
	retval=$?
	if [ $retval -ne 0 ]; then echo "$0 : fips_crypto_utils : unable to update hmac in vmlinux"; exit 1; fi
	rm -f crypto_hmac.bin builtime_bytes.txt builtime_bytes.bin
}

offsets_sizes_gen(){
	name=$1[@]
	array=("${!name}")
	outfile=$2
	rm -f $outfile
	reg='^[0-9A-Fa-f]+$'
	for i in "${array[@]}"; do
		var1=var2=var3=var4=var5=""
		first_addr=last_addr=start_addr=offset=file_offset=size=""
		k=1
		for j in $i; do export var$k=$j; let k+=1; done
		first_addr=`cat $system_map_var|grep -w $var2|awk '{print $1}'`
		if [[ ! $first_addr =~ $reg ]]; then echo "$0 : first_addr invalid"; exit 1; fi
		last_addr=`cat $system_map_var|grep -w $var3|awk '{print $1}'`
		if [[ ! $last_addr =~ $reg ]]; then echo "$0 : last_addr invalid"; exit 1; fi
		start_addr=`cat vmlinux.elf |grep -w "$var1 "|grep PROGBITS|awk '{print '$var4'}'`
		if [[ ! $start_addr =~ $reg ]]; then echo "$0 : start_addr invalid"; exit 1; fi
		offset=`cat vmlinux.elf |grep -w "$var1 "|grep PROGBITS|awk '{print '$var5'}'`
		if [[ ! $offset =~ $reg ]]; then echo "$0 : offset invalid"; exit 1; fi
		if [[ $((16#$first_addr)) -lt $((16#$start_addr)) ]]; then echo "$0 : first_addr < start_addr"; exit 1; fi
		if [[ $((16#$last_addr)) -le $((16#$first_addr)) ]]; then echo "$0 : last_addr <= first_addr"; exit 1; fi
		file_offset=`expr $((16#$offset)) + $((16#$first_addr)) - $((16#$start_addr))`
		if [[ $file_offset -le 0 ]]; then echo "$0 : file_offset invalid"; exit 1; fi
		size=`expr $((16#$last_addr)) - $((16#$first_addr))`
		if [[ $size -le 0 ]]; then echo "$0 : crypto section size invalid"; exit 1; fi
		echo "$var1 " $file_offset " " $size >> $outfile
	done
	if [[ ! -f $outfile ]]; then echo "$0 : offset_sizes.txt does not exist"; exit 1; fi
}

cal_hmac_offset(){
	first_addr=`cat $system_map_var|grep -w $1|awk '{print $1}' `
	if [[ ! $first_addr =~ $reg ]]; then echo "$0 : first_addr of hmac variable invalid"; exit 1; fi
	start_addr=`cat vmlinux.elf |grep -w $2|grep PROGBITS|awk '{print $5}' `
	if [[ ! $start_addr =~ $reg ]]; then echo "$0 : start_addr of .rodata invalid"; exit 1; fi
	offset=`cat vmlinux.elf |grep -w $2|grep PROGBITS| awk '{print $6}' `
	if [[ ! $offset =~ $reg ]]; then echo "$0 : offset of .rodata invalid"; exit 1; fi
	if [[ $((16#$first_addr)) -le $((16#$start_addr)) ]]; then echo "$0 : hmac var first_addr <= start_addr"; exit 1; fi
	if [ "$1" == "builtime_crypto_hmac" ]; then crypto_hmac_offset_base=`expr $((16#$offset)) + $((16#$first_addr)) - $((16#$start_addr)) `; elif [ "$1" == "builtime_fmp_hmac" ]; then fmp_hmac_offset_base=`expr $((16#$offset)) + $((16#$first_addr)) - $((16#$start_addr)) `; fi
}

START_TIME=$SECONDS
if test $# -ne 2; then echo "Usage: $0 vmlinux System.map"; exit 1; fi
vmlinux_var=$1
system_map_var=$2
if [[ -z "$vmlinux_var" || -z "$system_map_var" || -z "$READELF" || -z "$HOSTCC" ]]; then echo "$0 : variables not set"; exit 1; fi
if [[ ! -f $vmlinux_var || ! -f $system_map_var ]]; then echo "$0 : files does not exist"; exit 1; fi
rm -f vmlinux.elf
$READELF -S $vmlinux_var > vmlinux.elf
retval=$?
if [ $retval -ne 0 ]; then echo "$0 : $READELF returned error"; exit 1; fi

# These utilities are native host binaries. Android 11's clang prebuilt ships
# ld.lld next to clang, while the hermetic build PATH intentionally has no GNU
# ld. Put clang's own bin directory on PATH and explicitly select LLD.
HOSTCC_LDFLAGS=""
HOSTCC_BIN="${HOSTCC%% *}"
if [[ "$(basename "$HOSTCC_BIN")" == clang* ]]; then
	export PATH="$(dirname "$HOSTCC_BIN"):$PATH"
	HOSTCC_LDFLAGS="-fuse-ld=lld"
fi

rm -f kaslr_fips
$HOSTCC $HOSTCC_LDFLAGS -o kaslr_fips $srctree/scripts/kaslr_fips.c
retval=$?
if [ $retval -ne 0 ]; then echo "$0 : $HOSTCC returned error"; exit 1; fi
rm -f fips_crypto_utils
$HOSTCC $HOSTCC_LDFLAGS -o fips_crypto_utils $srctree/scripts/fips_crypto_utils.c
retval=$?
if [ $retval -ne 0 ]; then echo "$0 : $HOSTCC returned error"; exit 1; fi

var="__reloc_start"; var1=`cat $system_map_var|grep -w $var|awk '{print $1}'`
var="__reloc_end"; var2=`cat $system_map_var|grep -w $var|awk '{print $1}'`
var="__dynsym_start"; var3=`cat $system_map_var|grep -w $var|awk '{print $1}'`
var="first_crypto_rodata"; var4=`cat $system_map_var|grep -w $var|awk '{print $1}'`
var="last_crypto_rodata"; var5=`cat $system_map_var|grep -w $var|awk '{print $1}'`
reloc_start_addr=`expr $((16#$var1))`; reloc_end_addr=`expr $((16#$var2))`; dynsym_addr=`expr $((16#$var3))`; first_crypto_rodata=`expr $((16#$var4))`; last_crypto_rodata=`expr $((16#$var5))`
fips_crypto[0]=".text first_crypto_text last_crypto_text \$5 \$6"
fips_crypto[1]=".rodata first_crypto_rodata last_crypto_rodata \$5 \$6"
fips_crypto[2]=".init.text first_crypto_init last_crypto_init \$4 \$5"
fips_crypto[3]=".text first_crypto_asm_text last_crypto_asm_text \$5 \$6"
fips_crypto[4]=".rodata first_crypto_asm_rodata last_crypto_asm_rodata \$5 \$6"
fips_crypto[5]=".init.text first_crypto_asm_init last_crypto_asm_init \$4 \$5"
offsets_sizes_crypto="offsets_sizes_crypto.txt"
offsets_sizes_gen fips_crypto $offsets_sizes_crypto
cal_hmac_offset builtime_crypto_hmac .rodata
rodata_va_addr=`cat vmlinux.elf|grep -w '.rodata'|awk '{print $5}'`
rodata_file_addr=`cat vmlinux.elf|grep -w '.rodata'|awk '{print $6}'`
va_to_file=`expr $((16#$rodata_va_addr)) - $((16#$rodata_file_addr))`
for index in {0..63}; do kaslr_patch $index $va_to_file; hmac_patch $index $offsets_sizes_crypto crypto; done
rm -f kaslr_fips fips_crypto_utils vmlinux.elf offsets_sizes*
ELAPSED_TIME=$(($SECONDS - $START_TIME))
echo ">>>>> Time used for generated all hashes is $(($ELAPSED_TIME)) sec"

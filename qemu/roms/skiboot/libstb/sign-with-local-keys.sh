#!/bin/bash -x

PAYLOAD=$1
OUTPUT=$2

if [ ! -f $PAYLOAD ]; then
	echo "Can't read PAYLOAD";
	exit 1;
fi

KEYLOC="/tmp/keys"
T=`mktemp -d`

# Build enough of the container to create the Prefix and Software headers.
./create-container -a $KEYLOC/hw_key_a.key -b $KEYLOC/hw_key_b.key -c $KEYLOC/hw_key_c.key \
                   -p $KEYLOC/sw_key_a.key \
                    --payload $PAYLOAD --imagefile $OUTPUT \
                    --dumpPrefixHdr $T/prefix_hdr --dumpSwHdr $T/software_hdr

# Sign the Prefix header.
openssl dgst -SHA512 -sign $KEYLOC/hw_key_a.key $T/prefix_hdr > $T/hw_key_a.sig
openssl dgst -SHA512 -sign $KEYLOC/hw_key_b.key $T/prefix_hdr > $T/hw_key_b.sig
openssl dgst -SHA512 -sign $KEYLOC/hw_key_c.key $T/prefix_hdr > $T/hw_key_c.sig

# Sign the Software header.
# Only one SW key in Nick's repo, and it has a confusing name (should be "sw_key_p")
openssl dgst -SHA512 -sign $KEYLOC/sw_key_a.key $T/software_hdr > $T/sw_key_p.sig

# Build the full container with signatures.
./create-container -a $KEYLOC/hw_key_a.key -b $KEYLOC/hw_key_b.key -c $KEYLOC/hw_key_c.key \
                   -p $KEYLOC/sw_key_a.key \
                   -A $T/hw_key_a.sig -B $T/hw_key_b.sig -C $T/hw_key_c.sig \
                   -P $T/sw_key_p.sig \
                    --payload $PAYLOAD --imagefile $OUTPUT

rm -rf $T

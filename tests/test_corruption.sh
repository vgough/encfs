fresh_mount default.xml
cd $SCRATCH
dd if=/dev/urandom of=foo bs=1M count=1 2> /dev/null
A=$(md5 foo)
cp foo $UPPER
cd $UPPER
test_begin "Reading file"
B=$(md5 foo)
test $A = $B
test_ok

test_begin "Reading corrupted file"
echo DEADBEEF >> $LOWER/$(ls $LOWER)
B=$(md5 foo)
test $A != $B
test_ok

fresh_mount mac.xml
cd $SCRATCH
cp foo $UPPER
cd $UPPER
test_begin "Reading file with MAC"
B=$(md5 foo)
test $A = $B
test_ok

test_begin "Corruption with MAC returns IO error"
echo DEADBEEF >> $LOWER/$(ls $LOWER)
md5 foo 2>&1 | grep "Input/output error" > /dev/null
test_ok


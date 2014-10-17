fresh_mount default.xml
cd $UPPER
test_begin "Creating files of different sizes: "
for i in `seq 0 50` `seq 1000 1050`
do
	OUTPUT=$(dd if=/dev/zero bs=$i count=1 2> /dev/null | tee $i | md5sum)
	ARRAY=($OUTPUT)
	A=${ARRAY[0]} # Remove filename
	B=$(md5 $i)
	test $A = $B
done
test_ok

test_begin "Growing file"
rm -f ../grow
for i in `seq 0 300`
do
	echo -n "abcdefg" >> ../grow
	echo -n "abcdefg" >> grow
	
	A=$(md5 ../grow)
	B=$(md5 grow)
	test "$A" = "$B"
done
test_ok

test_begin "Internal modification"
dd if=/dev/urandom of=../internal bs=1M count=2 2> /dev/null
cp ../internal internal
for i in 0 30 1020 1200
do
	dd if=/dev/zero of=../internal bs=1 count=1 skip=$i 2> /dev/null
	dd if=/dev/zero of=internal bs=1 count=1 skip=$i 2> /dev/null

	A=$(md5 ../internal)
	B=$(md5 internal)
	test "$A" = "$B"
done
test_ok


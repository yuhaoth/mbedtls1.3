test_python(){

python3 - <<END
import shlex
print('$FUNCNAME',shlex.split('$(printf "%q " "$@")'))
END
}

test(){
    while [ $# -gt 0 ]; do
        echo "\"$1\""
        shift
    done
}
test1(){
    test_python '$*' $BASH_LINENO $BASH_SOURCE
}
test_python 1 '2 3'
function test_func()
{
    echo "Current $FUNCNAME, \$FUNCNAME => (${FUNCNAME[@]})"
    another_func
    echo "Current $FUNCNAME, \$FUNCNAME => (${FUNCNAME[@]})"
}

function another_func()
{
    echo "Current $FUNCNAME, \$FUNCNAME => (${FUNCNAME[@]})"
}

echo "Out of function, \$FUNCNAME => (${FUNCNAME[@]})"
test_func
echo "Out of function, \$FUNCNAME => (${FUNCNAME[@]})"
echo ${BASH_SOURCE:-A}
exit 0

test_python $(test 1 "2 3")

test1 1 "2 3"
expand-q() { for i; do echo ${i@Q}; done; }
expand-q word "two words" 'new
line' "single'quote" 'double"quote'
echo '---------------'
testx() {
    printf "%q " "$@"
}

testx "\"1112 2\"" 222
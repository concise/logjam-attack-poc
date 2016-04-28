#!/bin/bash

DV_CERT_CHAIN=/path/to/cert.chain
DV_CERT_PRIVATE_KEY=/path/to/cert.key


set -o pipefail         # proper status code for a pipeline
set -o errexit          # exit when seeing a nonzero status code (set -e)
set -o nounset          # using unbound variable is an error (set -u)
shopt -s failglob       # pathname expansion failing is an error


my_exit_trap () {
    LAST_EXIT_CODE=$?
    echo 
    echo Exiting
    echo Please remember to check if all the subprocesses are stopped
}; trap my_exit_trap EXIT


EXE=${BASH_SOURCE[0]}
CTR=0
while [[ -L $EXE ]]; do
  (( ++CTR <= 100 )) || { echo Too many level of symlinks; exit 1; }
  DIR=$( cd -P "$( dirname "$EXE" )" && pwd )
  EXE=$( readlink "$EXE" )
  [[ $EXE = /* ]] || EXE=$DIR/$EXE
done
__DIR__=$( cd -P "$( dirname "$EXE" )" && pwd )
__NAME__=$( basename "$EXE" )
__FILE__=$__DIR__/$__NAME__
cd "$__DIR__"


echo Checking the provided parameters
grep -q 'Ubuntu 14.04' /etc/issue
test $(id -u) = 0
test -f "$DV_CERT_CHAIN"
test -f "$DV_CERT_PRIVATE_KEY"


echo Ensuring dependencies
if [[ $(type -t php) != file ]]; then
    apt-get install -y php5-cli
fi
if [[ ! -f mitm-server/programs/ssl/ssl_server2 ||
      ! -f real-server/programs/ssl/ssl_server2 ]]; then
    make
fi


echo Trying to start all the subprocesses

mkdir -p static-sites/logjam-dlog-backdoor

CRT_FILE="$DV_CERT_CHAIN" KEY_FILE="$DV_CERT_PRIVATE_KEY" real-server/run &> https.real.log &
mitm-server/run &> https.mitm.log &
php -S 0.0.0.0:10444 -t static-sites/logjam-dlog-backdoor &> https.dlogbackdoor.log &
php -S 0.0.0.0:80    -t static-sites/real-server-http &> http.real.log &
php -S 0.0.0.0:20080 -t static-sites/fake-server-http &> http.mitm.log &

echo List of PIDs of child processes running in the background:
jobs -p
wait

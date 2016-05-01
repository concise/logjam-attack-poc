#!/bin/bash
#
# The caller must provide environment variables:
#
# CHAIN
# KEY
# RUNAS
#

setup_error_handling() {
  set -o pipefail
  set -o errexit
  set -o nounset
  shopt -s failglob
  trap exit_trap EXIT
}

exit_trap() {
  local STAT=$? CMD="$BASH_COMMAND"

  if [[ $STAT != 0 ]]; then
    printf '\ncommand `%s` has nonzero exit status = %s\n' "$CMD" "$STAT"
  fi

  iptables -t nat -F
}

get_absolute_paths() {
  local EXE=${BASH_SOURCE[0]}
  local CTR=0
  local DIR
  while [[ -L $EXE ]]; do
    (( ++CTR <= 100 )) || { echo Too many level of symlinks; exit 1; }
    DIR=$( cd -P "$( dirname "$EXE" )" && pwd )
    EXE=$( readlink "$EXE" )
    [[ $EXE = /* ]] || EXE=$DIR/$EXE
  done
  __DIR__=$( cd -P "$( dirname "$EXE" )" && pwd )
  __NAME__=$( basename "$EXE" )
  __FILE__=$__DIR__/$__NAME__
}

setup_error_handling
get_absolute_paths
cd "$__DIR__"

grep -q 'Ubuntu 14.04' /etc/issue
test "$(id -u)" = 0
test -f "$CHAIN"
test -f "$KEY"
test "$(id -u -- "$RUNAS")" != 0

if ! command -v php > /dev/null; then
    wget -q -O /dev/null https://duckduckgo.com/
    apt-get update
    apt-get install -y php5-cli
fi

if [[ ! -f mitm-server/programs/ssl/ssl_server2 || ! -f real-server/programs/ssl/ssl_server2 ]]; then
    make
fi

mkdir -pm0777 /tmp/static-sites/logjam-dlog-backdoor
mkdir -pm0777 /tmp/static-sites/real-server-http
mkdir -pm0777 /tmp/static-sites/fake-server-http
cp static-sites/real-server-http/index.html /tmp/static-sites/real-server-http
cp static-sites/fake-server-http/index.html /tmp/static-sites/fake-server-http

# Real HTTPS Server at port 10443 and dlog backdoor at port 10444
su "$RUNAS" -c "real-server/programs/ssl/ssl_server2 server_addr=0.0.0.0 server_port=10443 crt_file='$CHAIN' key_file='$KEY' &> /tmp/https.real.log" &
su "$RUNAS" -c "php -S 0.0.0.0:10444 -t /tmp/static-sites/logjam-dlog-backdoor &> /tmp/https.dlogbackdoor.log" &

# Real HTTP Server at port 10080
su "$RUNAS" -c "php -S 0.0.0.0:10080 -t /tmp/static-sites/real-server-http &> /tmp/http.real.log" &

# Set up port 80 and port 443
iptables -t nat -F
iptables -t nat -A PREROUTING       -p tcp --dport  80 -j REDIRECT --to-ports 10080
iptables -t nat -A OUTPUT     -o lo -p tcp --dport  80 -j REDIRECT --to-ports 10080
iptables -t nat -A PREROUTING       -p tcp --dport 443 -j REDIRECT --to-ports 10443
iptables -t nat -A OUTPUT     -o lo -p tcp --dport 443 -j REDIRECT --to-ports 10443



# MitM HTTPS Server
su "$RUNAS" -c "mitm-server/programs/ssl/ssl_server2 server_addr=0.0.0.0 server_port=20443 crt_file=mitm-server/localhost.crtchain key_file=mitm-server/localhost.key &> /tmp/https.mitm.log" &

# MitM HTTP Server
su "$RUNAS" -c "php -S 0.0.0.0:20080 -t /tmp/static-sites/fake-server-http &> /tmp/http.mitm.log" &



echo List of PIDs of child processes running in the background:
jobs -p

wait

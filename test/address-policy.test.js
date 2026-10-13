import assert from 'node:assert/strict';
import { test } from 'node:test';
import { isPublicAddress } from '../src/address-policy.js';

const PUBLIC = ['8.8.8.8', '1.1.1.1', '172.15.255.255', '172.32.0.1', '100.63.255.255', '2606:4700:4700::1111', '2a00:1450:4001:81b::200e', '::ffff:8.8.8.8'];

const REFUSED = [
  ['unspecified', '0.0.0.0'],
  ['private 10/8', '10.1.2.3'],
  ['carrier-grade NAT', '100.64.0.1'],
  ['loopback', '127.0.0.1'],
  ['loopback, not .1', '127.255.255.254'],
  ['link-local and cloud metadata', '169.254.169.254'],
  ['private 172.16/12', '172.16.0.1'],
  ['private 172.16/12 upper end', '172.31.255.255'],
  ['private 192.168/16', '192.168.1.1'],
  ['benchmarking', '198.18.0.1'],
  ['documentation', '203.0.113.9'],
  ['multicast', '224.0.0.1'],
  ['reserved', '240.0.0.1'],
  ['broadcast', '255.255.255.255'],
  ['IPv6 unspecified', '::'],
  ['IPv6 loopback', '::1'],
  ['IPv4-mapped loopback', '::ffff:127.0.0.1'],
  ['IPv4-mapped loopback, hexadecimal', '::ffff:7f00:1'],
  ['IPv4-mapped private', '::ffff:10.0.0.1'],
  ['IPv4-mapped metadata', '::ffff:a9fe:a9fe'],
  ['NAT64', '64:ff9b::7f00:1'],
  ['Teredo', '2001::1'],
  ['IPv6 documentation', '2001:db8::1'],
  ['6to4', '2002:7f00:1::1'],
  ['unique local', 'fd12:3456:789a::1'],
  ['IPv6 link-local', 'fe80::1'],
  ['IPv6 multicast', 'ff02::1'],
  ['not an address', 'example.com'],
  ['empty', ''],
];

for (const address of PUBLIC) {
  test(`allows ${address}`, () => {
    assert.equal(isPublicAddress(address), true);
  });
}

for (const [name, address] of REFUSED) {
  test(`refuses ${name}: "${address}"`, () => {
    assert.equal(isPublicAddress(address), false);
  });
}

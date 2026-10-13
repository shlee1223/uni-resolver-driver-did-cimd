import { BlockList, isIP } from 'node:net';

/**
 * Address space a resolver must not be steered into (spec 3.2 step 2, section 4):
 * private, loopback and link-local ranges, plus the other special-purpose blocks
 * of the IANA registries that never host a public HTTPS origin.
 */
const SPECIAL_PURPOSE = [
  ['0.0.0.0', 8, 'ipv4'],
  ['10.0.0.0', 8, 'ipv4'],
  ['100.64.0.0', 10, 'ipv4'],
  ['127.0.0.0', 8, 'ipv4'],
  ['169.254.0.0', 16, 'ipv4'],
  ['172.16.0.0', 12, 'ipv4'],
  ['192.0.0.0', 24, 'ipv4'],
  ['192.0.2.0', 24, 'ipv4'],
  ['192.88.99.0', 24, 'ipv4'],
  ['192.168.0.0', 16, 'ipv4'],
  ['198.18.0.0', 15, 'ipv4'],
  ['198.51.100.0', 24, 'ipv4'],
  ['203.0.113.0', 24, 'ipv4'],
  ['224.0.0.0', 4, 'ipv4'],
  ['240.0.0.0', 4, 'ipv4'],
  ['::', 96, 'ipv6'],
  ['64:ff9b::', 96, 'ipv6'],
  ['64:ff9b:1::', 48, 'ipv6'],
  ['100::', 64, 'ipv6'],
  ['2001::', 23, 'ipv6'],
  ['2001:db8::', 32, 'ipv6'],
  ['2002::', 16, 'ipv6'],
  ['fc00::', 7, 'ipv6'],
  ['fe80::', 10, 'ipv6'],
  ['fec0::', 10, 'ipv6'],
  ['ff00::', 8, 'ipv6'],
];

const blocked = new BlockList();
for (const [network, prefix, family] of SPECIAL_PURPOSE) {
  blocked.addSubnet(network, prefix, family);
}

/**
 * BlockList evaluates an IPv4-mapped IPv6 address against the IPv4 rules, so the
 * mapped form of a blocked IPv4 address is blocked as well.
 *
 * @param {string} address an IPv4 or IPv6 address literal
 * @returns {boolean} true only for globally routable unicast addresses
 */
export function isPublicAddress(address) {
  const family = isIP(address);
  if (family === 0) {
    return false;
  }
  return !blocked.check(address, family === 4 ? 'ipv4' : 'ipv6');
}

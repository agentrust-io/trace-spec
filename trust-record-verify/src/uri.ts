/**
 * The JSON Schema `uri` format: the `URI` rule of RFC 3986 Appendix A.
 *
 * Built from the ABNF rule by rule, so each constant below is one production.
 * An IRI is not a URI, so a character outside ASCII is refused, and the whole
 * string must match: a trailing line feed is not part of any URI.
 */

const HEXDIG = "[0-9A-Fa-f]";
const PCT_ENCODED = `%${HEXDIG}${HEXDIG}`;
const UNRESERVED = "[A-Za-z0-9\\-._~]";
const SUB_DELIMS = "[!$&'()*+,;=]";
const PCHAR = `(?:${UNRESERVED}|${PCT_ENCODED}|${SUB_DELIMS}|[:@])`;

const SCHEME = "[A-Za-z][A-Za-z0-9+\\-.]*";
const USERINFO = `(?:${UNRESERVED}|${PCT_ENCODED}|${SUB_DELIMS}|:)*`;

// dec-octet = DIGIT / %x31-39 DIGIT / "1" 2DIGIT / "2" %x30-34 DIGIT / "25" %x30-35
const DEC_OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])";
const IPV4ADDRESS = `(?:${DEC_OCTET}\\.${DEC_OCTET}\\.${DEC_OCTET}\\.${DEC_OCTET})`;
const H16 = `${HEXDIG}{1,4}`;
const LS32 = `(?:${H16}:${H16}|${IPV4ADDRESS})`;
const IPV6ADDRESS = `(?:${[
  `(?:${H16}:){6}${LS32}`,
  `::(?:${H16}:){5}${LS32}`,
  `(?:${H16})?::(?:${H16}:){4}${LS32}`,
  `(?:(?:${H16}:){0,1}${H16})?::(?:${H16}:){3}${LS32}`,
  `(?:(?:${H16}:){0,2}${H16})?::(?:${H16}:){2}${LS32}`,
  `(?:(?:${H16}:){0,3}${H16})?::${H16}:${LS32}`,
  `(?:(?:${H16}:){0,4}${H16})?::${LS32}`,
  `(?:(?:${H16}:){0,5}${H16})?::${H16}`,
  `(?:(?:${H16}:){0,6}${H16})?::`,
].join("|")})`;
const IPVFUTURE = `[vV]${HEXDIG}+\\.(?:${UNRESERVED}|${SUB_DELIMS}|:)+`;
const IP_LITERAL = `\\[(?:${IPV6ADDRESS}|${IPVFUTURE})\\]`;
const REG_NAME = `(?:${UNRESERVED}|${PCT_ENCODED}|${SUB_DELIMS})*`;
const HOST = `(?:${IP_LITERAL}|${IPV4ADDRESS}|${REG_NAME})`;
const AUTHORITY = `(?:${USERINFO}@)?${HOST}(?::[0-9]*)?`;

const SEGMENT = `${PCHAR}*`;
const SEGMENT_NZ = `${PCHAR}+`;
const PATH_ABEMPTY = `(?:/${SEGMENT})*`;
const PATH_ABSOLUTE = `/(?:${SEGMENT_NZ}(?:/${SEGMENT})*)?`;
const PATH_ROOTLESS = `${SEGMENT_NZ}(?:/${SEGMENT})*`;
const HIER_PART = `(?://${AUTHORITY}${PATH_ABEMPTY}|${PATH_ABSOLUTE}|${PATH_ROOTLESS}|)`;
const QUERY = `(?:${PCHAR}|[/?])*`;
const FRAGMENT = QUERY;

const URI = new RegExp(`^${SCHEME}:${HIER_PART}(?:\\?${QUERY})?(?:#${FRAGMENT})?$`);

/** True when *value* is a URI under RFC 3986. */
export function isUri(value: string): boolean {
  return URI.test(value);
}

/** The format checkers the generated schema validators call, keyed by format name. */
export const formats = { uri: isUri } as const;

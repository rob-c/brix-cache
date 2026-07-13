// Single source of truth for site-wide constants: repo links, nav, and the
// three protocols with their fixed accent colors. Color encodes protocol
// identity across the whole site, so it is defined once here.

/** Prefix an internal path with the configured GitHub Pages base. */
export function url(path = '/'): string {
  const base = import.meta.env.BASE_URL.replace(/\/$/, '');
  const clean = path.startsWith('/') ? path : `/${path}`;
  return `${base}${clean}`;
}

export const REPO_URL = 'https://github.com/rob-c/brix-cache';
export const DOCS_URL = `${REPO_URL}/blob/main/docs/index.md`;
export const LICENSE = 'AGPL-3.0-only';

export type AccentName = 'root' | 'dav' | 's3';

export interface Protocol {
  id: AccentName;
  scheme: string;
  name: string;
  port: string;
  transport: string;
  clients: string;
  blurb: string;
}

/** The three protocols one BriX-Cache server speaks, in fixed order + color. */
export const PROTOCOLS: Protocol[] = [
  {
    id: 'root',
    scheme: 'root://',
    name: 'Native XRootD',
    port: '1094',
    transport: 'raw TCP · TLS on 1095',
    clients: 'xrdcp · xrdfs · pyxrootd',
    blurb:
      'The full XRootD 5.2 wire protocol — all 32 active opcodes, per-page CRC32c, in-protocol TLS upgrade.',
  },
  {
    id: 'dav',
    scheme: 'davs://',
    name: 'WebDAV',
    port: '8443',
    transport: 'HTTPS',
    clients: 'curl · rucio · browser',
    blurb:
      'OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, PROPFIND, COPY, MOVE, LOCK, and HTTP third-party-copy.',
  },
  {
    id: 's3',
    scheme: 's3://',
    name: 'S3-compatible',
    port: 'site-set',
    transport: 'HTTP / HTTPS',
    clients: 'aws-cli · boto3',
    blurb:
      'SigV4 REST: GET, HEAD, PUT, DELETE, ListObjectsV2, and multipart upload against the same tree.',
  },
];

export interface NavItem {
  label: string;
  href: string;
  external?: boolean;
}

/** The four audience pages, in the order they appear in nav and on the home grid. */
export const AUDIENCES: NavItem[] = [
  { label: 'Sysadmins', href: '/for/sysadmins' },
  { label: 'Physicists', href: '/for/physicists' },
  { label: 'Engineers', href: '/for/engineers' },
  { label: 'Stakeholders', href: '/for/stakeholders' },
];

/** Product pages shown in the primary nav after the audience links. */
export const PRODUCT_PAGES: NavItem[] = [
  { label: 'About', href: '/about' },
  { label: 'brixMount', href: '/brixmount' },
  { label: 'Tools', href: '/tools' },
  { label: 'Evidence', href: '/evidence' },
];

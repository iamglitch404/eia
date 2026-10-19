#ifndef EIA_ED25519_C
#define EIA_ED25519_C

#include "eia_ed25519.h"
#include "spark0.h"
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#define FOR(i,n) for (i = 0;i < (u64)(n);++i)
#define sv static void

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long i64;
typedef i64 gf[16];

static const gf
  gf0,
  gf1 = {1},
  D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203},
  D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406},
  X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169},
  Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666},
  I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};

static u64 dl64(const u8 *x)
{
  u64 i,u=0;
  FOR(i,8) u=(u<<8)|x[i];
  return u;
}

sv ts64(u8 *x,u64 u)
{
  int i;
  for (i = 7;i >= 0;--i) { x[i] = (u8)u; u >>= 8; }
}

static int vn(const u8 *x,const u8 *y,int n)
{
  int i;
  u32 d = 0;
  for (i = 0; i < n; ++i) d |= x[i]^y[i];
  return (1 & ((d - 1) >> 8)) - 1;
}

static int crypto_verify_32(const u8 *x,const u8 *y)
{
  return vn(x,y,32);
}

static u64 R(u64 x,int c) { return (x >> c) | (x << (64 - c)); }
static u64 Ch(u64 x,u64 y,u64 z) { return (x & y) ^ (~x & z); }
static u64 Maj(u64 x,u64 y,u64 z) { return (x & y) ^ (x & z) ^ (y & z); }
static u64 Sigma0(u64 x) { return R(x,28) ^ R(x,34) ^ R(x,39); }
static u64 Sigma1(u64 x) { return R(x,14) ^ R(x,18) ^ R(x,41); }
static u64 sigma0(u64 x) { return R(x, 1) ^ R(x, 8) ^ (x >> 7); }
static u64 sigma1(u64 x) { return R(x,19) ^ R(x,61) ^ (x >> 6); }

static const u64 K[80] = 
{
  0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
  0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
  0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
  0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
  0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
  0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
  0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
  0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
  0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
  0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
  0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
  0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
  0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
  0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
  0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
  0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static int crypto_hashblocks(u8 *x,const u8 *m,u64 n)
{
  u64 z[8],b[8],a[8],w[16],t;
  u64 i,j;

  FOR(i,8) z[i] = a[i] = dl64(x + 8 * i);

  while (n >= 128) {
    FOR(i,16) w[i] = dl64(m + 8 * i);

    FOR(i,80) {
      FOR(j,8) b[j] = a[j];
      t = a[7] + Sigma1(a[4]) + Ch(a[4],a[5],a[6]) + K[i] + w[i%16];
      b[7] = t + Sigma0(a[0]) + Maj(a[0],a[1],a[2]);
      b[3] += t;
      FOR(j,8) a[(j+1)%8] = b[j];
      if (i%16 == 15)
	FOR(j,16)
	  w[j] += w[(j+9)%16] + sigma0(w[(j+1)%16]) + sigma1(w[(j+14)%16]);
    }

    FOR(i,8) { a[i] += z[i]; z[i] = a[i]; }

    m += 128;
    n -= 128;
  }

  FOR(i,8) ts64(x+8*i,z[i]);

  return n;
}

static const u8 iv[64] = {
  0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
  0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
  0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
  0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
  0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
  0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
  0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
  0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
};

static int crypto_hash(u8 *out,const u8 *m,u64 n)
{
  u8 h[64],x[256];
  u64 i,b = n;

  FOR(i,64) h[i] = iv[i];

  crypto_hashblocks(h,m,n);
  m += n;
  n &= 127;
  m -= n;

  FOR(i,256) x[i] = 0;
  FOR(i,n) x[i] = m[i];
  x[n] = 128;

  n = 256-128*(n<112);
  x[n-9] = (u8)(b >> 61);
  ts64(x+n-8,b<<3);
  crypto_hashblocks(h,x,n);

  FOR(i,64) out[i] = h[i];

  return 0;
}

sv set25519(gf r, const gf a)
{
  u64 i;
  FOR(i,16) r[i]=a[i];
}

sv car25519(gf o)
{
  u64 i;
  i64 c;
  FOR(i,16) {
    o[i]+=(1LL<<16);
    c=o[i]>>16;
    o[(i+1)*(i<15)]+=c-1+37*(c-1)*(i==15);
    o[i]-=c*65536;
  }
}

sv sel25519(gf p,gf q,int b)
{
  i64 t,c=~(b-1);
  u64 i;
  FOR(i,16) {
    t= c&(p[i]^q[i]);
    p[i]^=t;
    q[i]^=t;
  }
}

sv pack25519(u8 *o,const gf n)
{
  int b;
  u64 i,j;
  gf m,t;
  FOR(i,16) t[i]=n[i];
  car25519(t);
  car25519(t);
  car25519(t);
  FOR(j,2) {
    m[0]=t[0]-0xffed;
    for(i=1;i<15;i++) {
      m[i]=t[i]-0xffff-((m[i-1]>>16)&1);
      m[i-1]&=0xffff;
    }
    m[15]=t[15]-0x7fff-((m[14]>>16)&1);
    b=(m[15]>>16)&1;
    m[14]&=0xffff;
    sel25519(t,m,1-b);
  }
  FOR(i,16) {
    o[2*i]=t[i]&0xff;
    o[2*i+1]=t[i]>>8;
  }
}

static int neq25519(const gf a, const gf b)
{
  u8 c[32],d[32];
  pack25519(c,a);
  pack25519(d,b);
  return crypto_verify_32(c,d);
}

static u8 par25519(const gf a)
{
  u8 d[32];
  pack25519(d,a);
  return d[0]&1;
}

sv unpack25519(gf o, const u8 *n)
{
  u64 i;
  FOR(i,16) o[i]=n[2*i]+((i64)n[2*i+1]<<8);
  o[15]&=0x7fff;
}

sv A(gf o,const gf a,const gf b)
{
  u64 i;
  FOR(i,16) o[i]=a[i]+b[i];
}

sv Z(gf o,const gf a,const gf b)
{
  u64 i;
  FOR(i,16) o[i]=a[i]-b[i];
}

sv M(gf o,const gf a,const gf b)
{
  u64 i,j;
  i64 t[31];
  FOR(i,31) t[i]=0;
  FOR(i,16) FOR(j,16) t[i+j]+=a[i]*b[j];
  FOR(i,15) t[i]+=38*t[i+16];
  FOR(i,16) o[i]=t[i];
  car25519(o);
  car25519(o);
}

sv S(gf o,const gf a)
{
  M(o,a,a);
}

sv inv25519(gf o,const gf i)
{
  gf c;
  int a;
  u64 u;
  FOR(u,16) c[u]=i[u];
  for(a=253;a>=0;a--) {
    S(c,c);
    if(a!=2&&a!=4) M(c,c,i);
  }
  FOR(u,16) o[u]=c[u];
}

sv pow2523(gf o,const gf i)
{
  gf c;
  int a;
  u64 u;
  FOR(u,16) c[u]=i[u];
  for(a=250;a>=0;a--) {
    S(c,c);
    if(a!=1) M(c,c,i);
  }
  FOR(u,16) o[u]=c[u];
}

sv add(gf p[4],gf q[4])
{
  gf a,b,c,d,t,e,f,g,h;
  Z(a, p[1], p[0]);
  Z(t, q[1], q[0]);
  M(a, a, t);
  A(b, p[1], p[0]);
  A(t, q[1], q[0]);
  M(b, b, t);
  M(c, p[3], q[3]);
  M(c, c, D2);
  M(d, p[2], q[2]);
  A(d, d, d);
  Z(e, b, a);
  Z(f, d, c);
  A(g, d, c);
  A(h, b, a);
  M(p[0], e, f);
  M(p[1], h, g);
  M(p[2], g, f);
  M(p[3], e, h);
}

sv cswap(gf p[4],gf q[4],u8 b)
{
  u64 i;
  FOR(i,4) sel25519(p[i],q[i],b);
}

sv pack(u8 *r,gf p[4])
{
  gf tx, ty, zi;
  inv25519(zi, p[2]); 
  M(tx, p[0], zi);
  M(ty, p[1], zi);
  pack25519(r, ty);
  r[31] ^= par25519(tx) << 7;
}

sv scalarmult(gf p[4],gf q[4],const u8 *s)
{
  int i;
  set25519(p[0],gf0);
  set25519(p[1],gf1);
  set25519(p[2],gf1);
  set25519(p[3],gf0);
  for (i = 255;i >= 0;--i) {
    u8 b = (s[i/8]>>(i&7))&1;
    cswap(p,q,b);
    add(q,p);
    add(p,p);
    cswap(p,q,b);
  }
}

sv scalarbase(gf p[4],const u8 *s)
{
  gf q[4];
  set25519(q[0],X);
  set25519(q[1],Y);
  set25519(q[2],gf1);
  M(q[3],X,Y);
  scalarmult(p,q,s);
}

static const u64 L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

sv modL(u8 *r,i64 x[64])
{
  i64 carry,i,j;
  for (i = 63;i >= 32;--i) {
    carry = 0;
    for (j = i - 32;j < i - 12;++j) {
      x[j] += carry - 16 * x[i] * L[j - (i - 32)];
      carry = (x[j] + 128) >> 8;
      x[j] -= carry * 256;
    }
    x[j] += carry;
    x[i] = 0;
  }
  carry = 0;
  for (j = 0; j < 32; ++j) {
    x[j] += carry - (x[31] >> 4) * L[j];
    carry = x[j] >> 8;
    x[j] &= 255;
  }
  for (j = 0; j < 32; ++j) {
    x[j] -= carry * L[j];
    carry = x[j] >> 8;
    x[j] &= 255;
  }
  for (j = 0; j < 32; ++j) r[j] = (u8)x[j];
}

sv reduce(u8 *r)
{
  i64 x[64];
  u64 i;
  FOR(i,64) x[i] = (u64) r[i];
  FOR(i,64) r[i] = 0;
  modL(r,x);
}

static int unpackneg(gf r[4],const u8 p[32])
{
  gf t, chk, num, den, den2, den4, den6;
  set25519(r[2],gf1);
  unpack25519(r[1],p);
  S(num,r[1]);
  M(den,num,D);
  Z(num,num,r[2]);
  A(den,r[2],den);

  S(den2,den);
  S(den4,den2);
  M(den6,den4,den2);
  M(t,den6,num);
  M(t,t,den);

  pow2523(t,t);
  M(t,t,num);
  M(t,t,den);
  M(t,t,den);
  M(r[0],t,den);

  S(chk,r[0]);
  M(chk,chk,den);
  if (neq25519(chk, num)) M(r[0],r[0],I);

  S(chk,r[0]);
  M(chk,chk,den);
  if (neq25519(chk, num)) return -1;

  if (par25519(r[0]) == (p[31]>>7)) Z(r[0],gf0,r[0]);

  M(r[3],r[0],r[1]);
  return 0;
}

static int crypto_sign_open(u8 *m,u64 *mlen,const u8 *sm,u64 n,const u8 *pk)
{
  u64 i;
  u8 t[32],h[64];
  gf p[4],q[4];

  *mlen = (u64)-1;
  if (n < 64) return -1;

  if (unpackneg(q,pk)) return -1;

  FOR(i,n) m[i] = sm[i];
  FOR(i,32) m[i+32] = pk[i];
  crypto_hash(h,m,n);
  reduce(h);
  scalarmult(p,q,h);

  scalarbase(q,sm + 32);
  add(p,q);
  pack(t,p);

  n -= 64;
  if (crypto_verify_32(sm, t)) {
    FOR(i,n) m[i] = 0;
    return -1;
  }

  FOR(i,n) m[i] = sm[i + 64];
  *mlen = n;
  return 0;
}

int eia_ed25519_verify_detached(const uint8_t sig[64], const uint8_t *msg, size_t msg_len, const uint8_t pk[32])
{
  u64 total_len = 64 + msg_len;
  u8 *sm = (u8 *)malloc(total_len);
  if (!sm) return -1;

  memcpy(sm, sig, 64);
  if (msg_len > 0 && msg) {
    memcpy(sm + 64, msg, msg_len);
  }

  u8 *m = (u8 *)malloc(total_len);
  if (!m) { free(sm); return -1; }

  u64 mlen = 0;
  int rc = crypto_sign_open(m, &mlen, sm, total_len, pk);

  free(m);
  free(sm);
  return (rc == 0 ? 0 : -1);
}

/* =========================================================================
 * EIA Production Trust Store
 *
 * Supports multiple concurrent public keys, key rotation (new slots), and
 * revocation (EIA_KEYSTORE_FLAG_REVOKED).  The verifier iterates all
 * non-revoked entries that match the presented pubkey_id.  The signer picks
 * keys via EIA_SIGNING_KEY_FILE (binary 32-byte seed), EIA_SIGNING_KEY (raw
 * 32-byte env string), or the compiled-in root seed as a last resort.
 * =========================================================================*/


/*
 * EIA Root Public Key (slot 0 – derived from the compiled root seed).
 * Additional keys can be added at runtime via eia_trust_store_add().
 */
static const uint8_t EIA_ROOT_PUBKEY[32] = {
    0xd8, 0x54, 0xd5, 0xa4, 0xa6, 0x90, 0x82, 0x89,
    0x75, 0xe0, 0x20, 0xe8, 0xa5, 0xc5, 0xf8, 0xce,
    0x23, 0xbe, 0xe0, 0x30, 0x63, 0xbb, 0x93, 0x10,
    0x05, 0xb3, 0x7b, 0x35, 0x5a, 0x5a, 0xc1, 0x53
};

uint64_t eia_key_id_of(const uint8_t pk[32]) {
    /* FNV-1a 64-bit over the 32 public key bytes */
    uint64_t h = 0xcbf29ce484222325ULL;
    for (int i = 0; i < 32; ++i) {
        h ^= (uint64_t)pk[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

static EiaTrustEntry g_trust_store[EIA_KEYSTORE_MAX];
static int           g_trust_store_count = 0;
static int           g_trust_store_init  = 0;

static void eia_trust_store_ensure_init(void) {
    if (g_trust_store_init) return;
    g_trust_store_init = 1;
    memset(g_trust_store, 0, sizeof(g_trust_store));
    /* Slot 0: built-in EIA root key */
    g_trust_store[0].key_id           = eia_key_id_of(EIA_ROOT_PUBKEY);
    memcpy(g_trust_store[0].pubkey, EIA_ROOT_PUBKEY, 32);
    g_trust_store[0].introduced_epoch = 0;
    g_trust_store[0].revoked_epoch    = 0;
    g_trust_store[0].flags            = EIA_KEYSTORE_FLAG_ACTIVE;
    g_trust_store_count = 1;

    /* Check for external trust store file (list of raw 32-byte public keys) */
    const char *ts_file = getenv("EIA_TRUST_STORE");
    if (!ts_file) ts_file = getenv("EIA_TRUSTED_KEYS_FILE");
    if (ts_file) {
        FILE *f = fopen(ts_file, "rb");
        if (f) {
            uint8_t pk[32];
            while (fread(pk, 1, 32, f) == 32) {
                eia_trust_store_add(pk, 0);
            }
            fclose(f);
        }
    }

    /* Check for additional hex or binary trusted key in environment */
    const char *env_pk = getenv("EIA_TRUSTED_PUBKEY");
    if (env_pk) {
        if (strlen(env_pk) >= 64) {
            uint8_t pk[32];
            bool hex_ok = true;
            for (int i = 0; i < 32; ++i) {
                unsigned int byte_val = 0;
                if (sscanf(env_pk + (i * 2), "%02x", &byte_val) != 1) {
                    hex_ok = false;
                    break;
                }
                pk[i] = (uint8_t)byte_val;
            }
            if (hex_ok) {
                eia_trust_store_add(pk, 0);
            }
        } else if (strlen(env_pk) >= 32) {
            eia_trust_store_add((const uint8_t *)env_pk, 0);
        }
    }

    /* Check for revocation list in environment: EIA_REVOKED_KEY_IDS */
    const char *revoked_env = getenv("EIA_REVOKED_KEY_IDS");
    if (revoked_env) {
        char *copy = strdup(revoked_env);
        if (copy) {
            char *tok = strtok(copy, ", \t\n");
            while (tok) {
                uint64_t kid = (uint64_t)strtoull(tok, NULL, 0);
                if (kid != 0) {
                    eia_trust_store_revoke(kid, 0);
                }
                tok = strtok(NULL, ", \t\n");
            }
            free(copy);
        }
    }
}

void eia_trust_store_reset(void) {
    g_trust_store_init = 0;
    g_trust_store_count = 0;
    eia_trust_store_ensure_init();
}

/* Public API – add a new trusted public key.  Returns slot index or -1 if full. */
int eia_trust_store_add(const uint8_t pk[32], uint16_t introduced_epoch) {
    eia_trust_store_ensure_init();
    if (g_trust_store_count >= EIA_KEYSTORE_MAX) return -1;
    int slot = g_trust_store_count++;
    g_trust_store[slot].key_id           = eia_key_id_of(pk);
    memcpy(g_trust_store[slot].pubkey, pk, 32);
    g_trust_store[slot].introduced_epoch = introduced_epoch;
    g_trust_store[slot].revoked_epoch    = 0;
    g_trust_store[slot].flags            = EIA_KEYSTORE_FLAG_ACTIVE;
    return slot;
}

/* Public API – revoke a key by its key_id starting at revoked_epoch. */
int eia_trust_store_revoke(uint64_t key_id, uint16_t revoked_epoch) {
    eia_trust_store_ensure_init();
    for (int i = 0; i < g_trust_store_count; ++i) {
        if (g_trust_store[i].key_id == key_id) {
            g_trust_store[i].flags        |= EIA_KEYSTORE_FLAG_REVOKED;
            g_trust_store[i].revoked_epoch = revoked_epoch;
            return 0;
        }
    }
    return -1; /* not found */
}

/* Public API – look up a trust entry by key_id (returns NULL if absent/revoked). */
const EiaTrustEntry *eia_trust_store_lookup(uint64_t key_id, uint16_t for_epoch) {
    eia_trust_store_ensure_init();
    for (int i = 0; i < g_trust_store_count; ++i) {
        const EiaTrustEntry *e = &g_trust_store[i];
        if (!(e->flags & EIA_KEYSTORE_FLAG_ACTIVE)) continue;
        if (e->key_id != key_id && !(i == 0 && key_id == EIA_TRUSTED_PUBKEY_ID)) continue;
        if (for_epoch < e->introduced_epoch) continue;
        if (e->flags & EIA_KEYSTORE_FLAG_REVOKED) {
            if (for_epoch >= e->revoked_epoch) continue;
        }
        return e;
    }
    return NULL;
}

/*
 * eia_ed25519_keypair_from_seed – RFC 8032 §5.1.5 deterministic key expansion.
 * Derives the Ed25519 (pk, sk) pair from the given 32-byte seed.
 * sk[0..31]  = seed, sk[32..63] = pk  (standard NaCl 64-byte layout).
 */
int eia_ed25519_keypair_from_seed(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32]) {
    u8 d[64];
    gf p[4];
    u64 i;

    FOR(i, 32) sk[i] = seed[i];
    crypto_hash(d, sk, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    scalarbase(p, d);
    pack(pk, p);

    FOR(i, 32) sk[32 + i] = pk[i];
    return 0;
}

bool eia_verify_digest(const uint8_t digest[32], uint16_t key_epoch, uint64_t pubkey_id, const uint8_t sig[64]) {
    eia_trust_store_ensure_init();
    uint8_t payload[34];
    memcpy(payload, digest, 32);
    payload[32] = (uint8_t)(key_epoch & 0xFF);
    payload[33] = (uint8_t)((key_epoch >> 8) & 0xFF);

    /* Accept any non-revoked trust-store entry whose key_id matches */
    const EiaTrustEntry *entry = eia_trust_store_lookup(pubkey_id, key_epoch);
    if (!entry) return false;

    return (eia_ed25519_verify_detached(sig, payload, sizeof(payload), entry->pubkey) == 0);
}

bool spark0_verify_signature(const uint8_t digest[32], uint16_t key_epoch, uint64_t pubkey_id, const uint8_t sig[64]) {
    return eia_verify_digest(digest, key_epoch, pubkey_id, sig);
}

#ifdef EIA_SIGNER_ENABLED


static int crypto_sign(u8 *sm,u64 *smlen,const u8 *m,u64 n,const u8 *sk)
{
  u8 d[64],h[64],r[64];
  u64 i,j;
  i64 x[64];
  gf p[4];

  crypto_hash(d, sk, 32);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  *smlen = n+64;
  FOR(i,n) sm[64 + i] = m[i];
  FOR(i,32) sm[32 + i] = d[32 + i];

  crypto_hash(r, sm+32, n+32);
  reduce(r);
  scalarbase(p,r);
  pack(sm,p);

  FOR(i,32) sm[i+32] = sk[i+32];
  crypto_hash(h,sm,n + 64);
  reduce(h);

  FOR(i,64) x[i] = 0;
  FOR(i,32) x[i] = (u64) r[i];
  FOR(i,32) FOR(j,32) x[i+j] += h[i] * (u64) d[j];
  modL(sm + 32,x);

  return 0;
}

int eia_ed25519_sign_detached(uint8_t sig[64], const uint8_t *msg, size_t msg_len, const uint8_t sk[64])
{
  u64 smlen = 0;
  u8 *sm = (u8 *)malloc(64 + msg_len);
  if (!sm) return -1;

  crypto_sign(sm, &smlen, msg, msg_len, sk);
  memcpy(sig, sm, 64);

  free(sm);
  return 0;
}

/*
 * EIA Root Private Seed – used ONLY during compilation (signer path).
 * NEVER compiled into standalone loaders or runtimes.
 *
 * Key selection priority (highest first):
 *   1. EIA_SIGNING_KEY_FILE – path to a 32-byte binary seed file
 *   2. EIA_SIGNING_KEY      – first 32 bytes of the env-var string
 *   3. EIA_ROOT_SEED        – compiled-in fallback
 */
#ifdef EIA_ALLOW_DEV_FALLBACK_KEY
/* Development fallback key only enabled when explicitly compiled with -DEIA_ALLOW_DEV_FALLBACK_KEY */
static const uint8_t EIA_ROOT_SEED[32] = {
    0x53, 0x4f, 0x56, 0x45, 0x52, 0x45, 0x49, 0x47,
    0x4e, 0x5f, 0x45, 0x49, 0x41, 0x5f, 0x52, 0x4f,
    0x4f, 0x54, 0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x32,
    0x30, 0x32, 0x36, 0x5f, 0x53, 0x49, 0x47, 0x4e
};
#endif

/* Load a 32-byte seed from a file path (supports raw binary or 64-character hex).
 * Returns 0 on success, -1 on failure. */
static int eia_load_seed_from_file(const char *path, uint8_t seed[32]) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    char buf[128];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n >= 64) {
        bool is_hex = true;
        for (int i = 0; i < 64; ++i) {
            char c = buf[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                is_hex = false;
                break;
            }
        }
        if (is_hex) {
            for (int i = 0; i < 32; ++i) {
                unsigned int v = 0;
                sscanf(buf + (i * 2), "%02x", &v);
                seed[i] = (uint8_t)v;
            }
            return 0;
        }
    }
    if (n >= 32) {
        memcpy(seed, buf, 32);
        return 0;
    }
    return -1;
}

static int eia_load_active_signing_seed(uint8_t seed[32]) {
    /* Priority 1: external seed file (binary or 64-char hex) */
    const char *key_file = getenv("EIA_SIGNING_KEY_FILE");
    if (key_file && eia_load_seed_from_file(key_file, seed) == 0) {
        return 0;
    }
    /* Priority 2: raw env-var hex or bytes */
    const char *env_key = getenv("EIA_SIGNING_KEY");
    if (env_key) {
        if (strlen(env_key) >= 64) {
            bool is_hex = true;
            for (int i = 0; i < 64; ++i) {
                char c = env_key[i];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                    is_hex = false;
                    break;
                }
            }
            if (is_hex) {
                for (int i = 0; i < 32; ++i) {
                    unsigned int v = 0;
                    sscanf(env_key + (i * 2), "%02x", &v);
                    seed[i] = (uint8_t)v;
                }
                return 0;
            }
        }
        if (strlen(env_key) >= 32) {
            memcpy(seed, env_key, 32);
            return 0;
        }
    }
#ifdef EIA_ALLOW_DEV_FALLBACK_KEY
    memcpy(seed, EIA_ROOT_SEED, 32);
    return 0;
#else
    fprintf(stderr, "[EIA SIGNER ERROR] Production signing requires an external private key via EIA_SIGNING_KEY_FILE or EIA_SIGNING_KEY. Hardcoded fallback keys are disabled in production.\n");
    return -1;
#endif
}

int eia_sign_digest(const uint8_t digest[32], uint16_t key_epoch, uint8_t out_sig[64]) {
    uint8_t payload[34];
    memcpy(payload, digest, 32);
    payload[32] = (uint8_t)(key_epoch & 0xFF);
    payload[33] = (uint8_t)((key_epoch >> 8) & 0xFF);

    uint8_t seed[32];
    if (eia_load_active_signing_seed(seed) != 0) {
        return -1;
    }

    uint8_t pk[32], sk[64];
    eia_ed25519_keypair_from_seed(pk, sk, seed);
    eia_ed25519_sign_detached(out_sig, payload, sizeof(payload), sk);
    return 0;
}

int spark0_sign_digest(const uint8_t digest[32], uint16_t key_epoch, uint8_t out_sig[64]) {
    return eia_sign_digest(digest, key_epoch, out_sig);
}

uint64_t eia_get_active_signing_key_id(uint16_t *out_epoch, uint8_t out_pk[32]) {
    uint8_t seed[32];
    if (eia_load_active_signing_seed(seed) != 0) {
        if (out_epoch) *out_epoch = EIA_DEFAULT_KEY_EPOCH;
        if (out_pk) memset(out_pk, 0, 32);
        return 0;
    }

    uint8_t pk[32], sk[64];
    eia_ed25519_keypair_from_seed(pk, sk, seed);
    if (out_pk) memcpy(out_pk, pk, 32);

    if (out_epoch) {
        const char *ep = getenv("EIA_SIGNING_KEY_EPOCH");
        if (ep) {
            int val = atoi(ep);
            if (val > 0) *out_epoch = (uint16_t)val;
            else *out_epoch = EIA_DEFAULT_KEY_EPOCH;
        } else {
            *out_epoch = EIA_DEFAULT_KEY_EPOCH;
        }
    }

    return eia_key_id_of(pk);
}

#endif /* EIA_SIGNER_ENABLED */

#endif /* EIA_ED25519_C */

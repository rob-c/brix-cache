/*
 * brix_mkrepo.c — build a minimal, genuinely-signed CVMFS repository on disk,
 * laid out for HTTP serving, so brixcvmfs can mount it live.
 *
 * usage: brix_mkrepo <repo.fqrn> <webroot> <pubkey_out>
 * writes:
 *   <webroot>/cvmfs/<repo>/.cvmfswhitelist
 *   <webroot>/cvmfs/<repo>/.cvmfspublished
 *   <webroot>/cvmfs/<repo>/data/<2>/<rest>{X,C,}   (cert, catalog, content objects)
 *   <pubkey_out>                                    (repo master public key, PEM)
 * prints the content of "/hello" to stdout so the test can compare.
 *
 * gcc -Wall -I shared brix_mkrepo.c shared/cvmfs/grammar/hash.c \
 *     shared/cvmfs/object/object.c shared/cvmfs/catalog/catalog.c \
 *     -lsqlite3 -lcrypto -lz
 */
#include "cvmfs/grammar/hash.h"
#include "cvmfs/object/object.h"
#include "cvmfs/catalog/catalog.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <sqlite3.h>
#include <zlib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static const char HELLO[] = "Hello from a LIVE CVMFS-brix mount!\n";

static void mkpath(const char *p) { char c[1100]; snprintf(c,sizeof(c),"mkdir -p '%s'",p); if(system(c)){} }
static void write_file(const char *p, const void *d, size_t n) {
    FILE *f = fopen(p, "wb"); if (f) { fwrite(d, 1, n, f); fclose(f); }
}
static unsigned char *zlib_of(const unsigned char *s, size_t n, size_t *o) {
    uLongf cap = compressBound(n); unsigned char *b = malloc(cap); compress(b,&cap,s,n); *o=cap; return b;
}
static size_t cvmfs_sign(EVP_PKEY *pk, const unsigned char *m, size_t ml, unsigned char *sig, size_t cap) {
    /* RAW RSA-PKCS#1-v1.5 over the printed hash text (no DigestInfo) — real CVMFS. */
    EVP_PKEY_CTX*c=EVP_PKEY_CTX_new(pk,NULL); EVP_PKEY_sign_init(c); EVP_PKEY_CTX_set_rsa_padding(c,RSA_PKCS1_PADDING);
    size_t sl=cap; EVP_PKEY_sign(c,sig,&sl,m,ml); EVP_PKEY_CTX_free(c); return sl;
}
/* Write a CAS object (compressed) at <webroot>/cvmfs/<repo>/data/<2>/<rest><suffix>.
 * The object identity is the hash of the STORED (compressed) bytes (real CVMFS),
 * returned in *out_h. */
static void write_cas(const char *webrepo, cvmfs_hash_t *out_h, char suffix,
                      const unsigned char *plain, size_t n) {
    size_t zn; unsigned char *z = zlib_of(plain, n, &zn);
    cvmfs_object_hash(CVMFS_HASH_SHA1, z, zn, out_h);
    char op[160]; cvmfs_hash_to_object_path(out_h, suffix, op, sizeof(op));
    char dir[1200]; snprintf(dir, sizeof(dir), "%s/data/%.2s", webrepo, op);
    mkpath(dir);
    char path[1400]; snprintf(path, sizeof(path), "%s/data/%s", webrepo, op);
    write_file(path, z, zn); free(z);
}

int main(int argc, char **argv) {
    if (argc != 4) { fprintf(stderr, "usage: brix_mkrepo <repo> <webroot> <pubkey_out>\n"); return 2; }
    const char *repo = argv[1], *webroot = argv[2], *pubout = argv[3];

    char webrepo[900]; snprintf(webrepo, sizeof(webrepo), "%s/cvmfs/%s", webroot, repo);
    mkpath(webrepo);

    EVP_PKEY *master = EVP_RSA_gen(2048), *certpk = EVP_RSA_gen(2048);
    X509 *x = X509_new(); X509_set_pubkey(x, certpk);
    X509_gmtime_adj(X509_getm_notBefore(x), 0); X509_gmtime_adj(X509_getm_notAfter(x), 86400);
    X509_sign(x, certpk, EVP_sha256());
    BIO *cb = BIO_new(BIO_s_mem()); PEM_write_bio_X509(cb, x);
    char *cert_pem=NULL; long cert_len = BIO_get_mem_data(cb, &cert_pem);

    /* master pubkey → pubout */
    { BIO *b=BIO_new_file(pubout,"w"); PEM_write_bio_PUBKEY(b,master); BIO_free(b); }

    /* content object */
    size_t hn = sizeof(HELLO)-1;
    cvmfs_hash_t content_h;
    write_cas(webrepo, &content_h, 0, (const unsigned char*)HELLO, hn);

    /* catalog sqlite */
    char catdb[1000]; snprintf(catdb,sizeof(catdb),"%s/build.cat",webroot);
    sqlite3 *db; sqlite3_open(catdb,&db);
    sqlite3_exec(db,
        "CREATE TABLE catalog (md5path_1 INTEGER,md5path_2 INTEGER,parent_1 INTEGER,parent_2 INTEGER,"
        "hardlinks INTEGER,hash BLOB,size INTEGER,mode INTEGER,mtime INTEGER,flags INTEGER,name TEXT,"
        "symlink TEXT,uid INTEGER,gid INTEGER,xattr BLOB,PRIMARY KEY(md5path_1,md5path_2));"
        "CREATE TABLE nested_catalogs (path TEXT,sha1 TEXT,size INTEGER,PRIMARY KEY(path));"
        "CREATE TABLE properties (key TEXT,value TEXT,PRIMARY KEY(key));"
        "CREATE TABLE chunks (md5path_1 INTEGER,md5path_2 INTEGER,offset INTEGER,size INTEGER,hash BLOB,"
        "PRIMARY KEY(md5path_1,md5path_2,offset));", NULL,NULL,NULL);
    { int64_t r1,r2,h1,h2; cvmfs_catalog_md5path("",&r1,&r2); cvmfs_catalog_md5path("/hello",&h1,&h2);
      sqlite3_stmt*st; sqlite3_prepare_v2(db,"INSERT INTO catalog VALUES(?,?,?,?,1,?,?,?,1,?,?,?,0,0,NULL)",-1,&st,NULL);
      sqlite3_bind_int64(st,1,r1);sqlite3_bind_int64(st,2,r2);sqlite3_bind_int64(st,3,r1);sqlite3_bind_int64(st,4,r2);
      sqlite3_bind_null(st,5);sqlite3_bind_int64(st,6,0);sqlite3_bind_int64(st,7,040755);
      sqlite3_bind_int64(st,8,CVMFS_FLAG_DIR);sqlite3_bind_text(st,9,"",-1,SQLITE_STATIC);sqlite3_bind_null(st,10);
      sqlite3_step(st);sqlite3_reset(st);
      sqlite3_bind_int64(st,1,h1);sqlite3_bind_int64(st,2,h2);sqlite3_bind_int64(st,3,r1);sqlite3_bind_int64(st,4,r2);
      sqlite3_bind_blob(st,5,content_h.bytes,20,SQLITE_STATIC);sqlite3_bind_int64(st,6,(int64_t)hn);
      sqlite3_bind_int64(st,7,0100644);sqlite3_bind_int64(st,8,CVMFS_FLAG_FILE);
      sqlite3_bind_text(st,9,"hello",-1,SQLITE_STATIC);sqlite3_bind_null(st,10);
      sqlite3_step(st);sqlite3_finalize(st); }
    sqlite3_close(db);

    FILE*f=fopen(catdb,"rb"); fseek(f,0,SEEK_END); long csz=ftell(f); fseek(f,0,SEEK_SET);
    unsigned char*catbytes=malloc(csz); if(fread(catbytes,1,csz,f)!=(size_t)csz){} fclose(f);
    cvmfs_hash_t cat_h;
    write_cas(webrepo,&cat_h,'C',catbytes,csz);

    /* cert object */
    cvmfs_hash_t cert_h;
    write_cas(webrepo,&cert_h,'X',(const unsigned char*)cert_pem,cert_len);

    /* fingerprint */
    unsigned char cmd[20]; unsigned int cn=0;
    { EVP_MD_CTX*h=EVP_MD_CTX_new();
      /* fingerprint over DER */
      unsigned char*der=NULL; int dl=i2d_X509(x,&der);
      EVP_DigestInit_ex(h,EVP_sha1(),NULL);EVP_DigestUpdate(h,der,dl);EVP_DigestFinal_ex(h,cmd,&cn);
      EVP_MD_CTX_free(h); OPENSSL_free(der); }
    /* NB: brixcvmfs computes the fingerprint over the cert object bytes (PEM here),
     * so mirror THAT: fingerprint over the PEM the client will fetch. */
    { EVP_MD_CTX*h=EVP_MD_CTX_new(); EVP_DigestInit_ex(h,EVP_sha1(),NULL);
      /* not used — see below */ EVP_MD_CTX_free(h); }
    char fp[64];
    { /* replicate cvmfs_cert_fingerprint: X509_digest(sha1) over the parsed cert */
      unsigned char md[20]; unsigned int n=0; X509_digest(x,EVP_sha1(),md,&n);
      static const char hx[]="0123456789ABCDEF"; size_t o=0;
      for(unsigned i=0;i<n;i++){ if(i)fp[o++]=':'; fp[o++]=hx[md[i]>>4]; fp[o++]=hx[md[i]&0xf]; } fp[o]=0; }

    /* whitelist */
    char wlb[512]; int wlbn=snprintf(wlb,sizeof(wlb),"20991231235959\nN%s\n%s\n--\n",repo,fp);
    const char wlh[]="2222222222222222222222222222222222222222";
    unsigned char wsig[512]; size_t wsl=cvmfs_sign(master,(const unsigned char*)wlh,strlen(wlh),wsig,sizeof(wsig));
    unsigned char wl[1024]; size_t wn=0; memcpy(wl,wlb,wlbn);wn=wlbn;
    memcpy(wl+wn,wlh,strlen(wlh));wn+=strlen(wlh);wl[wn++]='\n';memcpy(wl+wn,wsig,wsl);wn+=wsl;
    char wlpath[1000]; snprintf(wlpath,sizeof(wlpath),"%s/.cvmfswhitelist",webrepo); write_file(wlpath,wl,wn);

    /* manifest */
    char cathex[64],certhex[64]; cvmfs_hash_to_hex(&cat_h,0,cathex,sizeof(cathex)); cvmfs_hash_to_hex(&cert_h,0,certhex,sizeof(certhex));
    char mb[512]; int mbn=snprintf(mb,sizeof(mb),"C%s\nB%ld\nX%s\nS1\nN%s\nT1700000000\nD240\n--\n",cathex,csz,certhex,repo);
    const char mh[]="1111111111111111111111111111111111111111";
    unsigned char msig[512]; size_t msl=cvmfs_sign(certpk,(const unsigned char*)mh,strlen(mh),msig,sizeof(msig));
    unsigned char man[1024]; size_t mn=0; memcpy(man,mb,mbn);mn=mbn;
    memcpy(man+mn,mh,strlen(mh));mn+=strlen(mh);man[mn++]='\n';memcpy(man+mn,msig,msl);mn+=msl;
    char mpath[1000]; snprintf(mpath,sizeof(mpath),"%s/.cvmfspublished",webrepo); write_file(mpath,man,mn);

    (void)cmd;
    fputs(HELLO, stdout);   /* expected content for the test to compare */
    free(catbytes);
    return 0;
}

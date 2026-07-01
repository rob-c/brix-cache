/*
 * spike_finalize.cpp — prove the "completion" path: turn a redirect-migrated
 * (zero-move) CephFS file into a fully CephFS-OWNED file by materializing each
 * redirect stub into a real in-cluster copy (copy_from, OSD→OSD), so the end
 * state is a normal read-write CephFS that no longer depends on the striper pool.
 *
 * After finalize we verify the three things the read-write end state needs:
 *   1. the file still reads byte-exact;
 *   2. a WRITE now stays LOCAL — the source object is NOT modified (materialized);
 *   3. the source objects can be DELETED and the file still reads (CephFS owns it).
 *
 *   g++ -std=c++17 -D_FILE_OFFSET_BITS=64 spike_finalize.cpp -lrados -lcephfs -o s_fin
 *   ./s_fin <striper_pool> <soid> <cephfs_data_pool> <cephfs_path>
 */
#include <rados/librados.hpp>
#include <cephfs/libcephfs.h>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <vector>

static unsigned long adler(const unsigned char *d, size_t n)
{ unsigned long a=1,b=0; while(n){size_t k=n<5552?n:5552;n-=k;while(k--){a+=*d++;b+=a;}a%=65521;b%=65521;} return (b<<16)|a; }
static long xnum(librados::IoCtx&io,const std::string&o,const char*n,long d)
{ ceph::bufferlist bl; if(io.getxattr(o,n,bl)<0)return d; std::string s(bl.c_str(),bl.length()); return strtol(s.c_str(),0,10); }

int main(int argc,char**argv)
{
    const char *conf=getenv("CEPH_CONF")?getenv("CEPH_CONF"):"/etc/ceph/ceph.conf";
    if(argc!=5){fprintf(stderr,"usage: %s <striper_pool> <soid> <cephfs_data_pool> <cephfs_path>\n",argv[0]);return 2;}
    std::string spool=argv[1],soid=argv[2],dpool=argv[3],cpath=argv[4];

    librados::Rados cl; librados::IoCtx src,dst;
    cl.init("admin"); cl.conf_read_file(conf); if(cl.connect()<0){fprintf(stderr,"connect\n");return 1;}
    cl.ioctx_create(spool.c_str(),src); cl.ioctx_create(dpool.c_str(),dst);
    std::string first=soid+".0000000000000000";
    long os=xnum(src,first,"striper.layout.object_size",4194304);
    long total=xnum(src,first,"striper.size",-1);
    if(total<os*2){fprintf(stderr,"need >=2-object file\n");return 1;}

    struct ceph_mount_info*cm; ceph_create(&cm,"admin"); ceph_conf_read_file(cm,conf); ceph_mount(cm,"/");
    struct ceph_statx stx;
    if(ceph_statx(cm,cpath.c_str(),&stx,CEPH_STATX_INO,0)){fprintf(stderr,"statx (migrate via redirect first)\n");return 1;}
    unsigned long long ino=(unsigned long long)stx.stx_ino;
    printf("finalizing inode 0x%llx (%s)\n",ino,cpath.c_str());

    /* materialize: copy_from each source object onto its CephFS stub, replacing
     * the redirect with an owned in-cluster copy. */
    int n=0;
    for(auto it=src.nobjects_begin(); it!=src.nobjects_end(); ++it){
        std::string name=it->get_oid();
        std::string pfx=soid+".";
        if(name.size()!=pfx.size()+16||name.compare(0,pfx.size(),pfx)!=0) continue;
        unsigned long idx=strtoul(name.substr(pfx.size()).c_str(),0,16);
        char d[64]; snprintf(d,sizeof(d),"%llx.%08lx",ino,idx);
        /* materialize the redirect: promote (copy target data local) then unset
         * the manifest so the object is a plain, source-independent owned copy. */
        { librados::ObjectWriteOperation pr; pr.tier_promote();
          if(dst.operate(d,&pr)<0){fprintf(stderr,"tier_promote %s\n",d);return 1;} }
        { librados::ObjectWriteOperation um; um.unset_manifest();
          dst.operate(d,&um); /* best-effort: promote may already have detached */ }
        for(const char*j:{"striper.layout.object_size","striper.layout.stripe_unit","striper.layout.stripe_count","striper.size","lock.striper.lock"}) dst.rmxattr(d,j);
        n++;
    }
    printf("materialized %d object(s) (redirect -> owned, in-cluster)\n",n);

    /* 1. reads correct */
    auto readfile=[&](long&got)->std::vector<char>{
        struct ceph_mount_info*vm; ceph_create(&vm,"admin"); ceph_conf_read_file(vm,conf); ceph_mount(vm,"/");
        int fd=ceph_open(vm,cpath.c_str(),O_RDONLY,0); std::vector<char>b(total); got=0; ssize_t r;
        while(got<total&&(r=ceph_read(vm,fd,b.data()+got,total-got,got))>0)got+=r; ceph_close(vm,fd);
        ceph_unmount(vm); ceph_release(vm); return b; };
    long got; auto b=readfile(got);
    int ok=(got==total); for(long o=0;o+8<=total&&ok;o+=8){unsigned long long v;memcpy(&v,b.data()+o,8);if(v!=(unsigned long long)o)ok=0;}
    printf("1. read after finalize: %s\n", ok?"OK byte-exact":"FAIL");

    /* 2. a write now stays local (source unchanged) */
    std::string s1=soid+".0000000000000001";
    ceph::bufferlist sb; src.read(s1,sb,os,0); unsigned long sbefore=adler((const unsigned char*)sb.c_str(),sb.length());
    { struct ceph_mount_info*wm; ceph_create(&wm,"admin"); ceph_conf_read_file(wm,conf); ceph_mount(wm,"/");
      int fd=ceph_open(wm,cpath.c_str(),O_RDWR,0); ceph_write(wm,fd,"FINALIZED-WRITE!",16,os+4096); ceph_fsync(wm,fd,0); ceph_close(wm,fd);
      ceph_unmount(wm); ceph_release(wm); }
    ceph::bufferlist sa; src.read(s1,sa,os,0); unsigned long safter=adler((const unsigned char*)sa.c_str(),sa.length());
    printf("2. write after finalize: source obj1 %s (before=%08lx after=%08lx)\n",
           sbefore==safter?"UNCHANGED -> write is LOCAL":"MODIFIED -> still write-through!", sbefore,safter);

    /* 3. delete the source objects; file must still read (CephFS owns the data) */
    for(auto it=src.nobjects_begin(); it!=src.nobjects_end(); ++it){
        std::string name=it->get_oid(), pfx=soid+".";
        if(name.size()==pfx.size()+16 && name.compare(0,pfx.size(),pfx)==0) src.remove(name);
    }
    long g2; auto b2=readfile(g2);
    int ok2=(g2==total); /* the written region differs; check the size + a clean region */
    for(long o=0;o+8<=total&&ok2;o+=8){ if(o>=os+4096&&o<os+4096+16)continue; unsigned long long v;memcpy(&v,b2.data()+o,8); if(v!=(unsigned long long)o)ok2=0; }
    printf("3. read after deleting SOURCE objects: %s\n", ok2?"OK -> CephFS fully owns the data":"FAIL -> still depends on source");

    int pass = ok && (sbefore==safter) && ok2;
    printf("RESULT: %s\n", pass?"PASS — finalize yields a self-owned read-write CephFS; source droppable":"FAIL");
    ceph_unmount(cm); ceph_release(cm); src.close(); dst.close(); cl.shutdown();
    return pass?0:1;
}

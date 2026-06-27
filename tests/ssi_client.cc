/*
 * ssi_client.cc — a real libXrdSsi client that drives the nginx module's SSI
 * engine, proving end-to-end interop with stock XRootD's own client stack.
 *
 * Build (headers from the xrootd source tree, libs from the system):
 *   g++ -std=c++17 -I/tmp/xrootd-src/src -o /tmp/ssi_client tests/ssi_client.cc \
 *       -lXrdSsiLib -lXrdCl -lXrdUtils
 *
 * Usage:  ssi_client <host:port> <resource> <request-bytes>
 * Prints "OK resp=<...> meta=<...>" and exits 0 on success; nonzero on error.
 */

#include "XrdSsi/XrdSsiProvider.hh"
#include "XrdSsi/XrdSsiService.hh"
#include "XrdSsi/XrdSsiRequest.hh"
#include "XrdSsi/XrdSsiResource.hh"
#include "XrdSsi/XrdSsiErrInfo.hh"
#include "XrdSsi/XrdSsiRespInfo.hh"

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>

extern XrdSsiProvider *XrdSsiProviderClient;

class OneShotReq : public XrdSsiRequest {
public:
    explicit OneShotReq(const std::string &r) : reqdata(r) {}

    char *GetRequest(int &dlen) override {
        dlen = (int) reqdata.size();
        return const_cast<char *>(reqdata.data());
    }

    bool ProcessResponse(const XrdSsiErrInfo &eInfo,
                         const XrdSsiRespInfo &rInfo) override {
        if (rInfo.rType == XrdSsiRespInfo::isError) {
            int n; std::string t = eInfo.Get(n);
            finish(false, !t.empty() ? t : (rInfo.eMsg ? rInfo.eMsg : "error"));
            return true;
        }
        if (rInfo.mdlen > 0 && rInfo.mdata) {
            meta.assign(rInfo.mdata, rInfo.mdlen);
        }
        if (rInfo.rType == XrdSsiRespInfo::isData ||
            rInfo.rType == XrdSsiRespInfo::isStream) {
            GetResponseData(rbuf, sizeof(rbuf));
            return true;
        }
        finish(true, "");           /* isNone: no data, success */
        return true;
    }

    void ProcessResponseData(const XrdSsiErrInfo &eInfo, char *buff,
                             int blen, bool last) override {
        (void) eInfo;
        if (blen > 0) {
            got.append(buff, blen);
        }
        if (last) {
            finish(true, "");
        } else {
            GetResponseData(rbuf, sizeof(rbuf));
        }
    }

    bool wait_done(int secs, std::string &resp, std::string &md,
                   std::string &errout) {
        std::unique_lock<std::mutex> lk(m);
        if (!cv.wait_for(lk, std::chrono::seconds(secs),
                         [&] { return done; })) {
            errout = "timeout";
            return false;
        }
        resp = got; md = meta; errout = err;
        return ok;
    }

private:
    void finish(bool o, const std::string &e) {
        std::lock_guard<std::mutex> lk(m);
        ok = o; err = e; done = true; cv.notify_all();
    }

    std::string reqdata, got, meta, err;
    char rbuf[1 << 16];
    bool ok = false, done = false;
    std::mutex m;
    std::condition_variable cv;
};

int
main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s host:port resource request\n", argv[0]);
        return 2;
    }
    std::string contact = argv[1], rname = argv[2], reqstr = argv[3];

    XrdSsiErrInfo eInfo;
    XrdSsiService *svc = XrdSsiProviderClient->GetService(eInfo, contact);
    if (!svc) {
        int n; std::string t = eInfo.Get(n);
        fprintf(stderr, "GetService failed: %s\n", t.c_str());
        return 3;
    }

    OneShotReq *req = new OneShotReq(reqstr);
    XrdSsiResource res(rname);
    svc->ProcessRequest(*req, res);

    std::string resp, md, err;
    bool good = req->wait_done(15, resp, md, err);
    if (good) {
        printf("OK resp=%s meta=%s\n", resp.c_str(), md.c_str());
    } else {
        printf("ERR %s\n", err.c_str());
    }
    req->Finished();
    delete req;
    return good ? 0 : 1;
}

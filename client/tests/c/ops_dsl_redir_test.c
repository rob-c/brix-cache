/* Unit test for §7.16 opdsl (declarative op pipeline) + §7.11 redir_registry
 * (redirect-collapse). Pure-logic, no server: pipeline steps are recording
 * stubs. Compiled against libbrix.a. */
#include "ops/opdsl.h"
#include "net/redir_registry.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(c,m) do{ if(c){printf("  PASS %s\n",m);} else {printf("  FAIL %s\n",m); fails++;} }while(0)

/* recording step: bumps *arg, returns 0 (ok) */
static int step_ok(brix_conn *c, void *arg, brix_status *st){ (void)c;(void)st; (*(int*)arg)++; return 0; }
/* failing step: bumps *arg, returns 1 (fail) */
static int step_fail(brix_conn *c, void *arg, brix_status *st){ (void)c;(void)st; (*(int*)arg)++; return 1; }

int main(void)
{
    /* ---- §7.16 opdsl ---- */
    {
        int a=0,b=0,d=0,els=0; size_t ran=0;
        brix_opd_t *p = brix_opd_new();
        brix_opd_step(p,"a",step_ok,&a);
        brix_opd_step(p,"b",step_ok,&b);
        brix_opd_step(p,"d",step_ok,&d);
        brix_opd_otherwise(p,step_ok,&els);
        int rc = brix_opd_run(p,NULL,NULL,&ran);
        CHECK(rc==0 && a==1 && b==1 && d==1 && els==0 && ran==3, "opdsl: all steps run in order, no otherwise");
        CHECK(brix_opd_len(p)==3, "opdsl: len==3");
        brix_opd_free(p);
    }
    {
        int a=0,bad=0,after=0,els=0; size_t ran=99;
        brix_opd_t *p = brix_opd_new();
        brix_opd_step(p,"a",step_ok,&a);
        brix_opd_step(p,"bad",step_fail,&bad);
        brix_opd_step(p,"after",step_ok,&after);   /* must NOT run */
        brix_opd_otherwise(p,step_ok,&els);
        int rc = brix_opd_run(p,NULL,NULL,&ran);
        CHECK(rc==-1 && a==1 && bad==1 && after==0 && els==1 && ran==1,
              "opdsl: short-circuits at failure, runs otherwise, skips rest");
        brix_opd_free(p);
    }
    {
        brix_opd_t *p = brix_opd_new();
        CHECK(brix_opd_run(p,NULL,NULL,NULL)==0, "opdsl: empty pipeline -> success");
        brix_opd_free(p);
    }

    /* ---- §7.11 redir_registry ---- */
    brix_vredir_clear();
    CHECK(brix_vredir_lookup("root://a:1094//f")==NULL, "vredir: unknown -> NULL");
    brix_vredir_record("root://a:1094//f","root://b:1094//f");
    CHECK(brix_vredir_lookup("root://a:1094//f") &&
          strcmp(brix_vredir_lookup("root://a:1094//f"),"root://b:1094//f")==0,
          "vredir: A->B recorded");
    /* B->C: A must now collapse to C */
    brix_vredir_record("root://b:1094//f","root://c:1094//f");
    CHECK(strcmp(brix_vredir_lookup("root://a:1094//f"),"root://c:1094//f")==0,
          "vredir: A->B->C collapses A->C");
    /* cycle C->A must be refused (would loop) */
    brix_vredir_record("root://c:1094//f","root://a:1094//f");
    CHECK(strcmp(brix_vredir_lookup("root://a:1094//f"),"root://c:1094//f")==0,
          "vredir: cycle C->A refused, chain intact");
    /* self-map refused */
    unsigned before = brix_vredir_count();
    brix_vredir_record("root://x:1//f","root://x:1//f");
    CHECK(brix_vredir_count()==before, "vredir: self-map refused");
    brix_vredir_clear();
    CHECK(brix_vredir_count()==0, "vredir: clear empties table");

    printf(fails? "FAILED %d\n":"ALL PASS\n", fails);
    return fails ? 1 : 0;
}

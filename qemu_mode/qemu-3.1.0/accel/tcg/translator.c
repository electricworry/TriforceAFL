/*
 * Generic intermediate code generation.
 *
 * Copyright (C) 2016-2017 Lluís Vilanova <vilanova@ac.upc.edu>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/error-report.h"
#include "cpu.h"
#include "tcg/tcg.h"
#include "tcg/tcg-op.h"
#include "exec/exec-all.h"
#include "exec/gen-icount.h"
#include "exec/log.h"
#include "exec/translator.h"

static void gen_aflBBlock(target_ulong pc);

/* Pairs with tcg_clear_temp_count.
   To be called by #TranslatorOps.{translate_insn,tb_stop} if
   (1) the target is sufficiently clean to support reporting,
   (2) as and when all temporaries are known to be consumed.
   For most targets, (2) is at the end of translate_insn.  */
void translator_loop_temp_check(DisasContextBase *db)
{
    if (tcg_check_temp_count()) {
        qemu_log("warning: TCG temporary leaks before "
                 TARGET_FMT_lx "\n", db->pc_next);
    }
}

void translator_loop(const TranslatorOps *ops, DisasContextBase *db,
                     CPUState *cpu, TranslationBlock *tb)
{
    int bp_insn = 0;

    /* Initialize DisasContext */
    db->tb = tb;
    db->pc_first = tb->pc;
    db->pc_next = db->pc_first;
    db->is_jmp = DISAS_NEXT;
    gen_aflBBlock(db->pc_first);
    db->num_insns = 0;
    db->singlestep_enabled = cpu->singlestep_enabled;

    /* Instruction counting */
    db->max_insns = tb_cflags(db->tb) & CF_COUNT_MASK;
    if (db->max_insns == 0) {
        db->max_insns = CF_COUNT_MASK;
    }
    if (db->max_insns > TCG_MAX_INSNS) {
        db->max_insns = TCG_MAX_INSNS;
    }
    if (db->singlestep_enabled || singlestep) {
        db->max_insns = 1;
    }

    ops->init_disas_context(db, cpu);
    tcg_debug_assert(db->is_jmp == DISAS_NEXT);  /* no early exit */

    /* Reset the temp count so that we can identify leaks */
    tcg_clear_temp_count();

    /* Start translating.  */
    gen_tb_start(db->tb);
    ops->tb_start(db, cpu);
    tcg_debug_assert(db->is_jmp == DISAS_NEXT);  /* no early exit */

    while (true) {
        db->num_insns++;
        ops->insn_start(db, cpu);
        tcg_debug_assert(db->is_jmp == DISAS_NEXT);  /* no early exit */

        /* Pass breakpoint hits to target for further processing */
        if (!db->singlestep_enabled
            && unlikely(!QTAILQ_EMPTY(&cpu->breakpoints))) {
            CPUBreakpoint *bp;
            QTAILQ_FOREACH(bp, &cpu->breakpoints, entry) {
                if (bp->pc == db->pc_next) {
                    if (ops->breakpoint_check(db, cpu, bp)) {
                        bp_insn = 1;
                        break;
                    }
                }
            }
            /* The breakpoint_check hook may use DISAS_TOO_MANY to indicate
               that only one more instruction is to be executed.  Otherwise
               it should use DISAS_NORETURN when generating an exception,
               but may use a DISAS_TARGET_* value for Something Else.  */
            if (db->is_jmp > DISAS_TOO_MANY) {
                break;
            }
        }

        /* Disassemble one instruction.  The translate_insn hook should
           update db->pc_next and db->is_jmp to indicate what should be
           done next -- either exiting this loop or locate the start of
           the next instruction.  */
        if (db->num_insns == db->max_insns
            && (tb_cflags(db->tb) & CF_LAST_IO)) {
            /* Accept I/O on the last instruction.  */
            gen_io_start();
            ops->translate_insn(db, cpu);
            gen_io_end();
        } else {
            ops->translate_insn(db, cpu);
        }

        /* Stop translation if translate_insn so indicated.  */
        if (db->is_jmp != DISAS_NEXT) {
            break;
        }

        /* Stop translation if the output buffer is full,
           or we have executed all of the allowed instructions.  */
        if (tcg_op_buf_full() || db->num_insns >= db->max_insns) {
            db->is_jmp = DISAS_TOO_MANY;
            break;
        }
    }

    /* Emit code to exit the TB, as indicated by db->is_jmp.  */
    ops->tb_stop(db, cpu);
    gen_tb_end(db->tb, db->num_insns - bp_insn);

    /* The disas_log hook may use these values rather than recompute.  */
    db->tb->size = db->pc_next - db->pc_first;
    db->tb->icount = db->num_insns;

#ifdef DEBUG_DISAS
    if (qemu_loglevel_mask(CPU_LOG_TB_IN_ASM)
        && qemu_log_in_addr_range(db->pc_first)) {
        qemu_log_lock();
        qemu_log("----------------\n");
        ops->disas_log(db, cpu);
        qemu_log("\n");
        qemu_log_unlock();
    }
#endif
}






#include "exec/cpu_ldst.h"


#include "../../../patches/afl-triforce.h"

static target_ulong startForkserver(CPUArchState *env, target_ulong enableTicks)
{
    //printf("pid %d: startForkServer\n", getpid()); fflush(stdout);
    if(afl_fork_child) {
        /* 
         * we've already started a fork server. perhaps a test case
         * accidentally triggered startForkserver again.  Exit the
         * test case without error.
         */
        exit(0);
    }
#ifdef CONFIG_USER_ONLY
    /* we're running in the main thread, get right to it! */
    afl_setup();
    afl_forkserver(env);
#else
    /*
     * we're running in a cpu thread. we'll exit the cpu thread
     * and notify the iothread.  The iothread will run the forkserver
     * and in the child will restart the cpu thread which will continue
     * execution.
     * N.B. We assume a single cpu here!
     */
    aflEnableTicks = enableTicks;
    afl_wants_cpu_to_stop = 1;
#endif
    return 0;
}

/* copy work into ptr[0..sz].  Assumes memory range is locked. */
static target_ulong getWork(CPUArchState *env, target_ulong ptr, target_ulong sz)
{
    target_ulong retsz;
    FILE *fp;
    unsigned char ch;

    //printf("pid %d: getWork %lx %lx\n", getpid(), ptr, sz);fflush(stdout);
    assert(aflStart == 0);
    fp = fopen(aflFile, "rb");
    if(!fp) {
         perror(aflFile);
         return -1;
    }
    retsz = 0;
    while(retsz < sz) {
        if(fread(&ch, 1, 1, fp) == 0)
            break;
        cpu_stb_data(env, ptr, ch);
        retsz ++;
        ptr ++;
    }
    fclose(fp);
    return retsz;
}

static target_ulong startWork(CPUArchState *env, target_ulong ptr)
{
    target_ulong start, end;

    //printf("pid %d: ptr %lx\n", getpid(), ptr);fflush(stdout);
    start = cpu_ldq_data(env, ptr);
    end = cpu_ldq_data(env, ptr + sizeof start); // For ARM it needs to be 8, not 4. Need to parameterise somehow.
    //printf("pid %d: startWork %lx - %lx\n", getpid(), start, end);fflush(stdout);

    afl_start_code = start;
    afl_end_code   = end;
    aflGotLog = 0;
    aflStart = 1;
    return 0;
}

static target_ulong doneWork(target_ulong val)
{
    //printf("pid %d: doneWork %lx\n", getpid(), val);fflush(stdout);
    assert(aflStart == 1);
/* detecting logging as crashes hasnt been helpful and
   has occasionally been a problem.  We'll leave it to
   a post-analysis phase to look over dmesg output for
   our corpus.
 */
#ifdef LETSNOT 
    if(aflGotLog)
        exit(64 | val);
#endif
    exit(val); /* exit forkserver child */
}

target_ulong helper_aflCall(CPUArchState *env, target_ulong code, target_ulong a0, target_ulong a1) {
    switch(code) {
    case 1: return startForkserver(env, a0);
    case 2: return getWork(env, a0, a1);
    case 3: return startWork(env, a0);
    case 4: return doneWork(a0);
    default: return -1;
    }
}

/* return pointer to static buf filled with strz from ptr[0..maxlen] */
static const char *
peekStrZ(CPUArchState *env, target_ulong ptr, int maxlen)
{
    static char buf[0x1000];
    int i;
    if(maxlen > sizeof buf - 1)
        maxlen = sizeof buf - 1;
    for(i = 0; i < maxlen; i++) {
        char ch = cpu_ldub_data(env, ptr + i);
        if(!ch)
            break;
        buf[i] = ch;
    }
    buf[i] = 0;
    return buf;
}

void helper_aflInterceptLog(CPUArchState *env)
{
    if(!aflStart)
        return;
    aflGotLog = 1;

#ifdef NOTYET
    static FILE *fp = NULL;
    if(fp == NULL) {
        fp = fopen("logstore.txt", "a");
        if(fp) {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            fprintf(fp, "\n----\npid %d time %ld.%06ld\n", getpid(), (u_long)tv.tv_sec, (u_long)tv.tv_usec);
        }
    }
    if(!fp) 
        return;

    target_ulong stack = env->regs[R_ESP];
    //target_ulong level = env->regs[R_ESI]; // arg 2
    target_ulong ptext = cpu_ldq_data(env, stack + 0x8); // arg7
    target_ulong len   = cpu_ldq_data(env, stack + 0x10) & 0xffff; // arg8
    const char *msg = peekStrZ(env, ptext, len);
    fprintf(fp, "%s\n", msg);
#endif
}

void helper_aflInterceptPanic(void)
{
    if(!aflStart)
        return;
    exit(32);
}

static void gen_aflBBlock(target_ulong pc)
{
    if(pc == aflPanicAddr)
        gen_helper_aflInterceptPanic();
    if(pc == aflDmesgAddr)
        gen_helper_aflInterceptLog(cpu_env);
}

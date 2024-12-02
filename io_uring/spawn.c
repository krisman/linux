// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Spawning a linked series of operations onto a dedicated task.
 *
 * Copyright (C) 2022 Josh Triplett
 */

#include <linux/binfmts.h>
#include <linux/nospec.h>
#include <linux/syscalls.h>

#include "io_uring.h"
#include "rsrc.h"
#include "spawn.h"

/* FIXME: Put this in a header */
int io_issue_sqe(struct io_kiocb *req, unsigned int issue_flags);

struct io_exec {
	struct file *file_unused;
	const char __user *filename;
	const char __user *const __user *argv;
	const char __user *const __user *envp;

	int dfd;
	u32 flags;
};

struct io_clone {
	struct file *file_unused;
	struct io_kiocb *link;
};

static void fail_link(struct io_kiocb *req)
{
	struct io_kiocb *nxt;
	while (req) {
		req_fail_link_node(req, -ECANCELED);
		io_req_complete_defer(req);

		nxt = req->link;
		req->link = NULL;
		req = nxt;
	}
}

static int io_uring_spawn_task(void *data)
{
	struct io_kiocb *head = data;
	struct io_clone *c = io_kiocb_to_cmd(head, struct io_clone);
	struct io_ring_ctx *ctx = head->ctx;
	struct io_kiocb *req, *next;
	int err, ret = -EINVAL;

	mutex_lock(&ctx->uring_lock);

	for (req = c->link; req; req = next) {
		int hardlink = req->flags & REQ_F_HARDLINK;

		if (WARN_ON(!(req->flags & (REQ_F_HARDLINK | REQ_F_LINK))))
			break;

		next = req->link;
		req->link = NULL;
		req->flags &= ~(REQ_F_HARDLINK | REQ_F_LINK | REQ_F_CREDS);

		if (!(req->flags & REQ_F_FAIL)) {
			err = io_issue_sqe(req, IO_URING_F_COMPLETE_DEFER);
			/*
			 * We can't requeue a request from the spawn
			 * context.  Fail the whole chain.
			 */
			if (err) {
				req_fail_link_node(req, -ECANCELED);
				io_req_complete_defer(req);
			}
		}
		if (req->flags & REQ_F_FAIL) {
			if (!hardlink) {
				fail_link(next);
				break;
			}
		} else if (req->opcode == IORING_OP_EXEC) {
			/*
			 * Don't execute anything after the first
			 * successful IORING_OP_EXEC.  Cancel anything
			 * coming after it and let userspace return
			 */
			fail_link(next);
			ret = 0;
			break;
		}
	}

	io_submit_flush_completions(ctx);
	percpu_ref_put(&ctx->refs);

	mutex_unlock(&ctx->uring_lock);

	/* If there was any error, terminate the new thread. */
	if (ret)
		force_exit_sig(SIGKILL);
	return 0;
}

/* FIXME: Put this in a header */
struct task_struct *create_io_uring_spawn_task(int (*fn)(void *), void *arg);

int io_clone_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	if (unlikely(sqe->fd || sqe->ioprio || sqe->addr2 || sqe->addr
		     || sqe->len || sqe->rw_flags || sqe->buf_index
		     || sqe->optlen || sqe->addr3))
		return -EINVAL;
	return 0;
}

int io_clone(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_clone *c = io_kiocb_to_cmd(req, struct io_clone);
	struct task_struct *tsk;

	/*
	 * Prevent the context from going away before the spawned task
	 * has had a chance to execute.  Dropped by io_uring_spawn_task.
	 */
	percpu_ref_get(&req->ctx->refs);

	tsk = create_io_uring_spawn_task(io_uring_spawn_task, req);
	if (IS_ERR(tsk)) {
		percpu_ref_put(&req->ctx->refs);
		return PTR_ERR(tsk);
	}

	/*
	 * Steal the link from io_uring dispatcher to have them
	 * submitted through the new thread.  Note we can no longer fail
	 * the clone(), so spawned task is responsible for completing
	 * these requests.
	 */
	c->link = req->link;
	req->flags &= ~(REQ_F_HARDLINK | REQ_F_LINK);
	req->link = NULL;

	wake_up_new_task(tsk);

	return IOU_OK;
}

int io_exec_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_exec *e = io_kiocb_to_cmd(req, typeof(*e));

	if (unlikely(sqe->buf_index || sqe->len || sqe->file_index))
		return -EINVAL;

	e->dfd = READ_ONCE(sqe->fd);
	e->filename = u64_to_user_ptr(READ_ONCE(sqe->addr));
	e->argv = u64_to_user_ptr(READ_ONCE(sqe->addr2));
	e->envp = u64_to_user_ptr(READ_ONCE(sqe->addr3));
	e->flags = READ_ONCE(sqe->execve_flags);

	return 0;
}

int io_exec(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_exec *e = io_kiocb_to_cmd(req, typeof(*e));
	int ret;

	ret = do_execveat(e->dfd, getname(e->filename),
			  e->argv, e->envp, e->flags);
	if (ret < 0) {
		req_set_fail(req);
		io_req_set_res(req, ret, 0);

		return ret;
	}
	io_req_set_res(req, ret, 0);
	return IOU_OK;

}

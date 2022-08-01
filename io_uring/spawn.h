// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Spawning a linked series of operations onto a dedicated task.
 *
 * Copyright © 2022 Josh Triplett
 */

int io_clone_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_clone(struct io_kiocb *req, unsigned int issue_flags);

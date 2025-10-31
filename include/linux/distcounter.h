#include <linux/percpu_counter.h>

#define LAZY_INIT_BIAS (1<<0)

struct lazy_percpu_counter {
	struct percpu_counter c;
};

static inline s64 add_bias(long val)
{
	return (val << 1) | LAZY_INIT_BIAS;
}
static inline s64 remove_bias(long val)
{
	return val >> 1;
}

static inline bool lazy_pcpu_counter_initialized(struct lazy_percpu_counter *lpc)
{
	return !(atomic_long_read(&lpc->c.remote) & LAZY_INIT_BIAS);
}

static inline void lazy_pcpu_counter_init_many(struct lazy_percpu_counter *lpc, int amount,
					       int nr_counters)
{
	for (int i = 0; i < nr_counters; i++) {
		lpc[i].c.count = amount;
		atomic_long_set(&lpc[i].c.remote, LAZY_INIT_BIAS);
		raw_spin_lock_init(&lpc[i].c.lock);
	}
}

static inline int lazy_pcpu_counter_upgrade(struct lazy_percpu_counter *lpc, gfp_t gfp)
{
	unsigned long flags;
	s32 __percpu *counters;
	s64 remote = 0;

	if (lazy_pcpu_counter_initialized(lpc))
		return 0;

	counters = __alloc_percpu_gfp(1, __alignof__(*counters), gfp);
	if (!counters)
		return -ENOMEM;

	cpu_hotplug_add_watchlist(&lpc->c, 1);

	/* Protects from races with cpu hotplug removal */
	raw_spin_lock_irqsave(&lpc->c.lock, flags);

	/*
	  Shouldn't happen. Retry locked, in case we
          raced.  But we can still recover.
	 */
	if (WARN_ON(lazy_pcpu_counter_initialized(lpc))) {
		raw_spin_unlock_irqrestore(&lpc->c.lock, flags);
		free_percpu(counters);
		return -ENOMEM;
	}

	/* After the xchg, lpc_counter behaves as a regular percpu counter. */
	remote = (s64) atomic_long_xchg(&lpc->c.remote, (s64)(uintptr_t) counters);

	raw_spin_unlock_irqrestore(&lpc->c.lock, flags);

	BUG_ON(!(remote & LAZY_INIT_BIAS));

	remote = remove_bias(remote);
	percpu_counter_add_local(&lpc->c, remote);

	return 0;
}

static inline int lazy_pcpu_counter_upgrade_many(struct lazy_percpu_counter *c, int nr_counters,
						 gfp_t gfp)
{
	s32 __percpu *counters;
	size_t counter_size;

	counter_size = ALIGN(sizeof(*counters), __alignof__(*counters));
	counters = __alloc_percpu_gfp(nr_counters * counter_size,
				      __alignof__(*counters), gfp);
	if (!counters)
		return -ENOMEM;

	for (int i = 0; i < nr_counters; i++) {
		struct lazy_percpu_counter *lpc = &c[i];
		s32 __percpu *n_counter;
		s64 remote = 0;

		WARN_ON(lazy_pcpu_counter_initialized(lpc));

		/* After the xchg, lpc_counter behaves as a regular percpu counter. */
		n_counter = (void __percpu *)counters + i * counter_size;
		remote = (s64) atomic_long_xchg(&lpc->c.remote, (s64)(uintptr_t) n_counter);

		BUG_ON(!(remote & LAZY_INIT_BIAS));

		percpu_counter_add_local(&lpc->c, remove_bias(remote));
	}
	cpu_hotplug_add_watchlist((struct percpu_counter*)c, nr_counters);

	return 0;
}

static inline void lazy_pcpu_counter_add_atomic(struct lazy_percpu_counter *lpc, s64 amount)
{
	long x = amount << 1;
	long counter;

	if (lazy_pcpu_counter_initialized(lpc)) {
		percpu_counter_add(&lpc->c, amount);
		return;
	}

	do {
		counter = atomic_long_read(&lpc->c.remote);
		if (!unlikely(counter & LAZY_INIT_BIAS)) {
			percpu_counter_add(&lpc->c, amount);
			return;
		}
	} while (atomic_long_cmpxchg_relaxed(&lpc->c.remote, counter, (counter+x)) != counter);
}

static inline void lazy_pcpu_counter_add_fast(struct lazy_percpu_counter *lpc, s64 amount)
{
	if (lazy_pcpu_counter_initialized(lpc))
		percpu_counter_add(&lpc->c, amount);
	else
		lpc->c.count += amount;
}

static inline void __lazy_pcpu_counter_sync(struct lazy_percpu_counter *lpc)
{
	lazy_pcpu_counter_add_atomic(lpc, lpc->c.count);
	lpc->c.count = 0;
}

static inline s64 lazy_pcpu_counter_sum(struct lazy_percpu_counter *lpc)
{
	if (lazy_pcpu_counter_initialized(lpc))
		return percpu_counter_sum(&lpc->c);

	__lazy_pcpu_counter_sync(lpc);
	return remove_bias(atomic_long_read(&lpc->c.remote));
}

static inline s64 lazy_pcpu_counter_sum_positive(struct lazy_percpu_counter *lpc)
{
	s64 val = lazy_pcpu_counter_sum(lpc);

	return (val > 0) ? val : 0;
}

static inline s64 lazy_pcpu_counter_read(struct lazy_percpu_counter *lpc)
{
	if (lazy_pcpu_counter_initialized(lpc))
		return percpu_counter_read(&lpc->c);
	return remove_bias(atomic_long_read(&lpc->c.remote)) + lpc->c.count;
}

static inline s64 lazy_pcpu_counter_read_positive(struct lazy_percpu_counter *lpc)
{
	s64 val = lazy_pcpu_counter_read(lpc);

	return (val > 0) ? val : 0;
}

static inline void lazy_percpu_counter_destroy_many(struct lazy_percpu_counter *lpc,
						    u32 nr_counters)
{
	int i;

	/*
	  Check and destroy them individually, because it is
          not guaranteed all counters created together were upgraded.
	 */
	for (i = 0; i < nr_counters; i++)
		if (lazy_pcpu_counter_initialized(&lpc[i]))
			percpu_counter_destroy_many(&lpc[i].c, 1);
}

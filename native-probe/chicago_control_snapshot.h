/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef GXFP_CHICAGO_CONTROL_SNAPSHOT_H
#define GXFP_CHICAGO_CONTROL_SNAPSHOT_H

/* Preserve only a complete ten-byte control ACK observed at a new IRQ.
 * No GPIO, delay, allocation, TLS bytes or image payload in the IRQ path.
 * A changed, twice-copied checksummed ACK is evidence; an identical old
 * mailbox is not. The ordinary receiver still handles identical fresh
 * ACKs and validates the separate command response before completion.
 */
struct chicago_control_snapshot {
	raw_spinlock_t lock;
	void __iomem *mailbox;
	u8 baseline[10], command;
	bool armed;
	int status;
};

static inline void chicago_control_snapshot_init(struct chicago_control_snapshot *s)
{
	raw_spin_lock_init(&s->lock);
	s->mailbox = NULL;
	s->armed = false;
	s->status = -1;
}

static inline void chicago_control_snapshot_begin(struct chicago_control_snapshot *s,
					   void __iomem *mailbox, u8 command,
					   const u8 *baseline)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&s->lock, flags);
	s->mailbox = mailbox;
	s->command = command;
	s->status = -1;
	memcpy(s->baseline, baseline, sizeof(s->baseline));
	s->armed = command == 0x80 || command == 0x82 || command == 0x98 || command == 0xa6;
	raw_spin_unlock_irqrestore(&s->lock, flags);
}

static inline void chicago_control_snapshot_irq(struct chicago_control_snapshot *s)
{
	u8 frame[10], stable[10];
	unsigned long flags;
	raw_spin_lock_irqsave(&s->lock, flags);
	if (!s->armed) goto done;
	memcpy_fromio(frame, s->mailbox, sizeof(frame));
	dma_rmb();
	memcpy_fromio(stable, s->mailbox, sizeof(stable));
	if (!memcmp(frame, stable, sizeof(frame)) &&
	    memcmp(frame, s->baseline, sizeof(frame)) &&
	    frame_valid(frame, sizeof(frame)) && frame[4] == 0xb0 &&
	    frame[7] == s->command) {
		/* Never let a later positive ACK conceal a negative one. */
		if (s->status == -1 || frame[8] != 1) s->status = frame[8];
	}
done:
	raw_spin_unlock_irqrestore(&s->lock, flags);
	memzero_explicit(frame, sizeof(frame));
	memzero_explicit(stable, sizeof(stable));
}

static inline int chicago_control_snapshot_status(struct chicago_control_snapshot *s)
{
	int status;
	unsigned long flags;
	raw_spin_lock_irqsave(&s->lock, flags);
	status = s->status;
	raw_spin_unlock_irqrestore(&s->lock, flags);
	return status;
}

static inline void chicago_control_snapshot_end(struct chicago_control_snapshot *s)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&s->lock, flags);
	s->armed = false;
	s->mailbox = NULL;
	s->command = 0;
	s->status = -1;
	memzero_explicit(s->baseline, sizeof(s->baseline));
	raw_spin_unlock_irqrestore(&s->lock, flags);
}
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <asm/io.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Timur Abdullin");

#define SEC_DELAY 60
#define INP_REG 0x60
#define SCANCODE_MASK 0x80
#define KEYBOARD_IRQ 1

static struct timer_list stats_timer;
static void *dev_id;
static atomic_t cnt;

static void timer_callback(struct timer_list *unused) {
    unsigned long curr_cnt = atomic_xchg(&cnt, 0);
    printk(KERN_INFO "keyboard stats: %lu chars in the last minute\n", curr_cnt);
    mod_timer(&stats_timer, jiffies + secs_to_jiffies(SEC_DELAY));
}

static enum irqreturn irq_handler(int Irq, void *dev_id) {
    unsigned char scancode = 0;
    scancode = inb(INP_REG);
    if (scancode & SCANCODE_MASK) {
        atomic_inc(&cnt);
    }
    return IRQ_NONE;
}

static int __init keyboard_stats_init(void) {
    int ret = 0;

    timer_setup(&stats_timer, timer_callback, 0);
    mod_timer(&stats_timer, jiffies + secs_to_jiffies(SEC_DELAY));

    ret = request_irq(KEYBOARD_IRQ, irq_handler, IRQF_SHARED, "keyboard_stats", &dev_id);
    if (ret) {
        printk(KERN_ERR "keyboard_stats: Failed to register IRQ handler\n");
        del_timer_sync(&stats_timer);
        return ret;
    }

    printk(KERN_INFO "keyboard stats: Module loaded\n");
    return 0;
}

static void __exit keyboard_stats_exit(void) {
    free_irq(KEYBOARD_IRQ, &dev_id);
    del_timer_sync(&stats_timer);
    printk(KERN_INFO "keyboard stats: Module unloaded\n");
}

module_init(keyboard_stats_init);
module_exit(keyboard_stats_exit);

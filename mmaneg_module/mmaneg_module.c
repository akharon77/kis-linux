#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Timur Abdullin");

#define CHECK_CMD(buf, cmd) (strncmp((buf), (cmd), sizeof(cmd) - 1) == 0)
#define BUF_SIZE 128

static void listvma_cmd(void) {
  struct mm_struct *mm = current->mm;
  if (!mm) {
    printk(KERN_INFO "mmaneg: No mm structure\n");
    return;
  }

  down_read(&mm->mmap_lock);
  struct vm_area_struct *vma = NULL;

  printk(KERN_INFO "mmaneg: List VMA for current process:\n");

  VMA_ITERATOR(iter, mm, 0);
  for_each_vma(iter, vma) {
    printk(KERN_INFO "\tVMA %lx-%lx, flags %lx\n", vma->vm_start, vma->vm_end,
           vma->vm_flags);
  }
  up_read(&mm->mmap_lock);
}

static void findpage_cmd(char *buf) {
  unsigned long addr = 0;
  if (sscanf(buf, "findpage %lx", &addr) != 1) {
    printk(KERN_ERR "mmaneg: Invalid format of command\n");
    return;
  }

  struct page *page = NULL;
  unsigned long paddr = 0;

  int ret = pin_user_pages_fast(addr, 1, FOLL_WRITE, &page);
  if (ret < 0) {
    printk(KERN_ERR "mmaneg: Failed to get user pages: %d\n", ret);
    return;
  }
  if (ret == 0) {
    printk(KERN_ERR "mmaneg: No page found for address %lx\n", addr);
    return;
  }

  paddr = page_to_phys(page) + (addr & ~PAGE_MASK);
  printk(KERN_INFO "mmaneg: VA %lx -> PA %lx\n", addr, paddr);
  unpin_user_pages(&page, 1);
}

static void writeval_cmd(char *buf) {
  unsigned long addr = 0;
  unsigned long val = 0;
  if (sscanf(buf, "writeval %lx %lx", &addr, &val) != 2) {
    printk(KERN_ERR "mmaneg: Invalid format of command\n");
    return;
  }

  if (!access_ok((void __user *)addr, sizeof(val))) {
    printk(KERN_ERR "mmaneg: Invalid address\n");
    return;
  }

  if (put_user(val, (unsigned long __user *)addr)) {
    printk(KERN_ERR "mmaneg: Write operation to address %lx failed\n", addr);
  } else {
    printk(KERN_INFO "mmaneg: Write %lx to address %lx\n", val, addr);
  }
}

static void readval_cmd(char *buf) {
  unsigned long addr = 0;
  unsigned long val = 0;
  if (sscanf(buf, "readval %lx", &addr) != 1) {
    printk(KERN_ERR "mmaneg: Invalid format of command\n");
    return;
  }

  if (!access_ok((void __user *)addr, sizeof(val))) {
    printk(KERN_ERR "mmaneg: Invalid address\n");
    return;
  }

  if (get_user(val, (unsigned long __user *)addr)) {
    printk(KERN_ERR "mmaneg: Read operation of address %lx failed\n", addr);
  } else {
    printk(KERN_INFO "mmaneg: %lx was readed from address %lx\n", val, addr);
  }
}

static ssize_t mmaneg_write(struct file *file, const char __user *ubuf,
                            size_t count, loff_t *ppos) {
  char buf[BUF_SIZE] = {};
  size_t len = min(count, BUF_SIZE - 1);

  if (copy_from_user(buf, ubuf, len)) {
    return -EFAULT;
  }
  buf[len] = '\0';

  if (CHECK_CMD(buf, "listvma")) {
    listvma_cmd();
  } else if (CHECK_CMD(buf, "findpage")) {
    findpage_cmd(buf);
  } else if (CHECK_CMD(buf, "writeval")) {
    writeval_cmd(buf);
  } else if (CHECK_CMD(buf, "readval")) {
    readval_cmd(buf);
  } else {
    printk(KERN_INFO "mmaneg: Unknown command\n");
  }

  return count;
}

static const struct proc_ops mmaneg_proc_ops = {
    .proc_write = mmaneg_write,
};

static int __init mmaneg_init(void) {
  proc_create("mmaneg", 0666, NULL, &mmaneg_proc_ops);
  printk(KERN_INFO "mmaneg: Module loaded\n");
  return 0;
}

static void __exit mmaneg_exit(void) {
  remove_proc_entry("mmaneg", NULL);
  printk(KERN_INFO "mmaneg: Module unloaded\n");
}

module_init(mmaneg_init);
module_exit(mmaneg_exit);

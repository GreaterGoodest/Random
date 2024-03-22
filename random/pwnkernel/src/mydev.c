#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>

MODULE_LICENSE("GPL"); 

#define BUFSIZE 256

char data[BUFSIZE] = {0};

static int device_open(struct inode *inode, struct file *filp)
{
	printk(KERN_ALERT "Device opened.");
  	return 0;
}

static int device_release(struct inode *inode, struct file *filp)
{
	printk(KERN_ALERT "Device closed.");
  	return 0;
}

static ssize_t device_read(struct file *filp, char *buffer, size_t length, loff_t *offset)
{
	return copy_to_user(buffer, data, BUFSIZE) ? -EFAULT : 0;
}

static ssize_t device_write(struct file *filp, const char *buf, size_t len, loff_t *off)
{
	if (strlen(buf) < BUFSIZE)
	{
		return copy_from_user(data, buf, BUFSIZE) ? -EFAULT : 0;
	}
  	return -EFAULT;
}

static struct file_operations fops = {
  	.read = device_read,
  	.write = device_write,
  	.open = device_open,
  	.release = device_release
};

struct proc_dir_entry *proc_entry = NULL;

int init_module(void)
{
  	proc_entry = proc_create("mydev", 0666, NULL, &fops);

	printk(KERN_ALERT "/proc/mydev created!");
  	return 0;
}

void cleanup_module(void)
{
	if (proc_entry)
	{
		proc_remove(proc_entry);                                                                                             
	}
	printk(KERN_ALERT "mydev removed!");
}


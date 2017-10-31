/*
 *	linux/mm/filemap_xip.c
 *
 * Copyright (C) 2005 IBM Corporation
 * Author: Carsten Otte <cotte@de.ibm.com>
 *
 * derived from linux/mm/filemap.c - Copyright (C) Linus Torvalds
 *
 */

#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/export.h>
#include <linux/uio.h>
#include <linux/rmap.h>
#include <linux/mmu_notifier.h>
#include <linux/sched.h>
#include <linux/seqlock.h>
#include <linux/mutex.h>
#include <linux/gfp.h>
#include <asm/tlbflush.h>
#include <asm/io.h>

#include <linux/pram_fs.h>

/*
 * We do use our own empty page to avoid interference with other users
 * of ZERO_PAGE(), such as /dev/zero
 */
static DEFINE_MUTEX(xip_sparse_mutex);
static seqcount_t xip_sparse_seq = SEQCNT_ZERO;
static struct page *__xip_sparse_page;

/* called under xip_sparse_mutex */
static struct page *xip_sparse_page(void)
{
	if (!__xip_sparse_page) {
		struct page *page = alloc_page(GFP_HIGHUSER | __GFP_ZERO);

		if (page)
			__xip_sparse_page = page;
	}
	return __xip_sparse_page;
}

/*
 * This is a file read routine for execute in place files, and uses
 * the mapping->a_ops->get_xip_mem() function for the actual low-level
 * stuff.
 *
 * Note the struct file* is not used at all.  It may be NULL.
 */
static ssize_t
do_xip_mapping_read(struct address_space *mapping,
		    struct file_ra_state *_ra,
		    struct file *filp,
		    char __user *buf,
		    size_t len,
		    loff_t *ppos)
{
	struct inode *inode = mapping->host;
	pgoff_t index, end_index;
	unsigned long offset;
	loff_t isize, pos;
	size_t copied = 0, error = 0;

	BUG_ON(!mapping->a_ops->get_xip_mem);

	pos = *ppos;
	index = pos >> PAGE_CACHE_SHIFT;
	offset = pos & ~PAGE_CACHE_MASK;

	isize = i_size_read(inode);
	if (!isize)
		goto out;

	end_index = (isize - 1) >> PAGE_CACHE_SHIFT;
	do {
		unsigned long nr, left;
		void *xip_mem;
		unsigned long xip_pfn;
		int zero = 0;

		/* nr is the maximum number of bytes to copy from this page */
		nr = PAGE_CACHE_SIZE;
		if (index >= end_index) {
			if (index > end_index)
				goto out;
			nr = ((isize - 1) & ~PAGE_CACHE_MASK) + 1;
			if (nr <= offset) {
				goto out;
			}
		}
		nr = nr - offset;
		if (nr > len - copied)
			nr = len - copied;

		error = mapping->a_ops->get_xip_mem(mapping, index, 0,
							&xip_mem, &xip_pfn);
		if (unlikely(error)) {
			if (error == -ENODATA) {
				/* sparse */
				zero = 1;
			} else
				goto out;
		}

		/* If users can be writing to this page using arbitrary
		 * virtual addresses, take care about potential aliasing
		 * before reading the page on the kernel side.
		 */
		if (mapping_writably_mapped(mapping))
			/* address based flush */ ;

		/*
		 * Ok, we have the mem, so now we can copy it to user space...
		 *
		 * The actor routine returns how many bytes were actually used..
		 * NOTE! This may not be the same as how much of a user buffer
		 * we filled up (we may be padding etc), so we can only update
		 * "pos" here (the actor routine has to update the user buffer
		 * pointers and the remaining count).
		 */
		if (!zero)
			left = __copy_to_user(buf+copied, xip_mem+offset, nr);
		else
			left = __clear_user(buf + copied, nr);

		if (left) {
			error = -EFAULT;
			goto out;
		}

		copied += (nr - left);
		offset += (nr - left);
		index += offset >> PAGE_CACHE_SHIFT;
		offset &= ~PAGE_CACHE_MASK;
	} while (copied < len);

out:
	*ppos = pos + copied;
	if (filp)
		file_accessed(filp);

	return (copied ? copied : error);
}

ssize_t
xip_file_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
	if (!access_ok(VERIFY_WRITE, buf, len))
		return -EFAULT;

	return do_xip_mapping_read(filp->f_mapping, &filp->f_ra, filp,
			    buf, len, ppos);
}
EXPORT_SYMBOL_GPL(xip_file_read);

/*
 * __xip_unmap is invoked from xip_unmap and
 * xip_write
 *
 * This function walks all vmas of the address_space and unmaps the
 * __xip_sparse_page when found at pgoff.
 */
static void
__xip_unmap (struct address_space * mapping,
		     unsigned long pgoff)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	unsigned long address;
	pte_t *pte;
	pte_t pteval;
	spinlock_t *ptl;
	struct page *page;
	unsigned count;
	int locked = 0;

	count = read_seqcount_begin(&xip_sparse_seq);

	page = __xip_sparse_page;
	if (!page)
		return;

retry:
	mutex_lock(&mapping->i_mmap_mutex);
	vma_interval_tree_foreach(vma, &mapping->i_mmap, pgoff, pgoff) {
		mm = vma->vm_mm;
		address = vma->vm_start +
			((pgoff - vma->vm_pgoff) << PAGE_SHIFT);
		BUG_ON(address < vma->vm_start || address >= vma->vm_end);
		pte = page_check_address(page, mm, address, &ptl, 1);
		if (pte) {
			/* Nuke the page table entry. */
			flush_cache_page(vma, address, pte_pfn(*pte));
			pteval = ptep_clear_flush(vma, address, pte);
			page_remove_rmap(page);
			dec_mm_counter(mm, MM_FILEPAGES);
			BUG_ON(pte_dirty(pteval));
			pte_unmap_unlock(pte, ptl);
			/* must invalidate_page _before_ freeing the page */
			mmu_notifier_invalidate_page(mm, address);
			page_cache_release(page);
		}
	}
	mutex_unlock(&mapping->i_mmap_mutex);

	if (locked) {
		mutex_unlock(&xip_sparse_mutex);
	} else if (read_seqcount_retry(&xip_sparse_seq, count)) {
		mutex_lock(&xip_sparse_mutex);
		locked = 1;
		goto retry;
	}
}

/*
 * xip_fault() is invoked via the vma operations vector for a
 * mapped memory region to read in file data during a page fault.
 *
 * This function is derived from filemap_fault, but used for execute in place
 */
//struct page *pram_page_old = NULL;
//struct page *pram_page_new = NULL;
//char *pram_xip_mem;
struct page *pram_page_prev = NULL;
int xip_file_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct file *file = vma->vm_file;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	pgoff_t size;
	void *xip_mem;
	unsigned long xip_pfn;
	struct page *page;
	int error;
	struct page *pram_page_old = NULL;
	//if (vma->vm_ops->page_mkwrite == pram_xip_mkwrite){
	//		printk(KERN_DEBUG "filemap_xip_fault;01\n");
	//}

	/* XXX: are VM_FAULT_ codes OK? */
again:
	size = (i_size_read(inode) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	if (vmf->pgoff >= size)
		return VM_FAULT_SIGBUS;

	error = mapping->a_ops->get_xip_mem(mapping, vmf->pgoff, 0,
						&xip_mem, &xip_pfn);

	if (likely(!error)){
		//if (vma->vm_ops->page_mkwrite == pram_xip_mkwrite){
		//	printk(KERN_DEBUG "filemap_xip_fault;02\n");
		//}
		goto found;
	}
	if (error != -ENODATA){
		//if (vma->vm_ops->page_mkwrite == pram_xip_mkwrite){
		//	printk(KERN_DEBUG "filemap_xip_fault;03\n");
		//}
		return VM_FAULT_OOM;
	}

	/* sparse block */
	if ((vma->vm_flags & (VM_WRITE | VM_MAYWRITE)) &&
	    (vma->vm_flags & (VM_SHARED | VM_MAYSHARE)) &&
	    (!(mapping->host->i_sb->s_flags & MS_RDONLY))) {

		//if (vma->vm_ops->page_mkwrite == pram_xip_mkwrite){
		//	printk(KERN_DEBUG "filemap_xip_fault;04\n");
		//}

		int err;

		/* maybe shared writable, allocate new block */
		mutex_lock(&xip_sparse_mutex);
		error = mapping->a_ops->get_xip_mem(mapping, vmf->pgoff, 1,
							&xip_mem, &xip_pfn);
		mutex_unlock(&xip_sparse_mutex);
		if (error)
			return VM_FAULT_SIGBUS;
		/* unmap sparse mappings at pgoff from all other vmas */
		__xip_unmap(mapping, vmf->pgoff);

found:

		if ((vma->vm_ops->page_mkwrite == pram_xip_mkwrite) && (pram_flags & PRAM_COW)){
			//printk(KERN_DEBUG "filemap_xip_fault;05\n");
			
			pram_page_old = pfn_to_page(xip_pfn);
			if (!pram_page_old){
				printk(KERN_DEBUG "p_er;02\n");
				//goto pram_oom;
			}

			printk(KERN_DEBUG "xip_pfn = %lx\n",xip_pfn);
			pte_t entry_old, entry_new;
			entry_old = mk_pte(pram_page_old, vma->vm_page_prot);
			printk(KERN_DEBUG "entry_old = %lx\n",entry_old);
			/*
			int pram_cow_er=0;
			unsigned long pram_cow_xip_pfn;
			void *pram_cow_xip_mem;
			pram_cow_er = pram_cow_alloc_block_mem(mapping, vmf->pgoff,&pram_cow_xip_mem, &pram_cow_xip_pfn);
			if (pram_cow_er != 0)
				printk(KERN_DEBUG "BUG : pram_cow_er\n");
			pram_page_new = pfn_to_page(pram_cow_xip_pfn);

			printk(KERN_DEBUG "p_cow;03\n");
			if (!pram_page_new){
				printk(KERN_DEBUG "p_er;03\n");
				//goto pram_oom;
			}
			*/

			struct page *pram_page_new = NULL;

			//pram_page_new = xip_sparse_page();
			pram_page_new = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, pram_address);
			if (!pram_page_new) {
				printk(KERN_DEBUG "p_er;03\n");
			}
			
			
			char *pram_vfrom, *pram_vto;
			//pram_vfrom = kmap_atomic(pram_page_old);
			pram_vfrom = xip_mem;
			pram_vto = kmap_atomic(pram_page_new);
			printk(KERN_DEBUG "pram_address = %lx\n",pram_address);
			printk(KERN_DEBUG "pram_vfrom = %lx\n",pram_vfrom);
			printk(KERN_DEBUG "pram_vto = %lx\n",pram_vto);
			copy_page(pram_vto, pram_vfrom);
			//printk(KERN_DEBUG "p_cow;05,2\n");
			//kunmap_atomic(pram_vfrom);
			kunmap_atomic(pram_vto);

			//printk(KERN_DEBUG "p_cow;05\n");
			//cow_user_page(pram_page_new, pram_page_old, pram_address, vma);
			
			//printk(KERN_DEBUG "p_cow;07\n");
			__SetPageUptodate(pram_page_new);

			entry_new = mk_pte(pram_page_new, vma->vm_page_prot);
			printk(KERN_DEBUG "entry_new = %lx\n",entry_new);

			if (pram_flags & PRAM_INIT ){
				//printk(KERN_DEBUG "p_cow;05_if(INIT)\n");
				ck_pram_flags();
				pram_flags &= ~PRAM_INIT;
				pram_page_new->pram_prev = NULL;
				pram_page_new->pram_num = 1;
			} else {
				//printk(KERN_DEBUG "p_cow;06_else(notINIT)\n");
				ck_pram_flags();
				pram_page_new->pram_prev = pram_page_prev;
				pram_page_prev->pram_next = pram_page_new;
				pram_page_new->pram_num = pram_page_prev->pram_num + 1;
			}
			pram_page_new->pram_xip_mem = xip_mem;
			pram_page_new->pram_next = NULL;
			pram_page_prev = pram_page_new;

			//printk(KERN_DEBUG "pram_xip_mem = %lx\n",pram_page_prev->pram_xip_mem);
		}

		err = vm_insert_mixed(vma, (unsigned long)vmf->virtual_address,
							xip_pfn);
		if (err == -ENOMEM)
			return VM_FAULT_OOM;
		/*
		 * err == -EBUSY is fine, we've raced against another thread
		 * that faulted-in the same page
		 */
		if (err != -EBUSY)
			BUG_ON(err);
		return VM_FAULT_NOPAGE;
	} else {
		int err, ret = VM_FAULT_OOM;

		mutex_lock(&xip_sparse_mutex);
		write_seqcount_begin(&xip_sparse_seq);
		error = mapping->a_ops->get_xip_mem(mapping, vmf->pgoff, 0,
							&xip_mem, &xip_pfn);
		if (unlikely(!error)) {
			write_seqcount_end(&xip_sparse_seq);
			mutex_unlock(&xip_sparse_mutex);
			goto again;
		}
		if (error != -ENODATA)
			goto out;
		/* not shared and writable, use xip_sparse_page() */
		page = xip_sparse_page();
		if (!page)
			goto out;
		err = vm_insert_page(vma, (unsigned long)vmf->virtual_address,
							page);

		//if (vma->vm_ops->page_mkwrite == pram_xip_mkwrite){
		//	printk(KERN_DEBUG "filemap_xip_fault;06\n");
		//}

		if (err == -ENOMEM)
			goto out;

		ret = VM_FAULT_NOPAGE;
		//if (vma->vm_ops->page_mkwrite == pram_xip_mkwrite){
		//	printk(KERN_DEBUG "filemap_xip_fault;07\n");
		//}
out:
		write_seqcount_end(&xip_sparse_seq);
		mutex_unlock(&xip_sparse_mutex);
		//if (vma->vm_ops->page_mkwrite == pram_xip_mkwrite){
		//	printk(KERN_DEBUG "filemap_xip_fault;08\n");
		//}

		return ret;
	}
}

EXPORT_SYMBOL_GPL(xip_file_fault);
static const struct vm_operations_struct xip_file_vm_ops = {
	.fault	= xip_file_fault,
	.page_mkwrite	= filemap_page_mkwrite,
	.remap_pages = generic_file_remap_pages,
};

int xip_file_mmap(struct file * file, struct vm_area_struct * vma)
{
	BUG_ON(!file->f_mapping->a_ops->get_xip_mem);

	file_accessed(file);
	vma->vm_ops = &xip_file_vm_ops;
	vma->vm_flags |= VM_MIXEDMAP;
	return 0;
}
EXPORT_SYMBOL_GPL(xip_file_mmap);

static ssize_t
__xip_file_write(struct file *filp, const char __user *buf,
		  size_t count, loff_t pos, loff_t *ppos)
{
	struct address_space * mapping = filp->f_mapping;
	const struct address_space_operations *a_ops = mapping->a_ops;
	struct inode 	*inode = mapping->host;
	long		status = 0;
	size_t		bytes;
	ssize_t		written = 0;

	BUG_ON(!mapping->a_ops->get_xip_mem);

	do {
		unsigned long index;
		unsigned long offset;
		size_t copied;
		void *xip_mem;
		unsigned long xip_pfn;

		offset = (pos & (PAGE_CACHE_SIZE -1)); /* Within page */
		index = pos >> PAGE_CACHE_SHIFT;
		bytes = PAGE_CACHE_SIZE - offset;
		if (bytes > count)
			bytes = count;

		status = a_ops->get_xip_mem(mapping, index, 0,
						&xip_mem, &xip_pfn);
		if (status == -ENODATA) {
			/* we allocate a new page unmap it */
			mutex_lock(&xip_sparse_mutex);
			status = a_ops->get_xip_mem(mapping, index, 1,
							&xip_mem, &xip_pfn);
			mutex_unlock(&xip_sparse_mutex);
			if (!status)
				/* unmap page at pgoff from all other vmas */
				__xip_unmap(mapping, index);
		}

		if (status)
			break;

		copied = bytes -
			__copy_from_user_nocache(xip_mem + offset, buf, bytes);

		if (likely(copied > 0)) {
			status = copied;

			if (status >= 0) {
				written += status;
				count -= status;
				pos += status;
				buf += status;
			}
		}
		if (unlikely(copied != bytes))
			if (status >= 0)
				status = -EFAULT;
		if (status < 0)
			break;
	} while (count);
	*ppos = pos;
	/*
	 * No need to use i_size_read() here, the i_size
	 * cannot change under us because we hold i_mutex.
	 */
	if (pos > inode->i_size) {
		i_size_write(inode, pos);
		mark_inode_dirty(inode);
	}

	return written ? written : status;
}

ssize_t
xip_file_write(struct file *filp, const char __user *buf, size_t len,
	       loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	size_t count;
	loff_t pos;
	ssize_t ret;

	mutex_lock(&inode->i_mutex);

	if (!access_ok(VERIFY_READ, buf, len)) {
		ret=-EFAULT;
		goto out_up;
	}

	pos = *ppos;
	count = len;

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = mapping->backing_dev_info;

	ret = generic_write_checks(filp, &pos, &count, S_ISBLK(inode->i_mode));
	if (ret)
		goto out_backing;
	if (count == 0)
		goto out_backing;

	ret = file_remove_suid(filp);
	if (ret)
		goto out_backing;

	ret = file_update_time(filp);
	if (ret)
		goto out_backing;

	ret = __xip_file_write (filp, buf, count, pos, ppos);

 out_backing:
	current->backing_dev_info = NULL;
 out_up:
	mutex_unlock(&inode->i_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(xip_file_write);

/*
 * truncate a page used for execute in place
 * functionality is analog to block_truncate_page but does use get_xip_mem
 * to get the page instead of page cache
 */
int
xip_truncate_page(struct address_space *mapping, loff_t from)
{
	pgoff_t index = from >> PAGE_CACHE_SHIFT;
	unsigned offset = from & (PAGE_CACHE_SIZE-1);
	unsigned blocksize;
	unsigned length;
	void *xip_mem;
	unsigned long xip_pfn;
	int err;

	BUG_ON(!mapping->a_ops->get_xip_mem);

	blocksize = 1 << mapping->host->i_blkbits;
	length = offset & (blocksize - 1);

	/* Block boundary? Nothing to do */
	if (!length)
		return 0;

	length = blocksize - length;

	err = mapping->a_ops->get_xip_mem(mapping, index, 0,
						&xip_mem, &xip_pfn);
	if (unlikely(err)) {
		if (err == -ENODATA)
			/* Hole? No need to truncate */
			return 0;
		else
			return err;
	}
	memset(xip_mem + offset, 0, length);
	return 0;
}
EXPORT_SYMBOL_GPL(xip_truncate_page);

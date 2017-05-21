/*
 *  linux/fs/ext2/dir.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/dir.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext2 directory handling functions
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *
 * All code that works with directory layout had been switched to pagecache
 * and moved here. AV
 */

#include "ext2.h"
#include <linux/buffer_head.h>
#include <linux/pagemap.h>
#include <linux/swap.h>

typedef struct ext2_dir_entry_2 ext2_dirent;

static inline unsigned ext2_rec_len_from_disk(__le16 dlen)
{
	unsigned len = le16_to_cpu(dlen);

	if (len == EXT2_MAX_REC_LEN)
		return 1 << 16;
	return len;
}

static inline __le16 ext2_rec_len_to_disk(unsigned len)
{
	if (len == (1 << 16))
		return cpu_to_le16(EXT2_MAX_REC_LEN);
	else
		BUG_ON(len > (1 << 16));
	return cpu_to_le16(len);
}

/*
 * ext2 uses block-sized chunks. Arguably, sector-sized ones would be
 * more robust, but we have what we have
 */
static inline unsigned ext2_chunk_size(struct inode *inode)
{
	return inode->i_sb->s_blocksize;
}

static inline void ext2_put_page(struct page *page)
{
	kunmap(page);
	page_cache_release(page);
}

static inline unsigned long dir_pages(struct inode *inode)
{
	return (inode->i_size+PAGE_CACHE_SIZE-1)>>PAGE_CACHE_SHIFT;
}

/*
 * Return the offset into page `page_nr' of the last valid
 * byte in that page, plus one.
 */
static unsigned
ext2_last_byte(struct inode *inode, unsigned long page_nr)
{
	unsigned last_byte = inode->i_size;
/*//page_nr为inode对应的dentry的目录项ext2_dentry_2所在那个页面在内存中的页面偏移量  假设是10吧
//page_nr<<12 =page_nr*4096  得到*/
	last_byte -= page_nr << PAGE_CACHE_SHIFT;
	if (last_byte > PAGE_CACHE_SIZE)
		last_byte = PAGE_CACHE_SIZE;
	return last_byte;
}

static int ext2_commit_chunk(struct page *page, loff_t pos, unsigned len)
{
	struct address_space *mapping = page->mapping;
	struct inode *dir = mapping->host;
	int err = 0;

	dir->i_version++;
	block_write_end(NULL, mapping, pos, len, len, page, NULL);

	if (pos+len > dir->i_size) {
		i_size_write(dir, pos+len);
		mark_inode_dirty(dir);
	}

	if (IS_DIRSYNC(dir)) {
		err = write_one_page(page, 1);
		if (!err)
			err = ext2_sync_inode(dir);
	} else {
		unlock_page(page);
	}

	return err;
}

static void ext2_check_page(struct page *page, int quiet)
{
	struct inode *dir = page->mapping->host;
	struct super_block *sb = dir->i_sb;
	unsigned chunk_size = ext2_chunk_size(dir);
	char *kaddr = page_address(page);
	u32 max_inumber = le32_to_cpu(EXT2_SB(sb)->s_es->s_inodes_count);
	unsigned offs, rec_len;
	unsigned limit = PAGE_CACHE_SIZE;
	ext2_dirent *p;
	char *error;

	if ((dir->i_size >> PAGE_CACHE_SHIFT) == page->index) {
		limit = dir->i_size & ~PAGE_CACHE_MASK;
		if (limit & (chunk_size - 1))
			goto Ebadsize;
		if (!limit)
			goto out;
	}
	for (offs = 0; offs <= limit - EXT2_DIR_REC_LEN(1); offs += rec_len) {
		p = (ext2_dirent *)(kaddr + offs);
		rec_len = ext2_rec_len_from_disk(p->rec_len);

		if (rec_len < EXT2_DIR_REC_LEN(1))
			goto Eshort;
		if (rec_len & 3)
			goto Ealign;
		if (rec_len < EXT2_DIR_REC_LEN(p->name_len))
			goto Enamelen;
		if (((offs + rec_len - 1) ^ offs) & ~(chunk_size-1))
			goto Espan;
		if (le32_to_cpu(p->inode) > max_inumber)
			goto Einumber;
	}
	if (offs != limit)
		goto Eend;
out:
	SetPageChecked(page);
	return;

	/* Too bad, we had an error */

Ebadsize:
	if (!quiet)
		ext2_error(sb, __func__,
			"size of directory #%lu is not a multiple "
			"of chunk size", dir->i_ino);
	goto fail;
Eshort:
	error = "rec_len is smaller than minimal";
	goto bad_entry;
Ealign:
	error = "unaligned directory entry";
	goto bad_entry;
Enamelen:
	error = "rec_len is too small for name_len";
	goto bad_entry;
Espan:
	error = "directory entry across blocks";
	goto bad_entry;
Einumber:
	error = "inode out of bounds";
bad_entry:
	if (!quiet)
		ext2_error(sb, __func__, "bad entry in directory #%lu: : %s - "
			"offset=%lu, inode=%lu, rec_len=%d, name_len=%d",
			dir->i_ino, error, (page->index<<PAGE_CACHE_SHIFT)+offs,
			(unsigned long) le32_to_cpu(p->inode),
			rec_len, p->name_len);
	goto fail;
Eend:
	if (!quiet) {
		p = (ext2_dirent *)(kaddr + offs);
		ext2_error(sb, "ext2_check_page",
			"entry in directory #%lu spans the page boundary"
			"offset=%lu, inode=%lu",
			dir->i_ino, (page->index<<PAGE_CACHE_SHIFT)+offs,
			(unsigned long) le32_to_cpu(p->inode));
	}
fail:
	SetPageChecked(page);
	SetPageError(page);
}

static struct page * ext2_get_page(struct inode *dir, unsigned long n,
				   int quiet)
{
	struct address_space *mapping = dir->i_mapping;
	struct page *page = read_mapping_page(mapping, n, NULL);
	if (!IS_ERR(page)) {
		kmap(page);
		if (!PageChecked(page))
			ext2_check_page(page, quiet);
		if (PageError(page))
			goto fail;
	}
	return page;

fail:
	ext2_put_page(page);
	return ERR_PTR(-EIO);
}

/*
 * NOTE! unlike strncmp, ext2_match returns 1 for success, 0 for failure.
 *
 * len <= EXT2_NAME_LEN and de != NULL are guaranteed by caller.
 */
 //比较两个字符串 相等时 返回1
static inline int ext2_match (int len, const char * const name,
					struct ext2_dir_entry_2 * de)
{
	if (len != de->name_len)//长度不等直接返回0 
		return 0;
	if (!de->inode)//索引节点号为0直接返回0
		return 0;
	return !memcmp(name, de->name, len);//比较字符串 相等时返回0
}

/*
 * p is at least 6 bytes before the end of page
 */
static inline ext2_dirent *ext2_next_entry(ext2_dirent *p)
{
	return (ext2_dirent *)((char *)p +
			ext2_rec_len_from_disk(p->rec_len));
}

static inline unsigned 
ext2_validate_entry(char *base, unsigned offset, unsigned mask)
{
	ext2_dirent *de = (ext2_dirent*)(base + offset);
	ext2_dirent *p = (ext2_dirent*)(base + (offset&mask));
	while ((char*)p < (char*)de) {
		if (p->rec_len == 0)
			break;
		p = ext2_next_entry(p);
	}
	return (char *)p - base;
}

static unsigned char ext2_filetype_table[EXT2_FT_MAX] = {
	[EXT2_FT_UNKNOWN]	= DT_UNKNOWN,
	[EXT2_FT_REG_FILE]	= DT_REG,
	[EXT2_FT_DIR]		= DT_DIR,
	[EXT2_FT_CHRDEV]	= DT_CHR,
	[EXT2_FT_BLKDEV]	= DT_BLK,
	[EXT2_FT_FIFO]		= DT_FIFO,
	[EXT2_FT_SOCK]		= DT_SOCK,
	[EXT2_FT_SYMLINK]	= DT_LNK,
};

#define S_SHIFT 12
static unsigned char ext2_type_by_mode[S_IFMT >> S_SHIFT] = {
	[S_IFREG >> S_SHIFT]	= EXT2_FT_REG_FILE,
	[S_IFDIR >> S_SHIFT]	= EXT2_FT_DIR,
	[S_IFCHR >> S_SHIFT]	= EXT2_FT_CHRDEV,
	[S_IFBLK >> S_SHIFT]	= EXT2_FT_BLKDEV,
	[S_IFIFO >> S_SHIFT]	= EXT2_FT_FIFO,
	[S_IFSOCK >> S_SHIFT]	= EXT2_FT_SOCK,
	[S_IFLNK >> S_SHIFT]	= EXT2_FT_SYMLINK,
};

static inline void ext2_set_de_type(ext2_dirent *de, struct inode *inode)
{
	mode_t mode = inode->i_mode;
	if (EXT2_HAS_INCOMPAT_FEATURE(inode->i_sb, EXT2_FEATURE_INCOMPAT_FILETYPE))
		de->file_type = ext2_type_by_mode[(mode & S_IFMT)>>S_SHIFT];
	else
		de->file_type = 0;
}

static int
ext2_readdir (struct file * filp, void * dirent, filldir_t filldir)
{
	loff_t pos = filp->f_pos;
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	unsigned int offset = pos & ~PAGE_CACHE_MASK;
	unsigned long n = pos >> PAGE_CACHE_SHIFT;
	unsigned long npages = dir_pages(inode);
	unsigned chunk_mask = ~(ext2_chunk_size(inode)-1);
	unsigned char *types = NULL;
	int need_revalidate = filp->f_version != inode->i_version;

	if (pos > inode->i_size - EXT2_DIR_REC_LEN(1))
		return 0;

	if (EXT2_HAS_INCOMPAT_FEATURE(sb, EXT2_FEATURE_INCOMPAT_FILETYPE))
		types = ext2_filetype_table;

	for ( ; n < npages; n++, offset = 0) {
		char *kaddr, *limit;
		ext2_dirent *de;
		struct page *page = ext2_get_page(inode, n, 0);

		if (IS_ERR(page)) {
			ext2_error(sb, __func__,
				   "bad page in #%lu",
				   inode->i_ino);
			filp->f_pos += PAGE_CACHE_SIZE - offset;
			return PTR_ERR(page);
		}
		kaddr = page_address(page);
		if (unlikely(need_revalidate)) {
			if (offset) {
				offset = ext2_validate_entry(kaddr, offset, chunk_mask);
				filp->f_pos = (n<<PAGE_CACHE_SHIFT) + offset;
			}
			filp->f_version = inode->i_version;
			need_revalidate = 0;
		}
		de = (ext2_dirent *)(kaddr+offset);
		limit = kaddr + ext2_last_byte(inode, n) - EXT2_DIR_REC_LEN(1);
		for ( ;(char*)de <= limit; de = ext2_next_entry(de)) {
			if (de->rec_len == 0) {
				ext2_error(sb, __func__,
					"zero-length directory entry");
				ext2_put_page(page);
				return -EIO;
			}
			if (de->inode) {
				int over;
				unsigned char d_type = DT_UNKNOWN;

				if (types && de->file_type < EXT2_FT_MAX)
					d_type = types[de->file_type];

				offset = (char *)de - kaddr;
				over = filldir(dirent, de->name, de->name_len,
						(n<<PAGE_CACHE_SHIFT) | offset,
						le32_to_cpu(de->inode), d_type);
				if (over) {
					ext2_put_page(page);
					return 0;
				}
			}
			filp->f_pos += ext2_rec_len_from_disk(de->rec_len);
		}
		ext2_put_page(page);
	}
	return 0;
}

/*
 *	ext2_find_entry()
 *
 * finds an entry in the specified directory with the wanted name. It
 * returns the page in which the entry was found, and the entry itself
 * (as a parameter - res_dir). Page is returned mapped and unlocked.
 * Entry is guaranteed to be valid.
 */
 //该函数返回0就是没找到child的目录项  该函数还没弄清
 //在页高速中获得父目录的目录项页面查找目录项看能否找到一个和我们要找的目录项匹配的ext2_dir_2目录项 
struct ext2_dir_entry_2 *ext2_find_entry (struct inode * dir,
			struct qstr *child, struct page ** res_page)
{
	const char *name = child->name;//文件名
	int namelen = child->len;//文件名长度
	unsigned reclen = EXT2_DIR_REC_LEN(namelen);//目录项长度
	unsigned long start, n;
	unsigned long npages = dir_pages(dir);//以字节为单位的文件大小，转换为物理页面数
	struct page *page = NULL;
	struct ext2_inode_info *ei = EXT2_I(dir);
	ext2_dirent * de;
	int dir_has_error = 0;

	if (npages == 0)
		goto out;

	/* OFFSET_CACHE */
	*res_page = NULL;

	start = ei->i_dir_start_lookup;//dir目录项在内存的起始位置(好像是page为单位的)
	if (start >= npages)
		start = 0;
	n = start;
	do {
		char *kaddr;
		page = ext2_get_page(dir, n, dir_has_error);//从页高速缓存中获得dir目录项所在的页面
		if (!IS_ERR(page)) {
			kaddr = page_address(page);//或的页面所对应的内核虚拟 地址
			de = (ext2_dirent *) kaddr;//获得目录项结构的起始地址
			kaddr += ext2_last_byte(dir, n) - reclen;
			//该循环是遍寻一个页面里面的目录项，看是否能找到与形参name匹配的目录项 不能的话继续往下执行
			while ((char *) de <= kaddr) {
				if (de->rec_len == 0) {
					ext2_error(dir->i_sb, __func__,
						"zero-length directory entry");
					ext2_put_page(page);
					goto out;
				}
				if (ext2_match (namelen, name, de))//如果匹配的话，则将namelen长度的name赋值到de->name中
					goto found;
				de = ext2_next_entry(de);//不匹配的话则跳到下一个目录项 
			}
			ext2_put_page(page);//一个页面内找不到则释放这个page
		} else
			dir_has_error = 1;

		if (++n >= npages)//n不能超过dir的文件大小(其实都转换成页面了)
			n = 0;
		/* next page is past the blocks we've got */
		if (unlikely(n > (dir->i_blocks >> (PAGE_CACHE_SHIFT - 9)))) {
			ext2_error(dir->i_sb, __func__,
				"dir %lu size %lld exceeds block count %llu",
				dir->i_ino, dir->i_size,
				(unsigned long long)dir->i_blocks);
			goto out;
		}
	} while (n != start);
out:
	return NULL;

found:
	*res_page = page;
	ei->i_dir_start_lookup = n;//file.doc的ext2_dir_2所在的页面
	return de;
}

struct ext2_dir_entry_2 * ext2_dotdot (struct inode *dir, struct page **p)
{
	struct page *page = ext2_get_page(dir, 0, 0);
	ext2_dirent *de = NULL;

	if (!IS_ERR(page)) {
		de = ext2_next_entry((ext2_dirent *) page_address(page));
		*p = page;
	}
	return de;
}
////在页高速缓存父目录的目录项中 查找child的目录项，找不到返回0
//找到则返回child的目录项对应的ino号
ino_t ext2_inode_by_name(struct inode *dir, struct qstr *child)
{
	ino_t res = 0;
	struct ext2_dir_entry_2 *de;
	struct page *page;
	
	de = ext2_find_entry (dir, child, &page);//在页高速缓存父目录的目录项中 查找child的目录项，找不到返回0
	if (de) {
		res = le32_to_cpu(de->inode);
		ext2_put_page(page);
	}
	return res;
}

/* Releases the page */
void ext2_set_link(struct inode *dir, struct ext2_dir_entry_2 *de,
		   struct page *page, struct inode *inode, int update_times)
{
	loff_t pos = page_offset(page) +
			(char *) de - (char *) page_address(page);
	unsigned len = ext2_rec_len_from_disk(de->rec_len);
	int err;

	lock_page(page);
	err = __ext2_write_begin(NULL, page->mapping, pos, len,
				AOP_FLAG_UNINTERRUPTIBLE, &page, NULL);
	BUG_ON(err);
	de->inode = cpu_to_le32(inode->i_ino);
	ext2_set_de_type(de, inode);
	err = ext2_commit_chunk(page, pos, len);
	ext2_put_page(page);
	if (update_times)
		dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
	EXT2_I(dir)->i_flags &= ~EXT2_BTREE_FL;
	mark_inode_dirty(dir);
}

/*
 *	Parent is locked.
 */
 //dentry是内存中新建的file.doc的dentry inode是内存中file.doc新建的 
 //该函数似乎是在页高速缓存中file.doc的父目录phf的目录项中找到一个空闲可用的ext2_dir_dentry_2
 //然后将file.doc的名字啊长度的等等之类的信息填充到该结构中
 //最后没看了。。。
int ext2_add_link (struct dentry *dentry, struct inode *inode)
{
	struct inode *dir = dentry->d_parent->d_inode;
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	unsigned chunk_size = ext2_chunk_size(dir);//块大小
	unsigned reclen = EXT2_DIR_REC_LEN(namelen);//目录项大小
	unsigned short rec_len, name_len;
	struct page *page = NULL;
	ext2_dirent * de;
	unsigned long npages = dir_pages(dir);//父目录phf的大小 换算成页
	unsigned long n;
	char *kaddr;
	loff_t pos;
	int err;

	/*
	 * We take care of directory expansion in the same loop.
	 * This code plays outside i_size, so it locks the page
	 * to protect that region.
	 */
	for (n = 0; n <= npages; n++) {
		char *dir_end;

		page = ext2_get_page(dir, n, 0);
		err = PTR_ERR(page);
		if (IS_ERR(page))
			goto out;
		lock_page(page);
		kaddr = page_address(page);
		dir_end = kaddr + ext2_last_byte(dir, n);
		de = (ext2_dirent *)kaddr;
		kaddr += PAGE_CACHE_SIZE - reclen;
		while ((char *)de <= kaddr) {
			if ((char *)de == dir_end) {
				/* We hit i_size */
				name_len = 0;
				rec_len = chunk_size;
				de->rec_len = ext2_rec_len_to_disk(chunk_size);
				de->inode = 0;
				goto got_it;
			}
			if (de->rec_len == 0) {
				ext2_error(dir->i_sb, __func__,
					"zero-length directory entry");
				err = -EIO;
				goto out_unlock;
			}
			err = -EEXIST;
			if (ext2_match (namelen, name, de))//比较name和de->name是否匹配，匹配返回1(其实是看是否含有同名的文件)
				goto out_unlock;
			name_len = EXT2_DIR_REC_LEN(de->name_len);//获取该目录项长度
			rec_len = ext2_rec_len_from_disk(de->rec_len);
			if (!de->inode && rec_len >= reclen)//如果该目录项的inode为null 且 该目录项长度大于形参 目录项长度
				goto got_it;//表示目录中的词节点已经被删除而且因为rec_len>=reclen。所以表示该目录项有足够的长度存储形参的目录项
			if (rec_len >= name_len + reclen)//这种也是说它后面有节点的 目录项被删除了
				goto got_it;
			de = (ext2_dirent *) ((char *) de + rec_len);//如果还没找到空闲可用的目录项则跳到下个目录项中
		}
		unlock_page(page);
		ext2_put_page(page);
	}
	BUG();
	return -EINVAL;

got_it:
	pos = page_offset(page) +
		(char*)de - (char*)page_address(page);//该目录项在该文件中的偏移量
	err = __ext2_write_begin(NULL, page->mapping, pos, rec_len, 0,
							&page, NULL);
	if (err)
		goto out_unlock;
	if (de->inode) {//inode不为0 意思是该节点应该是被删除了
		ext2_dirent *de1 = (ext2_dirent *) ((char *) de + name_len);
		de1->rec_len = ext2_rec_len_to_disk(rec_len - name_len);
		de->rec_len = ext2_rec_len_to_disk(name_len);
		de = de1;
	}
	//获取得到空闲的dentry之后初始化该dentry的各种值
	de->name_len = namelen;//长度
	memcpy(de->name, name, namelen);//名字
	de->inode = cpu_to_le32(inode->i_ino);//
	ext2_set_de_type (de, inode);
	err = ext2_commit_chunk(page, pos, rec_len);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
	EXT2_I(dir)->i_flags &= ~EXT2_BTREE_FL;
	mark_inode_dirty(dir);
	/* OFFSET_CACHE */
out_put:
	ext2_put_page(page);
out:
	return err;
out_unlock:
	unlock_page(page);
	goto out_put;
}

/*
 * ext2_delete_entry deletes a directory entry by merging it with the
 * previous entry. Page is up-to-date. Releases the page.
 */
int ext2_delete_entry (struct ext2_dir_entry_2 * dir, struct page * page )
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;
	char *kaddr = page_address(page);
	unsigned from = ((char*)dir - kaddr) & ~(ext2_chunk_size(inode)-1);//取得目录项在该page中的偏移量
	unsigned to = ((char *)dir - kaddr) +
				ext2_rec_len_from_disk(dir->rec_len);//该目录项
	loff_t pos;
	ext2_dirent * pde = NULL;
	ext2_dirent * de = (ext2_dirent *) (kaddr + from);//该目录项的虚拟地址
	int err;

	while ((char*)de < (char*)dir) {
		if (de->rec_len == 0) {
			ext2_error(inode->i_sb, __func__,
				"zero-length directory entry");
			err = -EIO;
			goto out;
		}
		pde = de;
		de = ext2_next_entry(de);
	}
	if (pde)
		from = (char*)pde - (char*)page_address(page);
	pos = page_offset(page) + from;
	lock_page(page);
	err = __ext2_write_begin(NULL, page->mapping, pos, to - from, 0,
							&page, NULL);
	BUG_ON(err);
	if (pde)
		pde->rec_len = ext2_rec_len_to_disk(to - from);
	dir->inode = 0;
	err = ext2_commit_chunk(page, pos, to - from);
	inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;
	EXT2_I(inode)->i_flags &= ~EXT2_BTREE_FL;
	mark_inode_dirty(inode);
out:
	ext2_put_page(page);
	return err;
}

/*
 * Set the first fragment of directory.
 */
int ext2_make_empty(struct inode *inode, struct inode *parent)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page = grab_cache_page(mapping, 0);
	unsigned chunk_size = ext2_chunk_size(inode);
	struct ext2_dir_entry_2 * de;
	int err;
	void *kaddr;

	if (!page)
		return -ENOMEM;

	err = __ext2_write_begin(NULL, page->mapping, 0, chunk_size, 0,
							&page, NULL);
	if (err) {
		unlock_page(page);
		goto fail;
	}
	kaddr = kmap_atomic(page, KM_USER0);
	memset(kaddr, 0, chunk_size);
	de = (struct ext2_dir_entry_2 *)kaddr;
	de->name_len = 1;
	de->rec_len = ext2_rec_len_to_disk(EXT2_DIR_REC_LEN(1));
	memcpy (de->name, ".\0\0", 4);
	de->inode = cpu_to_le32(inode->i_ino);
	ext2_set_de_type (de, inode);

	de = (struct ext2_dir_entry_2 *)(kaddr + EXT2_DIR_REC_LEN(1));
	de->name_len = 2;
	de->rec_len = ext2_rec_len_to_disk(chunk_size - EXT2_DIR_REC_LEN(1));
	de->inode = cpu_to_le32(parent->i_ino);
	memcpy (de->name, "..\0", 4);
	ext2_set_de_type (de, inode);
	kunmap_atomic(kaddr, KM_USER0);
	err = ext2_commit_chunk(page, 0, chunk_size);
fail:
	page_cache_release(page);
	return err;
}

/*
 * routine to check that the specified directory is empty (for rmdir)
 */
int ext2_empty_dir (struct inode * inode)
{
	struct page *page = NULL;
	unsigned long i, npages = dir_pages(inode);
	int dir_has_error = 0;

	for (i = 0; i < npages; i++) {
		char *kaddr;
		ext2_dirent * de;
		page = ext2_get_page(inode, i, dir_has_error);

		if (IS_ERR(page)) {
			dir_has_error = 1;
			continue;
		}

		kaddr = page_address(page);
		de = (ext2_dirent *)kaddr;
		kaddr += ext2_last_byte(inode, i) - EXT2_DIR_REC_LEN(1);

		while ((char *)de <= kaddr) {
			if (de->rec_len == 0) {
				ext2_error(inode->i_sb, __func__,
					"zero-length directory entry");
				printk("kaddr=%p, de=%p\n", kaddr, de);
				goto not_empty;
			}
			if (de->inode != 0) {
				/* check for . and .. */
				if (de->name[0] != '.')
					goto not_empty;
				if (de->name_len > 2)
					goto not_empty;
				if (de->name_len < 2) {
					if (de->inode !=
					    cpu_to_le32(inode->i_ino))
						goto not_empty;
				} else if (de->name[1] != '.')
					goto not_empty;
			}
			de = ext2_next_entry(de);
		}
		ext2_put_page(page);
	}
	return 1;

not_empty:
	ext2_put_page(page);
	return 0;
}

const struct file_operations ext2_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= ext2_readdir,
	.unlocked_ioctl = ext2_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ext2_compat_ioctl,
#endif
	.fsync		= simple_fsync,
};

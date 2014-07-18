/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 * SECNFS methods for handles
 */

#include "secnfs.h"
#include "fsal_handle_syscalls.h"

/* TODO replace this with something like 'struct secnfs_export'. */
struct next_ops {
	struct export_ops *exp_ops;	/*< Vector of operations */
	struct fsal_obj_ops *obj_ops;	/*< Shared handle methods vector */
	struct fsal_ds_ops *ds_ops;	/*< Shared handle methods vector */
	struct fsal_up_vector *up_ops;	/*< Upcall operations */
};

#define SECNFS_ERR(fmt, args...) LogCrit(COMPONENT_FSAL, "=secnfs=" fmt, ## args)
#define SECNFS_I(fmt, args...) LogInfo(COMPONENT_FSAL, "=secnfs=" fmt, ## args)
#define SECNFS_D(fmt, args...) LogDebug(COMPONENT_FSAL, "=secnfs=" fmt, ## args)
#define SECNFS_F(fmt, args...) LogFullDebug(COMPONENT_FSAL, "=secnfs=" fmt, ## args)

/*
 * SECNFS internal export
 */
struct secnfs_fsal_export {
	struct fsal_export export;
        struct fsal_export *next_export;
};

/* SECNFS FSAL module private storage */
struct secnfs_fsal_module {
	struct fsal_module fsal;
	struct fsal_staticfsinfo_t fs_info;
	fsal_init_info_t fsal_info;
	secnfs_info_t secnfs_info;
};

fsal_status_t secnfs_lookup_path(struct fsal_export *exp_hdl,
				 const struct req_op_context *opctx,
				 const char *path,
				 struct fsal_obj_handle **handle);

fsal_status_t secnfs_create_handle(struct fsal_export *exp_hdl,
				   const struct req_op_context *opctx,
				   struct gsh_buffdesc *hdl_desc,
				   struct fsal_obj_handle **handle);

/*
 * SECNFS internal object handle
 *
 * KeyFile is kept at the beginning of the data file.
 */
struct secnfs_fsal_obj_handle {
        struct fsal_obj_handle obj_handle;
        struct fsal_obj_handle *next_handle;    /*< handle of next layer */
        secnfs_key_t fk;                        /*< file symmetric key */
        secnfs_key_t iv;                        /*< initialization vector */
        secnfs_info_t *info;                    /*< secnfs info */
        /* NFSv4.2' support for sparse file will help us */
        uint32_t data_offset;                   /*< beginning of data file */
        uint32_t key_initialized;
        uint32_t has_dirty_meta;
        void *range_lock;
        void *holes;
        void *kf_cache;                         /* cached keyfile */
};

static inline struct secnfs_fsal_obj_handle*
secnfs_handle(struct fsal_obj_handle *handle)
{
        return container_of(handle, struct secnfs_fsal_obj_handle, obj_handle);
}

static inline struct secnfs_fsal_export*
secnfs_export(struct fsal_export *export)
{
        return container_of(export, struct secnfs_fsal_export, export);
}

static inline struct secnfs_fsal_module*
secnfs_module(struct fsal_module *fsal)
{
        return container_of(fsal, struct secnfs_fsal_module, fsal);
}

static inline struct fsal_obj_handle* next_handle(struct fsal_obj_handle *hdl)
{
        return secnfs_handle(hdl)->next_handle;
}

static inline struct fsal_export* next_export(struct fsal_export *exp)
{
        return secnfs_export(exp)->next_export;
}

/* TODO move to other header file? */
static inline uint64_t round_up(uint64_t n, uint64_t m)
{
        assert((m & (m - 1)) == 0);
        return (n + m - 1) & ~(m - 1);
}
static inline uint64_t round_down(uint64_t n, uint64_t m)
{
        assert((m & (m - 1)) == 0);
        return n & ~(m - 1);
}
static inline is_aligned(uint64_t n, uint64_t m)
{
        assert((m & (m - 1)) == 0);
        return (n & (m - 1)) == 0;
}
static inline uint64_t pi_round_up(uint64_t n)
{
        return round_up(n, PI_INTERVAL_SIZE);
}
static inline uint64_t pi_round_down(uint64_t n)
{
        return round_down(n, PI_INTERVAL_SIZE);
}

/* get effective filesize */
static inline uint64_t get_filesize(struct secnfs_fsal_obj_handle *hdl)
{
        return hdl->obj_handle.attributes.filesize;
}

/* update effective filesize in handle */
static inline void update_filesize(struct secnfs_fsal_obj_handle *hdl,
                                   uint64_t s)
{
        if (s != hdl->obj_handle.attributes.filesize) {
                hdl->obj_handle.attributes.filesize = s;
                hdl->has_dirty_meta = 1;
        }
}

int secnfs_fsal_open(struct secnfs_fsal_obj_handle *, int, fsal_errors_t *);
int secnfs_fsal_readlink(struct secnfs_fsal_obj_handle *, fsal_errors_t *);

static inline bool secnfs_unopenable_type(object_file_type_t type)
{
	if ((type == SOCKET_FILE) || (type == CHARACTER_FILE)
	    || (type == BLOCK_FILE)) {
		return true;
	} else {
		return false;
	}
}

fsal_status_t read_header(struct fsal_obj_handle *fsal_hdl,
                          const struct req_op_context *opctx);

fsal_status_t write_header(struct fsal_obj_handle *fsal_hdl,
                           const struct req_op_context *opctx);

	/* I/O management */
fsal_status_t secnfs_open(struct fsal_obj_handle * obj_hdl,
			  const struct req_op_context * opctx,
			  fsal_openflags_t openflags);
fsal_openflags_t secnfs_status(struct fsal_obj_handle *obj_hdl);
fsal_status_t secnfs_read(struct fsal_obj_handle *obj_hdl,
			  const struct req_op_context *opctx, uint64_t offset,
			  size_t buffer_size, void *buffer,
			  size_t * read_amount, bool * end_of_file);
fsal_status_t secnfs_write(struct fsal_obj_handle *obj_hdl,
			   const struct req_op_context *opctx, uint64_t offset,
			   size_t buffer_size, void *buffer,
			   size_t * write_amount, bool * fsal_stable);
fsal_status_t secnfs_truncate(struct secnfs_fsal_obj_handle *hdl,
                              const struct req_op_context *opctx,
                              uint64_t newsize);
fsal_status_t secnfs_commit(struct fsal_obj_handle *obj_hdl,	/* sync */
			    off_t offset, size_t len);
fsal_status_t secnfs_lock_op(struct fsal_obj_handle *obj_hdl,
			     const struct req_op_context *opctx, void *p_owner,
			     fsal_lock_op_t lock_op,
			     fsal_lock_param_t * request_lock,
			     fsal_lock_param_t * conflicting_lock);
fsal_status_t secnfs_share_op(struct fsal_obj_handle *obj_hdl, void *p_owner,	/* IN (opaque to FSAL) */
			      fsal_share_param_t request_share);
fsal_status_t secnfs_close(struct fsal_obj_handle *obj_hdl);
fsal_status_t secnfs_lru_cleanup(struct fsal_obj_handle *obj_hdl,
				 lru_actions_t requests);

/* extended attributes management */
fsal_status_t secnfs_list_ext_attrs(struct fsal_obj_handle *obj_hdl,
				    const struct req_op_context *opctx,
				    unsigned int cookie,
				    fsal_xattrent_t * xattrs_tab,
				    unsigned int xattrs_tabsize,
				    unsigned int *p_nb_returned,
				    int *end_of_list);
fsal_status_t secnfs_getextattr_id_by_name(struct fsal_obj_handle *obj_hdl,
					   const struct req_op_context *opctx,
					   const char *xattr_name,
					   unsigned int *pxattr_id);
fsal_status_t secnfs_getextattr_value_by_name(struct fsal_obj_handle *obj_hdl,
					      const struct req_op_context
					      *opctx, const char *xattr_name,
					      caddr_t buffer_addr,
					      size_t buffer_size,
					      size_t * p_output_size);
fsal_status_t secnfs_getextattr_value_by_id(struct fsal_obj_handle *obj_hdl,
					    const struct req_op_context *opctx,
					    unsigned int xattr_id,
					    caddr_t buffer_addr,
					    size_t buffer_size,
					    size_t * p_output_size);
fsal_status_t secnfs_setextattr_value(struct fsal_obj_handle *obj_hdl,
				      const struct req_op_context *opctx,
				      const char *xattr_name,
				      caddr_t buffer_addr, size_t buffer_size,
				      int create);
fsal_status_t secnfs_setextattr_value_by_id(struct fsal_obj_handle *obj_hdl,
					    const struct req_op_context *opctx,
					    unsigned int xattr_id,
					    caddr_t buffer_addr,
					    size_t buffer_size);
fsal_status_t secnfs_getextattr_attrs(struct fsal_obj_handle *obj_hdl,
				      const struct req_op_context *opctx,
				      unsigned int xattr_id,
				      struct attrlist *p_attrs);
fsal_status_t secnfs_remove_extattr_by_id(struct fsal_obj_handle *obj_hdl,
					  const struct req_op_context *opctx,
					  unsigned int xattr_id);
fsal_status_t secnfs_remove_extattr_by_name(struct fsal_obj_handle *obj_hdl,
					    const struct req_op_context *opctx,
					    const char *xattr_name);

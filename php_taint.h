/*
  +----------------------------------------------------------------------+
  | Taint                                                                |
  +----------------------------------------------------------------------+
  | Copyright (c) 2012-2015 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:  Xinchen Hui    <laruence@php.net>                           |
  +----------------------------------------------------------------------+
*/

#ifndef PHP_TAINT_H
#define PHP_TAINT_H

extern zend_module_entry taint_module_entry;
#define phpext_taint_ptr &taint_module_entry

#ifdef PHP_WIN32
#define PHP_TAINT_API __declspec(dllexport)
#else
#define PHP_TAINT_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

#define PHP_TAINT_VERSION "2.0.4"

/* it's important that make sure 
 * this value is not used by Zend or
 * any other extension agianst string */
#define IS_STR_TAINT_POSSIBLE    (1<<7)
#define IS_STR_TAINT_XSS         (1<<6)
#define IS_STR_TAINT_SQL         (1<<5)
#define IS_STR_TAINT_QUOTE       (1<<4)

#if PHP_VERSION_ID > 70000 
# if PHP_VERSION_ID < 70100
# define PHP_7_0  1
# define PHP_7_1  0
# elif PHP_VERSION_ID < 70200
# define PHP_7_0  0
# define PHP_7_1  1
# elif PHP_VERSION_ID < 70300
# undef IS_STR_TAINT_POSSIBLE
/* Coflicts with GC_COLLECTABLE which is introduced in 7.2 */
# define IS_STR_TAINT_POSSIBLE (1<<6)
# define PHP_7_0  0
# define PHP_7_1  2
# else
# error "Unsupported PHP Version ID:" PHP_VERSION_ID
# endif
#else
# error "Unsupported PHP Version ID:" PHP_VERSION_ID
#endif

#define TAINT_MARK(str)		(GC_FLAGS((str)) |= IS_STR_TAINT_POSSIBLE)
#define TAINT_POSSIBLE(str) (GC_FLAGS((str)) & IS_STR_TAINT_POSSIBLE)
#define TAINT_CLEAN(str)  	(GC_FLAGS((str)) &= ~IS_STR_TAINT_POSSIBLE)

#define TAINT_XSS(str)      (GC_FLAGS((str)) |= IS_STR_TAINT_XSS)
#define XSS_POSSIBLE(str)   (GC_FLAGS((str)) & IS_STR_TAINT_XSS)
#define XSS_CLEAN(str)      (GC_FLAGS((str)) &= ~IS_STR_TAINT_XSS)

#define TAINT_SQL(str)      (GC_FLAGS((str)) |= IS_STR_TAINT_SQL)
#define SQL_POSSIBLE(str)   (GC_FLAGS((str)) & IS_STR_TAINT_SQL)
#define SQL_CLEAN(str)      (GC_FLAGS((str)) &= ~IS_STR_TAINT_SQL)

#define TAINT_QUOTE(str)    (GC_FLAGS((str)) |= IS_STR_TAINT_QUOTE)
#define QUOTE_POSSIBLE(str) (GC_FLAGS((str)) & IS_STR_TAINT_QUOTE)
#define QUOTE_CLEAN(str)    (GC_FLAGS((str)) &= ~IS_STR_TAINT_QUOTE)

#define TAINT_OP1_TYPE(opline)	(opline->op1_type)
#define TAINT_OP2_TYPE(opline)	(opline->op2_type)


#if PHP_7_0
#define TAINT_RET_USED(opline) (!((opline)->result_type & EXT_TYPE_UNUSED))
#define TAINT_ISERR(var)       (var == &EG(error_zval))
#define TAINT_ERR_ZVAL(var)    (var = &EG(error_zval))
#elif PHP_7_1 
#define TAINT_RET_USED(opline) ((opline)->result_type != IS_UNUSED)
#define TAINT_ISERR(var)       (Z_ISERROR_P(var))
#define TAINT_ERR_ZVAL(var)    (ZVAL_ERROR(var))
#endif

typedef zval* taint_free_op;

PHP_MINIT_FUNCTION(taint);
PHP_MSHUTDOWN_FUNCTION(taint);
PHP_RINIT_FUNCTION(taint);
PHP_RSHUTDOWN_FUNCTION(taint);
PHP_MINFO_FUNCTION(taint);

PHP_FUNCTION(taint);
PHP_FUNCTION(untaint);
PHP_FUNCTION(is_tainted);

PHP_FUNCTION(taint_strval);
PHP_FUNCTION(taint_sprintf);
PHP_FUNCTION(taint_vsprintf);
PHP_FUNCTION(taint_explode);
PHP_FUNCTION(taint_implode);
PHP_FUNCTION(taint_trim);
PHP_FUNCTION(taint_rtrim);
PHP_FUNCTION(taint_ltrim);
PHP_FUNCTION(taint_strstr);
PHP_FUNCTION(taint_substr);
PHP_FUNCTION(taint_str_replace);
PHP_FUNCTION(taint_str_ireplace);
PHP_FUNCTION(taint_str_pad);
PHP_FUNCTION(taint_strtolower);
PHP_FUNCTION(taint_strtoupper);
PHP_FUNCTION(taint_dirname);
PHP_FUNCTION(taint_basename);
PHP_FUNCTION(taint_pathinfo);

PHP_FUNCTION(taint_json_decode);
PHP_FUNCTION(taint_base64_decode);
PHP_FUNCTION(taint_urldecode);


/**xss filter***/
PHP_FUNCTION(taint_htmlspecialchars);
PHP_FUNCTION(taint_json_encode);
PHP_FUNCTION(taint_htmlentities);
PHP_FUNCTION(taint_highlight_string);


/******SQL filter********/

PHP_FUNCTION(taint_addslashes);
PHP_FUNCTION(taint_dbx_escape_string);
PHP_FUNCTION(taint_db2_escape_string);
PHP_FUNCTION(taint_ingres_escape_string);
PHP_FUNCTION(taint_maxdb_escape_string);
PHP_FUNCTION(taint_maxdb_real_escape_string);
PHP_FUNCTION(taint_mysql_escape_string);
PHP_FUNCTION(taint_mysql_real_escape_string);
PHP_FUNCTION(taint_mysqli_escape_string);
PHP_FUNCTION(taint_mysqli_real_escape_string);
PHP_FUNCTION(taint_pg_escape_string);
PHP_FUNCTION(taint_pg_escape_bytea);
PHP_FUNCTION(taint_sqlite_escape_string);
PHP_FUNCTION(taint_sqlite_udf_encode_binary);
PHP_FUNCTION(taint_cubrid_real_escape_string);

/***dly   add*/
/**
PHP_FUNCTION(taint_intval);
PHP_FUNCTION(taint_floatval);
PHP_FUNCTION(taint_doubleval);
PHP_FUNCTION(taint_filter_input);
PHP_FUNCTION(taint_round);
PHP_FUNCTION(taint_floor);
PHP_FUNCTION(taint_strlen);
PHP_FUNCTION(taint_strpos);
PHP_FUNCTION(taint_strftime);
PHP_FUNCTION(taint_md5);
PHP_FUNCTION(taint_md5_file);
PHP_FUNCTION(taint_sha1);
PHP_FUNCTION(taint_sha1_file);
PHP_FUNCTION(taint_crypt);
PHP_FUNCTION(taint_crc32);
PHP_FUNCTION(taint_hash);
PHP_FUNCTION(taint_mhash);
PHP_FUNCTION(taint_hash_hmac);
PHP_FUNCTION(taint_size_of);

*/






typedef void (*php_func)(INTERNAL_FUNCTION_PARAMETERS);

ZEND_BEGIN_MODULE_GLOBALS(taint)
	zend_bool enable;
	int       error_level;
ZEND_END_MODULE_GLOBALS(taint)

#ifdef ZTS
#define TAINT_G(v) TSRMG(taint_globals_id, zend_taint_globals *, v)
#else
#define TAINT_G(v) (taint_globals.v)
#endif

#endif	/* PHP_TAINT_H */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */

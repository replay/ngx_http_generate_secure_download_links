
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <mhash.h>
#include <openssl/md5.h>

#define JSON_MIME "application/json"

typedef struct {
    ngx_str_t                url;
    ngx_array_t             *url_lengths;
    ngx_array_t             *url_values;
    ngx_uint_t               expiration_time;
    ngx_str_t                secret;
    ngx_array_t             *secret_lengths;
    ngx_array_t             *secret_values;
    ngx_flag_t               enable;
    ngx_flag_t               json;
    ngx_flag_t               mode;
    ngx_uint_t               period_length;
    ngx_uint_t               periods_to_expire;
} ngx_http_generate_secure_download_link_loc_conf_t;

typedef struct {
    ngx_http_generate_secure_download_link_loc_conf_t *conf;
    ngx_http_request_t *r;
    ngx_buf_t *result_b;
    ngx_int_t result_len;
    ngx_str_t secret;
    ngx_str_t url;
    ngx_str_t expiration_specification;
} ngx_http_generate_secure_download_link_state_t;

typedef struct {
    ngx_str_t   string;
    ngx_array_t **lengths;
    ngx_array_t **values;
} ngx_http_generate_secure_download_link_script_compiler_input_t;

static void *ngx_http_generate_secure_download_link_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_generate_secure_download_link_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_generate_secure_download_link_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_generate_secure_download_link_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_generate_secure_download_link_run_scripts(ngx_http_generate_secure_download_link_state_t *state);
static ngx_int_t ngx_http_generate_secure_download_link_do_generation(ngx_http_generate_secure_download_link_state_t *state);
static ngx_int_t ngx_http_generate_secure_download_link_create_expiration_specification_string(ngx_http_generate_secure_download_link_state_t *state);
static char *ngx_http_generate_secure_download_link_compile_link(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_generate_secure_download_link_compile_secret(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_generate_secure_download_generic_script_compiler(ngx_http_generate_secure_download_link_script_compiler_input_t compiler_input, ngx_conf_t *cf);

static ngx_conf_post_handler_pt ngx_http_generate_secure_download_link_compile_link_p = 
       ngx_http_generate_secure_download_link_compile_link;
       
static ngx_conf_post_handler_pt ngx_http_generate_secure_download_link_compile_secret_p = 
       ngx_http_generate_secure_download_link_compile_secret;
        
static ngx_command_t  ngx_http_generate_secure_download_link_commands[] = {
    
    { ngx_string("generate_secure_download_link"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_generate_secure_download_link_enable,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_generate_secure_download_link_loc_conf_t, enable),
      NULL },
    { ngx_string("generate_secure_download_link_json"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_generate_secure_download_link_loc_conf_t, json),
      NULL },
    { ngx_string("generate_secure_download_link_url"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_generate_secure_download_link_loc_conf_t, url),
      &ngx_http_generate_secure_download_link_compile_link_p },
    { ngx_string("generate_secure_download_link_expiration_time"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_generate_secure_download_link_loc_conf_t, expiration_time),
      NULL },
    { ngx_string("generate_secure_download_link_period_length"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_generate_secure_download_link_loc_conf_t, period_length),
      NULL },
    { ngx_string("generate_secure_download_link_secret"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_generate_secure_download_link_loc_conf_t, secret),
      &ngx_http_generate_secure_download_link_compile_secret_p },
      ngx_null_command
};

static ngx_http_module_t  ngx_http_generate_secure_download_link_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_generate_secure_download_link_create_loc_conf,        /* create location configration */
    ngx_http_generate_secure_download_link_merge_loc_conf          /* merge location configration */
};

ngx_module_t  ngx_http_generate_secure_download_link_module = {
    NGX_MODULE_V1,
    &ngx_http_generate_secure_download_link_module_ctx,            /* module context */
    ngx_http_generate_secure_download_link_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static char *ngx_http_generate_secure_download_link_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;
    
    ngx_conf_set_flag_slot(cf, cmd, conf);
    
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_generate_secure_download_link_handler;

    return NGX_CONF_OK;
}

static void *
ngx_http_generate_secure_download_link_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_generate_secure_download_link_loc_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_generate_secure_download_link_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->expiration_time = NGX_CONF_UNSET;
    conf->secret.data = NULL;
    conf->secret.len = 0;

    conf->url.data = NULL;
    conf->url.len = 0;
    
    conf->json = NGX_CONF_UNSET;
    conf->enable = NGX_CONF_UNSET;
    conf->mode = NGX_CONF_UNSET;
    conf->period_length = NGX_CONF_UNSET;
    
    return conf;
}

static char *
ngx_http_generate_secure_download_link_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_generate_secure_download_link_loc_conf_t  *prev = parent;
    ngx_http_generate_secure_download_link_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->json, prev->json, 0);
    ngx_conf_merge_uint_value(conf->period_length, prev->period_length, 1);
    ngx_conf_merge_str_value(conf->url, prev->url, "");
    ngx_conf_merge_uint_value(conf->expiration_time, prev->expiration_time, NGX_CONF_UNSET_UINT);
    ngx_conf_merge_str_value(conf->secret, prev->secret, "");

    if (conf->enable == 0) {
        return NGX_CONF_OK;
    }
    
    if (conf->url.len == 0 || conf->url.data == NULL) {
          ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
               "no generate_secure_download_link_url specified");
             return NGX_CONF_ERROR;
    }
    
    if (conf->secret.len == 0 || conf->secret.data == NULL) {
          ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
               "no generate_secure_download_link_secret specified");
             return NGX_CONF_ERROR;
    }
    
    return NGX_CONF_OK;
}

static char *ngx_http_generate_secure_download_link_compile_link(
    ngx_conf_t *cf, void *post, void *data) {
    
    ngx_http_generate_secure_download_link_loc_conf_t *gsdllc = 
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_generate_secure_download_link_module);
    
    ngx_http_generate_secure_download_link_script_compiler_input_t compiler_input;
    
    compiler_input.string = gsdllc->url;
    compiler_input.lengths = &gsdllc->url_lengths;
    compiler_input.values = &gsdllc->url_values;
    
    return ngx_http_generate_secure_download_generic_script_compiler(compiler_input, cf);
}

static char *ngx_http_generate_secure_download_link_compile_secret(
    ngx_conf_t *cf, void *post, void *data) {
    
    ngx_http_generate_secure_download_link_loc_conf_t *gsdllc = 
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_generate_secure_download_link_module);
    
    ngx_http_generate_secure_download_link_script_compiler_input_t compiler_input;
    
    compiler_input.string = gsdllc->secret;
    compiler_input.lengths = &gsdllc->secret_lengths;
    compiler_input.values = &gsdllc->secret_values;
    
    return ngx_http_generate_secure_download_generic_script_compiler(compiler_input, cf);
}


static char *ngx_http_generate_secure_download_generic_script_compiler(ngx_http_generate_secure_download_link_script_compiler_input_t compiler_input, ngx_conf_t *cf) {
    ngx_http_script_compile_t sc;

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
    
    sc.cf = cf;
    sc.source = &compiler_input.string;
    *compiler_input.lengths=NULL;
    *compiler_input.values=NULL;
    sc.lengths = compiler_input.lengths;
    sc.values = compiler_input.values;
    sc.variables = ngx_http_script_variables_count(&compiler_input.string);
    sc.complete_lengths = 1;
    sc.complete_values = 1;
    
    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_generate_secure_download_link_handler(ngx_http_request_t *r)
{
    ngx_chain_t   out;
    ngx_int_t     rc;
    
    ngx_http_generate_secure_download_link_state_t state;
    ngx_http_generate_secure_download_link_loc_conf_t *gsdllc = ngx_http_get_module_loc_conf(r, ngx_http_generate_secure_download_link_module);
    
    //printf("----- handler start -----\n");
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK && rc != NGX_AGAIN) {
        return rc;
    }
    
    state.conf = gsdllc;
    state.r = r;
    
    if (ngx_http_generate_secure_download_link_run_scripts(&state) != NGX_OK) {
        return NGX_ERROR;
    }
    
    if (ngx_http_generate_secure_download_link_create_expiration_specification_string(&state) != NGX_OK) {
        return NGX_ERROR;
    }
    
    // 8 = hex timestamp, 2 = two slashes, 32 = md5, len of url
    state.result_len = state.expiration_specification.len + 2 + 32 + state.url.len;
    //printf("estimated result len is %i, url.len is %i, url.data is %s\n", (int)state.result_len, (int)state.url.len, (char *)state.url.data);
    
    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html";
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = state.result_len;
    
    out.next = NULL;
    
    rc = ngx_http_send_header(r);
    /*printf("method is %i\n", (int) r->method);
    printf("send_header's rc was %i\n", (int) rc);
    printf("header_only is %i\n", r->header_only);
    printf("sent content_length is %i\n", (int) state.result_len);*/

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    
    state.result_b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (state.result_b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    out.buf = state.result_b;
    out.buf->memory = 1;
    
    if (ngx_http_generate_secure_download_link_do_generation(&state) != NGX_OK) {
        return NGX_ERROR;
    }
    
    /*printf("counted content_length is %i\n", (int) (out.buf->last - out.buf->pos + 1));
    printf("returning with buffer \"%s\"\n", out.buf->pos);*/
    
    return ngx_http_output_filter(r,&out);
}

static ngx_int_t ngx_http_generate_secure_download_link_run_scripts(ngx_http_generate_secure_download_link_state_t *state) {
    ngx_str_t secret;
    ngx_str_t url;
    
    if (ngx_http_script_run(state->r, &secret, state->conf->secret_lengths->elts, 0, state->conf->secret_values->elts) == NULL) {  
        return NGX_ERROR;
    }
    if (ngx_http_script_run(state->r, &url, state->conf->url_lengths->elts, 0, state->conf->url_values->elts) == NULL) {
            return NGX_ERROR;
    }
    
    state->url.data = ngx_pcalloc(state->r->pool, sizeof(char) * (url.len + 1));
    state->secret.data = ngx_pcalloc(state->r->pool, sizeof(char) * (secret.len + 1));

    if (state->url.data == NULL || state->secret.data == NULL) {
        return NGX_ERROR;
    }
    
    ngx_memcpy(state->url.data, url.data, url.len);
    ngx_memcpy(state->secret.data, secret.data, secret.len);
    state->url.len = url.len;
    state->secret.len = secret.len;
    
	/*printf("state->url.len is %i, state->url.data is \"%s\"\n", (int) state->url.len, state->url.data);
	printf("state->secret.len is %i, state->secret.data is \"%s\"\n", (int) state->secret.len, state->secret.data);*/

    state->url.data[url.len] = (char) 0;
    state->secret.data[secret.len] = (char) 0;

/*	printf("url.len is %i, url.data is \"%s\"\n", (int) url.len, url.data);
	printf("secret.len is %i, secret.data is \"%s\"\n", (int) secret.len, secret.data);
    
	printf("state->url.len is %i, state->url.data is \"%s\"\n", (int) state->url.len, state->url.data);
	printf("state->secret.len is %i, state->secret.data is \"%s\"\n", (int) state->secret.len, state->secret.data);*/
    
    return NGX_OK;
}

static ngx_int_t ngx_http_generate_secure_download_link_do_generation(ngx_http_generate_secure_download_link_state_t *state)
{
    unsigned char generated_hash[16]; 
    u_char *to_hash;
    u_char *to_hash_pos;
    u_char *result;
    u_char *result_pos;
    int to_hash_len;
    MHASH td;
    int i;
    int slashes_to_escape = 0;
    static const char xtoc[] = "0123456789abcdef";
    
    if (state->conf->json == 1) {
        for (result_pos = state->url.data; result_pos <= state->url.data + state->url.len; result_pos++) {
            if (*result_pos == 47) {
                slashes_to_escape++;
            }
        }
        slashes_to_escape += 2; // in url/md5/time
    }
    
    result = ngx_pcalloc(state->r->pool, sizeof(char) * (state->result_len + 2 + slashes_to_escape));
    to_hash_len = state->expiration_specification.len + 2 + state->url.len + state->secret.len;
    to_hash = ngx_pcalloc(state->r->pool, sizeof(char) * to_hash_len + 1);
    if (to_hash == NULL || result == NULL) {
        return NGX_ERROR;
    }
    to_hash_pos = to_hash;
    result_pos  = result;
    
	//printf("secret.data is \"%s\"\n", state->secret.data);
	//printf("url.data is \"%s\"\n", state->url.data);
	
    memcpy(to_hash_pos, state->url.data, state->url.len);
    to_hash_pos += state->url.len;
    *to_hash_pos++ = '/';
    memcpy(to_hash_pos, state->secret.data, state->secret.len);
    to_hash_pos += state->secret.len;
    *to_hash_pos++ = '/';
    memcpy(to_hash_pos, state->expiration_specification.data, state->expiration_specification.len);
    to_hash_pos += state->expiration_specification.len;
    *to_hash_pos = (char) 0;
    
    td = mhash_init(MHASH_MD5);
    if (td == MHASH_FAILED)
    {
        ngx_pfree(state->r->pool, to_hash);
        return NGX_ERROR;
    }
    printf("string to be hashed: \"%s\"\n", to_hash);
    mhash(td, to_hash, to_hash_len);
    mhash_deinit(td, generated_hash);
    
    ngx_pfree(state->r->pool, to_hash);
    
	if (state->conf->json == 1) {
        for (result_pos = result, to_hash_pos = state->url.data; to_hash_pos < state->url.data + state->url.len; to_hash_pos++) {
            if (*to_hash_pos == 47) {
                *result_pos = 92;
                result_pos++;
            }
            *result_pos = *to_hash_pos;
            result_pos++;
        }
	} else {
	    memcpy(result, state->url.data, state->url.len);
	    result_pos += state->url.len;
	}
    
    if (state->conf->json == 1) {
        *result_pos++ = 92;
    }
    *result_pos++ = 47;
    for (i = 0; i < 16; ++i) {
  	  result_pos[2 * i + 0] = xtoc[generated_hash[i] >> 4];
  	  result_pos[2 * i + 1] = xtoc[generated_hash[i] & 0xf];
    }
    result_pos += 32;
    if (state->conf->json == 1) {
        *result_pos++ = 92;
    }
    *result_pos++ = 47;
    memcpy(result_pos, state->expiration_specification.data, state->expiration_specification.len);
    
    state->result_b->pos = result;
    result_pos += state->expiration_specification.len;
    state->result_b->last = result_pos;
    *state->result_b->last = (char) 0;
    
    //printf("reply will be %s\n", result);
    return NGX_OK;
}

static ngx_int_t ngx_http_generate_secure_download_link_create_expiration_specification_string(ngx_http_generate_secure_download_link_state_t *state) {
    unsigned int dtimestamp;
    ngx_str_t *result = &state->expiration_specification;
    
    dtimestamp = (time_t) time(NULL);
    dtimestamp += state->conf->expiration_time;
    if (state->conf->period_length != 1) {
        dtimestamp = (dtimestamp / state->conf->period_length) * state->conf->period_length;
    }
    // 12 = max string len of converted int plus terminating \0
    result->data = ngx_pcalloc(state->r->pool, sizeof(char) * 12);
    sprintf((char *)result->data, "%X", dtimestamp);
    result->len = strlen((const char *) result->data);

    return NGX_OK;
}

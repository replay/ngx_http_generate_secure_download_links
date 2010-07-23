
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <mhash.h>
#include <openssl/md5.h>

typedef struct {
    ngx_str_t                url;
    ngx_array_t             *url_lengths;
    ngx_array_t             *url_values;
    ngx_uint_t                expiration_time;
    ngx_str_t                secret;
    ngx_array_t             *secret_lengths;
    ngx_array_t             *secret_values;
} ngx_http_generate_secure_download_link_loc_conf_t;

typedef struct {
    ngx_http_generate_secure_download_link_loc_conf_t *conf;
    ngx_http_request_t *r;
    ngx_buf_t *result_b;
    ngx_int_t result_len;
    ngx_str_t secret;
    ngx_str_t url;
} ngx_http_generate_secure_download_link_state_t;

static void *ngx_http_generate_secure_download_link_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_generate_secure_download_link_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_generate_secure_download_link_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_generate_secure_download_link_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_generate_secure_download_link_run_scripts(ngx_http_generate_secure_download_link_state_t *state);
static ngx_int_t ngx_http_generate_secure_download_link_do_generation(ngx_http_generate_secure_download_link_state_t *state);

static char *ngx_http_generate_secure_download_link_compile_link(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_generate_secure_download_link_compile_secret(ngx_conf_t *cf, void *post, void *data);

static ngx_conf_post_handler_pt ngx_http_generate_secure_download_link_compile_link_p = 
       ngx_http_generate_secure_download_link_compile_link;
       
static ngx_conf_post_handler_pt ngx_http_generate_secure_download_link_compile_secret_p = 
       ngx_http_generate_secure_download_link_compile_secret;
        
static ngx_command_t  ngx_http_generate_secure_download_link_commands[] = {
    
    { ngx_string("generate_secure_download_link"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_generate_secure_download_link_enable,
      0,
      0,
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

static void *
ngx_http_generate_secure_download_link_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_generate_secure_download_link_loc_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_generate_secure_download_link_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->expiration_time = NGX_CONF_UNSET;
    conf->secret.data = NULL;
    conf->secret.len = 0;

    conf->url.data = NULL;
    conf->url.len = 0;
    
    return conf;
}

static char *
ngx_http_generate_secure_download_link_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_generate_secure_download_link_loc_conf_t  *prev = parent;
    ngx_http_generate_secure_download_link_loc_conf_t  *conf = child;

    ngx_conf_merge_str_value(conf->url, prev->url, "");
    ngx_conf_merge_uint_value(conf->expiration_time, prev->expiration_time, 0);
    ngx_conf_merge_str_value(conf->secret, prev->secret, "");
    
    return NGX_CONF_OK;
}

static char *ngx_http_generate_secure_download_link_compile_link(
    ngx_conf_t *cf, void *post, void *data) {
    ngx_http_generate_secure_download_link_loc_conf_t *gsdllc = 
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_generate_secure_download_link_module);
    
    ngx_http_script_compile_t sc;
    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
    
    sc.cf = cf;
    sc.source = &gsdllc->url;
    sc.lengths = &gsdllc->url_lengths;
    sc.values = &gsdllc->url_values;
    sc.variables = ngx_http_script_variables_count(&gsdllc->url);
    sc.complete_lengths = 1;
    sc.complete_values = 1;
    
    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static char *ngx_http_generate_secure_download_link_compile_secret(
        ngx_conf_t *cf, void *post, void *data) {
        ngx_http_generate_secure_download_link_loc_conf_t *gsdllc = 
            ngx_http_conf_get_module_loc_conf(cf, ngx_http_generate_secure_download_link_module);

        ngx_http_script_compile_t sc;
        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &gsdllc->secret;
        sc.lengths = &gsdllc->secret_lengths;
        sc.values = &gsdllc->secret_values;
        sc.variables = ngx_http_script_variables_count(&gsdllc->secret);
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
        return NGX_CONF_OK;
    }
    
static char *ngx_http_generate_secure_download_link_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_generate_secure_download_link_handler;
    
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_generate_secure_download_link_handler(ngx_http_request_t *r)
{
    ngx_chain_t      out;
    ngx_int_t     rc;
    
    ngx_http_generate_secure_download_link_state_t state;
    ngx_http_generate_secure_download_link_loc_conf_t *gsdllc = ngx_http_get_module_loc_conf(r, ngx_http_generate_secure_download_link_module);
    
    printf("----- handler start -----\n");
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK && rc != NGX_AGAIN) {
        return rc;
    }
    
    //if (r->headers_in.if_modified_since) {
    //    return NGX_HTTP_NOT_MODIFIED;
    //}
    
    state.conf = gsdllc;
    state.r = r;
    
    /*if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;
        
        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }*/
    
    if (ngx_http_generate_secure_download_link_run_scripts(&state) != NGX_OK) {
        return NGX_ERROR;
    }
    
    // 8 = hex timestamp, 2 = two slashes, 32 = md5, len of url
    state.result_len = 8 + 2 + 32 + state.url.len;
    printf("estimated result len is %i, url.len is %i, url.data is %s\n", (int)state.result_len, (int)state.url.len, (char *)state.url.data);
    
    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html";
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = state.result_len;
    
    out.next = NULL;
    
    rc = ngx_http_send_header(r);
    printf("method is %i\n", (int) r->method);
    printf("send_header's rc was %i\n", (int) rc);
    printf("header_only is %i\n", r->header_only);
    printf("sent content_length is %i\n", state.result_len);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    
    state.result_b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (state.result_b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    out.buf = state.result_b;
    out.buf->last_buf = 1; 
    out.buf->memory = 1;
    
    if (ngx_http_generate_secure_download_link_do_generation(&state) != NGX_OK) {
        return NGX_ERROR;
    }
    
    ngx_pfree(state.r->pool, state.url.data);
    ngx_pfree(state.r->pool, state.secret.data);
    
    printf("counted content_length is %i\n", out.buf->last - out.buf->pos + 1);
    
    printf("returning with buffer \"%s\"\n", out.buf->pos);
    
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
    
    memcpy(state->url.data, url.data, url.len);
    memcpy(state->url.data, url.data, url.len);
    state->url.len = url.len;
    state->secret.len = secret.len;
    
    state->url.data[state->url.len + 1] = NULL;
    state->secret.data[state->secret.len + 1] = NULL;
    
    ngx_pfree(state->r->pool, secret.data);
    ngx_pfree(state->r->pool, url.data);
    
    return NGX_OK;
}

static ngx_int_t ngx_http_generate_secure_download_link_do_generation(ngx_http_generate_secure_download_link_state_t *state)
{
    unsigned dtimestamp;
    char htimestamp[9];
    unsigned char generated_hash[16]; 
    u_char *to_hash;
    u_char *to_hash_pos;
    u_char *result;
    u_char *result_pos;
    int to_hash_len;
    int result_len;
    char hash[33];
    MHASH td;
    int i;
    static const char xtoc[] = "0123456789abcdef";
    
    result = ngx_pcalloc(state->r->pool, sizeof(char) * (state->result_len + 1));
    to_hash_len = 8 + 2 + state->url.len + state->secret.len;
    to_hash = ngx_pcalloc(state->r->pool, sizeof(char) * to_hash_len + 1);
    if (to_hash == NULL || result == NULL) {
        return NGX_ERROR;
    }
    to_hash_pos = to_hash;
    result_pos  = result;
    
    dtimestamp = (time_t) time(NULL);
    printf("%i\n",dtimestamp);
    sprintf(&htimestamp, "%08X", dtimestamp);
    printf("%s\n", htimestamp);
    
    memcpy(to_hash_pos, state->url.data, state->url.len);
    to_hash_pos += state->url.len;
    *to_hash_pos++ = '/';
    memcpy(to_hash_pos, state->secret.data, state->secret.len);
    to_hash_pos += state->secret.len;
    *to_hash_pos++ = '/';
    memcpy(to_hash_pos, htimestamp, 8);
    to_hash_pos += 8;
    *to_hash_pos = NULL;
    
    td = mhash_init(MHASH_MD5);
    if (td == MHASH_FAILED)
    {
        ngx_pfree(state->r->pool, to_hash);
        return NGX_ERROR;
    }
    mhash(td, to_hash, to_hash_len);
    mhash_deinit(td, generated_hash);
    
    ngx_pfree(state->r->pool, to_hash);
    
    memcpy(result, state->url.data, state->url.len);
    result_pos += state->url.len;
    *result_pos++ = '/';
    for (i = 0; i < 16; ++i) {
  	  result_pos[2 * i + 0] = xtoc[generated_hash[i] >> 4];
  	  result_pos[2 * i + 1] = xtoc[generated_hash[i] & 0xf];
    }
    result_pos += 32;
    *result_pos++ = '/';
    memcpy(result_pos, htimestamp, 8);
    
    state->result_b->pos = result;
    result_pos += 8;
    state->result_b->last = result_pos;
    *state->result_b->last = NULL;
    
    printf("reply will be %s\n", result);
    return NGX_OK;
}
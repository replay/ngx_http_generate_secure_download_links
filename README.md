# TOC #

* Overview
* Parameters
* Howto by example

## Overview ##

nginx module to generate secure download links that can be used in combination with the module ngx_http_secure_download. 
ngx_http_generate_secure_download_links should be used via ssi, so it can replace ssi tags by secured download links on the fly like an output filter.

## Parameters ##

* generate_secure_download_link
* generate_secure_download_link_json
* generate_secure_download_link_url
* generate_secure_download_link_expiration_time
* generate_secure_download_link_period_length
* generate_secure_download_link_secret

## Howto by example ##
## TOC ##

* Overview
* Parameters
* Howto by example

## Overview ##

nginx module to generate secure download links that can be used in combination with the module ngx_http_secure_download. 

ngx_http_generate_secure_download_links should be used via ssi, so it can replace ssi tags by secured download links on the fly like an output filter.

## Parameters ##

### generate_secure_download_link ###

Parameters: on/off

Default: off

Enable/disable the module for this location

### generate_secure_download_link_json ###

Parameters: on/off

Default: off

Add \ in front of all /, like json requires it

### generate_secure_download_link_url ###

Parameters: string

Default: "" \(required\)

The url that should be secured

### generate_secure_download_link_expiration_time ###

Parameters: int

Default: "" \(required\)

Time in seconds until the generated link should not be valid anymore

### generate_secure_download_link_period_length ###

Parameters: int

Default: 1

Time in seconds which specifies how often the links should be regenerated. This also influences the precision of the spcified expiration time. If period_length is 60 and expiration_time is 300, the generated links will be valid for a timerange between 240 and 300 seconds.

You might be wondering why anybody would want a period_length other than 1 second, simply because the browser caches don't work if the link changes every second.

### generate_secure_download_link_secret ###

Parameters: string

Default: "" \(required\)

A string which should act as some kind of salt in the MD5 hash. It can also contain variables like the $remote_addr.

## Howto by example ##
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

Default: none \(required\)

The url that should be secured

### generate_secure_download_link_expiration_time ###

Parameters: int

Default: none \(required\)

Time in seconds until the generated link should not be valid anymore

### generate_secure_download_link_period_length ###

Parameters: int

Default: 1

Time in seconds which specifies how often the links should be regenerated. This also influences the precision of the spcified expiration time. If period_length is 60 and expiration_time is 300, the generated links will be valid for a timerange between 240 and 300 seconds.

You might be wondering why anybody would want a period_length other than 1 second, simply because the browser caches don't work if the link changes every second.

### generate_secure_download_link_secret ###

Parameters: string

Default: none \(required\)

A string which should act as some kind of salt in the MD5 hash. It can also contain variables like the $remote_addr.

## Howto by example ##

### simple ###

This is a very simple example which is making the Nginx generate links that expire after 1 hour. In the location / its important that SSI is turned on, because the generate_secure_download_links_module is access via the SSI. 

	37         location / {
	38             ssi on;
	39             root   html;
	40         }
	41 
	42        location /gen_sec_link {
	43             internal;
	44             rewrite /gen_sec_link(.*)$ $1 break;
	45             generate_secure_download_link_expiration_time 3600;
	46             generate_secure_download_link_secret $remote_addr;
	47             generate_secure_download_link_url $uri;
	48             generate_secure_download_link on;
	49         }

In the location / you could now have an html file like this.

	1 this is some text
	2 <a href="<!--# include virtual="/gen_sec_link/this_is_my_link" -->">this_is_my_link</a>
	3 some more text
	4 <a href="http://somewhateverhost.com<!--# include virtual="/gen_sec_link/this_is_another_link" -->">this_is_another_link</a>
	5 even more text

The Nginx SSI module will see the \<!\-\-\# include \-\-\> tag and replace it by what it gets from the URL which is specified in the virtual parameter "/gen_sec_link/this_is_another_link". So the Nginx will do an internal subrequest to the given url which is then going to the generate_secure_download_links module, the reply from that subrequest will replace the whole \<!\-\-\# include \-\-\>. The result will then look like for example this:

	1 this is some text
	2 <a href="/this_is_my_link/509325bc5fac6e4e42687fe096d67a9d/4C4EC7C3">this_is_my_link</a>
	3 some more text
	4 <a href="http://somewhateverhost.com/this_is_another_link/badbcb4d20500cca464c609da41001b2/4C4EC7C3">this_is_another_link</a>
	5 even more text
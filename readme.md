# Wisc Content Auth LTI

LTI Integration for Pressbooks at UW. Based on the UI Fork of the Candela LTI integration from Lumen Learning (https://github.com/lumenlearning/candela-lti). 
Primary differences:

- Looks for a specified custom LTI parameter to use for the WordPress login id (instead of using the generated LTI user id)
- Allow for grades to be passed back through LTI 1.1 spec


## Requirements

Must have the core WordPress LTI plugin from Lumen Learning installed: https://github.com/lumenlearning/lti

This core LTI plugin requires the PHP OAuth module be installed. Our dev server is running PHP 5.6, which requires installation of older OAuth package (oauth-1.2.3, instead of current 2.x)

	sudo pecl install oauth-1.2.3

Activate the module by editing (or creating) the php.ini file at /etc/php/5.6/apache2/conf.d with the contents: 

	extension=oauth.so

Then restart Apache with:

	sudo service apache2 restart


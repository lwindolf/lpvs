lpvs
====

Linux Package Vulnerability Scanner for CentOS and Ubuntu

License: GPLv2 or later

For more information visit the homepage http://lzone.de/lpvs

Installation
============

Ensure to have the required libraries installed:

   * XML::LibXSLT
   * XML::LibXML

To install them on CentOS run the following command

   yum install perl-XML-LibXML perl-XML-LibXSLT

To install them on Ubuntu run the following command

   apt-get install libxml-libxslt-perl

Finally copy the "lpvs-scan.pl" to a location of your choice and provide it
with the proper permissions. For example as root run:

   cp lpvs lpvs-scan.pl /usr/local/bin
   cd /usr/local/bin && chmod a+x lpvs lpvs-scan.pl

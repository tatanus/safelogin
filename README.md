# "Safelogin.co" Phishing App
Simple application/website designed to illustrate how simple it is to set up phishing websites.
Based on the website I created a few years ago: http://safelogin.co

In order to use the new tool/script, you will need a DNS domain to use as the base, much as I  sed "safelogin.co".  Once you have the domain, then you will need to set up a wildcard dns entry pointing to the system on which you plan to run the tool.

Running the actual tool is simple enough.

```
# python phish.py <registered DNS domain> <passphrase used to protect credentials>
```

# Requirements:
 * DNS domain
 * cutycapt
 * twisted python module
 * sqlite3 python module

# Misc
Video of sample usage

[![Video of simple usage](http://img.youtube.com/vi/38vsWI9YSts/0.jpg)](http://www.youtube.com/watch?v=38vsWI9YSts)

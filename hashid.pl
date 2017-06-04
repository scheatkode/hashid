#!/usr/bin/env perl

 ###########################################################################//*!
 # @mainpage HashId                                                           #
 # @file     hashid.pl                                                        #
 # @author   alice <chaoticmurlock@gmail.com>                                 #
 # @version  1.0                                                              #
 # @date     02/11/2014                                                       #
 #                                                                            #
 # @brief    Hashing algorithm identifier.                                    #
 #                                                                            #
 # @section  LICENSE                                                          #
 # Copyright (c) 2014, alice                                                  #
 # All rights reserved.                                                       #
 #                                                                            #
 # Redistribution and use in source and binary forms, with or without         #
 # modification, are permitted provided that the following conditions         #
 # are met:                                                                   #
 # 1. Redistributions of source code must retain the above copyright          #
 #    notice, this list of conditions and the following disclaimer.           #
 # 2. Redistributions in binary form must reproduce the above copyright       #
 #    notice, this list of conditions and the following disclaimer in the     #
 #    documentation and/or other materials provided with the distribution.    #
 # 3. Neither the name of the University nor the names of its contributors    #
 #    may be used to endorse or promote products derived from this software   #
 #    without specific prior written permission.                              #
 #                                                                            #
 # THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND    #
 # ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE      #
 # IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE #
 # ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE   #
 # FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL #
 # DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS    #
 # OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)      #
 # HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT #
 # LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY  #
 # OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF     #
 # SUCH DAMAGE.                                                               #
 #//##########################################################################*/

use strict;
use warnings;

print "Usage :\n\t$0 \[hash|hashfile\]\n" and exit(0) if @ARGV != 1;

sub identify
{
my $h  = $_[0];
my $l  = length $h;

my $an = $h =~ /^[[:alnum:]]+$/a;
my $a  = $h =~ /^[[:alpha:]]+$/a;
my $L  = $h =~ /^[[:lower:]]+$/a;
my $n  = $h =~ /^[[:digit:]]+$/a;

print "\nPossible for $h :\n\n";

my $md5wp   = (not $an and not $a and not $n and (substr $h,0,3 )=~/^\$P\$$/ );
my $md5php  = (not $an and not $a and not $n and (substr $h,0,3 )=~/^\$H\$$/ );
my $md5unix = (not $an and not $a and not $n and (substr $h,0,3 )=~/^\$1\$$/ );
my $lineage = (    $an and not $a and not $n and (substr $h,0,2 )=~/^0x$/    );
my $md5apr  = (not $an and not $a and not $n and (substr $h,0,4 )=~/^\$apr$/ );
my $sql160  = (not $an and not $a and not $n and (substr $h,0,1 )=~/^\*$/    );
my $joomla  = (not $an and not $a and not $n and (substr $h,32,1)=~/^:$/     );
my $sha1dja = (    $an and not $a and not $n and (substr $h,0,4 )=~/^sha1$/  );
my $sha2dja = (not $an and not $a and not $n and (substr $h,0,6 )=~/^sha256$/);
my $sha2lin = (not $an and not $a and not $n and (substr $h,0,3 )=~/^\$6\$$/ );
my $sha3dja = (not $an and not $a and not $n and (substr $h,0,6 )=~/^sha384$/);
my $bfish   = (not $an and not $a and not $n and (substr $h,0,4 )=~/^\$2a\$$/);

print"\t[*] CRC-16\n"	                if $l==4  and $an and not $a;
print"\t[*] CRC-16-CITT\n"	            if $l==4  and $an and not $a and not $n;
print"\t[*] FCS-16\n"	                if $l==4  and $an and not $a and not $n;
print"\t[*] ADLER_32\n"	                if $l==4  and $an and not $a and not $n;
print"\t[*] CRC-32\n"	                if $l==8  and $an and not $a and not $n;
print"\t[*] CRC-32B\n"	                if $l==8  and $an and not $a and not $n;
print"\t[*] XOR32\n"	                if $l==8  and $an and not $a and not $n;
print"\t[*] GHash-32-3\n"	            if $l==8  and $an and not $a and     $n;
print"\t[*] GHash-32-5\n"	            if $l==8  and $an and not $a and     $n;
print"\t[*] DES (Unix)\n"	            if $l==13         and not $a and not $n;
print"\t[*] MySQL\n"	                if $l==16 and $an and not $a and not $n;
print"\t[*] MD5 (Middle)\n"	            if $l==16 and $an and not $a and not $n;
print"\t[*] MD5 (Half)\n"	            if $l==16 and $an and not $a and not $n;
print"\t[*] MD5\n"	                    if $l==32 and $an and not $a and not $n;
print"\t[*] DomainCachedCredentials\n"	if $l==32 and $an and not $a and not $n;
print"\t[*] RAdmin v2.x\n"	            if $l==32 and $an and not $a and not $n;
print"\t[*] NTLM\n"	                    if $l==32 and $an and not $a and not $n;
print"\t[*] MD4\n"	                    if $l==32 and $an and not $a and not $n;
print"\t[*] MD2\n"	                    if $l==32 and $an and not $a and not $n;
print"\t[*] Haval-128\n"	            if $l==32 and $an and not $a and not $n;
print"\t[*] RipeMD-128\n"	            if $l==32 and $an and not $a and not $n;
print"\t[*] SNEFRU-128\n"	            if $l==32 and $an and not $a and not $n;
print"\t[*] Tiger-128\n"	            if $l==32 and $an and not $a and not $n;
print"\t[*] MD5 (Wordpress)\n"	        if $l==34 and $md5wp;
print"\t[*] MD5 (phpBB3)\n"	            if $l==34 and $md5php;
print"\t[*] MD5 (Unix)\n"	            if $l==34 and $md5unix;
print"\t[*] Lineage II C4\n"	        if $l==34 and $lineage;
print"\t[*] MD5 (APR)\n"	            if $l==37 and $md5apr;
print"\t[*] SHA-1\n"	                if $l==40 and $an and not $a and not $n;
print"\t[*] MySQL5\n"               	if $l==40 and $an and not $a and not $n;
print"\t[*] MySQL 160bit\n"	            if $l==41 and $sql160;
print"\t[*] Tiger-160\n"	            if $l==40 and $an and not $a and not $n;
print"\t[*] Haval-160\n"	            if $l==40 and $an and not $a and not $n;
print"\t[*] RipeMD-160\n"	            if $l==40 and $an and not $a and not $n;
print"\t[*] SHA-1 (MaNGOS)\n"	        if $l==40 and $an and not $a and not $n;
print"\t[*] SHA-1 (MaNGOS2)\n"	        if $l==40 and $an and not $a and not $n;
print"\t[*] Tiger-192\n"	            if $l==48 and $an and not $a and not $n;
print"\t[*] Haval-192\n"	            if $l==48 and $an and not $a and not $n;
print"\t[*] Joomla - MD5 (pass.salt)\n" if $l==49 and $joomla;
print"\t[*] SHA-1 (Django)\n"	        if $l==53 and $sha1dja;
print"\t[*] SHA-224\n"	                if $l==56 and $an and not $a and not $n;
print"\t[*] Haval-224\n"	            if $l==56 and $an and not $a and not $n;
print"\t[*] SHA-256\n"	                if $l==64 and $an and not $a and not $n;
print"\t[*] Haval-256\n"	            if $l==64 and $an and not $a and not $n;
print"\t[*] GOST R 34.11-94\n"	        if $l==64 and $an and not $a and not $n;
print"\t[*] RipeMD-256\n"	            if $l==64 and $an and not $a and not $n;
print"\t[*] SNEFRU-256\n"	            if $l==64 and $an and not $a and not $n;
print"\t[*] Joomla - MD5 (pass.salt)\n" if $l==66 and $joomla;
print"\t[*] SAM - (LM_Hash:NT_Hash)\n"	if $l==65 and $joomla and not $L;
print"\t[*] SHA-256 (Django)\n"	        if $l==78 and $sha2dja;
print"\t[*] RipeMD-320\n"	            if $l==80 and $an and not $a and not $n;
print"\t[*] SHA-384\n"	                if $l==96 and $an and not $a and not $n;
print"\t[*] SHA-256 (Linux)\n"         	if $l==98 and $sha2lin;
print"\t[*] SHA-384 (Django)\n"	        if $l==110 and $sha3dja;
print"\t[*] SHA-512\n"	                if$l==128 and $an and not $a and not $n;
print"\t[*] Whirlpool\n"	            if$l==128 and $an and not $a and not $n;
print"\t[*] BlowFish\n"	                if $l==60 and $bfish;

print "\n";
}

if(-e $ARGV[0])
{
    open(FILE, $ARGV[0]) or die "Couldn't open $ARGV[0]\n";
    identify substr($_,0,-1) while <FILE>;
    close FILE or die "Couldn't properly close $ARGV[0]\n";
}
else { identify $ARGV[0] }


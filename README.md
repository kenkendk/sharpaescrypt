SharpAESCrypt
=============

A C# implementation of the [AESCrypt file format](http://www.aescrypt.com/).

This .NET AES Crypt package contains the C# class SharpAESCrypt.SharpAESCrypt, which provides file encryption and decryption using aescrypt file format.

Version 2 of the AES File Format is supported for reading and writing. Versions 0 and 1 are not verified, but there is code to read and write the formats.


Downloads
=========

If you use [NuGet](https://www.nuget.org) you can [install SharpAESCrypt from NuGet](https://www.nuget.org/packages/SharpAESCrypt.dll/1.0.0).

You can download either the [commandline executable version](https://github.com/kenkendk/sharpaescrypt/raw/master/Executable/SharpAESCrypt.exe) or the [dll library version](https://github.com/kenkendk/sharpaescrypt/raw/master/Library/SharpAESCrypt.dll).

Requirements
============

The SharpAESCrypt package works with .NET 2.0+, and is tested with:

Windows, Microsoft.Net, 32bit and 64bit
Linux, various distrbutions, Mono 2.6+, 32bit and 64bit
OSX 10.6+, Mono 2.6+, 32bit and 64bit

Besides a CLI runtime, no further dependencies are required.

Using From the Command Line
===========================

Windows, Microsoft.Net

    SharpAESCrypt.exe e|d password fromPath toPath
    
Mono, Any platform

    mono SharpAESCrypt.exe e|d password fromPath toPath
    
Operation mode is selected with (e)ncrypt or (d)ecrypt.


Using as a library in a project
===============================

Simply add a reference to SharpAESCrypt.dll, and you can use the static methods like this:

    SharpAESCrypt.Encrypt("password", "inputfile", "outputfile");
    SharpAESCrypt.Decrypt("password", "inputfile", "outputfile");
    SharpAESCrypt.Encrypt("password", inputStream, outputStream);
    SharpAESCrypt.Decrypt("password", inputStream, outputStream);
    
The syntax is for C# but the DLL works with any supported .NET language.

For more advanced uses, you can create a stream like this:

    Stream aesStream = new SharpAESCrypt(password, inputStream, mode);
You can set various properties on the stream. Remember to either call Dispose() or FlushFinalBlock() after using the stream.

See the documentation provided with the library for further details.

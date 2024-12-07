# Implementing AES encryption using vb.net

<i>Originally from website blog 2022/2023</i>
<br>

Although seemingly daunting at first, implementing good encryption in most languages (in this case vb.net) isn't that hard, with most of the hard work done by the developers of the libraries we use.  And if then wrapped into a simple function or class, only a small amount of code needs to be written.  The following outlines one approach for implementing AES256 within vb.net.

<br>

Firstly, the following needs to go at the top of the module.  This allows us to inherit all of Microsoft's hard work in putting this library together.

```
Imports System.Security.Cryptography
```

<br>

Next, we need our encryption key.  For simplicity here I'll set this as a constant within the module/code (and the code repository should be private if you ever do this).  For AES265 this needs to be 256 bits, so it'll be 32 bytes/characters long.  That's the length of a GUID, so I've used the Visual Studio menu option 'Create GUID' to get a value and taken out any non-alpha characters:

```
Private Const AesKey256 As String = "1C77D4721927421390D663C670DBBC47"
```

<br>

To go with the key, we need an Initialisation Vector (IV).  This needs to be unique for every use of the key, so we'll have a small function that we can use to generate this as required.  We'll use vb's GUID generator, but cut the string down to 16 characters to suit a 128 bit IV.

```
''' <summary>
''' Creates 16 char IV from GUID
''' </summary>
''' <returns>String containing 16 character uniqueish string</returns>

Function GetNewIV()
	Dim newIV As String = System.Guid.NewGuid.ToString()
    ' the guid generated above will have dashes - remove them...
	newIV = Replace(newIV, "-", "")   
    Return Left(newIV, 16)
End Function
```

>Side note: Generally we will store the IV alongside the encrypted data. The IV does NOT need to be secret - only the key needs to be kept secret, so we can store an unencrypted IV, and this is also necessary to be able to decrypt the data in question.  The IV's purpose is to perform an initial scrambling of data prior to encryption, so using a unique IV on every use ensures that if (say) two different fields/values are the same, their encrypted values are not.  

>Even if the (unique) IV is known it is still computationally infeasible to decrypt by brute force as long as the key remains secret.  However, if the same IV were used - even if kept secret - the data can be potentially subject to brute force attack, as commonly used values such as 'password123' or 'chris' will have the same cyphertext.     
<br>
Next we'll create an encryption function to actually perform the encryption using the library from .net that we imported earlier.  The expected usage here is that the encrypted value will end up in a database, so the function will return a string containing the IV at the start followed by the encrypted value.  Doing this allows us to easily have a unique IV (see note above) and also to decrypt.
<br>
<br>

>Note: the block size of 128 (AES default) and Keysize of 256 which tells .net we want to use AES256.  
>Note: The selected mode of CBC here is no longer typically used but at the very least don't use ECB mode.  

```
''' <summary>
''' Encrypts the provided string using AES256 encryption
''' </summary>
''' <returns>String containing a unique IV, delimited with *, followed by the ciphertext</returns>

Function Encrypt256(_thestring As String)
     If _thestring = "" Then Return ""

	' setup for encryption
     Dim AesCrypto As New AesCryptoServiceProvider()
     With AesCrypto
     	.BlockSize = 128
     	.KeySize = 256
     	.Mode = CipherMode.CBC
     	.Padding = PaddingMode.PKCS7

		' set the key
		.Key = Encoding.UTF8.GetBytes(AesKey256)

		' get a unique IV
     	Dim _iv As String = GetNewIV()
     	.IV = Encoding.UTF8.GetBytes(_iv)
     End With 

     ' encrypt
     Dim SrcText() As Byte
     SrcText = Encoding.Unicode.GetBytes(_thestring)
     Dim Encrypt = AesCrypto.CreateEncryptor()
     Dim DestText() As Byte
     DestText = Encrypt.TransformFinalBlock(SrcText, 0, SrcText.Length)

	' return the IV (with * delimiters) plus ciphertext
     Return "*" + _iv + "*" + Convert.ToBase64String(DestText)
End Function

```

<br>

Lastly, we need a decrypt function.  We have the same setup as above.  Note that we read in our IV from the provided string for use, but we only ever output the plain text here. 

```
''' <summary>
''' Decrypts the provided string using AES256
''' </summary>
''' <param name="_thestring">String to decrypt, consisting of 16 char plaintext IV delimited with *, followed by the ciphertext</param>
''' <returns>String containing the decrypted text</returns>

Function Decrypt256(_thestring As String)
	If _thestring = "" Or IsNothing(_thestring) Or IsDBNull(_thestring)
		Then Return ""

	' parse the input string for our IV and ciphertext
     Dim _ctext As String = Mid(_thestring, 19)
     Dim _iv As String = Mid(_thestring, 2, 16)

	' setup for decrypt
     Dim AesCrypto As New AesCryptoServiceProvider()
     With AesCrypto
		.BlockSize = 128
     	.KeySize = 256
     	.Mode = CipherMode.CBC
     	.Padding = PaddingMode.PKCS7
     	.IV = Encoding.UTF8.GetBytes(_iv)
     	.Key = Encoding.UTF8.GetBytes(AesKey256)
     End With

	' decrypt
     Dim SrcText() As Byte
     Dim DestText() As Byte

     Try
         SrcText = System.Convert.FromBase64String(_ctext)
         Dim Decrypt = AesCrypto.CreateDecryptor()
         DestText = 
			Decrypt.TransformFinalBlock(SrcText, 0, SrcText.Length)
      Catch
		' if we can't decrypt, return the original string
         DestText = System.Text.Encoding.Unicode.GetBytes(_ctext)
       End Try

     ' Note - only ever return the plain text, not the IV portion 
     Return Encoding.Unicode.GetString(DestText)
End Function
```

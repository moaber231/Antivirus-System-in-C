import "hash"
rule KOZALI_BEAR : KOZALI
{
meta:
description = "This is just an example"
threat_level = 3
in_the_wild = true
strings:
$a = {98 1d 00 00 ec 33 ff ff 06 00 00 00 46 0e 10}
$b = "bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6"
condition:
$a or $b or 
hash.md5(0, filesize) == "85578cd4404c6d586cd0ae1b36c98aca" or
hash.sha256(0, filesize) == "d56d67f2c43411d966525b3250bfaa1a85db34bf371468df1b6a9882fee78849"   
}
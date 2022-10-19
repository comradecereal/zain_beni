rule zain_bani_malware_weird_encoding 
{
meta:
    Description = "Detection of the Zain Beni file that has a weird encoding, The function always starts with MHaJ1 in the samples I've seen "

strings:
    $a = "I could not have a more welcome visitor 64 group of zain bani"
    $b = "MHaJ1"
condition:
        $a and $b
}

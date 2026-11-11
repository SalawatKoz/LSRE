// Правила LSRE (MIT). Только общеизвестные константы и строки — ничего чужого.
// Движок: YARA-X (BSD-3), bin: yr.exe

rule crypto_aes_sbox
{
  meta:
    category = "cryptography"
    description = "Таблица S-Box AES (256 байт)"
    license = "MIT"
  strings:
    $sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
  condition:
    $sbox
}

rule crypto_sha256_k
{
  meta:
    category = "cryptography"
    description = "Константы SHA-256 (первые слова K)"
    license = "MIT"
  strings:
    $k = { 42 8A 2F 98 D7 28 AE 22 70 38 34 2C }
  condition:
    $k
}

rule crypto_md5_init
{
  meta:
    category = "cryptography"
    description = "Инициализация MD5 (0x67452301, 0xefcdab89)"
    license = "MIT"
  strings:
    $init = { 01 23 45 67 89 AB CD EF }
  condition:
    $init
}

rule crypto_base64_table
{
  meta:
    category = "cryptography"
    description = "Стандартная таблица Base64"
    license = "MIT"
  strings:
    $table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  condition:
    $table
}

rule packer_upx_sections
{
  meta:
    category = "packer"
    description = "Секции UPX в заголовке"
    license = "MIT"
  strings:
    $upx0 = "UPX0"
    $upx1 = "UPX1"
  condition:
    $upx0 or $upx1
}

rule packer_mpress_section
{
  meta:
    category = "packer"
    description = "Секция MPRESS"
    license = "MIT"
  strings:
    $mpress = ".MPRESS1"
  condition:
    $mpress
}

rule antidebug_winapi_strings
{
  meta:
    category = "anti_analysis"
    description = "Строки типовых анти-отладочных вызовов"
    license = "MIT"
  strings:
    $a1 = "IsDebuggerPresent"
    $a2 = "CheckRemoteDebuggerPresent"
    $a3 = "NtQueryInformationProcess"
    $a4 = "OutputDebugString"
  condition:
    2 of them
}

rule library_zlib_header
{
  meta:
    category = "library"
    description = "Строка версии zlib"
    license = "MIT"
  strings:
    $z = "inflate 1." ascii
  condition:
    $z
}

rule library_openssl_strings
{
  meta:
    category = "library"
    description = "Признаки статически вкомпилированного OpenSSL"
    license = "MIT"
  strings:
    $o1 = "OpenSSL 1." ascii
    $o2 = "OpenSSL 3." ascii
    $o3 = "SSL_CTX_new" ascii
  condition:
    any of them
}

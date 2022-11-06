declare module 'react-native-aes-crypto' {

  function aesEncrypt(
    inputBase: string,
    ivBase: string|null,
    keyBase: string,
  ): Promise<string>
  function aesDecrypt(
    cipherBase: string,
    ivBase: string,
    keyBase: string,
  ): Promise<string>

  function pbkdf2(
    inputBase: string,
    saltBase: string,
    iterations: number,
    bitCount: number,
  ): Promise<string>

  function hmac256(
    inputBase: string,
    keyBase: string,
  ): Promise<string>
  function hmac512(
    inputBase: string,
    keyBase: string,
  ): Promise<string>

  function sha1(inputBase: string): Promise<string>
  function sha256(inputBase: string): Promise<string>
  function sha512(inputBase: string): Promise<string>

  function csprng(byteCount: number): Promise<string>
  function uuid(): Promise<string>

}

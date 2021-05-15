declare module 'react-native-aes-crypto' {

  function encrypt(
    inputBase: string,
    keyBase: string,
    ivBase: string|null,
  ): Promise<string>
  function decrypt(
    cipherBase: string,
    keyBase: string,
    ivBase: string,
  ): Promise<string>

  function pbkdf2(
    inputBase: string,
    saltBase: string,
    iterations: number,
    byteCount: number,
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

  function randomUuid(): Promise<string>
  function randomKey(byteCount: number): Promise<string>

}

require "base64"
require "openssl"
require "json"

@cipher = 'aes-128-gcm'
credentials = File.read("config/credentials.yml.enc")
@key = [File.read("config/master.key")].pack("H*")
puts @key.length

def new_cipher
  OpenSSL::Cipher.new(@cipher)
end

def decrypt(value)
  cipher = new_cipher
  encrypted_data, iv, auth_tag = value.split("--".freeze).map { |v| ::Base64.strict_decode64(v) }

  cipher.decrypt
  cipher.key = @key
  cipher.iv  = iv
  cipher.auth_tag = auth_tag
  cipher.auth_data = ""

  decrypted_data = cipher.update(encrypted_data)
  decrypted_data << cipher.final
  return decrypted_data
end

decrypted = decrypt(credentials)
puts decrypted
